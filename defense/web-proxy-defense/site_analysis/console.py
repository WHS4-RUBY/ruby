"""Local web console: one screen that walks through environment, AI connection, cost, target, an optional
ordinary-account session, a run with live progress and the result counts of one analysis.

python -B -m site_analysis.console [--port N] [--open]
"""
import argparse
from collections import Counter, deque
from decimal import Decimal
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from . import status
from .analyze import parser as analyzer_parser
from .model import Codex, cost_settings
from .observer import authority, session_summary
from .record import PACKAGE, PRIVATE, write_json
from .resume import checkpoint_path, owner_only
from .session_prepare import session_path, settings as login_settings

WORKDIR = PACKAGE.parent
RECORDS = PRIVATE / 'site-analysis'
STALL_MINUTES = 20
DRY_SECONDS = 900
SESSION_CHECK_SECONDS = 120
FIELDS = ('origin', 'name', 'proxy', 'allow_origins', 'runs', 'session_runs', 'session_file', 'provider', 'model',
          'rates', 'max_cost', 'context_chars', 'max_pages')
# Empty values are not passed, so the analyzer default applies.
FLAGS = {'runs': '--runs', 'session_runs': '--session-runs', 'session_file': '--session-file',
         'provider': '--provider', 'model': '--model', 'rates': '--rates', 'max_cost': '--max-cost-usd',
         'context_chars': '--context-chars', 'max_pages': '--max-pages'}
NAME = re.compile(r'\w[\w.-]{0,79}')  # never starts with '-', so no name reads like an option
NAME_ERROR = ('기록 이름은 글자, 숫자, 밑줄로 시작하고 글자, 숫자, 점, 밑줄, 붙임표로 80자 이하이며 CON, NUL 같은 '
              'Windows 예약 이름이거나 점으로 끝나면 안 됨')
# ASCII only: \d and \w also match other scripts' digits and letters.
MODEL = re.compile(r'[A-Za-z0-9][\w.:/-]{0,79}', re.ASCII)
INTEGER = re.compile(r'[0-9]{1,9}')
NUMBER = re.compile(r'[0-9]{1,9}(\.[0-9]{1,6})?')
PROVIDERS = ('codex', 'claude')
LOGGED_IN = ('subscription', 'api_key', 'yes')
LOGIN_FILE, ACCOUNT_FILE = 'session-login.json', 'account.json'
ACCOUNT_KEYS = ('username', 'email')
TARGET_KINDS = ('field', 'selector')
AXIS_STATES = ('관찰됨', '없음', '사례 부족', '못 봄')
FINDING_LABELS = ('both-runs', 'single-run', 'contradictory')
STAGES = ('browse', 'analysis', 'privacy')
DOCS = {'records': RECORDS, 'outputs': PACKAGE / 'OUTPUTS.md', 'integration': PACKAGE / 'INTEGRATION.md',
        'readme': PACKAGE / 'README.md'}
RATE_FIELDS = {'input': '입력 단가', 'cached_input': '캐시 입력 단가', 'output': '출력 단가',
               'long_input': '장문 입력 단가', 'long_cached_input': '장문 캐시 입력 단가', 'long_output': '장문 출력 단가',
               'threshold': '장문 임계 토큰 수', 'max_cost': '전체 비용 상한'}
RATES_COMMENT = ('콘솔 3단계에서 저장한 단가. 100만 토큰당 달러이며 운영자가 제공자 가격 페이지에서 확인한 값이다. '
                 'long은 입력 토큰이 long_input_threshold_tokens를 넘는 호출의 단가, max_cost_usd는 웹 하나 분석 전체의 상한이다.')
EXIT = {0: '모든 단계 끝남', 2: '실패했거나 남은 단계가 있음. 원인을 고친 뒤 같은 설정으로 점검하고 시작하면 체크포인트에서 이어서 돈다',
        130: '중단됨'}
# Analyzer lines that say why it stopped (analyze.main, Observer.report_model_error, argparse).
FAILURE_PREFIXES = ('분석 실패:', 'dry-run 검사 실패:', '못 얻음:', '중단됨')
GROUP = ({'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True})
BROWSER_PROBE = ('from playwright.sync_api import sync_playwright\n'
                 'with sync_playwright() as playwright:\n'
                 '    browser = playwright.chromium.launch(headless=True)\n'
                 '    print(browser.version)\n'
                 '    browser.close()\n')
# A fresh interpreter, so a package installed after the console started is seen.
VERSION_PROBE = ('import importlib.metadata as metadata\n'
                 'try:\n'
                 '    print(metadata.version("playwright"))\n'
                 'except metadata.PackageNotFoundError:\n'
                 '    pass\n')
# One tiny call through the analyzer's own model wrapper. Without saved prices it counts tokens only.
CONNECTION_PROBE = '''import asyncio, json, sys
from decimal import Decimal
from pathlib import Path
from site_analysis.model import Codex, ModelError, cost_settings
provider, model, rates, folder = sys.argv[1:5]
rate, priced = {'base': {'input': 0, 'cached_input': 0, 'output': 0}}, False
if rates:
    try:
        rate, _ = cost_settings(Path(rates), model, '1')
        priced = True
    except Exception:
        pass
client = Codex(model, 180, Path(folder), rate=rate, ceiling=Decimal(1), provider=provider)
schema = {'type': 'object', 'properties': {'ok': {'type': 'boolean'}}, 'required': ['ok']}
print('모델 호출 시작: ' + provider + ', ' + model + (', 저장한 단가로 비용 계산' if priced else ', 단가 없음: 토큰 수만 셈'),
      flush=True)
error = None
try:
    asyncio.run(client.call('connection_check', 'Connection check only. Reply with the JSON object {"ok": true}.',
                            {}, schema, retry=False))
except ModelError as caught:
    error = caught.code
row = client.calls[-1] if client.calls else {}
usage = row.get('usage') if isinstance(row.get('usage'), dict) else {}
print('RESULT ' + json.dumps({'error': error, 'priced': priced, 'provider': provider, 'usd': row.get('usd'),
                              'usd_estimated': bool(row.get('usd_estimated')), 'seconds': row.get('elapsed_seconds'),
                              'usage': {key: value for key, value in usage.items() if type(value) is int}}), flush=True)
sys.exit(0 if error is None else 2)
'''
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?')
TASK_LABELS = {'playwright': 'Playwright 설치', 'chromium': '브라우저 설치', 'codex-install': 'Codex CLI 설치',
               'codex-login': '구독으로 로그인', 'codex-key': 'API 키로 로그인', 'claude-login': 'Claude 로그인',
               'connection': '연결 시험', 'session': '세션 준비'}
TASK_GROUPS = {'playwright': 'env', 'chromium': 'env', 'codex-install': 'ai', 'codex-login': 'ai', 'codex-key': 'ai',
               'claude-login': 'ai', 'connection': 'ai', 'session': 'session'}
CODEX_PACKAGE = '@openai/codex'
# `claude auth login --help`: the Claude subscription is the default, --console bills Anthropic Console API usage.
CLAUDE_METHODS = {'claudeai': [], 'console': ['--console']}
CLI_HINTS = {'codex': 'Codex CLI 설치 버튼을 누른다(npm 패키지 @openai/codex를 전역 설치)',
             'codex-npm': 'npm이 없어 이 화면에서 설치할 수 없다. nodejs.org에서 Node.js LTS를 설치한 뒤 콘솔 창을 닫고 '
                          'run-console.cmd로 다시 연다',
             'codex-path': '설치는 끝났지만 PATH에서 codex를 찾지 못함. 콘솔 창을 닫고 run-console.cmd로 다시 열면 PATH를 새로 읽는다',
             'claude': 'Claude Code CLI를 공식 설치 안내대로 설치한다. 설치한 뒤 콘솔을 다시 열어야 PATH를 새로 읽는다'}
STOP_REASONS = {'cost_budget': '비용 상한 도달', 'cost_usage_unknown': '사용량을 알 수 없는 호출',
                'provider_start_failed': 'AI CLI 시작 실패 반복', 'same_failure_limit': '같은 실패 반복 상한',
                'time_budget': '시간 예산 소진', 'operator_session_expired': '세션 만료'}
JOBS, TASKS, CHECKED, ENV, AI = {}, {}, {}, {}, {}
LOCK = threading.Lock()


class ConsoleError(Exception):
    pass


class Job:
    def __init__(self, values, process, log):
        self.values, self.process, self.log = values, process, log
        self.started, self.stopped = time.time(), False


class Task:
    """A short helper process (install, login, connection check, session) whose output the page streams."""

    def __init__(self, kind, process, hidden=()):
        self.kind, self.process, self.hidden = kind, process, tuple(value for value in hidden if value)
        self.lines, self.started = deque(maxlen=400), time.time()
        self.code, self.cancelled, self.result = None, False, None

    def add(self, chunks):
        for chunk in chunks:
            line = scrub(chunk.decode('utf-8', 'replace'), self.hidden).rstrip()
            if not line.strip():
                continue
            if self.kind == 'connection' and line.startswith('RESULT '):
                try:
                    self.result = json.loads(line[7:])
                except ValueError:
                    pass
                continue
            with LOCK:
                self.lines.append(line)

    def finish(self, code):
        # The API key is kept only while its login process can still print.
        self.code, self.hidden = code, ()


def clock(moment=None):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(moment))


def private_root():
    # Same private base as the checkpoints, including the non-Windows fallback.
    return checkpoint_path('console', '').parent


def private_dir(*parts):
    """A folder under the private base; folders this console creates are owner-only."""
    folder = private_root()
    if not folder.is_dir():
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        owner_only(folder)
    for part in parts:
        folder = folder / part
        if not folder.is_dir():
            folder.mkdir(exist_ok=True, mode=0o700)
            owner_only(folder)
    return folder


def console_folder():
    folder = private_dir('console')
    owner_only(folder)
    return folder


def account_folder(name, create=False):
    if not create:
        return private_root() / 'accounts' / name
    folder = private_dir('accounts', name)
    owner_only(folder)
    return folder


def default_session(name):
    return private_root() / 'sessions' / (name + '.json')


def rates_file():
    return console_folder() / 'rates.json'


def record_path(name):
    return RECORDS / (name + '.json')


def log_path(name):
    return console_folder() / (name + '.log')


def local_path(value):
    path = Path(os.path.expandvars(value)).expanduser()
    return path if path.is_absolute() else WORKDIR / path


def normal_origin(origin):
    part = urlsplit(origin)
    return part._replace(path=part.path or '/').geturl()


def shown_url(value):
    """A URL without user name or password, for display."""
    try:
        part = urlsplit(value)
        host, port = part.hostname or '', f':{part.port}' if part.port else ''
    except ValueError:
        return '해석 못 함'
    host = f'[{host}]' if ':' in host else host
    return part._replace(netloc=host + port).geturl()


def defaults():
    parser = analyzer_parser()
    return {'origin': '', 'name': '', 'proxy': os.environ.get('SITE_ANALYSIS_PROXY', ''), 'allow_origins': '',
            'runs': str(parser.get_default('runs')), 'session_runs': str(parser.get_default('session_runs')),
            'session_file': '', 'provider': parser.get_default('provider'), 'model': parser.get_default('model'),
            'rates': '', 'max_cost': '', 'context_chars': '', 'max_pages': ''}


def without_userinfo(value):
    """The address with any user name and password removed from its authority part."""
    try:
        part = urlsplit(value)
    except ValueError:
        return '' if '@' in value else value
    return part._replace(netloc=part.netloc.rpartition('@')[2]).geturl() if '@' in part.netloc else value


def settings_only(values):
    """Settings as saved and sent to the page: an address never carries a user name or password."""
    values = dict(values)
    values['origin'] = without_userinfo(values['origin'])
    proxy = without_userinfo(values['proxy'])
    values['proxy'] = '' if '@' in proxy else proxy  # e.g. 'user:pw@relay:8080' typed without a scheme
    values['allow_origins'] = '\n'.join(without_userinfo(line) for line in values['allow_origins'].splitlines())
    return values


def load_settings():
    path = console_folder() / 'settings.json'
    base = defaults()
    try:
        saved = json.loads(path.read_text(encoding='utf-8-sig')) if path.exists() else {}
    except ValueError:
        saved = {}
    return settings_only({key: str(saved.get(key, base[key])) for key in FIELDS} if isinstance(saved, dict) else base)


def save_settings(values):
    write_json(console_folder() / 'settings.json', settings_only(values), private=True)


def control(text):
    return any(ord(char) < 32 or ord(char) == 127 for char in text)


def loose(body):
    values = {key: str(body.get(key, '')).strip() for key in FIELDS}
    # Extra origins are one per line; every other value is a single line.
    values['allow_origins'] = '\n'.join(line.strip() for line in values['allow_origins'].splitlines() if line.strip())
    if any(control(value.replace('\n', '') if key == 'allow_origins' else value) for key, value in values.items()):
        raise ConsoleError('입력값에 줄바꿈이나 제어 문자를 넣을 수 없음')
    return values


def valid_name(name):
    reserved = getattr(os.path, 'isreserved', None)  # Windows only, Python 3.13+
    return bool(NAME.fullmatch(name)) and not (reserved and (reserved(name) or reserved(name + '.json')))


def check_name(value):
    name = str(value or '').strip().removesuffix('.json')
    if not name:
        raise ConsoleError('4단계에서 기록 이름을 넣는다. 예: target-analysis-1')
    if not valid_name(name):
        raise ConsoleError(NAME_ERROR)
    return name


def check_origin(value):
    if not value:
        raise ConsoleError('4단계에서 대상 주소를 넣는다. 예: http://target.test/')
    try:
        part = urlsplit(value)
        part.port
    except ValueError:
        raise ConsoleError('대상 주소의 포트가 잘못됨') from None
    if (part.scheme not in ('http', 'https') or not part.hostname
            or part.username is not None or part.password is not None):
        raise ConsoleError('대상 주소는 자격 값 없는 http 또는 https 주소여야 함')
    return normal_origin(value)


def check_relay(value):
    if not value:
        return ''
    try:
        part = urlsplit(value)
        part.port
    except ValueError:
        raise ConsoleError('중계 주소의 포트가 잘못됨') from None
    if part.scheme not in ('http', 'https', 'socks5') or not part.hostname:
        raise ConsoleError('중계 주소는 http, https 또는 socks5 주소여야 함')
    if part.username is not None or part.password is not None:
        raise ConsoleError('중계 주소에는 사용자 이름이나 비밀번호를 넣을 수 없음(콘솔은 인증 값을 저장하지 않는다). '
                           '인증 없는 중계 주소를 넣는다')
    return value


def extra_origins(text):
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        try:
            part = urlsplit(line)
            part.port
        except ValueError:
            raise ConsoleError(f'추가 출처 {number}번째 줄의 포트가 잘못됨') from None
        if (part.scheme not in ('http', 'https') or not part.hostname or part.username is not None
                or part.password is not None or part.path not in ('', '/') or part.query or part.fragment):
            raise ConsoleError(f'추가 출처 {number}번째 줄: 경로 없는 http 또는 https 주소를 한 줄에 하나씩 넣는다')
        found.append(f'{part.scheme}://{part.netloc}')
    if len(found) > 20:
        raise ConsoleError('추가 출처는 20개까지')
    return found


def check_provider(value):
    if value not in PROVIDERS:
        raise ConsoleError('제공자는 codex 또는 claude')
    return value


def check_model(value):
    # The provider CLI may be a .cmd file, so keep shell metacharacters out of the model name.
    if not MODEL.fullmatch(value or ''):
        raise ConsoleError('모델 이름은 영문, 숫자, 점, 밑줄, 콜론, 빗금, 붙임표만 쓴다')
    return value


def target_values(values):
    check_origin(values['origin'])
    check_relay(values['proxy'])
    extra_origins(values['allow_origins'])
    check_name(values['name'])


def clean(body):
    values = loose(body)
    values['name'] = check_name(values['name'])
    check_origin(values['origin'])
    check_relay(values['proxy'])
    values['allow_origins'] = '\n'.join(extra_origins(values['allow_origins']))
    for key in ('runs', 'session_runs', 'context_chars', 'max_pages'):
        if values[key] and not INTEGER.fullmatch(values[key]):
            raise ConsoleError(f'{FLAGS[key]} 값은 0 이상 정수여야 함')
    if values['max_cost'] and not NUMBER.fullmatch(values['max_cost']):
        raise ConsoleError('비용 상한은 숫자여야 함')
    check_provider(values['provider'])
    check_model(values['model'])
    if values['session_runs'] not in ('', '0') and not values['session_file']:
        values['session_file'] = str(default_session(values['name']))
    return values


def signature(values):
    return json.dumps(values, sort_keys=True, ensure_ascii=False)


def analyzer_argv(values, dry_run=False):
    argv = [sys.executable, '-B', '-m', 'site_analysis.analyze',
            '--origin-url', values['origin'], '--out', str(record_path(values['name']))]
    session = values['session_runs'] not in ('', '0')
    for key, flag in FLAGS.items():
        value = values[key]
        if key == 'session_file' and not session:
            continue  # the analyzer refuses a named session file that does not exist yet
        if value and key in ('session_file', 'rates'):
            value = str(local_path(value))
        if value:
            argv += [flag, value]
    for origin in values['allow_origins'].splitlines():
        argv += ['--allow-origin', origin]
    return argv + (['--dry-run'] if dry_run else [])


def child_env(values=None):
    env = {key: value for key, value in os.environ.items() if key != 'SITE_ANALYSIS_PROXY'}
    if values and values['proxy']:
        env['SITE_ANALYSIS_PROXY'] = values['proxy']
    env.update(PYTHONIOENCODING='utf-8', PYTHONUNBUFFERED='1', NO_COLOR='1')
    return env


def quiet(argv, timeout):
    return subprocess.run(argv, cwd=WORKDIR, env=child_env(), stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, encoding='utf-8', errors='replace', timeout=timeout)


def row(name, ok, detail, hint=''):
    return {'name': name, 'ok': ok, 'detail': detail, 'hint': '' if ok else hint}


# Step 1: environment.

def chromium_row():
    install = '브라우저 설치 버튼을 누른다'
    try:
        result = quiet([sys.executable, '-B', '-c', BROWSER_PROBE], 90)
    except subprocess.TimeoutExpired:
        return row('Chromium', False, '헤드리스 실행이 90초 안에 끝나지 않음', install)
    except OSError as error:
        return row('Chromium', False, f'확인 프로세스를 띄우지 못함({type(error).__name__})', install)
    if result.returncode:
        reason = ([line for line in result.stderr.splitlines() if line.strip() and line.strip()[0] not in '╔║╚']
                  or ['원인 출력 없음'])[-1]
        return row('Chromium', False, '헤드리스 실행 실패: ' + reason[:200], install)
    return row('Chromium', True, '헤드리스 실행 확인, 버전 ' + result.stdout.strip()[-40:])


def environment(_body):
    rows = [row('Python', sys.version_info >= (3, 13), f'{platform.python_version()} ({sys.executable})',
                'python.org에서 Python 3.13 이상을 설치한 뒤 그 Python으로 콘솔을 다시 연다. 이 화면에서는 설치할 수 없다')]
    try:
        found = quiet([sys.executable, '-B', '-c', VERSION_PROBE], 60)
        version = found.stdout.strip().splitlines()[-1][:40] if found.returncode == 0 and found.stdout.strip() else ''
    except (OSError, subprocess.TimeoutExpired):
        version = ''
    if version:
        rows += [row('Playwright', True, '패키지 ' + version), chromium_row()]
    else:
        rows += [row('Playwright', False, '설치 안 됨', 'Playwright 설치 버튼을 누른다'),
                 row('Chromium', False, 'Playwright가 없어 확인 못 함', 'Playwright를 설치한 뒤 브라우저 설치 버튼을 누른다')]
    with LOCK:
        ENV.update(rows=rows, checked=clock())
        return {'rows': rows, 'checked': ENV['checked']}


# Step 2: AI connection.

def cli_path(provider):
    # Same lookup as model.Codex._call, so a CLI found here is the one the analyzer runs.
    executable = shutil.which(provider + '.cmd' if os.name == 'nt' else provider)
    if provider == 'claude' and not executable:
        executable = shutil.which('claude')
    return executable


def npm_path():
    return shutil.which('npm.cmd' if os.name == 'nt' else 'npm')


def cli_version(executable):
    try:
        result = quiet([executable, '--version'], 30)
    except (OSError, subprocess.TimeoutExpired):
        return '버전 확인 실패'
    return (result.stdout.strip().splitlines() or ['버전 출력 없음'])[0][:80]


def codex_login(executable):
    # `codex login status` names the method; with an API key it also prints part of the key, so only a fixed
    # message derived from it reaches the page.
    try:
        result = quiet([executable, 'login', 'status'], 30)
    except (OSError, subprocess.TimeoutExpired) as error:
        return {'login': 'unknown', 'login_text': f'로그인 상태를 읽지 못함({type(error).__name__})'}
    text = result.stdout + result.stderr
    if result.returncode == 0:
        if 'ChatGPT' in text:
            return {'login': 'subscription', 'login_text': '구독(ChatGPT 계정)으로 로그인됨'}
        if 'API key' in text:
            return {'login': 'api_key', 'login_text': 'API 키로 로그인됨'}
        return {'login': 'yes', 'login_text': '로그인됨(방식은 CLI가 밝히지 않음)'}
    if 'Not logged in' in text:
        return {'login': 'none', 'login_text': '로그인 안 됨'}
    return {'login': 'unknown', 'login_text': f'로그인 상태를 읽지 못함(종료 코드 {result.returncode})'}


def claude_login(executable):
    # `claude auth status --json` also carries the e-mail and organization; only the flag and method are kept.
    try:
        result = quiet([executable, 'auth', 'status', '--json'], 30)
        data = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        return {'login': 'unknown', 'login_text': f'로그인 상태를 읽지 못함({type(error).__name__})'}
    if not isinstance(data, dict) or not isinstance(data.get('loggedIn'), bool):
        return {'login': 'unknown', 'login_text': '로그인 상태 형식을 읽지 못함'}
    if not data['loggedIn']:
        return {'login': 'none', 'login_text': '로그인 안 됨'}
    method = data.get('authMethod')
    method = method if isinstance(method, str) and re.fullmatch(r'[\w.-]{1,40}', method) else '표시 없음'
    return {'login': 'yes', 'login_text': f'로그인됨(방식 {method})'}


def ai_check(body):
    provider = check_provider(str(body.get('provider', '')))
    executable = cli_path(provider)
    view = {'provider': provider, 'found': bool(executable), 'path': executable or '', 'version': '',
            'login': 'none', 'login_text': 'CLI가 없어 확인 못 함', 'hint': '', 'checked': clock(),
            'npm': provider == 'codex' and bool(npm_path())}
    if not executable:
        with LOCK:
            installed = TASKS.get('codex-install')
            installed = installed is not None and installed.code == 0
        view['hint'] = (CLI_HINTS[provider] if provider == 'claude' else CLI_HINTS['codex-path'] if installed
                        else CLI_HINTS['codex'] if view['npm'] else CLI_HINTS['codex-npm'])
    else:
        view['version'] = cli_version(executable)
        view.update(codex_login(executable) if provider == 'codex' else claude_login(executable))
    with LOCK:
        AI[provider] = view
    return view


# Helper processes whose output the page streams.

def scrub(text, hidden):
    text = ANSI.sub('', text)
    for value in hidden:
        text = text.replace(value, '<가림>')
    return ''.join(char for char in text if char == '\t' or not control(char))[:2000]


def pump(task):
    stream, pending = task.process.stdout, b''
    try:
        while True:
            try:
                chunk = stream.read1(65536)
            except (OSError, ValueError):
                chunk = b''
            if not chunk:
                break
            parts = re.split(rb'\r\n|\r|\n', pending + chunk)
            pending = parts.pop()
            if len(pending) > 65536:
                parts.append(pending)
                pending = b''
            task.add(parts)
        if pending:
            task.add([pending])
    finally:
        code = task.process.wait()
        if task.process.stdin is not None:
            try:
                task.process.stdin.close()
            except OSError:
                pass
        task.finish(code)


def launch(kind, argv, env=None, stdin_text=None, hidden=(), keep_stdin=False):
    with LOCK:
        for other in TASKS.values():
            if TASK_GROUPS[other.kind] == TASK_GROUPS[kind] and other.code is None:
                raise ConsoleError(f'{TASK_LABELS[other.kind]} 작업이 아직 실행 중임. 끝나거나 취소한 뒤 다시 누른다')
        try:
            process = subprocess.Popen(argv, cwd=WORKDIR, env=env or child_env(),
                                       stdin=subprocess.PIPE if keep_stdin or stdin_text is not None
                                       else subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, **GROUP)
        except OSError as error:
            raise ConsoleError(f'{TASK_LABELS[kind]} 프로세스를 띄우지 못함({type(error).__name__})') from None
        task = TASKS[kind] = Task(kind, process, hidden)
    threading.Thread(target=pump, args=(task,), daemon=True).start()
    # keep_stdin leaves standard input open for lines the page sends later (task_input).
    if stdin_text is not None:
        # Standard input only: the value never appears on a command line, in settings or in a log.
        try:
            process.stdin.write(stdin_text.encode('utf-8'))
            process.stdin.close()
        except OSError:
            pass
    return task_view(kind)


def task_view(kind):
    with LOCK:
        task = TASKS.get(kind)
        lines = list(task.lines)[-200:] if task else []
    if task is None:
        return {'kind': kind, 'label': TASK_LABELS.get(kind, kind), 'exists': False, 'running': False}
    return {'kind': kind, 'label': TASK_LABELS[kind], 'exists': True, 'running': task.code is None,
            'code': task.code, 'cancelled': task.cancelled, 'started': clock(task.started), 'lines': lines,
            'result': task.result}


def task_kind(body):
    kind = str(body.get('kind', ''))
    if kind not in TASK_LABELS:
        raise ConsoleError('없는 작업')
    return kind


def task_get(body):
    return task_view(task_kind(body))


def task_cancel(body):
    kind = task_kind(body)
    with LOCK:
        task = TASKS.get(kind)
        if task is None or task.process.poll() is not None:
            raise ConsoleError('실행 중인 작업이 없음')
        task.cancelled = True
    try:
        kill_tree(task.process)
    except subprocess.TimeoutExpired:
        raise ConsoleError('작업 프로세스가 30초 안에 끝나지 않음') from None
    return task_view(kind)


def task_input(body):
    """One line for a running Claude login: the code its browser page shows when the browser could not reach
    the CLI's local callback. It goes only to that process's standard input and is hidden in its output."""
    kind = task_kind(body)
    if kind != 'claude-login':
        raise ConsoleError('이 작업에는 입력을 보낼 수 없음')
    code = body.get('code')
    code = code.strip() if isinstance(code, str) else ''
    if not code:
        raise ConsoleError('코드 칸이 비어 있음')
    if len(code) > 1024 or any(char.isspace() or control(char) for char in code):
        raise ConsoleError('코드에 공백, 줄바꿈이나 제어 문자가 있음. 브라우저에 나온 코드를 그대로 붙여 넣는다')
    with LOCK:
        task = TASKS.get(kind)
        if task is None or task.code is not None or task.process.stdin is None:
            raise ConsoleError('실행 중인 Claude 로그인이 없음. Claude 로그인을 먼저 누른다')
        task.hidden += (code,)
    try:
        task.process.stdin.write((code + '\n').encode('utf-8'))
        task.process.stdin.flush()
    except (OSError, ValueError):
        raise ConsoleError('로그인 프로세스에 코드를 넘기지 못함. 프로세스가 이미 끝났을 수 있다') from None
    return task_view(kind)


def task_start(body):
    kind = task_kind(body)
    if kind == 'playwright':
        return launch(kind, [sys.executable, '-m', 'pip', 'install', 'playwright'])
    if kind == 'chromium':
        return launch(kind, [sys.executable, '-m', 'playwright', 'install', 'chromium'])
    if kind == 'codex-install':
        if cli_path('codex'):
            raise ConsoleError('Codex CLI가 이미 있음. 로그인 상태 확인을 누른다')
        npm = npm_path()
        if not npm:
            raise ConsoleError(CLI_HINTS['codex-npm'])
        return launch(kind, [npm, 'install', '--global', CODEX_PACKAGE])
    if kind in ('codex-login', 'codex-key'):
        executable = cli_path('codex')
        if not executable:
            raise ConsoleError('PATH에서 Codex CLI를 찾지 못함. ' + CLI_HINTS['codex'])
        if kind == 'codex-login':
            return launch(kind, [executable, 'login'])
        key = body.get('api_key')
        key = key.strip() if isinstance(key, str) else ''
        if not key:
            raise ConsoleError('API 키 칸이 비어 있음')
        if len(key) > 512 or any(char.isspace() or control(char) for char in key):
            raise ConsoleError('API 키에 공백, 줄바꿈이나 제어 문자가 있음')
        return launch(kind, [executable, 'login', '--with-api-key'], stdin_text=key + '\n', hidden=(key,))
    if kind == 'claude-login':
        executable = cli_path('claude')
        if not executable:
            raise ConsoleError('PATH에서 Claude CLI를 찾지 못함. ' + CLI_HINTS['claude'])
        method = body.get('method', 'claudeai')
        if not isinstance(method, str) or method not in CLAUDE_METHODS:
            raise ConsoleError('로그인 방식은 Claude 구독 또는 Anthropic Console 중 하나')
        # No terminal needed: the CLI prints the address, opens the browser and waits for its local callback,
        # and it also reads a pasted code from standard input, which therefore stays open.
        return launch(kind, [executable, 'auth', 'login', *CLAUDE_METHODS[method]], keep_stdin=True)
    if kind == 'connection':
        values = loose(body)
        provider, model = check_provider(values['provider']), check_model(values['model'])
        if not cli_path(provider):
            raise ConsoleError(f'PATH에서 {provider} CLI를 찾지 못함')
        rates = str(local_path(values['rates'])) if values['rates'] else ''
        folder = private_dir('console', 'connection-check')
        return launch(kind, [sys.executable, '-B', '-c', CONNECTION_PROBE, provider, model, rates, str(folder)])
    return session_task(body)


# Step 3: cost.

def rates_problem(path, model, shown=None):
    """(None, ceiling) when the analyzer accepts the price file for the model, else (Korean reason, None)."""
    shown = shown or path.name
    try:
        _, ceiling = cost_settings(path, model, None)
    except FileNotFoundError:
        return f'파일 없음: {path}', None
    except UnicodeDecodeError:
        return f'{shown}: UTF-8 텍스트가 아님', None
    except json.JSONDecodeError:
        return f'{shown}: JSON 형식 오류', None
    except ValueError as error:
        return f'{shown}: {error}', None
    except (ArithmeticError, LookupError, TypeError, AttributeError):
        return f'{shown}: 채우지 않았거나 숫자가 아닌 칸이 있음', None
    except OSError as error:
        return f'{shown}: 읽지 못함({type(error).__name__})', None
    return None, ceiling


def read_private_json(path):
    try:
        data = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def plain(value):
    return str(value) if isinstance(value, (str, int, float)) and not isinstance(value, bool) else ''


def rates_get(body):
    model = check_model(str(body.get('model', '')).strip())
    path = rates_file()
    data = read_private_json(path) or {}
    prices = data.get('model_prices') if isinstance(data.get('model_prices'), dict) else {}
    entry = prices.get(model) if isinstance(prices.get(model), dict) else {}
    form = {'max_cost': plain(data.get('max_cost_usd')), 'threshold': plain(entry.get('long_input_threshold_tokens'))}
    for prefix, tier in (('', 'base'), ('long_', 'long')):
        part = entry.get(tier) if isinstance(entry.get(tier), dict) else {}
        for key in ('input', 'cached_input', 'output'):
            form[prefix + key] = plain(part.get(key))
    return {'path': str(path), 'exists': path.is_file(), 'form': form, 'models': sorted(prices)}


def rates_save(body):
    model = check_model(str(body.get('model', '')).strip())
    fields = {}
    for key, label in RATE_FIELDS.items():
        value = str(body.get(key, '')).strip()
        if value and not NUMBER.fullmatch(value):
            raise ConsoleError(f'{label}: 0 이상의 숫자만 넣는다(쉼표 없이, 소수점 아래 6자리까지)')
        fields[key] = value
    missing = [RATE_FIELDS[key] for key in ('input', 'cached_input', 'output', 'max_cost') if not fields[key]]
    if missing:
        raise ConsoleError('채워야 하는 칸: ' + ', '.join(missing))
    if Decimal(fields['max_cost']) <= 0:
        raise ConsoleError('전체 비용 상한은 0보다 커야 함')
    tiers = ('long_input', 'long_cached_input', 'long_output', 'threshold')
    if any(fields[key] for key in tiers) and not all(fields[key] for key in tiers):
        raise ConsoleError('장문 단가를 쓰려면 장문 입력, 장문 캐시 입력, 장문 출력 단가와 임계 토큰 수를 모두 채운다. '
                           '쓰지 않으면 네 칸을 모두 비운다')
    if fields['threshold'] and not INTEGER.fullmatch(fields['threshold']):
        raise ConsoleError('장문 임계 토큰 수는 정수로 넣는다')
    entry = {'base': {key: fields[key] for key in ('input', 'cached_input', 'output')}}
    if fields['threshold']:
        entry['long_input_threshold_tokens'] = fields['threshold']
        entry['long'] = {'input': fields['long_input'], 'cached_input': fields['long_cached_input'],
                         'output': fields['long_output']}
    path = rates_file()
    saved = read_private_json(path) or {}
    prices = saved.get('model_prices') if isinstance(saved.get('model_prices'), dict) else {}
    data = {'_comment': RATES_COMMENT, 'max_cost_usd': fields['max_cost'], 'model_prices': {**prices, model: entry}}
    pending = path.with_name('rates.check.json')
    try:
        write_json(pending, data, private=True)
        # The analyzer's own check decides; the saved file is replaced only when it passes.
        problem, ceiling = rates_problem(pending, model, path.name)
        if problem:
            raise ConsoleError('분석기 단가 검사 실패: ' + problem)
        os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)
    values = load_settings()
    values.update(rates=str(path), max_cost='', model=model)
    save_settings(values)
    return {'path': str(path), 'detail': f'모델 {model}, 비용 상한 {ceiling}달러'}


# Step 4: target.

def connection_reason(error):
    reason = getattr(error, 'reason', error)
    names = {'ConnectionRefusedError': '연결 거부: 중계나 대상이 꺼져 있거나 주소가 틀림',
             'gaierror': '이름을 찾지 못함: 주소의 호스트 이름을 확인한다',
             'TimeoutError': '20초 안에 응답 없음', 'timeout': '20초 안에 응답 없음',
             'SSLCertVerificationError': 'HTTPS 인증서 확인 실패',
             'ConnectionResetError': '연결이 끊김', 'RemoteDisconnected': '응답 없이 연결이 끊김'}
    name = type(reason).__name__
    return names.get(name, '연결 실패') + f'({name})'


def target_check(body):
    values = loose(body)
    origin = check_origin(values['origin'])
    relay = check_relay(values['proxy'])
    extras = extra_origins(values['allow_origins'])
    if relay and urlsplit(relay).scheme == 'socks5':
        raise ConsoleError('socks5 중계는 이 확인에서 쓸 수 없음. 점검과 실행에서는 분석기가 그 중계를 그대로 쓴다')
    scope = {authority(origin), *(authority(item) for item in extras)}

    def inside(url):
        try:
            part = urlsplit(url)
            return (part.scheme in ('http', 'https') and part.username is None and part.password is None
                    and authority(url) in scope)
        except ValueError:
            return False

    hops, refused = [], []

    class Guard(HTTPRedirectHandler):
        def redirect_request(self, request, stream, code, message, headers, new_url):
            # Follow only moves inside the analysis scope, at most five; nothing is sent outside it.
            if not inside(new_url) or len(hops) >= 5:
                refused.append(new_url)
                return None
            hops.append(code)
            return super().redirect_request(request, stream, code, message, headers, new_url)

    opener = build_opener(Guard(), ProxyHandler({'http': relay, 'https': relay} if relay else {}))
    started = time.monotonic()
    try:
        with opener.open(Request(origin, method='GET'), timeout=20) as response:
            code, final = response.status, response.geturl()
    except HTTPError as error:
        code, final = error.code, error.geturl()
        error.close()
    except (URLError, OSError, ValueError) as error:
        raise ConsoleError(connection_reason(error)) from None
    note = ''
    if refused:
        final = refused[-1]
        note = '범위 밖 주소로 이동하라는 응답이라 따라가지 않음' if not inside(final) else '이동이 5번을 넘어 더 따라가지 않음'
    return {'code': code, 'final_url': shown_url(final), 'in_scope': inside(final) and not refused,
            'redirects': len(hops), 'via': ('중계 ' + shown_url(relay)) if relay else '직접',
            'seconds': round(time.monotonic() - started, 2), 'note': note}


# Step 5: ordinary account and session.

def session_target(values):
    return local_path(values['session_file']) if values['session_file'] else default_session(values['name'])


def session_view(path):
    try:
        path = session_path(path)
    except ValueError as error:
        return {'path': str(path), 'exists': False, 'error': str(error)}
    if not path.is_file():
        return {'path': str(path), 'exists': False}
    try:
        summary = session_summary(path)
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
        return {'path': str(path), 'exists': True, 'error': f'세션 파일을 읽지 못함({type(error).__name__})'}
    return {'path': str(path), 'exists': True, 'summary': summary, 'modified': clock(path.stat().st_mtime)}


def account_view(values):
    name = check_name(values['name'])
    folder = account_folder(name)
    config = read_private_json(folder / LOGIN_FILE) or {}
    account = read_private_json(folder / ACCOUNT_FILE) or {}
    # The login form description goes back to the page; the account values never do.
    form = {'login_path': plain(config.get('login_path')), 'success_selector': plain(config.get('success_selector')),
            'account_key': config.get('account_key') if config.get('account_key') in ACCOUNT_KEYS else ''}
    for side in ('user', 'password'):
        kind = 'selector' if config.get(side + '_selector') else 'field'
        form[side + '_kind'], form[side + '_target'] = kind, plain(config.get(f'{side}_{kind}'))
    id_kind = next((key for key in ACCOUNT_KEYS if isinstance(account.get(key), str) and account[key]), '')
    return {'folder': str(folder), 'config_saved': bool(config), 'id_saved': bool(id_kind), 'id_kind': id_kind,
            'password_saved': isinstance(account.get('password'), str) and bool(account['password']),
            'form': form, 'session': session_view(session_target({**values, 'name': name}))}


def account_get(body):
    return account_view(loose(body))


def account_save(body):
    values = loose(body)
    name = check_name(values['name'])

    def line(key, label, required=True):
        value = body.get(key, '')
        value = value.strip() if isinstance(value, str) else ''
        if control(value) or len(value) > 300:
            raise ConsoleError(f'{label}: 줄바꿈이나 제어 문자 없이 300자 이하로 넣는다')
        if required and not value:
            raise ConsoleError(f'{label} 칸을 채운다')
        return value

    login_path = line('login_path', '로그인 화면 경로')
    kinds = {side: body.get(side + '_kind') for side in ('user', 'password')}
    if any(kind not in TARGET_KINDS for kind in kinds.values()):
        raise ConsoleError('칸 찾는 법은 name 속성 또는 CSS 선택자')
    user_target = line('user_target', '아이디 칸')
    password_target = line('password_target', '비밀번호 칸')
    success = line('success_selector', '로그인 성공 표시', required=False)
    key = body.get('account_key') if body.get('account_key') in ACCOUNT_KEYS else 'username'
    account_id = line('account_id', '사용자 이름 또는 메일', required=False)
    secret = body.get('account_secret', '')
    secret = secret if isinstance(secret, str) else ''
    if control(secret) or len(secret) > 300:
        raise ConsoleError('비밀번호: 줄바꿈이나 제어 문자 없이 300자 이하로 넣는다')
    if values['origin']:
        origin = check_origin(values['origin'])
        try:
            same = authority(urljoin(origin, login_path)) == authority(origin)
        except ValueError:
            same = False
        if not same:
            raise ConsoleError('로그인 화면 경로는 대상 주소와 같은 원본이어야 함')
    folder = account_folder(name, create=True)
    saved = read_private_json(folder / ACCOUNT_FILE) or {}
    # An empty field keeps the stored value, so the page never needs it back.
    account_id = account_id or next((saved[item] for item in (key, *ACCOUNT_KEYS)
                                     if isinstance(saved.get(item), str) and saved[item]), '')
    secret = secret or (saved['password'] if isinstance(saved.get('password'), str) else '')
    if not account_id or not secret:
        raise ConsoleError('사용자 이름(또는 메일)과 비밀번호를 넣는다. 저장된 값이 있으면 빈칸은 그 값을 그대로 쓴다')
    config = {'login_path': login_path, 'user_' + kinds['user']: user_target,
              'password_' + kinds['password']: password_target, 'account_file': ACCOUNT_FILE, 'account_key': key}
    if success:
        config['success_selector'] = success
    write_json(folder / ACCOUNT_FILE, {key: account_id, 'password': secret}, private=True)
    write_json(folder / LOGIN_FILE, config, private=True)
    return account_view(values)


def session_in_use(values, target):
    if values['session_runs'] in ('', '0'):
        return False
    try:
        return session_path(session_target(values)) == target
    except (OSError, ValueError):
        return False


def account_delete(body):
    """Remove what step 5 stored for one record name: its account folder and, when asked, its session file."""
    values = loose(body)
    name = check_name(values['name'])
    folder = account_folder(name)
    found = folder.resolve()
    linked = folder.is_symlink() or getattr(folder, 'is_junction', lambda: False)()
    # Only a real folder directly under the private accounts folder, never a place a link leads to.
    if (linked or found.parent != private_root().resolve() / 'accounts' or found.name.casefold() != name.casefold()
            or (found.exists() and not found.is_dir())):
        raise ConsoleError('계정 폴더가 비공개 accounts 폴더 바로 아래의 폴더가 아니어서 지우지 않음')
    target = None
    if body.get('session') is True:
        try:
            target = session_path(session_target({**values, 'name': name}))  # inside the private sessions folder
        except ValueError as error:
            raise ConsoleError(f'세션 파일을 지우지 않음: {error}') from None
        if target.exists() and not target.is_file():
            raise ConsoleError('세션 경로가 파일이 아니어서 지우지 않음')
    removed, kept, session_removed = [], [], False
    with LOCK:
        for key, job in JOBS.items():
            if job.process.poll() is not None:
                continue
            if key.casefold() == name.casefold():
                raise ConsoleError(f'이 기록 이름({key})으로 이 콘솔이 시작한 분석이 실행 중이라 지우지 않음. '
                                   '6단계에서 멈춘 뒤 지운다')
            if target is not None and session_in_use(job.values, target):
                raise ConsoleError(f'다른 기록 이름({key})으로 실행 중인 분석이 이 세션 파일을 써서 지우지 않음')
        task = TASKS.get('session')
        if task is not None and task.code is None:
            raise ConsoleError('세션 준비가 실행 중이라 지우지 않음. 끝나거나 취소한 뒤 지운다')
        try:
            if found.is_dir():
                with os.scandir(found) as entries:
                    for entry in entries:
                        # Regular files only (the two saved files and any unfinished write); links are left alone.
                        if entry.is_file(follow_symlinks=False):
                            os.unlink(entry.path)
                            removed.append(entry.name)
                        else:
                            kept.append(entry.name)
                if not kept:
                    found.rmdir()
            if target is not None and target.is_file():
                target.unlink()
                session_removed = True
        except OSError as error:
            raise ConsoleError(f'지우다가 멈춤({type(error).__name__}). 이미 지운 파일: '
                               f'{", ".join(removed) or "없음"}') from None
        # A passed check no longer describes the stored session.
        for key in [key for key in CHECKED if key.casefold() == name.casefold()]:
            del CHECKED[key]
    labels = {LOGIN_FILE: '로그인 화면 설명', ACCOUNT_FILE: '계정 값'}
    removed.sort(key=lambda item: (item not in labels, item != LOGIN_FILE, item))
    done = [labels.get(item, '쓰다 남은 임시 파일 ' + item) for item in removed] + (['세션 파일'] if session_removed else [])
    message = '지움: ' + ', '.join(done) if done else '지울 저장 값이 없음'
    if target is not None and not session_removed:
        message += '. 세션 파일은 없었음'
    if kept:
        message += '. 파일이 아닌 항목이 있어 폴더는 남김: ' + ', '.join(kept)
    return {'message': message, 'account': account_view(values)}


def session_argv(origin, config, output, dry_run):
    return ([sys.executable, '-B', '-m', 'site_analysis.session_prepare', '--origin-url', origin,
             '--login-config', str(config), '--out', str(output)] + (['--dry-run'] if dry_run else []))


def session_check(body):
    values = loose(body)
    name, origin = check_name(values['name']), check_origin(values['origin'])
    config = account_folder(name) / LOGIN_FILE
    if not config.is_file():
        raise ConsoleError('먼저 로그인 화면과 계정 값을 저장한다')
    output = session_target({**values, 'name': name})
    try:
        result = subprocess.run(session_argv(origin, config, output, True), cwd=WORKDIR, env=child_env(values),
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=SESSION_CHECK_SECONDS)
    except subprocess.TimeoutExpired:
        raise ConsoleError(f'dry-run이 {SESSION_CHECK_SECONDS}초 안에 끝나지 않음') from None
    try:
        report = json.loads((result.stdout.strip().splitlines() or [''])[-1])
    except ValueError:
        report = None
    if result.returncode == 0 and isinstance(report, dict):
        line = (f'dry-run 통과: 로그인 설정 검사 {report.get("config_check")}, 비공개 경로 검사 '
                f'{report.get("private_path_check")}, 계정 값 읽음 {"예" if report.get("account_values_read") else "아니오"}, '
                f'네트워크 요청 {report.get("network_requests")}, 파일 쓰기 {report.get("files_written")}')
        return {'ok': True, 'line': line, 'relay': bool(values['proxy'])}
    # session_prepare prints only the error type; the same checks run here for their fixed Korean reason.
    reason = ''
    try:
        session_path(output)
        login_settings(origin, config)
    except ValueError as error:
        reason = str(error)[:300]
    except Exception as error:
        reason = type(error).__name__
    last = (result.stderr.strip().splitlines() or [f'종료 코드 {result.returncode}'])[-1][:300]
    return {'ok': False, 'line': 'dry-run 실패: ' + last, 'reason': reason, 'relay': bool(values['proxy'])}


def session_task(body):
    values = loose(body)
    name, origin = check_name(values['name']), check_origin(values['origin'])
    if not values['proxy']:
        raise ConsoleError('실제 로그인에는 중계 주소가 필요함(session_prepare가 SITE_ANALYSIS_PROXY를 요구함). '
                           '4단계에서 중계 주소를 넣는다')
    check_relay(values['proxy'])
    check = session_check(body)
    if not check['ok']:
        raise ConsoleError('dry-run을 통과하지 못해 로그인하지 않음: ' + (check['reason'] or check['line']))
    output = session_target({**values, 'name': name})
    return launch('session', session_argv(origin, account_folder(name) / LOGIN_FILE, output, False),
                  env=child_env(values))


# Step 6: dry-run, start, stop and progress.

def tail(path, count=40):
    if not path.exists():
        return []
    with path.open('rb') as stream:
        stream.seek(max(0, path.stat().st_size - 65536))
        return stream.read().decode('utf-8', 'replace').splitlines()[-count:]


def failure_lines(lines):
    """The analyzer's own stop-reason lines from the last run in a log or stderr tail."""
    starts = [index for index, line in enumerate(lines) if line.startswith('=== 시작 ')]
    lines = lines[starts[-1] + 1:] if starts else lines
    return [line for line in lines if line.startswith(FAILURE_PREFIXES) or ': error: ' in line][-4:]


def dry_run(body):
    values = clean(body)
    save_settings(values)
    with LOCK:
        CHECKED.pop(values['name'], None)
    try:
        result = subprocess.run(analyzer_argv(values, dry_run=True), cwd=WORKDIR, env=child_env(values),
                                stdin=subprocess.DEVNULL, capture_output=True, timeout=DRY_SECONDS)
    except subprocess.TimeoutExpired:
        raise ConsoleError(f'점검이 {DRY_SECONDS}초 안에 끝나지 않음') from None
    stdout = result.stdout.decode('utf-8', 'replace')
    try:
        report = json.loads(stdout)
    except ValueError:
        report = None
    report = report if isinstance(report, dict) else None
    stderr = result.stderr.decode('utf-8', 'replace').splitlines()
    if result.returncode == 0:
        with LOCK:
            CHECKED[values['name']] = signature(values)
    return {'code': result.returncode, 'report': report, 'stdout': '' if report else stdout[-4000:],
            'stderr': stderr[-40:], 'reasons': failure_lines(stderr) if result.returncode else []}


def start(body):
    values = clean(body)
    with LOCK:
        if CHECKED.get(values['name']) != signature(values):
            raise ConsoleError('이 설정으로 점검을 먼저 통과해야 시작할 수 있음. 설정을 바꿨다면 점검을 다시 누른다')
        same = [key for key, other in JOBS.items()
                if key.casefold() == values['name'].casefold() and other.process.poll() is None]
        if same:
            raise ConsoleError(f'같은 기록 이름({same[0]})의 분석이 이미 실행 중임. 기록 이름은 대소문자를 구분하지 않는다')
        log = log_path(values['name'])
        with log.open('a', encoding='utf-8') as stream:
            stream.write(f'\n=== 시작 {clock()} ===\n')
        try:
            with log.open('ab') as stream:
                process = subprocess.Popen(analyzer_argv(values), cwd=WORKDIR, env=child_env(values),
                                           stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, **GROUP)
        except OSError as error:
            with log.open('a', encoding='utf-8') as stream:
                stream.write(f'=== 시작 실패 {clock()}: {type(error).__name__} ===\n')
            raise ConsoleError(f'분석 프로세스를 띄우지 못함({type(error).__name__})') from None
        job = JOBS[values['name']] = Job(values, process, log)
    save_settings(values)
    threading.Thread(target=watch, args=(job,), daemon=True).start()
    return {'pid': process.pid}


def watch(job):
    code = job.process.wait()
    note = '멈춤 버튼으로 끝냄' if job.stopped else EXIT.get(code, '비정상 종료')
    with job.log.open('a', encoding='utf-8') as stream:
        stream.write(f'=== 끝 {clock()}: 종료 코드 {code}, {note} ===\n')


if os.name == 'nt':
    import ctypes
    from ctypes import wintypes

    class ProcessEntry(ctypes.Structure):  # PROCESSENTRY32W
        _fields_ = [('size', wintypes.DWORD), ('usage', wintypes.DWORD), ('pid', wintypes.DWORD),
                    ('heap', ctypes.c_size_t), ('module', wintypes.DWORD), ('threads', wintypes.DWORD),
                    ('parent', wintypes.DWORD), ('priority', ctypes.c_long), ('flags', wintypes.DWORD),
                    ('exe', wintypes.WCHAR * 260)]

    KERNEL = ctypes.WinDLL('kernel32', use_last_error=True)
    KERNEL.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    KERNEL.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    KERNEL.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    KERNEL.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessEntry)]
    KERNEL.OpenProcess.restype = wintypes.HANDLE
    KERNEL.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    KERNEL.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(ctypes.c_ulonglong)] * 4
    KERNEL.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    KERNEL.CloseHandle.argtypes = [wintypes.HANDLE]


def process_table():
    """Process ID to parent process ID for every process now running."""
    snapshot = KERNEL.CreateToolhelp32Snapshot(2, 0)  # TH32CS_SNAPPROCESS
    if not snapshot or snapshot == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        entry, table = ProcessEntry(size=ctypes.sizeof(ProcessEntry)), {}
        more = KERNEL.Process32FirstW(snapshot, ctypes.byref(entry))
        while more:
            table[entry.pid] = entry.parent
            more = KERNEL.Process32NextW(snapshot, ctypes.byref(entry))
        return table
    finally:
        KERNEL.CloseHandle(snapshot)


def open_process(pid):
    """(handle that can end the process, creation time), or None when it is gone or cannot be opened."""
    handle = KERNEL.OpenProcess(0x1001, False, pid)  # PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        return None
    times = [ctypes.c_ulonglong() for _ in range(4)]
    if not KERNEL.GetProcessTimes(handle, *map(ctypes.byref, times)):
        KERNEL.CloseHandle(handle)
        return None
    return handle, times[0].value


def end_windows_tree(pid):
    """End pid and its descendants without taskkill /T.

    A child keeps its parent's process ID after the parent exits, and Windows reuses IDs, so a parent-ID
    match alone can pull in an unrelated older process. A process joins the tree only when it was created
    after the parent it names and still names that parent once its handle is open. Holding the handles
    keeps every ID in the tree from being reused, and each process is ended through its own handle.
    """
    root = open_process(pid)
    if root is None:
        return
    held, refused, ended = {pid: root}, set(), set()
    try:
        for _ in range(4):  # later rounds catch children started while the tree was being ended
            while True:
                wanted = {child: parent for child, parent in process_table().items()
                          if parent in held and child not in held and child not in refused and child != parent}
                if not wanted:
                    break
                opened = {child: open_process(child) for child in wanted}
                table = process_table()
                for child, value in opened.items():
                    parent = wanted[child]
                    if value is None or table.get(child) != parent or value[1] < held[parent][1]:
                        refused.add(child)
                        if value is not None:
                            KERNEL.CloseHandle(value[0])
                    else:
                        held[child] = value
            fresh = [target for target in held if target not in ended]
            if not fresh:
                break
            for target in fresh:
                KERNEL.TerminateProcess(held[target][0], 1)
                ended.add(target)
    finally:
        for handle, _ in held.values():
            KERNEL.CloseHandle(handle)


def kill_tree(process):
    """End a process this console started and its descendants. False when only the process itself was ended."""
    complete = True
    if os.name == 'nt':
        try:
            end_windows_tree(process.pid)
        except OSError:
            complete = False
        if process.poll() is None:
            process.kill()
    else:
        for sign, wait in ((signal.SIGTERM, 10), (signal.SIGKILL, 0)):
            try:
                os.killpg(process.pid, sign)
            except ProcessLookupError:
                break
            try:
                process.wait(wait)
            except subprocess.TimeoutExpired:
                pass
    process.wait(30)
    return complete


def stop(body):
    name = str(body.get('name', '')).strip().removesuffix('.json')
    with LOCK:
        job = JOBS.get(name)
        if job is None or job.process.poll() is not None:
            raise ConsoleError('이 콘솔이 시작한 실행 중인 분석이 없음')
        job.stopped = True
    try:
        complete = kill_tree(job.process)
    except subprocess.TimeoutExpired:
        raise ConsoleError('프로세스가 30초 안에 끝나지 않음. 작업 관리자에서 PID를 확인한다') from None
    if not complete:
        raise ConsoleError('분석 프로세스는 끝냈지만 하위 프로세스 목록을 읽지 못함. 작업 관리자에서 남은 '
                           'chrome, node, codex 프로세스를 확인한다')
    return {'code': job.process.returncode}


def stop_all():
    with LOCK:
        running = [job for job in JOBS.values() if job.process.poll() is None]
        helpers = [task for task in TASKS.values() if task.process.poll() is None]
    for task in helpers:
        task.cancelled = True
        try:
            kill_tree(task.process)
        except subprocess.TimeoutExpired:
            print(f'{TASK_LABELS[task.kind]} 작업 PID {task.process.pid}가 끝나지 않음', file=sys.stderr)
    for job in running:
        job.stopped = True
        try:
            if not kill_tree(job.process):
                print(f'PID {job.process.pid}의 하위 프로세스 목록을 읽지 못함. 작업 관리자에서 확인한다', file=sys.stderr)
        except subprocess.TimeoutExpired:
            print(f'PID {job.process.pid}가 끝나지 않음', file=sys.stderr)
    return len(running)


def job_view(job, log):
    if job is None:
        return None
    code = job.process.poll()
    return {'pid': job.process.pid, 'started': clock(job.started), 'code': code, 'stopped': job.stopped,
            'note': '' if code is None else '멈춤 버튼으로 끝냄' if job.stopped else EXIT.get(code, '비정상 종료'),
            'reasons': failure_lines(log) if code not in (None, 0) and not job.stopped else []}


def count(value, default):
    return min(int(value), 50) if INTEGER.fullmatch(value or '') else default


def timeline(plan, ledger, running, record):
    """Planned stages per run and per merge, marked from the ledger's remaining stages."""
    runs, session_runs = count(plan['runs'], 2), count(plan['session_runs'], 0)
    remaining = None if ledger is None else {
        (item['stage'], item['authority'] if item['stage'] == 'merge' else item['run']): item
        for item in ledger.get('remaining', [])}
    active = Codex.stage(ledger['last_purpose']) if running and ledger and ledger.get('last_purpose') else None

    def cell(stage, key):
        if remaining is None:
            return {'stage': stage, 'state': '대기'}
        if (stage, key) in remaining:
            return {'stage': stage, 'state': '남음', 'count': remaining[(stage, key)].get('count')}
        return {'stage': stage, 'state': '완료' if remaining or record else '대기'}

    rows = []
    for index in range(1, runs + session_runs + 1):
        rows.append({'label': f'{index}회차', 'authority': 'anonymous' if index <= runs else 'session',
                     'cells': [cell(stage, index) for stage in STAGES]})
    for mode, total in (('anonymous', runs), ('session', session_runs)):
        if total > 1:
            rows.append({'label': '합치기', 'authority': mode, 'cells': [cell('merge', mode)]})
    # The stage of the latest model call marks its first remaining cell as the one in progress.
    pending = [item for line in rows for item in line['cells'] if item['stage'] == active and item['state'] == '남음']
    if pending:
        pending[0]['state'] = '진행 중'
    return rows


def progress(values):
    name = values['name'].removesuffix('.json')
    origin = values['origin']
    with LOCK:
        job = JOBS.get(name)
        others = sorted(key for key, value in JOBS.items() if key != name and value.process.poll() is None)
    running = job is not None and job.process.poll() is None
    # While a run is going, its own settings name the checkpoint and the plan; afterwards the current settings do,
    # matching the caption under the stage table.
    plan = job.values if running else values
    if running:
        origin = job.values['origin']
    result = {'running': running, 'job': job_view(job, []),
              'others': others, 'ledger': None, 'note': '', 'stall_minutes': STALL_MINUTES, 'log': [],
              'timeline': [], 'active_stage': None}
    if not valid_name(name) or not origin:
        result['note'] = '4단계에서 대상 주소와 기록 이름을 넣으면 진행을 보여 준다'
        return result
    record = record_path(name).is_file()
    result['log'] = tail(log_path(name))
    result['job'] = job_view(job, result['log'])
    try:
        found = status.folders(argparse.Namespace(out=str(record_path(name)), origin_url=normal_origin(origin),
                                                  checkpoint_root=None))
        result['ledger'] = status.summary(found[0], STALL_MINUTES) if found else None
        if result['ledger'] and result['ledger'].get('last_purpose'):
            result['active_stage'] = Codex.stage(result['ledger']['last_purpose'])
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as error:
        result['ledger'] = None
        result['note'] = f'장부를 읽지 못함({type(error).__name__}). 다음 갱신에서 다시 읽는다'
        result['timeline'] = timeline(plan, None, result['running'], record)
        return result
    ledger = result['ledger']
    result['timeline'] = timeline(plan, ledger, result['running'], record)
    if ledger is None:
        result['note'] = ('장부 없음: 이 실행은 비용 장부를 남기기 전에 끝남' if result['job'] and not result['running']
                          else '장부 없음: 아직 시작 전이거나 다른 대상 주소의 체크포인트')
    return result


def state(body):
    """What the page refreshes every few seconds: step states, prerequisites and run progress."""
    values = loose(body)
    values['name'] = values['name'].removesuffix('.json')
    view = progress(values)
    steps, notes = {}, {}
    with LOCK:
        env_rows, ai = ENV.get('rows'), AI.get(values['provider'])
        tasks = {kind: task.code is None for kind, task in TASKS.items()}
        checked = CHECKED.get(values['name'])
    steps['env'] = '확인 중' if env_rows is None else '완료' if all(item['ok'] for item in env_rows) else '필요'
    steps['ai'] = '확인 중' if ai is None else '완료' if ai['found'] and ai['login'] in LOGGED_IN else '필요'
    try:
        model = check_model(values['model'])
        problem, ceiling = (rates_problem(local_path(values['rates']), model) if values['rates']
                            else ('단가를 아직 저장하지 않음', None))
    except ConsoleError as error:
        problem, ceiling = str(error), None
    steps['cost'] = '완료' if problem is None else '필요'
    notes['cost'] = problem or f'{Path(values["rates"]).name}, 모델 {model}, 비용 상한 {ceiling}달러'
    try:
        target_values(values)
        steps['target'], notes['target'] = '완료', '대상 주소와 기록 이름 형식 확인됨'
    except ConsoleError as error:
        steps['target'], notes['target'] = '필요', str(error)
    notes['record'] = ('이 이름의 기록 파일이 이미 있음: 시작하면 분석기가 같은 파일에 결과를 다시 쓴다. '
                       '이전 기록을 남기려면 4단계에서 다른 기록 이름을 쓴다'
                       if valid_name(values['name']) and record_path(values['name']).is_file() else '')
    needed = values['session_runs'] not in ('', '0')
    session = None
    if valid_name(values['name']):
        try:
            session = session_view(session_target(values))
        except (OSError, ValueError) as error:
            session = {'exists': False, 'error': f'세션 경로를 정하지 못함({type(error).__name__})'}
    ready = bool(session and session.get('summary') and not session['summary']['expired'])
    steps['account'] = '완료' if ready else '필요' if needed else '선택'
    record = valid_name(values['name']) and record_path(values['name']).is_file()
    ledger = view['ledger']
    steps['run'] = ('실행 중' if view['running'] else
                    '완료' if record and (ledger is None or not ledger['remaining_stages']) else '필요')
    steps['result'] = '완료' if record else '필요'
    try:
        passed = checked is not None and checked == signature(clean(body))
    except (ConsoleError, OSError, ValueError):
        passed = False
    view.update(steps=steps, notes=notes, checked=passed, session=session, session_needed=needed, tasks=tasks,
                record_exists=bool(record))
    return view


# Step 7: result counts.

def axis_state(answer):
    value = answer.get('status') if isinstance(answer, dict) else None
    return value if value in AXIS_STATES else '기타'


def result(body):
    name = check_name(body.get('name'))
    path = record_path(name)
    view = {'path': str(path), 'folder': str(RECORDS), 'exists': path.is_file()}
    if not view['exists']:
        return view
    try:
        record = json.loads(path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError) as error:
        return {**view, 'error': f'기록을 읽지 못함({type(error).__name__})'}
    if not isinstance(record, dict):
        return {**view, 'error': '기록 형식을 읽지 못함'}
    # Counts and fixed labels only: no axis description, evidence or value leaves the record.
    runs = []
    for index, run in enumerate(record.get('runs') if isinstance(record.get('runs'), list) else []):
        if not isinstance(run, dict):
            continue
        axes = run.get('axes') if isinstance(run.get('axes'), dict) else {}
        tally = Counter(axis_state(answer) for answer in axes.values())
        mode = run.get('authority', {}).get('requested') if isinstance(run.get('authority'), dict) else None
        runs.append({'run': run['run'] if type(run.get('run')) is int else index + 1,
                     'authority': mode if mode in ('anonymous', 'session') else 'other',
                     'counts': {key: tally.get(key, 0) for key in (*AXIS_STATES, '기타')}, 'axes': len(axes)})
    merged = []
    blocks = record.get('merged_by_authority') if isinstance(record.get('merged_by_authority'), dict) else {}
    for mode, block in blocks.items():
        if not isinstance(block, dict) or 'agreement_count' not in block:
            continue  # one run of that authority: the block is that run, not a merge
        labels = Counter()
        axes = block.get('axes') if isinstance(block.get('axes'), dict) else {}
        for axis in axes.values():
            answer = axis.get('combined_answer') if isinstance(axis, dict) else None
            findings = answer.get('findings') if isinstance(answer, dict) else None
            for item in findings if isinstance(findings, list) else []:
                label = item.get('label', item.get('support')) if isinstance(item, dict) else None
                labels[label if label in FINDING_LABELS else '기타'] += 1
        merged.append({'authority': mode if mode in ('anonymous', 'session') else 'other',
                       'labels': {key: labels.get(key, 0) for key in (*FINDING_LABELS, '기타')},
                       'agreement': block['agreement_count'] if type(block.get('agreement_count')) is int else 0,
                       'disagreement': block['disagreement_count'] if type(block.get('disagreement_count')) is int else 0,
                       'axes': len(axes)})
    metrics = record.get('metrics') if isinstance(record.get('metrics'), dict) else {}
    reason = record.get('stop_reason')
    reason = reason if isinstance(reason, str) and re.fullmatch(r'[a-z_]{1,60}', reason) else None
    return {**view, 'created': plain(record.get('created_at'))[:40], 'runs': runs, 'merged': merged,
            'cost': plain(metrics.get('cost_usd')), 'max_cost': plain(metrics.get('max_cost_usd')),
            'calls': metrics['call_count'] if type(metrics.get('call_count')) is int else None,
            'stop_reason': reason, 'stop_text': STOP_REASONS.get(reason, '') if reason else '',
            'pending': 'resume_pending' in record or 'copy_resume_pending' in record}


def open_path(body):
    target = DOCS.get(str(body.get('target', '')))
    if target is None:
        raise ConsoleError('열 수 없는 대상')
    if not hasattr(os, 'startfile'):
        raise ConsoleError('열기는 Windows에서만 된다. 경로를 직접 연다: ' + str(target))
    if not target.exists():
        raise ConsoleError('아직 없음: ' + str(target))
    try:
        os.startfile(str(target))
    except OSError as error:
        raise ConsoleError(f'열지 못함({type(error).__name__}). 경로를 직접 연다: {target}') from None
    return {'opened': str(target)}


def settings(_body):
    return {'settings': load_settings(), 'records': str(RECORDS),
            'docs': {key: str(value) for key, value in DOCS.items() if key != 'records'}}


def settings_save(body):
    save_settings(loose(body))
    return {'saved': True}


ROUTES = {'/api/state': state, '/api/settings/save': settings_save, '/api/env': environment, '/api/ai': ai_check,
          '/api/rates': rates_get, '/api/rates/save': rates_save, '/api/target/check': target_check,
          '/api/account': account_get, '/api/account/save': account_save, '/api/account/delete': account_delete,
          '/api/session/check': session_check, '/api/task/start': task_start, '/api/task': task_get,
          '/api/task/cancel': task_cancel, '/api/task/input': task_input,
          '/api/check': dry_run, '/api/start': start, '/api/stop': stop, '/api/result': result,
          '/api/open': open_path}


class Server(ThreadingHTTPServer):
    # On Windows SO_REUSEADDR lets another local program bind the same port and receive the token URL.
    allow_reuse_address = False

    def server_bind(self):
        if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def handle_error(self, request, client_address):
        # The default prints a full traceback for every dropped browser connection.
        print(f'요청 처리 중 연결 오류: {sys.exc_info()[0].__name__}', file=sys.stderr)


class Handler(BaseHTTPRequestHandler):
    server_version = 'site-analysis-console'
    sys_version = ''

    def log_message(self, format, *args):
        pass  # request lines carry the token

    def trusted(self, token):
        return (self.headers.get('Host') in self.server.hosts
                and secrets.compare_digest(token.encode('utf-8'), self.server.token.encode('utf-8')))

    def same_origin(self):
        origin, site = self.headers.get('Origin'), self.headers.get('Sec-Fetch-Site')
        return ((origin is None or origin in {'http://' + host for host in self.server.hosts})
                and site in (None, 'same-origin') and self.headers.get_content_type() == 'application/json')

    def do_GET(self):
        part = urlsplit(self.path)
        token = self.headers.get('X-Console-Token') or parse_qs(part.query).get('token', [''])[0]
        if not self.trusted(token):
            if part.path == '/':
                return self.text(403, '토큰이 없거나 틀림. 콘솔 창에 찍힌 주소(?token=... 포함)를 그대로 연다. '
                                      '콘솔을 다시 켜면 주소가 바뀐다.')
            return self.reply(403, {'error': '토큰이 없거나 틀림'})
        if part.path == '/':
            return self.page()
        if part.path == '/api/settings':
            return self.answer(settings, {})
        self.reply(404, {'error': '없는 주소'})

    def do_POST(self):
        part = urlsplit(self.path)
        if not self.trusted(self.headers.get('X-Console-Token', '')) or not self.same_origin():
            return self.reply(403, {'error': '토큰이 없거나 다른 출처의 요청. 콘솔을 다시 켰다면 콘솔 창에 새로 찍힌 주소로 '
                                             '이 화면을 다시 연다'})
        if part.path not in ROUTES:
            return self.reply(404, {'error': '없는 주소'})
        try:
            length = int(self.headers.get('Content-Length') or 0)
            if not 0 <= length <= 65536:
                raise ValueError
            body = json.loads(self.rfile.read(length) or b'{}')
        except (ValueError, RecursionError):
            return self.reply(400, {'error': '요청 형식 오류'})
        self.answer(ROUTES[part.path], body if isinstance(body, dict) else {})

    def answer(self, route, body):
        # Reply outside the try: a browser that left mid-request is a connection error, not a console error.
        try:
            code, value = 200, route(body)
        except ConsoleError as error:
            code, value = 400, {'error': str(error)}
        except Exception as error:
            # The message can echo request values, so print only the type and where it was raised.
            where = ', '.join(f'{Path(frame.filename).name}:{frame.lineno}'
                              for frame in traceback.extract_tb(error.__traceback__)[-3:])
            print(f'콘솔 처리 오류: {type(error).__name__} ({where})', file=sys.stderr)
            code, value = 500, {'error': '콘솔 내부 오류: ' + type(error).__name__}
        self.reply(code, value)

    def headers_common(self, kind, length):
        self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(length))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')

    def text(self, code, message):
        data = (message + '\n').encode('utf-8')
        self.send_response(code)
        self.headers_common('text/plain; charset=utf-8', len(data))
        self.end_headers()
        self.wfile.write(data)

    def reply(self, code, value):
        data = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.headers_common('application/json; charset=utf-8', len(data))
        self.end_headers()
        self.wfile.write(data)

    def page(self):
        nonce = secrets.token_urlsafe(16)
        data = PAGE.replace('__NONCE__', nonce).encode('utf-8')
        self.send_response(200)
        self.headers_common('text/html; charset=utf-8', len(data))
        self.send_header('Content-Security-Policy', f"default-src 'none'; script-src 'nonce-{nonce}'; "
                         f"style-src 'nonce-{nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; "
                         "frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(data)


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description='사이트 분석기 로컬 콘솔')
    parser.add_argument('--port', type=int, default=0, help='0이면 빈 포트를 고른다')
    parser.add_argument('--open', action='store_true', help='시작한 뒤 기본 브라우저로 콘솔 주소를 연다')
    args = parser.parse_args(argv)
    try:
        console_folder()
        server = Server(('127.0.0.1', args.port), Handler)
    except (OSError, ValueError) as error:
        print(f'콘솔 시작 실패: {type(error).__name__}: {error}', file=sys.stderr)
        return 2
    port = server.server_address[1]
    server.token = secrets.token_urlsafe(32)
    server.hosts = {f'127.0.0.1:{port}', f'localhost:{port}'}
    url = f'http://127.0.0.1:{port}/?token={server.token}'
    print(f'콘솔 주소: {url}', flush=True)
    print('이 주소를 아는 사람은 분석을 시작하고 멈출 수 있다. 끝내려면 이 창에서 Ctrl+C. '
          '이 콘솔이 시작한 분석과 작업도 함께 멈춘다.', flush=True)
    if args.open:
        threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        stopped = stop_all()
        if stopped:
            print(f'실행 중이던 분석 {stopped}개를 멈춤. 같은 설정으로 점검한 뒤 시작하면 이어서 돈다.', flush=True)
    return 0


PAGE = r'''<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>사이트 분석 콘솔</title>
<style nonce="__NONCE__">
:root { --bg: #f5f6f8; --panel: #ffffff; --text: #1c2230; --muted: #5a6374; --line: #d8dce4;
  --accent: #2456c4; --on-accent: #ffffff; --accent-bg: #e8eefb; --ok: #1d7444; --ok-bg: #e5f3ea;
  --bad: #b2261d; --bad-bg: #fbe8e6; --warn: #7d5200; --warn-bg: #fff3d4; --code: #eef0f4; color-scheme: light; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #14171c; --panel: #1b1f26; --text: #e5e8ee; --muted: #9aa3b2; --line: #2e3440;
    --accent: #7ea4ff; --on-accent: #0c1222; --accent-bg: #1d2a47; --ok: #72d39d; --ok-bg: #15301f;
    --bad: #ff8b80; --bad-bg: #3b1d1a; --warn: #f1c46e; --warn-bg: #3a2f12; --code: #232831; color-scheme: dark; }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
/* Korean breaks only between words; a word longer than the line still wraps instead of overflowing. */
body { margin: 0; background: var(--bg); color: var(--text);
  font: 15px/1.55 system-ui, "Segoe UI", "Malgun Gothic", "Apple SD Gothic Neo", sans-serif;
  word-break: keep-all; overflow-wrap: break-word; }
main { max-width: 1180px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 22px; margin: 0 0 4px; }
h2 { font-size: 19px; margin: 0 0 6px; }
h3 { font-size: 14px; margin: 22px 0 6px; }
p { margin: 6px 0; }
code, pre { font-family: ui-monospace, Consolas, monospace; word-break: normal; overflow-wrap: anywhere; }
code { font-size: 13px; }
.layout { display: grid; grid-template-columns: 224px minmax(0, 1fr); gap: 20px; align-items: start; margin-top: 16px; }
.steps { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; position: sticky; top: 16px; }
.step { width: 100%; display: grid; grid-template-columns: 24px minmax(0, 1fr) auto; align-items: center; gap: 8px;
  text-align: left; padding: 9px 10px; border-radius: 8px; border: 1px solid var(--line); background: var(--panel); }
.step[aria-current="step"] { border-color: var(--accent); background: var(--accent-bg); font-weight: 600; }
.num { display: inline-grid; place-items: center; width: 24px; height: 24px; border-radius: 50%; background: var(--code);
  font-size: 12px; font-weight: 700; }
.step[aria-current="step"] .num { background: var(--accent); color: var(--on-accent); }
.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 18px 20px; }
.lead { color: var(--text); max-width: 72ch; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px 16px; margin-top: 10px; }
.wide { grid-column: 1 / -1; }
label { display: block; font-weight: 600; font-size: 13px; }
label small { display: block; font-weight: 400; color: var(--muted); overflow-wrap: anywhere; }
input, select, textarea { width: 100%; margin-top: 4px; padding: 7px 9px; border: 1px solid var(--line); border-radius: 6px;
  background: var(--bg); color: var(--text); font: inherit; }
textarea { resize: vertical; font: 13px/1.45 ui-monospace, Consolas, monospace; }
input[type="radio"], input[type="checkbox"] { width: auto; margin: 0 6px 0 0; }
fieldset { border: 0; padding: 0; margin: 10px 0; display: flex; gap: 20px; flex-wrap: wrap; align-items: center; }
legend { font-weight: 600; font-size: 13px; padding: 0; margin-bottom: 4px; }
.inline { display: inline-flex; align-items: center; font-weight: 400; font-size: 15px; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
button { font: inherit; padding: 7px 16px; border-radius: 6px; border: 1px solid var(--line); background: var(--panel);
  color: var(--text); cursor: pointer; white-space: nowrap; }
td:last-child > button { margin-top: 2px; }
button.primary { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
button.danger { border-color: var(--bad); color: var(--bad); }
button.link { border: 0; background: none; padding: 0; color: var(--accent); text-decoration: underline; text-align: left; }
button:disabled { opacity: .45; cursor: default; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 14px; }
.next { display: flex; justify-content: flex-end; margin-top: 22px; padding-top: 14px; border-top: 1px solid var(--line); }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 7px 8px; border-top: 1px solid var(--line); vertical-align: top; overflow-wrap: anywhere; }
th { font-size: 13px; font-weight: 600; color: var(--muted); }
.checks td:first-child { white-space: nowrap; font-weight: 600; width: 1%; }
.checks td:nth-child(2) { width: 1%; }
td.num-cell, th.num-cell { text-align: right; font-variant-numeric: tabular-nums; }
.scroll { overflow-x: auto; }
.scroll th, .scroll td:nth-child(-n+2) { white-space: nowrap; }
.badge { display: inline-block; padding: 1px 9px; border-radius: 10px; font-size: 12px; font-weight: 700; white-space: nowrap;
  background: var(--code); color: var(--muted); }
.badge.ok { background: var(--ok-bg); color: var(--ok); }
.badge.bad { background: var(--bad-bg); color: var(--bad); }
.badge.warn { background: var(--warn-bg); color: var(--warn); }
.badge.run { background: var(--accent); color: var(--on-accent); }
.badge.opt { background: transparent; color: var(--muted); box-shadow: inset 0 0 0 1px var(--line); }
.hint { color: var(--bad); font-size: 13px; }
.why { color: var(--muted); font-size: 13px; margin-top: 6px; }
.why:empty { display: none; }
.muted { color: var(--muted); font-size: 13px; }
pre { background: var(--code); padding: 10px 12px; border-radius: 6px; overflow: auto; max-height: 340px; margin: 0;
  font: 12.5px/1.45 ui-monospace, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
.notice { padding: 8px 12px; border-radius: 6px; margin: 8px 0; background: var(--code); overflow-wrap: anywhere; }
.notice.ok { background: var(--ok-bg); color: var(--ok); }
.notice.bad { background: var(--bad-bg); color: var(--bad); }
.notice.warn { background: var(--warn-bg); color: var(--warn); }
.task { margin-top: 14px; border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
.task-head { display: flex; gap: 10px; align-items: center; justify-content: space-between; flex-wrap: wrap; margin-bottom: 8px; }
.links { margin: 6px 0 10px; }
.links a { color: var(--accent); overflow-wrap: anywhere; }
dl { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 16px; margin: 8px 0; }
dt { color: var(--muted); }
dd { margin: 0; overflow-wrap: anywhere; }
details { margin-top: 10px; }
summary { cursor: pointer; color: var(--muted); }
.reqs { list-style: none; padding: 0; margin: 0; display: grid; gap: 6px; }
.reqs li { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.cost { margin: 10px 0; }
progress { width: 100%; height: 12px; accent-color: var(--accent); }
@media (max-width: 760px) {
  .layout { grid-template-columns: minmax(0, 1fr); }
  .steps { position: static; grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .panel { padding: 14px; }
  dl { grid-template-columns: 1fr; }
  dd { margin-bottom: 6px; }
  .checks tr { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 0 10px; align-items: center;
    border-top: 1px solid var(--line); padding: 6px 0; }
  .checks td, .checks td:first-child, .checks td:nth-child(2) { border-top: 0; padding: 2px 0; width: auto; justify-self: start; }
  .checks td:nth-child(3), .checks td[colspan] { grid-column: 1 / -1; }
}
</style>
</head>
<body>
<main>
<header>
<h1>사이트 분석 콘솔</h1>
<p class="muted">이 PC에서만 열리는 site_analysis 실행 화면. 왼쪽 단계를 위에서부터 채우면 명령어 없이 준비, 실행, 결과 확인까지 끝난다. 공개 기록은 <code id="records"></code> 아래에 저장된다.</p>
</header>
<div class="layout">
<nav aria-label="단계">
<ol class="steps">
<li><button class="step" id="nav-env" type="button" data-step="env"><span class="num">1</span><span>환경</span><span class="badge" id="badge-env">확인 중</span></button></li>
<li><button class="step" id="nav-ai" type="button" data-step="ai"><span class="num">2</span><span>AI 연결</span><span class="badge" id="badge-ai">확인 중</span></button></li>
<li><button class="step" id="nav-cost" type="button" data-step="cost"><span class="num">3</span><span>비용</span><span class="badge" id="badge-cost">확인 중</span></button></li>
<li><button class="step" id="nav-target" type="button" data-step="target"><span class="num">4</span><span>분석할 웹</span><span class="badge" id="badge-target">확인 중</span></button></li>
<li><button class="step" id="nav-account" type="button" data-step="account"><span class="num">5</span><span>일반 계정</span><span class="badge" id="badge-account">확인 중</span></button></li>
<li><button class="step" id="nav-run" type="button" data-step="run"><span class="num">6</span><span>실행</span><span class="badge" id="badge-run">확인 중</span></button></li>
<li><button class="step" id="nav-result" type="button" data-step="result"><span class="num">7</span><span>결과</span><span class="badge" id="badge-result">확인 중</span></button></li>
</ol>
</nav>
<div>

<section class="panel" id="panel-env" aria-labelledby="title-env">
<h2 id="title-env">1. 환경</h2>
<p class="lead">분석기가 쓰는 Python, Playwright 패키지와 Chromium 브라우저가 이 PC에 있는지 확인한다. Chromium은 실제로 한 번 띄워서 확인한다. Python은 이 화면에서 설치할 수 없다. 없거나 3.13보다 낮으면 python.org에서 설치한 뒤 그 Python으로 콘솔을 다시 연다.</p>
<table class="checks"><tbody id="env-rows"></tbody></table>
<div class="actions">
<button id="env-check" type="button" aria-describedby="why-env">다시 확인</button>
<button id="install-playwright" type="button" aria-describedby="why-env">Playwright 설치</button>
<button id="install-chromium" type="button" aria-describedby="why-env">브라우저 설치</button>
<span id="env-message" class="muted" role="status"></span>
</div>
<div id="why-env" class="why"></div>
<p class="muted">Playwright 설치는 <code>python -m pip install playwright</code>, 브라우저 설치는 <code>python -m playwright install chromium</code>을 이 콘솔이 대신 실행하고 출력을 아래에 보여 준다. 이미 확인된 항목의 설치 버튼은 꺼진다.</p>
<div id="task-env" class="task" hidden></div>
<div class="next"><button type="button" data-go="ai">다음: AI 연결</button></div>
</section>

<section class="panel" id="panel-ai" aria-labelledby="title-ai" hidden>
<h2 id="title-ai">2. AI 연결</h2>
<p class="lead">분석기는 API 키를 직접 받지 않고 이 PC에 로그인된 AI CLI를 부른다. 기본은 Codex CLI다. 여기서 CLI가 있는지, 로그인됐는지 확인하고 필요하면 설치와 로그인을 한다.</p>
<fieldset>
<legend>제공자</legend>
<label class="inline"><input type="radio" name="provider" value="codex" checked>Codex(기본)</label>
<label class="inline"><input type="radio" name="provider" value="claude">Claude</label>
</fieldset>
<div class="grid">
<label>모델<small>그 CLI가 받는 모델 이름. 3단계 단가와 6단계 실행에 같은 값이 쓰인다</small><input id="model" autocomplete="off" spellcheck="false"></label>
</div>
<h3>상태</h3>
<table class="checks"><tbody id="ai-rows"></tbody></table>
<div class="actions"><button id="ai-check" type="button" aria-describedby="why-ai">로그인 상태 확인</button><span id="ai-message" class="muted" role="status"></span></div>
<div id="why-ai" class="why"></div>
<div id="codex-box">
<h3>Codex 설치와 로그인</h3>
<p class="muted">Codex CLI 설치는 <code>npm install --global @openai/codex</code>를 이 콘솔이 대신 실행하고 출력을 아래에 보여 준다. Node.js의 npm이 있어야 한다. 구독으로 로그인은 <code>codex login</code>을 실행한다. 브라우저가 열리면 ChatGPT 계정으로 로그인한다. 브라우저가 열리지 않으면 아래 출력에 나오는 주소를 누른다.</p>
<div class="actions"><button id="codex-install" type="button" aria-describedby="why-codex">Codex CLI 설치</button><button id="codex-login" type="button" aria-describedby="why-codex">구독으로 로그인</button></div>
<div id="why-codex" class="why"></div>
<div class="grid">
<label class="wide">OpenAI API 키<small>키는 <code>codex login --with-api-key</code>의 표준 입력으로만 넘긴다. 명령줄, 콘솔 설정, 로그에 남기지 않고 화면으로 다시 보내지 않는다. 보관은 Codex CLI가 자기 위치에 한다</small><input id="api-key" type="password" autocomplete="new-password" spellcheck="false"></label>
</div>
<div class="actions"><button id="codex-key" type="button" aria-describedby="why-codex-key">API 키로 로그인</button></div>
<div id="why-codex-key" class="why"></div>
</div>
<div id="claude-box" hidden>
<h3>Claude 로그인</h3>
<p class="muted">Claude 로그인은 <code>claude auth login</code>(Claude 구독, 기본) 또는 <code>claude auth login --console</code>(Anthropic Console, API 사용량 과금)을 이 콘솔이 대신 실행하고 출력을 아래에 보여 준다. 브라우저가 열리면 로그인하고 접근을 허용한다. 로그인이 끝나면 상태를 자동으로 다시 확인한다. 상태 확인은 <code>claude auth status</code>를 쓰며 메일과 조직 정보는 화면에 옮기지 않는다.</p>
<div class="grid">
<label>로그인 방식<select id="claude-method"><option value="claudeai">Claude 구독(기본)</option><option value="console">Anthropic Console(API 사용량 과금)</option></select></label>
</div>
<div class="actions"><button id="claude-login" type="button" aria-describedby="why-claude">Claude 로그인</button></div>
<div id="why-claude" class="why"></div>
<div class="grid">
<label class="wide">브라우저에 나온 코드(브라우저가 열리지 않았을 때만)<small>브라우저가 열리지 않으면 아래 출력의 주소를 눌러 로그인한다. 그 화면에 나온 코드를 여기에 붙여 넣고 코드 보내기를 누른다. 코드는 실행 중인 로그인 프로세스의 표준 입력으로만 넘기고 저장하지 않는다</small><input id="claude-code" type="password" autocomplete="off" spellcheck="false"></label>
</div>
<div class="actions"><button id="claude-code-send" type="button" aria-describedby="why-claude-code">코드 보내기</button></div>
<div id="why-claude-code" class="why"></div>
</div>
<h3>연결 시험(선택, 소액 비용)</h3>
<p class="muted">분석기의 모델 호출 코드(<code>model.Codex</code>)로 아주 작은 요청 하나를 보낸다. 누를 때만 보내며 소액 비용이 든다(구독 로그인이면 사용량에서 빠진다). 3단계 단가를 저장했다면 비용을 달러로, 아니면 토큰 수만 보여 준다.</p>
<div class="actions"><button id="connection" type="button" aria-describedby="why-connection">연결 시험</button></div>
<div id="why-connection" class="why"></div>
<div id="task-ai" class="task" hidden></div>
<div class="next"><button type="button" data-go="cost">다음: 비용</button></div>
</section>

<section class="panel" id="panel-cost" aria-labelledby="title-cost" hidden>
<h2 id="title-cost">3. 비용</h2>
<p class="lead">분석기는 호출마다 토큰 사용량에 단가를 곱해 비용을 적고, 누적이 전체 상한에 닿으면 멈춘다. 단가는 100만 토큰당 달러다. 이 콘솔은 가격을 모른다. 반드시 제공자의 가격 페이지에서 확인한 값을 넣는다.</p>
<p class="muted">구독으로 로그인했어도 단가와 상한을 채워야 분석이 시작된다. Codex는 여기 넣은 단가로 사용량을 달러로 환산하고, Claude는 CLI가 알려 주는 비용을 쓴다. 구독이면 이 비용은 실제 청구액이 아니라 사용량을 달러로 나타낸 값이며, 상한도 그 값으로 작동한다.</p>
<p>모델 <code id="rate-model"></code>의 단가</p>
<div class="grid">
<label>입력 단가<small>100만 토큰당 달러</small><input id="rate-input" inputmode="decimal" autocomplete="off"></label>
<label>캐시 입력 단가<small>100만 토큰당 달러</small><input id="rate-cached" inputmode="decimal" autocomplete="off"></label>
<label>출력 단가<small>100만 토큰당 달러, 추론 토큰 포함</small><input id="rate-output" inputmode="decimal" autocomplete="off"></label>
<label>전체 비용 상한(달러)<small>웹 하나 분석 전체의 합. 닿으면 분석기가 멈춘다</small><input id="rate-max" inputmode="decimal" autocomplete="off"></label>
</div>
<details id="rate-long">
<summary>장문 단가(선택): 입력 토큰이 임계값을 넘는 호출에 다른 단가를 쓰는 모델</summary>
<div class="grid">
<label>장문 입력 단가<input id="rate-long-input" inputmode="decimal" autocomplete="off"></label>
<label>장문 캐시 입력 단가<input id="rate-long-cached" inputmode="decimal" autocomplete="off"></label>
<label>장문 출력 단가<input id="rate-long-output" inputmode="decimal" autocomplete="off"></label>
<label>장문 임계 토큰 수<small>입력이 이 토큰 수를 넘으면 장문 단가</small><input id="rate-threshold" inputmode="numeric" autocomplete="off"></label>
</div>
</details>
<div class="actions"><button id="rates-save" class="primary" type="button" aria-describedby="why-rates">저장하고 검사</button><span id="rate-message" class="muted" role="status"></span></div>
<div id="why-rates" class="why"></div>
<p class="muted">저장 위치: <code id="rate-path"></code>(이 PC 사용자만 읽을 수 있음). 저장할 때 분석기의 단가 검사(<code>model.cost_settings</code>)를 통과해야 파일이 바뀐다.</p>
<p>현재 상태: <span id="cost-state" class="muted"></span></p>
<div class="next"><button type="button" data-go="target">다음: 분석할 웹</button></div>
</section>

<section class="panel" id="panel-target" aria-labelledby="title-target" hidden>
<h2 id="title-target">4. 분석할 웹</h2>
<p class="lead">분석할 웹의 주소와 기록 이름을 정한다. 분석기는 이 웹에 GET과 HEAD만 보내며 폼 제출이나 상태를 바꾸는 요청은 보내지 않는다. 대상 주소와 다른 출처는 아래 추가 출처에 넣은 것만 연다.</p>
<div class="grid">
<label class="wide">대상 주소<small>예: http://target.test/</small><input id="origin" placeholder="http://target.test/" autocomplete="off" spellcheck="false"></label>
<label>중계 주소(선택)<small>원본에 직접 닿지 않을 때 그 대상만 전달하는 중계. 이 분석 프로세스에만 SITE_ANALYSIS_PROXY로 넘긴다. 사용자 이름과 비밀번호는 넣지 않는다</small><input id="proxy" placeholder="http://127.0.0.1:18095" autocomplete="off" spellcheck="false"></label>
<label>기록 이름<small id="record-path"></small><input id="name" placeholder="target-analysis-1" autocomplete="off" spellcheck="false"></label>
<label class="wide">추가 출처(선택)<small>같은 웹의 다른 출처(CDN, api 호스트). 한 줄에 하나, 경로 없이 넣으며 줄마다 --allow-origin으로 넘긴다</small><textarea id="allow_origins" rows="3" placeholder="https://cdn.example.com" spellcheck="false"></textarea></label>
</div>
<div class="actions"><button id="target-check" type="button" aria-describedby="why-target">연결 확인</button><span id="target-message" class="muted" role="status"></span></div>
<div id="why-target" class="why"></div>
<p class="muted">연결 확인은 대상 주소로 GET을 중계(없으면 직접)로 보내 상태 코드, 마지막 주소, 그 주소가 분석 범위 안인지 보여 준다. 범위 안의 이동은 5번까지 따라가며 이동마다 GET을 한 번 더 보낸다. 범위 밖으로의 이동은 따라가지 않는다. 응답 본문은 읽지 않는다. socks5 중계는 이 확인에서 쓰지 못한다.</p>
<div id="target-result"></div>
<p>현재 상태: <span id="target-state" class="muted"></span></p>
<div id="target-warn" class="notice warn" hidden></div>
<div class="next"><button type="button" data-go="account">다음: 일반 계정(선택)</button></div>
</section>

<section class="panel" id="panel-account" aria-labelledby="title-account" hidden>
<h2 id="title-account">5. 일반 계정(선택)</h2>
<p class="lead">로그인한 일반 사용자에게만 보이는 화면도 분석하려면 대상 웹에 분석 전용 일반 계정을 만들어 여기에 넣는다. 관리자 계정이나 실제 사용자 계정은 쓰지 않는다. 건너뛰면 익명 회차만 돈다. 계정 값은 이 PC의 비공개 폴더에만 저장하고 화면으로 다시 보내지 않는다.</p>
<h3>로그인 화면</h3>
<div class="grid">
<label class="wide">로그인 화면 경로<small>대상 주소 기준 경로. 예: /login</small><input id="login-path" autocomplete="off" spellcheck="false"></label>
<label>아이디 칸 찾는 법<select id="user-kind"><option value="field">name 속성</option><option value="selector">CSS 선택자</option></select></label>
<label>아이디 칸<small>name 속성 값 또는 CSS 선택자</small><input id="user-target" autocomplete="off" spellcheck="false"></label>
<label>비밀번호 칸 찾는 법<select id="password-kind"><option value="field">name 속성</option><option value="selector">CSS 선택자</option></select></label>
<label>비밀번호 칸<small>name 속성 값 또는 CSS 선택자</small><input id="password-target" autocomplete="off" spellcheck="false"></label>
<label class="wide">로그인 성공 표시(선택)<small>로그인한 뒤에만 보이는 요소의 CSS 선택자(예: 로그아웃 링크). 비우면 비밀번호 칸이 사라지는 것으로 확인한다</small><input id="success-selector" autocomplete="off" spellcheck="false"></label>
</div>
<h3>계정 값</h3>
<div class="grid">
<label>계정 값 종류<select id="account-key"><option value="username">사용자 이름(username)</option><option value="email">메일(email)</option></select></label>
<label>사용자 이름 또는 메일<input id="account-id" autocomplete="off" spellcheck="false"></label>
<label>비밀번호<input id="account-secret" type="password" autocomplete="new-password"></label>
</div>
<div class="actions"><button id="account-save" class="primary" type="button" aria-describedby="why-account">저장</button><span id="account-message" class="muted" role="status"></span></div>
<div id="why-account" class="why"></div>
<p class="muted" id="account-state"></p>
<h3>세션 준비</h3>
<p class="muted">먼저 <code>session_prepare --dry-run</code>으로 로그인 설정과 저장 경로만 확인한다(네트워크와 계정 값을 쓰지 않음). 통과하면 확인을 받은 뒤 실제로 한 번 로그인해 쿠키와 local storage만 비공개 세션 파일에 저장한다. 실제 로그인에는 4단계의 중계 주소가 필요하다(session_prepare 요구).</p>
<div class="actions"><button id="session-prepare" type="button" aria-describedby="why-session">세션 준비</button><span id="session-message" class="muted" role="status"></span></div>
<div id="why-session" class="why"></div>
<div id="session-line"></div>
<div id="session-state"></div>
<details>
<summary>다른 세션 파일 쓰기(선택)</summary>
<label>세션 파일 경로<small>비우면 기록 이름의 기본 경로. LOCALAPPDATA/ruby-site-analysis/sessions 아래만 허용</small><input id="session_file" autocomplete="off" spellcheck="false"></label>
</details>
<div id="task-account" class="task" hidden></div>
<h3>저장한 계정 지우기</h3>
<p class="muted">이 기록 이름으로 저장한 로그인 화면 설명과 계정 값을 이 PC의 비공개 폴더(<code>accounts/&lt;기록 이름&gt;/</code>)에서 지운다. 아래 칸을 고르면 위 세션 준비에 보이는 세션 파일도 지운다. 이 콘솔이 이 기록 이름으로 시작한 분석이 실행 중이면 지우지 않는다. 대상 웹에 만든 계정은 그대로 남는다.</p>
<label class="inline"><input type="checkbox" id="delete-session">세션 파일도 지운다</label>
<div class="actions"><button id="account-delete" class="danger" type="button" aria-describedby="why-account-delete">저장한 계정 지우기</button><span id="account-delete-message" class="muted" role="status"></span></div>
<div id="why-account-delete" class="why"></div>
<div class="next"><button type="button" data-go="run">다음: 실행</button></div>
</section>

<section class="panel" id="panel-run" aria-labelledby="title-run" hidden>
<h2 id="title-run">6. 실행</h2>
<p class="lead">분석을 돌린다. 점검은 네트워크와 모델 없이 설정과 내부 검사만 하며(--dry-run) 몇 초 걸린다. 시작은 같은 설정으로 점검을 통과한 뒤에만 누를 수 있고, 체크포인트가 있으면 이어서 돈다. 멈춤은 이 콘솔이 시작한 분석과 하위 프로세스를 끝낸다. 콘솔을 끄면 이 콘솔이 시작한 분석도 멈춘다.</p>
<div class="grid">
<label>익명 회차<small>--runs</small><input id="runs" inputmode="numeric" autocomplete="off"></label>
<label>계정 회차<small>--session-runs. 0이면 익명만. 쓰려면 5단계 세션이 있어야 한다</small><input id="session_runs" inputmode="numeric" autocomplete="off"></label>
<label>최대 화면 수<small>--max-pages. 비우면 분석기 기본값(회차당 60)</small><input id="max_pages" inputmode="numeric" autocomplete="off"></label>
<label>문맥 글자 수<small>--context-chars. 비우면 분석기 기본값(600000)</small><input id="context_chars" inputmode="numeric" autocomplete="off"></label>
<label>모델<small>--model. 2단계와 같은 칸</small><input id="model-run" autocomplete="off" spellcheck="false"></label>
</div>
<h3>시작 전 조건</h3>
<ul id="requirements" class="reqs"></ul>
<div id="run-warn" class="notice warn" hidden></div>
<div class="actions">
<button id="check" type="button" aria-describedby="why-run">점검</button>
<button id="start" class="primary" type="button" aria-describedby="why-run">시작(이어하기 포함)</button>
<button id="stop" class="danger" type="button" aria-describedby="why-run">멈춤</button>
<span id="message" class="muted" role="status"></span>
</div>
<div id="why-run" class="why"></div>
<div id="dry-stale" class="notice warn" hidden>설정이 바뀌어 아래 점검 결과는 지금 설정의 것이 아니다. 다시 점검한다</div>
<div id="dry"></div>
<h3>진행 <span id="updated" class="muted"></span></h3>
<div id="run-state"></div>
<div id="ledger"></div>
<div class="scroll"><table>
<thead><tr><th>회차</th><th>권한</th><th>둘러보기</th><th>축 분석</th><th>공개 전 가림</th></tr></thead>
<tbody id="timeline"></tbody>
</table></div>
<p id="timeline-note" class="muted"></p>
<h3>로그 마지막 40줄</h3>
<pre id="log">아직 없음</pre>
<div class="next"><button type="button" data-go="result">다음: 결과</button></div>
</section>

<section class="panel" id="panel-result" aria-labelledby="title-result" hidden>
<h2 id="title-result">7. 결과</h2>
<p class="lead">기록이 생기면 개수만 보여 준다. 축 설명, 근거와 원본 값은 이 화면에 나오지 않는다. 내용은 기록 파일과 아래 문서로 확인한다.</p>
<div class="actions">
<button id="result-load" type="button">새로 읽기</button>
<button id="open-records" type="button" aria-describedby="why-result">폴더 열기</button>
<span id="result-message" class="muted" role="status"></span>
</div>
<div id="why-result" class="why"></div>
<div id="result"></div>
<h3>읽을 문서</h3>
<table><tbody>
<tr><td>OUTPUTS.md<div class="muted">분석기가 내놓는 것과 방어 모듈별 사용</div><code id="doc-outputs"></code></td><td><button type="button" data-open="outputs">열기</button></td></tr>
<tr><td>INTEGRATION.md<div class="muted">요청 경로에서 분석기의 위치와 연결 순서</div><code id="doc-integration"></code></td><td><button type="button" data-open="integration">열기</button></td></tr>
<tr><td>README.md<div class="muted">준비, 실행, 결과 절</div><code id="doc-readme"></code></td><td><button type="button" data-open="readme">열기</button></td></tr>
</tbody></table>
</section>

</div>
</div>
</main>
<script nonce="__NONCE__">
const token = new URLSearchParams(location.search).get('token') || '';
const $ = (id) => document.getElementById(id);
const STEPS = ['env', 'ai', 'cost', 'target', 'account', 'run', 'result'];
const FIELD_IDS = ['origin', 'name', 'proxy', 'allow_origins', 'runs', 'session_runs', 'session_file', 'context_chars', 'max_pages'];
const LOGGED = ['subscription', 'api_key', 'yes'];
const TASK_BOX = {playwright: 'env', chromium: 'env', 'codex-install': 'ai', 'codex-login': 'ai', 'codex-key': 'ai',
  'claude-login': 'ai', connection: 'ai', session: 'account'};
const TASK_MESSAGE = {env: 'env-message', ai: 'ai-message', account: 'session-message'};
const RATE_INPUTS = {input: 'rate-input', cached_input: 'rate-cached', output: 'rate-output', max_cost: 'rate-max',
  long_input: 'rate-long-input', long_cached_input: 'rate-long-cached', long_output: 'rate-long-output', threshold: 'rate-threshold'};
const STAGE_NAMES = {browse: '둘러보기', analysis: '축 분석', privacy: '공개 전 가림', merge: '합치기'};
const PLAN_NAMES = {observation: '둘러보기', analysis: '축 분석', privacy: '공개 전 가림', run_completion: '회차 마무리',
  semantic_merge: '합치기', semantic_merge_privacy: '합친 답 가림'};
const AUTHORITY = {anonymous: '익명', session: '계정', other: '기타'};
const REASONS = {new: '새로 시작', resume: '체크포인트에서 이어서', fresh: '처음부터',
  different_origin_catalog_or_output: '저장된 체크포인트와 원본, 축 목록 또는 출력이 달라 새로 시작'};
const MODEL_RE = /^[A-Za-z0-9][A-Za-z0-9_.:\/-]{0,79}$/;
// Each CLI's default model; switching provider replaces only an empty field or the other CLI's default.
const MODEL_DEFAULT = {codex: 'gpt-6-sol', claude: 'claude-opus-5-5'};
let records = '', current = 'env', rates = '', snapshot = null, env = null, account = null, saveTimer = null;
let refreshing = false, loadedModel = null, ratesTouched = false, dryValues = null, dryFolded = false;
const ai = {}, busy = {}, polling = {}, seen = {};

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

async function api(path, body) {
  const options = {headers: {'X-Console-Token': token}};
  if (body !== undefined) {
    options.method = 'POST';
    options.headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch (error) {
    throw new Error('콘솔에 연결하지 못함. 콘솔 창이 켜져 있는지 확인한다. 콘솔을 다시 켰다면 창에 새로 찍힌 주소로 연다');
  }
  let data;
  try { data = await response.json(); } catch (error) { data = {error: '응답을 읽지 못함'}; }
  if (!response.ok) throw new Error(data.error || ('콘솔 응답 오류 ' + response.status));
  return data;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function say(id, text, bad) { const node = $(id); node.textContent = text || ''; node.className = bad ? 'hint' : 'muted'; }
function badgeClass(text) {
  return {'완료': 'ok', '필요': 'bad', '선택': 'opt', '실행 중': 'run', '진행 중': 'run', '남음': 'warn'}[text] || '';
}
function badge(text) { return el('span', text, 'badge ' + badgeClass(text)); }
function provider() { return document.querySelector('input[name="provider"]:checked').value; }
function validModel() { return MODEL_RE.test($('model').value.trim()); }
function envRow(name) { return env ? env.rows.find((item) => item.name === name) : null; }
function pairs(list) { return list && list.length ? list.map(([name, count]) => name + ' ' + count).join(', ') : '없음'; }
function dl(entries) {
  const list = el('dl');
  for (const [name, value] of entries) list.append(el('dt', name), el('dd', value));
  return list;
}

function values() {
  const result = {};
  for (const id of FIELD_IDS) result[id] = $(id).value.trim();
  result.provider = provider();
  result.model = $('model').value.trim();
  result.rates = rates;
  result.max_cost = '';
  return result;
}

function show(step) {
  if (!STEPS.includes(step)) step = 'env';
  current = step;
  for (const key of STEPS) {
    $('panel-' + key).hidden = key !== step;
    $('nav-' + key).setAttribute('aria-current', key === step ? 'step' : 'false');
  }
  if (location.hash !== '#' + step) history.replaceState(null, '', location.pathname + location.search + '#' + step);
  if (step === 'cost') loadRates();
  if (step === 'account') loadAccount();
  if (step === 'result') loadResult();
  gate();
}

function renderNav() {
  const steps = (snapshot && snapshot.steps) || {};
  for (const key of STEPS) {
    const node = $('badge-' + key), text = steps[key] || '확인 중';
    node.textContent = text;
    node.className = 'badge ' + badgeClass(text);
  }
}

function checkRow(check) {
  const tr = el('tr'), state = el('td'), detail = el('td');
  state.append(badge(check.ok ? '완료' : '필요'));
  detail.append(el('div', check.detail));
  if (check.hint && !check.ok) detail.append(el('div', check.hint, 'hint'));
  tr.append(el('td', check.name), state, detail);
  return tr;
}

function messageRow(text) {
  const tr = el('tr'), td = el('td', text, 'muted');
  td.colSpan = 3;
  tr.append(td);
  return tr;
}

function renderEnv() {
  const body = $('env-rows');
  if (!env) {
    body.replaceChildren(messageRow(busy.env ? '확인 중. Chromium을 한 번 띄워 보느라 몇 초 걸린다' : '아직 확인 안 함'));
    return;
  }
  body.replaceChildren(...env.rows.map(checkRow));
  if (!busy.env) say('env-message', '확인 ' + env.checked);
}

async function checkEnv() {
  if (busy.env) return;
  busy.env = true;
  say('env-message', '확인 중');
  renderEnv();
  gate();
  try {
    env = await api('/api/env', {});
  } catch (error) {
    say('env-message', error.message, true);
  } finally {
    busy.env = false;
    renderEnv();
    gate();
    refresh();
  }
}

function renderAi() {
  const name = provider(), view = ai[name];
  $('codex-box').hidden = name !== 'codex';
  $('claude-box').hidden = name !== 'claude';
  const body = $('ai-rows');
  if (!view) {
    body.replaceChildren(messageRow(busy.ai ? '확인 중' : '아직 확인 안 함'));
    return;
  }
  const loginHint = !view.found ? '' : name === 'codex' ? '아래 구독으로 로그인 또는 API 키로 로그인을 쓴다'
    : '아래 Claude 로그인을 누른다';
  body.replaceChildren(
    checkRow({name: name + ' CLI', ok: view.found, detail: view.found ? view.path + ', ' + view.version : 'PATH에서 찾지 못함', hint: view.hint}),
    checkRow({name: '로그인', ok: LOGGED.includes(view.login), detail: view.login_text, hint: loginHint}));
  if (!busy.ai) say('ai-message', '확인 ' + view.checked);
}

async function checkAi() {
  if (busy.ai) return;
  const name = provider();
  busy.ai = true;
  say('ai-message', '확인 중');
  renderAi();
  gate();
  try {
    ai[name] = await api('/api/ai', {provider: name});
  } catch (error) {
    say('ai-message', error.message, true);
  } finally {
    busy.ai = false;
    renderAi();
    gate();
    refresh();
  }
  if (provider() !== name && !ai[provider()]) checkAi();
}

function connectionView(result) {
  const ok = !result.error;
  const box = el('div', ok ? '연결 시험 통과: 모델이 응답함' : '연결 시험 실패: ' + result.error, 'notice ' + (ok ? 'ok' : 'bad'));
  const usage = Object.entries(result.usage || {}).map(([key, value]) => key + ' ' + value).join(', ');
  if (usage) box.append(el('div', '토큰: ' + usage));
  let cost = '단가가 없어 달러 비용은 계산하지 않음. 3단계에서 단가를 저장하면 다음 시험부터 보인다';
  if (result.priced || result.provider === 'claude') {
    cost = result.usd === null || result.usd === undefined ? '비용 기록 없음'
      : '비용 ' + Number(result.usd).toFixed(4) + ' 달러' + (result.usd_estimated ? '(추정)' : '');
  }
  box.append(el('div', cost));
  if (result.seconds) box.append(el('div', result.seconds + '초 걸림'));
  return box;
}

function renderTask(data) {
  if (!data || !data.exists) return;
  const box = $('task-' + TASK_BOX[data.kind]);
  box.hidden = false;
  const stateText = data.running ? '실행 중' : data.cancelled ? '취소함' : '끝남: 종료 코드 ' + data.code;
  const head = el('div', null, 'task-head');
  const title = el('strong', data.label + ' ');
  title.append(el('span', stateText, 'badge ' + (data.running ? 'run' : data.cancelled ? '' : data.code === 0 ? 'ok' : 'bad')));
  const cancel = el('button', '취소', 'danger');
  cancel.type = 'button';
  cancel.hidden = !data.running;
  cancel.addEventListener('click', () => cancelTask(data.kind));
  head.append(title, el('span', data.started + ' 시작', 'muted'), cancel);
  const parts = [head];
  if (data.kind === 'connection' && data.result) parts.push(connectionView(data.result));
  if (data.kind === 'codex-login' || data.kind === 'claude-login') {
    const urls = [...new Set(data.lines.flatMap((line) => line.match(/https:\/\/[^\s"'<>]+/g) || []))];
    if (urls.length) {
      const links = el('div', null, 'links');
      links.append(el('div', data.kind === 'claude-login' ? 'CLI가 알려 준 주소(브라우저가 열리지 않았으면 누른다. ' +
        '로그인 뒤 그 화면에 나온 코드는 위 코드 칸에 붙여 넣는다)' : 'CLI가 알려 준 주소(브라우저가 열리지 않았으면 누른다)', 'muted'));
      for (const url of urls.slice(-3)) {
        const link = el('a', url);
        link.href = url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        const line = el('div');
        line.append(link);
        links.append(line);
      }
      parts.push(links);
    }
  }
  const pre = el('pre', data.lines.length ? data.lines.join('\n') : '출력 없음');
  parts.push(pre);
  box.replaceChildren(...parts);
  pre.scrollTop = pre.scrollHeight;
}

async function startTask(kind, extra) {
  const message = TASK_MESSAGE[TASK_BOX[kind]];
  try {
    const data = await api('/api/task/start', Object.assign(values(), extra || {}, {kind}));
    if (snapshot) snapshot.tasks = Object.assign({}, snapshot.tasks, {[kind]: true});
    say(message, data.label + ' 시작함');
    renderTask(data);
    pollTask(kind);
  } catch (error) {
    say(message, error.message, true);
  }
  gate();
}

async function pollTask(kind) {
  if (polling[kind]) return;
  polling[kind] = true;
  try {
    for (;;) {
      const data = await api('/api/task', {kind});
      renderTask(data);
      if (!data.running) {
        if (snapshot && snapshot.tasks) snapshot.tasks[kind] = false;
        say(TASK_MESSAGE[TASK_BOX[kind]], data.label + (data.cancelled ? ' 취소함' : ' 끝남: 종료 코드 ' + data.code), !data.cancelled && data.code !== 0);
        finished(kind);
        break;
      }
      await sleep(1000);
    }
  } catch (error) {
    say(TASK_MESSAGE[TASK_BOX[kind]], '작업 상태를 읽지 못함: ' + error.message, true);
  } finally {
    polling[kind] = false;
    gate();
  }
}

function finished(kind) {
  if (kind === 'claude-login') $('claude-code').value = '';
  if (kind === 'playwright' || kind === 'chromium') checkEnv();
  else if (['codex-install', 'codex-login', 'codex-key', 'claude-login'].includes(kind)) checkAi();
  else if (kind === 'session') loadAccount();
  refresh();
}

async function sendClaudeCode() {
  const code = $('claude-code').value.trim();
  $('claude-code').value = '';
  busy.claudeCode = true;
  gate();
  try {
    renderTask(await api('/api/task/input', {kind: 'claude-login', code}));
    say('ai-message', '코드를 Claude 로그인 프로세스에 넘김');
  } catch (error) {
    say('ai-message', error.message, true);
  } finally {
    busy.claudeCode = false;
    gate();
  }
}

async function cancelTask(kind) {
  try {
    renderTask(await api('/api/task/cancel', {kind}));
  } catch (error) {
    say(TASK_MESSAGE[TASK_BOX[kind]], error.message, true);
  }
}

async function loadRates() {
  const model = $('model').value.trim();
  $('rate-model').textContent = model || '없음: 2단계에서 모델 이름을 넣는다';
  if (!validModel() || loadedModel === model) { gate(); return; }
  try {
    const data = await api('/api/rates', {model});
    // Saved prices fill the form only when nothing was typed meanwhile.
    if (!ratesTouched) {
      for (const [key, id] of Object.entries(RATE_INPUTS)) $(id).value = data.form[key] || '';
      $('rate-long').open = Boolean(data.form.threshold);
    }
    $('rate-path').textContent = data.path;
    loadedModel = model;
  } catch (error) {
    say('rate-message', error.message, true);
  }
  gate();
}

async function saveRates() {
  const body = {model: $('model').value.trim()};
  for (const [key, id] of Object.entries(RATE_INPUTS)) body[key] = $(id).value.trim();
  busy.rates = true;
  say('rate-message', '검사 중');
  gate();
  try {
    const data = await api('/api/rates/save', body);
    rates = data.path;
    loadedModel = body.model;
    $('rate-path').textContent = data.path;
    say('rate-message', '저장함: ' + data.detail);
  } catch (error) {
    say('rate-message', error.message, true);
  } finally {
    busy.rates = false;
    await refresh();
  }
}

function recordPath() {
  const name = $('name').value.trim().replace(/\.json$/, '');
  const sep = records.includes('\\') ? '\\' : '/';
  $('record-path').textContent = '공개 기록 ' + records + sep + (name || '<이름>') + '.json. 계정 폴더와 세션 파일 이름에도 쓴다';
}

async function checkTarget() {
  busy.target = true;
  gate();
  say('target-message', '확인 중');
  $('target-result').replaceChildren();
  try {
    const data = await api('/api/target/check', values());
    const parts = [el('div', data.in_scope ? '마지막 주소가 분석 범위 안에 있음' :
      '마지막 주소가 분석 범위 밖임. 대상 주소나 추가 출처를 확인한다', 'notice ' + (data.in_scope ? 'ok' : 'warn'))];
    if (data.code >= 400) parts.push(el('div', '상태 코드 ' + data.code + ': 대상이 요청을 거부했거나 오류를 냄. 주소와 중계를 확인한다', 'notice warn'));
    const entries = [['상태 코드', data.code], ['마지막 주소', data.final_url], ['분석 범위', data.in_scope ? '안' : '밖'],
      ['따라간 이동', data.redirects + '번'], ['경로', data.via], ['걸린 시간', data.seconds + '초']];
    if (data.note) entries.push(['참고', data.note]);
    parts.push(dl(entries));
    $('target-result').replaceChildren(...parts);
    say('target-message', '');
  } catch (error) {
    say('target-message', error.message, true);
  } finally {
    busy.target = false;
    gate();
  }
}

function accountBody() {
  return Object.assign(values(), {login_path: $('login-path').value.trim(), user_kind: $('user-kind').value,
    user_target: $('user-target').value.trim(), password_kind: $('password-kind').value,
    password_target: $('password-target').value.trim(), success_selector: $('success-selector').value.trim(),
    account_key: $('account-key').value, account_id: $('account-id').value.trim(), account_secret: $('account-secret').value});
}

function renderAccount() {
  $('account-id').value = '';
  $('account-secret').value = '';
  $('account-id').placeholder = account && account.id_saved ? '저장됨. 바꿀 때만 넣는다' : '';
  $('account-secret').placeholder = account && account.password_saved ? '저장됨. 바꿀 때만 넣는다' : '';
  $('account-state').textContent = !account ? '' : '저장 위치 ' + account.folder + '. 로그인 화면 ' +
    (account.config_saved ? '저장됨' : '없음') + ', 계정 값 ' + (account.id_saved && account.password_saved ? '저장됨' : '없음');
  renderSession(account ? account.session : null);
}

function renderSession(session) {
  const box = $('session-state');
  if (!session) { box.replaceChildren(); return; }
  if (session.error) { box.replaceChildren(el('div', session.error, 'notice bad')); return; }
  if (!session.exists) { box.replaceChildren(el('div', '세션 파일 없음: ' + session.path, 'notice')); return; }
  const s = session.summary;
  const node = el('div', (s.expired ? '세션이 만료됨. 세션 준비를 다시 누른다. ' : '세션 파일 있음. ') + '쿠키 ' + s.cookies +
    '개(브라우저 세션 쿠키 ' + s.session_cookies + '개), 만료 ' + s.expired_cookies + '개, local storage 출처 ' +
    s.local_storage_origins + '개', 'notice ' + (s.expired ? 'bad' : 'ok'));
  node.append(el('div', session.path + ', ' + session.modified + ' 저장. 값은 이 화면에 나오지 않는다', 'muted'));
  box.replaceChildren(node);
}

async function loadAccount() {
  if (!$('name').value.trim()) {
    account = null;
    renderAccount();
    say('account-message', '4단계에서 기록 이름을 먼저 넣는다. 계정 폴더 이름으로 쓴다', true);
    gate();
    return;
  }
  try {
    account = await api('/api/account', values());
    const form = account.form;
    if (account.config_saved) {
      $('login-path').value = form.login_path;
      $('user-kind').value = form.user_kind;
      $('user-target').value = form.user_target;
      $('password-kind').value = form.password_kind;
      $('password-target').value = form.password_target;
      $('success-selector').value = form.success_selector;
    }
    $('account-key').value = form.account_key || account.id_kind || 'username';
    say('account-message', '');
  } catch (error) {
    account = null;
    say('account-message', error.message, true);
  }
  renderAccount();
  gate();
}

async function saveAccount() {
  busy.account = true;
  say('account-message', '저장 중');
  gate();
  try {
    account = await api('/api/account/save', accountBody());
    renderAccount();
    say('account-message', '저장함. 계정 값은 화면으로 다시 보내지 않는다');
  } catch (error) {
    say('account-message', error.message, true);
  } finally {
    busy.account = false;
    gate();
  }
}

async function prepareSession() {
  busy.session = true;
  gate();
  say('session-message', 'dry-run 점검 중');
  $('session-line').replaceChildren();
  try {
    const check = await api('/api/session/check', values());
    const line = el('div', check.line, 'notice ' + (check.ok ? 'ok' : 'bad'));
    if (check.reason) line.append(el('div', '원인: ' + check.reason));
    $('session-line').replaceChildren(line);
    if (!check.ok) { say('session-message', 'dry-run을 통과하지 못해 로그인하지 않음', true); return; }
    if (!check.relay) { say('session-message', '실제 로그인에는 4단계의 중계 주소가 필요함(session_prepare 요구)', true); return; }
    if (!confirm('dry-run을 통과했다. 이제 ' + values().origin + '에 저장한 일반 계정으로 실제로 한 번 로그인하고 ' +
      '쿠키와 local storage를 비공개 세션 파일에 저장한다. 계속할까?')) {
      say('session-message', '로그인하지 않음: dry-run 결과만 확인함');
      return;
    }
    await startTask('session');
  } catch (error) {
    say('session-message', error.message, true);
  } finally {
    busy.session = false;
    gate();
  }
}

async function deleteAccount() {
  const name = $('name').value.trim(), withSession = $('delete-session').checked;
  const sessionPath = snapshot && snapshot.session && snapshot.session.path ? snapshot.session.path : '';
  if (!confirm('기록 이름 ' + name + '로 저장한 로그인 화면 설명과 계정 값을 이 PC의 비공개 폴더에서 지운다' +
    (withSession ? '. 세션 파일 ' + sessionPath + '도 지운다' : '. 세션 파일은 남긴다') + '. 되돌릴 수 없다. 계속할까?')) {
    say('account-delete-message', '지우지 않음');
    return;
  }
  busy.accountDelete = true;
  say('account-delete-message', '지우는 중');
  gate();
  try {
    const data = await api('/api/account/delete', Object.assign(values(), {session: withSession}));
    account = data.account;
    for (const id of ['login-path', 'user-target', 'password-target', 'success-selector']) $(id).value = '';
    $('user-kind').value = $('password-kind').value = 'field';
    $('account-key').value = 'username';
    $('delete-session').checked = false;
    renderAccount();
    say('account-delete-message', data.message);
  } catch (error) {
    say('account-delete-message', error.message, true);
  } finally {
    busy.accountDelete = false;
    await refresh();
  }
}

function budgetText(budget) {
  if (!budget || typeof budget !== 'object') return String(budget);
  const names = {requests: ['요청 ', '개'], pages: ['화면 ', '개'], seconds: ['', '초'], sample_chars: ['표본 ', '자']};
  return Object.entries(budget).map(([key, value]) => names[key] ? names[key][0] + value + names[key][1] : key + ' ' + value).join(', ');
}

function stageText(stage) {
  if (!stage) return '없음';
  if (stage.stage === 'complete') return '모든 단계 끝남';
  return [stage.run ? stage.run + '회차' : '', PLAN_NAMES[stage.stage] || stage.stage,
    stage.group || stage.scope || AUTHORITY[stage.authority] || ''].filter(Boolean).join(' ');
}

function showDry(data) {
  const box = $('dry');
  const failed = el('div', '점검 실패: 종료 코드 ' + data.code + (data.code === 2 ?
    '. 분석기가 설정이나 단가 검사에서 멈춤. 아래 원인을 고친 뒤 다시 점검한다' : ''), 'notice bad');
  for (const line of data.reasons || []) failed.append(el('div', line));
  box.replaceChildren(data.code === 0 ? el('div', '점검 통과. 이 설정 그대로이고 위 시작 전 조건이 모두 완료면 시작을 누를 수 있다', 'notice ok') : failed);
  const report = data.report;
  if (report) {
    const entries = [['기록 파일', report.out], ['체크포인트', report.checkpoint_folder],
      ['재개 판단', REASONS[report.resume_reason] || report.resume_reason], ['시작할 단계', stageText(report.resume_from)]];
    if (report.saved_cost) entries.push(['저장된 비용', report.saved_cost.spent_usd + ' / ' + report.saved_cost.max_cost_usd + ' 달러']);
    entries.push(['단가', report.rates_check],
      ['회차', (report.observation_runs || []).map((run) => run.run + '회차 ' + (run.authority === 'session' ? '계정' : '익명')).join(', ')],
      ['제공자와 모델', report.provider + ', ' + report.model], ['문맥 글자 수', report.context_chars],
      ['회차당 예산', budgetText(report.budget_per_run)],
      ['점검 중 네트워크 요청, 모델 호출, 파일 쓰기', [report.network_requests, report.model_calls, report.files_written].join(', ')]);
    const details = el('details'), more = el('details');
    details.append(el('summary', '전체 결과'), el('pre', JSON.stringify(report, null, 2)));
    more.id = 'dry-more';
    more.open = true;
    more.append(el('summary', '점검 내용'), dl(entries), details);
    box.append(more);
    dryFolded = false;
  } else if (data.stdout) {
    box.append(el('pre', data.stdout));
  }
  if (data.stderr && data.stderr.length) {
    const details = el('details');
    details.open = data.code !== 0;
    details.append(el('summary', '표준 오류 마지막 ' + data.stderr.length + '줄'), el('pre', data.stderr.join('\n')));
    box.append(details);
  }
}

function renderRequirements(data) {
  const steps = data.steps || {};
  const items = [['env', '1. 환경', steps.env], ['ai', '2. AI 연결', steps.ai], ['cost', '3. 비용', steps.cost],
    ['target', '4. 분석할 웹', steps.target],
    ['account', data.session_needed ? '5. 일반 계정 세션' : '5. 일반 계정(계정 회차 0: 익명만)', data.session_needed ? steps.account : '선택'],
    [null, '같은 설정으로 점검 통과', data.checked ? '완료' : '필요']];
  $('requirements').replaceChildren(...items.map(([key, label, stateText]) => {
    const item = el('li');
    item.append(badge(stateText || '확인 중'));
    if (key) {
      const link = el('button', label, 'link');
      link.type = 'button';
      link.addEventListener('click', () => show(key));
      item.append(link);
    } else {
      item.append(el('span', label));
    }
    return item;
  }));
}

function renderTimeline(rows) {
  const body = $('timeline');
  if (!rows || !rows.length) {
    const tr = el('tr'), td = el('td', '대상 주소와 기록 이름을 넣으면 계획이 보인다', 'muted');
    td.colSpan = 5;
    tr.append(td);
    body.replaceChildren(tr);
    return;
  }
  body.replaceChildren(...rows.map((line) => {
    const tr = el('tr');
    tr.append(el('td', line.label), el('td', AUTHORITY[line.authority] || line.authority));
    for (const item of line.cells) {
      const td = el('td');
      if (line.cells.length === 1) td.colSpan = 3;
      td.append(badge(item.state));
      if (item.count) {
        const unit = {analysis: '묶음', privacy: '칸', merge: '축'}[item.stage];
        if (unit) td.append(el('span', ' ' + unit + ' ' + item.count + '개 남음', 'muted'));
      }
      tr.append(td);
    }
    return tr;
  }));
}

function showProgress(data) {
  if (data.running && !dryFolded && $('dry-more')) {
    $('dry-more').open = false;
    dryFolded = true;
  }
  const state = $('run-state');
  if (data.running) {
    state.replaceChildren(el('div', '실행 중: PID ' + data.job.pid + ', ' + data.job.started + ' 시작', 'notice ok'));
  } else if (data.job) {
    const code = data.job.code;
    const tone = data.job.stopped ? '' : code === 0 ? ' ok' : code === 2 ? ' warn' : ' bad';
    const ended = el('div', '끝남: ' + data.job.started + ' 시작, 종료 코드 ' + code + '. ' + data.job.note, 'notice' + tone);
    if (data.job.reasons.length) ended.append(el('div', '분석기가 남긴 원인: ' + data.job.reasons.join(' / ')));
    state.replaceChildren(ended);
  } else {
    state.replaceChildren(el('div', '이 콘솔이 시작한 실행 없음. 다른 창에서 돌린 분석은 아래 장부로만 보인다', 'notice'));
  }
  if (data.others && data.others.length) {
    state.append(el('div', '다른 기록 이름으로 실행 중: ' + data.others.join(', ') +
      '. 4단계 기록 이름을 그 이름으로 바꾸면 진행을 보고 멈출 수 있다', 'notice warn'));
  }
  const box = $('ledger'), view = data.ledger;
  box.replaceChildren();
  if (!view) {
    box.append(el('p', data.note, 'muted'));
  } else {
    if (view.stalled) box.append(el('div', '남은 일이 있는데 ' + data.stall_minutes + '분 넘게 기록이 없음: 멈춤 의심. 로그를 보고 필요하면 멈춤 뒤 다시 점검하고 시작한다', 'notice warn'));
    if (!data.running && view.remaining_stages) box.append(el('div', '남은 단계가 있음. 같은 설정으로 점검한 뒤 시작하면 체크포인트에서 이어서 돈다', 'notice'));
    const ceiling = Number(view.max_cost_usd);
    const bar = el('progress');
    bar.max = ceiling > 0 ? ceiling : 1;
    bar.value = Math.min(view.spent_usd, bar.max);
    bar.setAttribute('aria-label', '비용 상한 대비 사용액');
    const cost = el('div', null, 'cost');
    cost.append(el('div', '비용 ' + view.spent_usd.toFixed(2) + ' / ' + (ceiling > 0 ? ceiling.toFixed(2) : '?') + ' 달러' +
      (ceiling > 0 ? ' (' + Math.round(view.spent_usd / ceiling * 100) + '%)' : '')), bar);
    box.append(cost, dl([['호출', view.calls + '회' + (view.inflight ? ', 호출 진행 중' : '')],
      ['최근 호출 단계', data.active_stage ? STAGE_NAMES[data.active_stage] : '없음'],
      ['마지막 기록', Math.round(view.minutes_since_record) + '분 전'], ['남은 단계', view.remaining_stages + '개'],
      ['실패 호출', pairs(view.failed_calls)], ['체크포인트', view.folder]]));
  }
  renderTimeline(data.timeline);
  const plan = data.running && data.job ? '실행 중인 분석의 설정' : '지금 설정';
  $('timeline-note').textContent = data.timeline && data.timeline.length ? '표의 회차와 합치기는 ' + plan +
    ' 기준 계획이다. 완료와 남음은 비공개 비용 장부의 남은 단계로 표시하며, 다른 설정으로 만든 기록은 표와 다를 수 있다. ' +
    '진행 중 표시는 마지막 모델 호출의 단계에서 아직 남은 첫 칸이다.' : '';
  const log = $('log');
  log.textContent = data.log.length ? data.log.join('\n') : '아직 없음';
  log.scrollTop = log.scrollHeight;
}

async function act(kind) {
  const form = values();
  if (kind === 'start' && !confirm('대상 ' + form.origin + '에 실제 요청을 보내고 비용이 드는 분석을 시작한다. ' +
    '체크포인트가 있으면 이어서 돈다. ' + (snapshot && snapshot.record_exists ?
    '이 이름의 기록 파일이 이미 있어 분석기가 같은 파일에 결과를 다시 쓴다. ' : '') + '계속할까?')) return;
  if (kind === 'stop' && !confirm('분석 프로세스와 하위 프로세스를 강제로 끝낸다. 진행 중이던 모델 호출의 비용은 ' +
    '돌려받지 못할 수 있다. 계속할까?')) return;
  busy.run = true;
  gate();
  say('message', {check: '점검 중', start: '시작 중', stop: '멈추는 중'}[kind]);
  try {
    if (kind === 'check') {
      const data = await api('/api/check', form);
      dryValues = JSON.stringify(form);
      showDry(data);
      say('message', data.code === 0 ? '점검 끝: 통과' : '점검 끝: 실패', data.code !== 0);
    } else if (kind === 'start') {
      const data = await api('/api/start', form);
      say('message', '시작함: PID ' + data.pid);
    } else {
      const data = await api('/api/stop', {name: form.name});
      say('message', '멈춤: 종료 코드 ' + data.code);
    }
  } catch (error) {
    say('message', error.message, true);
  } finally {
    busy.run = false;
    await refresh();
  }
}

function countTable(headers, rows, textColumns) {
  const table = el('table'), head = el('tr'), thead = el('thead'), tbody = el('tbody');
  headers.forEach((name, index) => head.append(el('th', name, index >= textColumns ? 'num-cell' : '')));
  thead.append(head);
  for (const cells of rows) {
    const tr = el('tr');
    cells.forEach((value, index) => tr.append(el('td', value, index >= textColumns ? 'num-cell' : '')));
    tbody.append(tr);
  }
  table.append(thead, tbody);
  const wrap = el('div', null, 'scroll');
  wrap.append(table);
  return wrap;
}

function renderResult(data) {
  const box = $('result');
  if (!data.exists) {
    box.replaceChildren(el('div', '기록 없음: ' + data.path + '. 6단계 실행이 기록을 남기면 여기에 개수가 나온다', 'notice'));
    return;
  }
  if (data.error) { box.replaceChildren(el('div', data.error, 'notice bad')); return; }
  const cost = data.cost ? Number(data.cost).toFixed(2) + (data.max_cost ? ' / ' + Number(data.max_cost).toFixed(2) : '') + ' 달러' : '기록 없음';
  const parts = [dl([['기록 파일', data.path], ['만든 시각', data.created || '표시 없음'], ['비용', cost],
    ['모델 호출', data.calls === null ? '기록 없음' : data.calls + '회'],
    ['멈춘 사유', data.stop_reason ? data.stop_reason + (data.stop_text ? '(' + data.stop_text + ')' : '') : '없음'],
    ['남은 단계', data.pending ? '있음: 6단계에서 같은 설정으로 점검한 뒤 시작하면 이어서 돈다' : '없음']])];
  parts.push(el('h3', '회차별 축 상태 개수'));
  parts.push(data.runs.length ? countTable(['회차', '권한', '관찰됨', '없음', '사례 부족', '못 봄', '기타', '축 수'],
    data.runs.map((run) => [run.run + '회차', AUTHORITY[run.authority], run.counts['관찰됨'], run.counts['없음'],
      run.counts['사례 부족'], run.counts['못 봄'], run.counts['기타'], run.axes]), 2) : el('p', '회차 기록 없음', 'muted'));
  parts.push(el('h3', '합친 결과의 사실 표시 개수'));
  parts.push(data.merged.length ? countTable(['권한', 'both-runs', 'single-run', 'contradictory', '기타 표시', '의미 일치 축', '불일치 축', '축 수'],
    data.merged.map((block) => [AUTHORITY[block.authority], block.labels['both-runs'], block.labels['single-run'],
      block.labels.contradictory, block.labels['기타'], block.agreement, block.disagreement, block.axes]), 1)
    : el('p', '합친 결과 없음: 같은 권한의 회차가 2개 이상일 때만 합친다', 'muted'));
  parts.push(el('p', 'both-runs는 두 회차 모두에서 본 사실, single-run은 한 회차에서만 본 사실, contradictory는 회차끼리 어긋난 사실이다. 미끼웹 메움은 both-runs만 근거로 쓴다.', 'muted'));
  box.replaceChildren(...parts);
}

async function loadResult() {
  if (!$('name').value.trim()) {
    $('result').replaceChildren(el('div', '4단계에서 기록 이름을 넣는다', 'notice'));
    return;
  }
  try {
    renderResult(await api('/api/result', {name: $('name').value.trim()}));
    say('result-message', '읽음 ' + new Date().toLocaleTimeString('ko-KR'));
  } catch (error) {
    say('result-message', error.message, true);
  }
}

async function openTarget(target) {
  try {
    const data = await api('/api/open', {target});
    say('result-message', '열었음: ' + data.opened);
  } catch (error) {
    say('result-message', error.message, true);
  }
}

// Each [id, reasons] pair: the first true reason disables the button and is shown under its row.
function gateRow(whyId, buttons) {
  const lines = [];
  for (const [id, reasons] of buttons) {
    const found = reasons.find(([failed]) => failed);
    $(id).disabled = Boolean(found);
    if (found) lines.push($(id).textContent + ': ' + found[1]);
  }
  const box = $(whyId), text = lines.join('\n');
  if (box.dataset.text !== text) {
    box.dataset.text = text;
    box.replaceChildren(...lines.map((line) => el('div', line)));
  }
}

function gate() {
  const s = snapshot || {steps: {}, tasks: {}};
  const tasks = s.tasks || {}, steps = s.steps || {};
  const playwright = envRow('Playwright'), chromium = envRow('Chromium');
  const envTask = Boolean(tasks.playwright || tasks.chromium);
  const envWait = [[Boolean(busy.env), '환경을 확인하는 중'], [!env, '환경 확인 결과가 없음. 다시 확인을 누른다'],
    [envTask, '설치 작업이 실행 중. 끝나거나 취소한 뒤 누른다']];
  gateRow('why-env', [
    ['env-check', [[Boolean(busy.env), '환경을 확인하는 중'], [envTask, '설치가 끝나면 자동으로 다시 확인한다']]],
    ['install-playwright', [...envWait, [Boolean(playwright && playwright.ok), '이미 설치됨']]],
    ['install-chromium', [...envWait, [!(playwright && playwright.ok), 'Playwright를 먼저 설치한다'],
      [Boolean(chromium && chromium.ok), '이미 설치되어 실행까지 확인됨']]]]);
  const view = ai[provider()], codex = ai.codex;
  const aiTask = Boolean(tasks['codex-install'] || tasks['codex-login'] || tasks['codex-key'] || tasks['claude-login'] ||
    tasks.connection);
  const found = Boolean(view && view.found), logged = Boolean(view && LOGGED.includes(view.login));
  const codexFound = Boolean(codex && codex.found);
  const aiWait = (current) => [[Boolean(busy.ai), '상태를 확인하는 중'], [!current, '로그인 상태 확인을 먼저 누른다'],
    [aiTask, '다른 작업이 실행 중. 끝나거나 취소한 뒤 누른다']];
  gateRow('why-ai', [['ai-check', [[Boolean(busy.ai), '상태를 확인하는 중'], [aiTask, '작업이 실행 중. 끝나면 다시 누를 수 있다']]]]);
  gateRow('why-codex', [
    ['codex-install', [...aiWait(codex), [codexFound, '이미 설치됨'], [Boolean(codex && !codex.npm), 'npm이 없음. 위 상태 표의 안내를 따른다']]],
    ['codex-login', [...aiWait(codex), [!codexFound, 'Codex CLI를 먼저 설치한다']]]]);
  gateRow('why-codex-key', [['codex-key', [...aiWait(codex), [!codexFound, 'Codex CLI를 먼저 설치한다'],
    [!$('api-key').value.trim(), 'API 키를 칸에 넣으면 켜진다']]]]);
  const claude = ai.claude;
  gateRow('why-claude', [['claude-login', [...aiWait(claude),
    [!(claude && claude.found), 'Claude CLI를 먼저 설치한다. 위 상태 표의 안내를 따른다']]]]);
  gateRow('why-claude-code', [['claude-code-send', [[!tasks['claude-login'], 'Claude 로그인이 실행 중일 때만 쓴다'],
    [!$('claude-code').value.trim(), '코드를 칸에 넣으면 켜진다'], [Boolean(busy.claudeCode), '보내는 중']]]]);
  gateRow('why-connection', [['connection', [...aiWait(view), [!found, 'CLI를 먼저 설치한다'], [!logged, '먼저 로그인한다'],
    [!validModel(), '모델 이름을 확인한다(영문, 숫자, 점, 밑줄, 콜론, 빗금, 붙임표)']]]]);
  const missing = [['rate-input', '입력 단가'], ['rate-cached', '캐시 입력 단가'], ['rate-output', '출력 단가'],
    ['rate-max', '전체 비용 상한']].filter(([id]) => !$(id).value.trim()).map(([, label]) => label);
  gateRow('why-rates', [['rates-save', [[!validModel(), '2단계에서 모델 이름을 바르게 넣는다'],
    [missing.length > 0, missing.join(', ') + ' 칸을 채운다'], [Boolean(busy.rates), '검사 중']]]]);
  gateRow('why-target', [['target-check', [[!$('origin').value.trim(), '대상 주소를 넣으면 켜진다'], [Boolean(busy.target), '확인 중']]]]);
  gateRow('why-account', [['account-save', [[!$('name').value.trim(), '4단계에서 기록 이름을 먼저 넣는다'],
    [!$('login-path').value.trim(), '로그인 화면 경로를 넣는다'], [!$('user-target').value.trim(), '아이디 칸을 넣는다'],
    [!$('password-target').value.trim(), '비밀번호 칸을 넣는다'],
    [!($('account-id').value.trim() || (account && account.id_saved)), '사용자 이름 또는 메일을 넣는다'],
    [!($('account-secret').value || (account && account.password_saved)), '비밀번호를 넣는다'], [Boolean(busy.account), '저장 중']]]]);
  const accountSaved = Boolean(account && account.config_saved && account.id_saved && account.password_saved);
  gateRow('why-session', [['session-prepare', [[steps.target !== '완료', '4단계의 대상 주소와 기록 이름을 먼저 채운다'],
    [!accountSaved, '로그인 화면과 계정 값을 먼저 저장한다'], [Boolean(tasks.session), '세션 준비가 실행 중'],
    [Boolean(busy.session), 'dry-run 점검 중']]]]);
  const stored = Boolean(account && (account.config_saved || account.id_saved || account.password_saved));
  const sessionThere = Boolean(s.session && s.session.exists), withSession = $('delete-session').checked;
  gateRow('why-account-delete', [['account-delete', [[!$('name').value.trim(), '4단계에서 기록 이름을 먼저 넣는다'],
    [!account, '저장 상태를 아직 읽지 못함'], [Boolean(s.running), '이 기록 이름의 분석이 실행 중. 6단계에서 멈춘 뒤 지운다'],
    [Boolean(tasks.session), '세션 준비가 실행 중'], [Boolean(busy.accountDelete), '지우는 중'],
    [!stored && !(withSession && sessionThere), sessionThere ? '저장한 계정 값이 없음. 세션 파일만 지우려면 위 칸을 고른다'
      : '지울 저장 값이 없음']]]]);
  const runWait = [[!snapshot, '상태를 읽는 중'], [Boolean(busy.run), '처리 중']];
  gateRow('why-run', [
    ['check', [...runWait, [Boolean(s.running), '분석이 실행 중'], [steps.cost !== '완료', '3. 비용 단계를 먼저 마친다'],
      [steps.target !== '완료', '4. 분석할 웹 단계를 먼저 마친다']]],
    ['start', [...runWait, [Boolean(s.running), '이미 실행 중'], [steps.env !== '완료', '1. 환경 단계가 필요함'],
      [steps.ai !== '완료', '2. AI 연결 단계가 필요함'], [steps.cost !== '완료', '3. 비용 단계가 필요함'],
      [steps.target !== '완료', '4. 분석할 웹 단계가 필요함'],
      [Boolean(s.session_needed && steps.account !== '완료'), '계정 회차를 쓰려면 5단계 세션이 필요함'],
      [!s.checked, '이 설정으로 점검을 먼저 통과한다']]],
    ['stop', [...runWait, [!s.running, '이 콘솔이 시작한 실행 중인 분석이 없음']]]]);
  gateRow('why-result', [['open-records', [[!s.record_exists, '이 기록 이름의 기록 파일이 아직 없음']]]]);
}

async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const data = await api('/api/state', values());
    snapshot = data;
    renderNav();
    $('cost-state').textContent = data.notes.cost;
    $('target-state').textContent = data.notes.target;
    for (const id of ['target-warn', 'run-warn']) {
      $(id).textContent = data.notes.record;
      $(id).hidden = !data.notes.record;
    }
    renderRequirements(data);
    renderSession(data.session);
    showProgress(data);
    $('dry-stale').hidden = dryValues === null || dryValues === JSON.stringify(values());
    for (const [kind, running] of Object.entries(data.tasks || {})) {
      if (running) pollTask(kind);
      else if (!seen[kind]) api('/api/task', {kind}).then(renderTask).catch(() => {});
      seen[kind] = true;
    }
    $('updated').textContent = '갱신 ' + new Date().toLocaleTimeString('ko-KR');
  } catch (error) {
    $('updated').textContent = '갱신 실패: ' + error.message;
  } finally {
    refreshing = false;
    gate();
  }
}

function scheduleSave() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    try { await api('/api/settings/save', values()); } catch (error) { /* the next refresh shows the problem */ }
    refresh();
  }, 700);
}

function setModel(source, other) {
  $(other).value = $(source).value;
  loadedModel = null;
  ratesTouched = false;
  if (current === 'cost') loadRates();
  scheduleSave();
  gate();
}

async function init() {
  try {
    const data = await api('/api/settings');
    records = data.records;
    $('records').textContent = records;
    for (const id of FIELD_IDS) $(id).value = data.settings[id] || '';
    $('model').value = $('model-run').value = data.settings.model || '';
    const chosen = data.settings.provider === 'claude' ? 'claude' : 'codex';
    document.querySelector('input[name="provider"][value="' + chosen + '"]').checked = true;
    rates = data.settings.rates || '';
    for (const [key, path] of Object.entries(data.docs || {})) { const node = $('doc-' + key); if (node) node.textContent = path; }
  } catch (error) {
    say('env-message', error.message, true);
  }
  recordPath();
  for (const id of FIELD_IDS) $(id).addEventListener('input', () => { scheduleSave(); gate(); });
  $('name').addEventListener('input', recordPath);
  $('model').addEventListener('input', () => setModel('model', 'model-run'));
  $('model-run').addEventListener('input', () => setModel('model-run', 'model'));
  for (const radio of document.querySelectorAll('input[name="provider"]')) {
    radio.addEventListener('change', () => {
      const model = $('model').value.trim();
      if (!model || Object.values(MODEL_DEFAULT).includes(model)) {
        $('model').value = MODEL_DEFAULT[provider()];
        setModel('model', 'model-run');
      }
      renderAi(); if (!ai[provider()]) checkAi(); scheduleSave(); gate();
    });
  }
  for (const button of document.querySelectorAll('[data-step]')) button.addEventListener('click', () => show(button.dataset.step));
  for (const button of document.querySelectorAll('[data-go]')) button.addEventListener('click', () => show(button.dataset.go));
  for (const button of document.querySelectorAll('[data-open]')) button.addEventListener('click', () => openTarget(button.dataset.open));
  for (const id of Object.values(RATE_INPUTS)) $(id).addEventListener('input', () => { ratesTouched = true; gate(); });
  for (const id of ['api-key', 'claude-code', 'login-path', 'user-target', 'password-target', 'account-id', 'account-secret']) {
    $(id).addEventListener('input', gate);
  }
  $('delete-session').addEventListener('change', gate);
  $('env-check').addEventListener('click', checkEnv);
  $('install-playwright').addEventListener('click', () => startTask('playwright'));
  $('install-chromium').addEventListener('click', () => startTask('chromium'));
  $('ai-check').addEventListener('click', checkAi);
  $('codex-install').addEventListener('click', () => startTask('codex-install'));
  $('codex-login').addEventListener('click', () => startTask('codex-login'));
  $('codex-key').addEventListener('click', async () => {
    const key = $('api-key').value.trim();
    $('api-key').value = '';
    await startTask('codex-key', {api_key: key});
  });
  $('claude-login').addEventListener('click', () => startTask('claude-login', {method: $('claude-method').value}));
  $('claude-code-send').addEventListener('click', sendClaudeCode);
  $('connection').addEventListener('click', () => {
    if (confirm('모델에 아주 작은 요청 하나를 보낸다. 소액 비용이 든다. 계속할까?')) startTask('connection');
  });
  $('rates-save').addEventListener('click', saveRates);
  $('target-check').addEventListener('click', checkTarget);
  $('account-save').addEventListener('click', saveAccount);
  $('session-prepare').addEventListener('click', prepareSession);
  $('account-delete').addEventListener('click', deleteAccount);
  $('check').addEventListener('click', () => act('check'));
  $('start').addEventListener('click', () => act('start'));
  $('stop').addEventListener('click', () => act('stop'));
  $('result-load').addEventListener('click', loadResult);
  $('open-records').addEventListener('click', () => openTarget('records'));
  renderEnv();
  renderAi();
  show(location.hash.slice(1));
  checkEnv();
  checkAi();
  refresh();
  setInterval(refresh, 5000);
}

init();
</script>
</body>
</html>
'''


if __name__ == '__main__':
    sys.exit(main())
