"""Operator-only login preparation; no model and no credential diagnostics."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys
from urllib.parse import urljoin, urlsplit

from .observer import authority
from .record import ROOT, write_json
from .resume import owner_only


def session_path(path):
    local = os.environ.get('LOCALAPPDATA')
    if not local or not Path(local).is_absolute():
        raise ValueError('절대 LOCALAPPDATA 경로가 필요함')
    root = (Path(local) / 'ruby-site-analysis' / 'sessions').resolve()
    target = Path(path).resolve()
    if Path(local).resolve() not in root.parents or root not in target.parents or ROOT in target.parents or target == ROOT:
        raise ValueError('세션 파일은 LOCALAPPDATA/ruby-site-analysis/sessions 아래만 허용함')
    if any((parent / '.git').exists() for parent in (target.parent, *target.parents)
           if parent == Path(local).resolve() or Path(local).resolve() in parent.parents):
        raise ValueError('세션 파일을 저장소 안에 둘 수 없음')
    return target


def settings(origin, config):
    part = urlsplit(origin)
    if part.scheme not in ('http', 'https') or not part.hostname or part.username is not None or part.password is not None:
        raise ValueError('자격 값 없는 http/https 원본 주소가 필요함')
    authority(origin)
    config = Path(config).resolve()
    data = json.loads(config.read_text(encoding='utf-8-sig'))
    keys = ('login_path', 'account_file')
    if not isinstance(data, dict) or any(not isinstance(data.get(key), str) or not data[key] for key in keys):
        raise ValueError('로그인 설정 형식 오류')
    # Each field is named by a CSS selector or, failing that, by its name attribute.
    for field in ('user', 'password'):
        if not any(isinstance(data.get(field + key), str) and data[field + key] for key in ('_selector', '_field')):
            raise ValueError(f'로그인 설정에 {field}_selector 또는 {field}_field가 필요함')
    login_url = urljoin(origin, data['login_path'])
    login_part = urlsplit(login_url)
    if authority(login_url) != authority(origin) or login_part.username is not None or login_part.password is not None:
        raise ValueError('로그인 화면은 같은 원본이어야 함')
    account = (config.parent / data['account_file']).resolve()
    if account.parent != config.parent or account == config:
        raise ValueError('계정 파일은 로그인 설정과 같은 폴더여야 함')
    return data, login_url, account


async def prepare(origin, config, output):
    data, login_url, account_path = settings(origin, config)
    relay = os.environ.get('SITE_ANALYSIS_PROXY')
    if not relay:
        raise ValueError('SITE_ANALYSIS_PROXY 중계 설정이 필요함')
    account = json.loads(account_path.read_text(encoding='utf-8-sig'))
    if not isinstance(account, dict):
        raise ValueError('계정 파일 형식 오류')
    # account_key names which account-file value goes into the user field; the web's field name is not read.
    key = data.get('account_key') or ('username' if account.get('username') else 'email')
    username = account.get(key)
    password = account.get('password')
    if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
        raise ValueError('계정 파일의 로그인 값이 없음')
    from playwright.async_api import async_playwright
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True, proxy={'server': relay})
        try:
            context = await browser.new_context(service_workers='block')
            submitted, post_sent, form_action = False, False, None
            async def route(handler, request):
                nonlocal post_sent
                part = urlsplit(request.url)
                same = authority(request.url) == authority(origin) and part.username is None and part.password is None
                allowed = same and request.method in ('GET', 'HEAD')
                if (same and submitted and not post_sent and request.method == 'POST'
                        and request.is_navigation_request() and request.frame == page.main_frame
                        and request.url.split('#', 1)[0] == form_action):
                    allowed, post_sent = True, True
                if allowed:
                    await handler.continue_()
                else:
                    await handler.abort()
            await context.route('**/*', route)
            await context.route_web_socket('**/*', lambda socket: socket.close())
            page = await context.new_page()
            await page.goto(login_url, wait_until='domcontentloaded')
            def field(kind):
                selector = data.get(kind + '_selector') or '[name=' + json.dumps(data[kind + '_field']) + ']'
                return page.locator(selector).first
            user, secret = field('user'), field('password')
            await user.fill(username)
            await secret.fill(password)
            form = secret.locator('xpath=ancestor::form[1]')
            same_form = await form.evaluate('(form, element) => Array.from(form.elements).includes(element)',
                                            await user.element_handle())
            if not same_form:
                raise ValueError('설정한 두 칸이 같은 폼에 없음')
            form_action = (await form.get_attribute('action')) or page.url
            form_action = urljoin(page.url, form_action).split('#', 1)[0]
            if authority(form_action) != authority(origin):
                raise ValueError('다른 원본의 로그인 제출은 허용하지 않음')
            submitted = True
            await form.evaluate('''(form) => {
                const button = Array.from(form.elements).find(e =>
                    !e.disabled && (e.type === 'submit' || e.type === 'image'));
                form.requestSubmit(button);
            }''')
            await page.wait_for_load_state('domcontentloaded')
            # The operator names what proves a login (success_selector, e.g. a sign-out link). Without it the
            # signal is the password field going away, which also holds for single-page and dialog logins.
            signal = data.get('success_selector')
            try:
                if signal:
                    await page.locator(signal).first.wait_for(state='visible', timeout=10000)
                else:
                    await secret.wait_for(state='hidden', timeout=10000)
            except Exception:
                print('로그인 확인: ' + ('success_selector가 나타나지 않음' if signal else '비밀번호 칸이 남아 있음') +
                      '. 성공을 확인하지 못해 세션을 저장하지 않음.')
                return 2
            moved = urlsplit(page.url).path != urlsplit(login_url).path
            state = await context.storage_state()
            # Cookies and local storage both stay: some webs keep the login token in local storage.
            # The file is written only to the private sessions folder.
            output = session_path(output)
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            owner_only(output.parent)
            write_json(output, state, private=True)
            print('로그인 확인: ' + ('success_selector가 나타남' if signal else '비밀번호 칸이 사라짐') +
                  (', 화면 경로가 바뀜' if moved else ', 화면 경로는 그대로') +
                  f'. 쿠키 {len(state.get("cookies", []))}개, local storage 출처 {len(state.get("origins", []))}개를 비공개 세션에 저장함. 권한 범위는 확인하지 않음.')
            return 0
        finally:
            await browser.close()


def main(argv=None):
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, 'reconfigure'):
            stream.reconfigure(encoding='utf-8')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin-url', required=True)
    parser.add_argument('--login-config', '--config', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        output = session_path(args.out)
        if args.dry_run:
            settings(args.origin_url, args.login_config)
            print(json.dumps({'dry_run': True, 'config_check': 'passed', 'private_path_check': 'passed',
                              'account_values_read': False, 'network_requests': 0, 'files_written': 0}))
            return 0
        return asyncio.run(prepare(args.origin_url, args.login_config, output))
    except Exception as error:
        print('세션 준비 실패: ' + type(error).__name__, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
