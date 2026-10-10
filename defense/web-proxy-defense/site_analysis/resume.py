"""Private, atomic stage checkpoints; dry-run reads without creating files."""
import base64
from copy import deepcopy
import json
import os
from pathlib import Path
import threading
import sys

from .record import ROOT, now, ref, runs_by_authority, write_json


class CheckpointError(BaseException):
    """A failed private write must bypass item-level retry/fallback handlers."""


def encode(value):
    # Tag containers as well as bytes so a source JSON key cannot collide.
    if isinstance(value, bytes):
        return {'type': 'bytes', 'value': base64.b64encode(value).decode('ascii')}
    if isinstance(value, (list, tuple)):
        return {'type': 'list', 'value': [encode(item) for item in value]}
    if isinstance(value, dict):
        return {'type': 'dict', 'value': {key: encode(item) for key, item in value.items()}}
    return {'type': 'scalar', 'value': value}


def decode(value):
    kind, data = value['type'], value['value']
    if kind == 'bytes':
        return base64.b64decode(data, validate=True)
    if kind == 'list':
        return [decode(item) for item in data]
    if kind == 'dict':
        return {key: decode(item) for key, item in data.items()}
    if kind != 'scalar':
        raise ValueError('알 수 없는 체크포인트 자료형')
    return data


def owner_only(path):
    """Set permissions before writing source material, including Windows DACLs."""
    path = Path(path)
    if os.name != 'nt':
        path.chmod(0o700 if path.is_dir() else 0o600)
        return
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    token, length = wintypes.HANDLE(), wintypes.DWORD()
    sid, descriptor = wintypes.LPWSTR(), ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise ctypes.WinError(ctypes.get_last_error())
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(length))
        data = ctypes.create_string_buffer(length.value)
        if not advapi.GetTokenInformation(token, 1, data, length, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi.ConvertSidToStringSidW(ctypes.cast(data, ctypes.POINTER(ctypes.c_void_p))[0], ctypes.byref(sid)):
            raise ctypes.WinError(ctypes.get_last_error())
        acl = 'D:P(A;OICI;FA;;;' + sid.value + ')'
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(acl, 1, ctypes.byref(descriptor), None):
            raise ctypes.WinError(ctypes.get_last_error())
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        if descriptor:
            kernel.LocalFree(descriptor)
        if sid:
            kernel.LocalFree(ctypes.cast(sid, ctypes.c_void_p))
        if token:
            kernel.CloseHandle(token)


def checkpoint_path(output, origin='', root=None):
    local = root or os.environ.get('LOCALAPPDATA') or (Path.home() / 'Library' / 'Application Support'
             if sys.platform == 'darwin' else Path.home() / '.local' / 'state')
    if not local or not Path(local).is_absolute():
        raise ValueError('저장소 밖의 절대 LOCALAPPDATA 경로가 필요함')
    key = ref(str(Path(output).resolve()) + '\n' + origin)
    path = (Path(local) / 'ruby-site-analysis' / (Path(output).name + '-' + key[:24])).resolve()
    local_root = Path(local).resolve()
    # A home-directory dotfiles repository does not change the requested
    # LOCALAPPDATA destination; reject project repos within that destination.
    if path == ROOT or ROOT in path.parents or any((parent / '.git').exists()
            for parent in (path, *path.parents) if parent == local_root or local_root in parent.parents):
        raise ValueError('원자료 체크포인트를 저장소 안에 쓸 수 없음')
    return path


def identity(origin, catalog, output):
    return {'origin_sha256': ref(origin),
            'catalog_sha256': ref(json.dumps(catalog, ensure_ascii=False, sort_keys=True)),
            'output_sha256': ref(str(Path(output).resolve()))}


class ResumeStore:
    VERSION = 'site-analysis-resume/1'

    def __init__(self, output, origin, catalog, fresh=False, root=None):
        self.output, self.origin, self.catalog, self.fresh, self.root = output, origin, catalog, fresh, root
        self.path = checkpoint_path(output, origin, root)
        self.identity = identity(origin, catalog, output)
        self.lock = threading.RLock()
        self.reason = 'fresh' if fresh else 'new'
        self.state = {'version': self.VERSION, 'identity': self.identity, 'created_at': now(),
                      'runs': {}, 'merge': {}}
        self.ledger = None
        self.process_lock = None
        self.legacy_source = None
        manifest = self.path / 'state.json'
        # Earlier releases keyed folders only by output name. Read a matching
        # legacy snapshot without moving or rewriting another process's files.
        legacy = self.path.parent / Path(output).name / 'state.json'
        if not fresh and not manifest.exists() and legacy.exists() and not (legacy.parent / 'archive-progress.json').exists():
            candidate = decode(json.loads(legacy.read_text(encoding='utf-8-sig')))
            if candidate.get('identity') == self.identity:
                manifest, self.legacy_source = legacy, legacy.parent
        if not fresh and manifest.exists() and not (self.path / 'archive-progress.json').exists():
            saved = decode(json.loads(manifest.read_text(encoding='utf-8-sig')))
            if saved.get('version') != self.VERSION:
                raise ValueError('지원하지 않는 재개 저장 형식')
            if saved.get('identity') == self.identity:
                self.state, self.reason = saved, 'resume'
                ledger_path = manifest.parent / 'ledger.json'
                if ledger_path.exists() or saved['runs']:
                    self.ledger = json.loads(ledger_path.read_text(encoding='utf-8-sig'))
                    if self.ledger.get('session') != saved['session']:
                        raise ValueError('체크포인트와 비용 장부의 실행 식별자가 다름')
            else:
                self.reason = 'different_origin_catalog_or_output'

    def write(self, name, value, tagged=False):
        try:
            with self.lock:
                # Resolve again before every write, including existing symlinks.
                target = self.path / name
                for candidate in (target,):
                    resolved = candidate.resolve()
                    if resolved.parent != self.path or ROOT in resolved.parents:
                        raise ValueError('비공개 저장 경로가 바뀜')
                if checkpoint_path(self.output, self.origin, self.root) != self.path:
                    raise ValueError('비공개 저장 경로가 바뀜')
                write_json(target, encode(value) if tagged else value, private=True)
        except Exception as error:
            raise CheckpointError('비공개 체크포인트 저장 실패: ' + type(error).__name__) from error

    def begin(self):
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        owner_only(self.path)
        lock_path = self.path / 'run.lock'
        if lock_path.is_symlink():
            raise CheckpointError('실행 잠금 경로가 바뀜')
        self.process_lock = lock_path.open('a+b')
        owner_only(lock_path)
        try:
            if os.name == 'nt':
                import msvcrt
                if lock_path.stat().st_size == 0:
                    self.process_lock.write(b'0')
                    self.process_lock.flush()
                self.process_lock.seek(0)
                msvcrt.locking(self.process_lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.process_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            self.close()
            raise CheckpointError('같은 출력과 원본의 분석이 이미 실행 중임') from error
        # Recover a partially moved archive before reading the stage/ledger pair.
        journal = self.path / 'archive-progress.json'
        if journal.exists():
            self.finish_archive(json.loads(journal.read_text(encoding='utf-8-sig')))
        loaded = ResumeStore(self.output, self.origin, self.catalog, self.fresh, self.root)
        self.state, self.reason, self.ledger = loaded.state, loaded.reason, loaded.ledger
        if loaded.legacy_source is not None:
            self.state['legacy_import'] = {'source_sha256': ref(str(loaded.legacy_source)), 'imported_at': now()}
            if self.ledger is not None:
                self.write('ledger.json', self.ledger)
            self.save()
        # The protected directory blocks traversal while existing descendants
        # receive owner permissions as well. Never follow a stored symlink.
        for entry in self.path.rglob('*'):
            if entry.is_symlink():
                raise CheckpointError('비공개 저장에 심볼릭 링크가 있음')
            owner_only(entry)
        if self.reason != 'resume':
            # Keep the old run reviewable, including --fresh; never recursively delete.
            if (self.path / 'state.json').exists():
                previous = self.path / ('archive-' + now().replace(':', '-'))
                try:
                    plan = {'folder': previous.name, 'files': sorted(entry.name for entry in self.path.glob('*.json')
                                                                   if entry.name != journal.name)}
                    self.write(journal.name, plan)
                    self.finish_archive(plan)
                except Exception as error:
                    raise CheckpointError('이전 체크포인트 보존 실패: ' + type(error).__name__) from error
            self.state['session'] = ref(now() + str(os.getpid()))
            self.save()

    def finish_archive(self, plan):
        previous = self.path / plan['folder']
        if previous.parent != self.path or not previous.name.startswith('archive-') or previous.is_symlink():
            raise CheckpointError('보관 경로 오류')
        previous.mkdir(exist_ok=True, mode=0o700)
        owner_only(previous)
        # State moves last; the journal makes interruption at any file resumable.
        for name in sorted(plan['files'], key=lambda name: name == 'state.json'):
            if Path(name).name != name:
                raise CheckpointError('보관 파일 경로 오류')
            entry = self.path / name
            if entry.exists():
                owner_only(entry)
                entry.replace(previous / name)
            elif not (previous / name).exists():
                raise CheckpointError('보관 파일이 양쪽에서 누락됨')
        (self.path / 'archive-progress.json').unlink()

    def close(self):
        if self.process_lock is not None:
            self.process_lock.close()
            self.process_lock = None

    def save(self, model=None):
        self.state['updated_at'] = now()
        if model is not None:
            self.state['acknowledged_calls'] = (len(model.calls) - 1 if model.pending_answer and not model.receipt_delivered
                                                else len(model.calls))
        self.write('state.json', self.state, tagged=True)
        if model is not None:
            # Stage state is durable before acknowledging a paid answer receipt.
            if model.receipt_delivered:
                model.pending_answer = None
                model.receipt_delivered = False
            model.persist()

    def save_ledger(self, model):
        self.write('ledger.json', {'session': self.state['session'], **model.resume_record()})

    def plan(self, catalog, count):
        for index in range(1, count + 1):
            run = self.state['runs'].get(str(index), {})
            if run.get('complete') and run.get('privacy', {}).get('working_notes', {}).get('complete'):
                continue
            if not run.get('observation_complete'):
                return {'run': index, 'stage': 'observation', 'has_partial_observation': bool(run.get('observation'))}
            for group in catalog['call_order']:
                if not run.get('groups', {}).get(group, {}).get('complete'):
                    return {'run': index, 'stage': 'analysis', 'group': group}
            for scope in [*('axis:' + group for group in catalog['call_order']), 'facts', 'decisions', 'working_notes']:
                if not run.get('privacy', {}).get(scope, {}).get('complete'):
                    cells = run.get('privacy', {}).get(scope, {})
                    return {'run': index, 'stage': 'privacy', 'scope': scope,
                            'saved_cells': len(cells.get('released', {})) + len(cells.get('terminal', [])),
                            'pending_cell_ids': [key for key in cells.get('cell_ids', [])
                                                 if key not in cells.get('released', {}) and key not in cells.get('terminal', [])]}
            return {'run': index, 'stage': 'run_completion'}
        runs = [self.state['runs'][str(i)]['published'] for i in range(1, count + 1)]
        for mode, rows in runs_by_authority(runs).items():
            merged = self.state.get('merge_by_authority', {}).get(mode, self.state['merge'] if mode == 'anonymous' else {})
            signature = ref(json.dumps([row['axes'] for row in rows], ensure_ascii=False, sort_keys=True))
            if merged.get('input_sha256') not in (None, signature):
                return {'stage': 'semantic_merge', 'authority': mode, 'reason': 'different_run_inputs'}
            if merged.get('complete'):
                continue
            for group in catalog['groups']:
                pending = [axis['id'] for axis in catalog['axes'] if axis['group'] == group
                           and axis['id'] not in merged.get('judgments', {})]
                if pending:
                    raw = [key for key in pending if key in merged.get('raw', {})]
                    return {'stage': 'semantic_merge_privacy' if raw else 'semantic_merge', 'authority': mode,
                            'group': group, 'pending_axis_ids': raw or pending}
            return {'stage': 'semantic_merge', 'authority': mode}
        return {'stage': 'complete'}


def restore_failures(failures, saved):
    failures.counts = {(row['operation_sha256'], row['failure_sha256']): row['count'] for row in saved['counts']}
    failures.stopped = False  # a repeated failure gives up that operation only


def restored_copy(value):
    """Exercise the on-disk codec in dry-run without writing private data."""
    return decode(json.loads(json.dumps(encode(deepcopy(value)), ensure_ascii=False, allow_nan=False)))
