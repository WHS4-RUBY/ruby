"""One-worker container entrypoint for the response overlay."""
import hmac
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from .security_store import SecurityStore, initialize_security_store


def _regular_private_file(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError(f'{path.name} must be a regular file with mode 0600')
    return path.read_bytes()


def _create_private_file(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(content)


def initialize_runtime_state() -> None:
    """Bind a new persistent store to the detector key; never reset old state."""
    supplied = os.environ.get('OVERLAY_DETECTOR_KEY')
    if supplied is not None and not re.fullmatch(r'[0-9a-fA-F]{64}', supplied):
        raise ValueError('OVERLAY_DETECTOR_KEY must be exactly 64 hex characters')
    detector_path = Path(os.environ.get('DEFENSE_DETECTOR_SECRET_FILE', 'state/detector.key'))
    session_path = Path(os.environ.get('DEFENSE_SECRET_FILE', 'state/session.key'))
    database = Path(os.environ.get('DEFENSE_SECURITY_DB', 'state/security.sqlite3'))
    detector_exists, database_exists = detector_path.exists(), database.exists()
    if detector_exists != database_exists:
        raise ValueError('detector key and security database must be preserved together')

    if detector_exists:
        detector_secret = _regular_private_file(detector_path)
        if len(detector_secret) < 32:
            raise ValueError('persisted detector key is too short')
        if supplied is not None and not hmac.compare_digest(
                detector_secret, supplied.encode('ascii')):
            raise ValueError('persisted detector key does not match OVERLAY_DETECTOR_KEY')
        if not session_path.exists():
            # A lost synthetic-session key invalidates decoy cookies, not the
            # permanent actor quarantine in the detector-bound security DB.
            _create_private_file(session_path, secrets.token_bytes(32))
        if len(_regular_private_file(session_path)) < 32:
            raise ValueError('persisted session key is too short')
    else:
        if supplied is None:
            raise ValueError('OVERLAY_DETECTOR_KEY is required for new state')
        if session_path.exists():
            raise ValueError('orphaned session key requires explicit state recovery')
        detector_secret = supplied.encode('ascii')  # Same UTF-8 bytes used by Defense.
        _create_private_file(detector_path, detector_secret)
        _create_private_file(session_path, secrets.token_bytes(32))
        database.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        initialize_security_store(str(database))

    SecurityStore(str(database), detector_secret)


def main():
    os.umask(0o077)
    initialize_runtime_state()
    os.execv(sys.executable, [sys.executable, '-m', 'uvicorn', 'defense.overlay:app_factory',
                            '--factory', '--host', '0.0.0.0', '--port', '8080', '--workers', '1',
                            '--no-proxy-headers', '--no-access-log', '--no-server-header',
                            '--limit-concurrency', '40', '--backlog', '64',
                            '--h11-max-incomplete-event-size', '16384',
                            '--timeout-keep-alive', '3', '--ws', 'none'])


if __name__ == '__main__':
    main()
