"""Initialize private state for the opt-in, local all-Agent experiment."""
import os
from pathlib import Path
import secrets

from .security_store import initialize_security_store


def main():
    os.umask(0o077)
    root = Path(os.environ.get('LIVE_LAB_STATE_DIR', '/app/state'))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in ('session.key', 'detector.key'):
        target = root / name
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if len(target.read_bytes()) < 32:
                raise ValueError(f'{name} is too short')
        else:
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(secrets.token_bytes(32))
    database = root / 'security.sqlite3'
    if not database.exists():
        initialize_security_store(str(database))
    print('Local experiment state ready')


if __name__ == '__main__':
    main()
