"""One-worker container entrypoint for the response overlay."""
import os
from pathlib import Path
import secrets
import sys


def main():
    os.umask(0o077)
    path = Path(os.environ.get('DEFENSE_SECRET_FILE', 'state/session.key'))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(secrets.token_bytes(32))
    os.execv(sys.executable, [sys.executable, '-m', 'uvicorn', 'defense.overlay:app_factory',
                            '--factory', '--host', '0.0.0.0', '--port', '8080', '--workers', '1',
                            '--no-proxy-headers', '--no-access-log', '--no-server-header',
                            '--limit-concurrency', '40', '--backlog', '64',
                            '--h11-max-incomplete-event-size', '16384',
                            '--timeout-keep-alive', '3', '--ws', 'none'])


if __name__ == '__main__':
    main()
