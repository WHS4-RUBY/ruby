"""Persistent detector trust and high-risk markers survive container restarts."""
import stat

import pytest

from defense.detector import DetectorVerifier
from defense.overlay_bootstrap import initialize_runtime_state
from defense.security_store import SecurityStoreError


KEY = '0123456789abcdef' * 4


def _environment(monkeypatch, tmp_path, key=KEY):
    monkeypatch.setenv('OVERLAY_DETECTOR_KEY', key)
    monkeypatch.setenv('DEFENSE_DETECTOR_SECRET_FILE', str(tmp_path / 'detector.key'))
    monkeypatch.setenv('DEFENSE_SECRET_FILE', str(tmp_path / 'session.key'))
    monkeypatch.setenv('DEFENSE_SECURITY_DB', str(tmp_path / 'security.sqlite3'))


def test_first_boot_and_restart_preserve_key_session_and_high_risk(monkeypatch, tmp_path):
    _environment(monkeypatch, tmp_path)
    initialize_runtime_state()
    detector = tmp_path / 'detector.key'
    session = tmp_path / 'session.key'
    database = tmp_path / 'security.sqlite3'
    assert detector.read_bytes() == KEY.encode()
    assert len(session.read_bytes()) == 32
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600
               for path in (detector, session, database))
    verifier = DetectorVerifier(KEY.encode(), store_path=str(database))
    verifier.mark_high_risk('actor-a')
    session_before = session.read_bytes()
    initialize_runtime_state()
    assert session.read_bytes() == session_before
    assert DetectorVerifier(KEY.encode(), store_path=str(database)).is_high_risk('actor-a')


def test_preprovisioned_legacy_state_still_starts_without_env(monkeypatch, tmp_path):
    _environment(monkeypatch, tmp_path)
    initialize_runtime_state()
    database = tmp_path / 'security.sqlite3'
    DetectorVerifier(KEY.encode(), store_path=str(database)).mark_high_risk('actor-a')
    monkeypatch.delenv('OVERLAY_DETECTOR_KEY')
    (tmp_path / 'session.key').unlink()
    initialize_runtime_state()
    assert len((tmp_path / 'session.key').read_bytes()) == 32
    assert DetectorVerifier(KEY.encode(), store_path=str(database)).is_high_risk('actor-a')


def test_rotated_or_missing_detector_state_fails_closed(monkeypatch, tmp_path):
    _environment(monkeypatch, tmp_path)
    initialize_runtime_state()
    monkeypatch.setenv('OVERLAY_DETECTOR_KEY', 'f' * 64)
    with pytest.raises(ValueError, match='does not match'):
        initialize_runtime_state()
    monkeypatch.setenv('OVERLAY_DETECTOR_KEY', KEY)
    (tmp_path / 'security.sqlite3').unlink()
    with pytest.raises(ValueError, match='preserved together'):
        initialize_runtime_state()


def test_partial_or_invalid_state_is_not_repaired(monkeypatch, tmp_path):
    _environment(monkeypatch, tmp_path)
    monkeypatch.setenv('OVERLAY_DETECTOR_KEY', 'not-a-key')
    with pytest.raises(ValueError, match='64 hex'):
        initialize_runtime_state()
    assert not list(tmp_path.iterdir())
    monkeypatch.setenv('OVERLAY_DETECTOR_KEY', KEY)
    initialize_runtime_state()
    (tmp_path / 'security.sqlite3').unlink()
    with pytest.raises(ValueError, match='preserved together'):
        initialize_runtime_state()
    assert (tmp_path / 'detector.key').exists()


def test_wrong_permissions_or_wrong_database_key_are_rejected(monkeypatch, tmp_path):
    _environment(monkeypatch, tmp_path)
    initialize_runtime_state()
    detector = tmp_path / 'detector.key'
    detector.chmod(0o644)
    with pytest.raises(ValueError, match='mode 0600'):
        initialize_runtime_state()
    detector.chmod(0o600)
    # A valid-looking key file cannot silently rebind an already scoped DB.
    rotated = b'f' * 64
    detector.write_bytes(rotated)
    monkeypatch.setenv('OVERLAY_DETECTOR_KEY', rotated.decode())
    with pytest.raises(SecurityStoreError, match='key scope mismatch'):
        initialize_runtime_state()
