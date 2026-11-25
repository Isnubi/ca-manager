import os
import stat

import pytest

from app import _load_secret_key, MIN_SECRET_KEY_LENGTH


def test_strong_env_key_is_used(tmp_path, monkeypatch):
    monkeypatch.setenv('SECRET_KEY', 'k' * MIN_SECRET_KEY_LENGTH)
    assert _load_secret_key(str(tmp_path)) == 'k' * MIN_SECRET_KEY_LENGTH
    assert not (tmp_path / 'secret_key').exists()


@pytest.mark.parametrize('value', [
    '', 'dev-secret-please-change', 'change-this-to-a-long-random-secret', 'short',
])
def test_weak_or_placeholder_key_is_replaced_by_persisted_random_key(tmp_path, monkeypatch, value):
    monkeypatch.setenv('SECRET_KEY', value)
    key = _load_secret_key(str(tmp_path))
    assert key != value
    assert len(key) >= MIN_SECRET_KEY_LENGTH
    key_file = tmp_path / 'secret_key'
    assert key_file.read_text() == key
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    # Stable across restarts.
    assert _load_secret_key(str(tmp_path)) == key


def test_missing_env_key(tmp_path, monkeypatch):
    monkeypatch.delenv('SECRET_KEY', raising=False)
    key = _load_secret_key(str(tmp_path))
    assert len(key) == 64


def test_app_config_hardening(app):
    assert app.config['SECRET_KEY'] not in ('dev-secret-please-change',)
    assert app.config['SESSION_COOKIE_HTTPONLY'] is True
    assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
    assert app.config['REMEMBER_COOKIE_SAMESITE'] == 'Lax'
    assert app.config['REMEMBER_COOKIE_DURATION'].days == 30


def test_secure_cookie_flag_from_env(make_app, monkeypatch):
    monkeypatch.setenv('SESSION_COOKIE_SECURE', 'true')
    app = make_app()
    assert app.config['SESSION_COOKIE_SECURE'] is True
    assert app.config['REMEMBER_COOKIE_SECURE'] is True


def test_security_headers(client):
    response = client.get('/login')
    assert response.headers['X-Frame-Options'] == 'DENY'
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert response.headers['Cache-Control'] == 'no-store'


def test_static_files_are_cacheable(client):
    response = client.get('/static/css/main.css')
    assert response.status_code == 200
    assert response.headers.get('Cache-Control') != 'no-store'


def test_first_run_redirects_to_setup(client):
    response = client.get('/dashboard')
    assert response.status_code == 302
    assert response.headers['Location'].endswith('/setup')


def test_migration_marks_reissued_history_as_revoked(make_app):
    from datetime import datetime
    from app import db, _migrate
    from app.models import CertificateHistory
    app = make_app()
    with app.app_context():
        db.session.add(CertificateHistory(domain='a.local', serial='AA', issued_at=datetime(2024, 1, 1),
                                          action='reissued'))
        db.session.add(CertificateHistory(domain='b.local', serial='BB', issued_at=datetime(2024, 1, 1),
                                          action='renewed'))
        db.session.commit()
        _migrate()
        rows = {h.serial: h for h in CertificateHistory.query.all()}
        assert rows['AA'].revoked_at is not None
        assert rows['BB'].revoked_at is None
