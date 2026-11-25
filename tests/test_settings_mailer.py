from datetime import datetime, timedelta

import pytest

from app import db
from app.blueprints.utils import mailer
from app.models import Certificate, Setting, get_setting, set_setting


@pytest.fixture
def sent(monkeypatch):
    calls = []

    def fake_send(host, port, user, password, sender, verify, to, msg):
        calls.append({'host': host, 'port': port, 'user': user, 'password': password,
                      'verify': verify, 'to': to, 'subject': msg['Subject'], 'body': msg.get_payload(decode=True).decode()})

    monkeypatch.setattr(mailer, '_send_mail', fake_send)
    return calls


def test_get_and_set_setting(app, monkeypatch):
    with app.app_context():
        assert get_setting('CA_ORG') == 'Homelab'
        monkeypatch.setenv('CA_OU', 'FromEnv')
        assert get_setting('CA_OU') == 'FromEnv'
        set_setting('CA_ORG', 'Mine')
        set_setting('CA_ORG', 'Mine2')
        assert get_setting('CA_ORG') == 'Mine2'


def test_save_and_reset_settings(app, admin_client):
    r = admin_client.post('/settings/', data={'CA_ORG': 'NewOrg', 'CA_OU': ''})
    assert r.headers['Location'] == '/settings/'
    with app.app_context():
        assert get_setting('CA_ORG') == 'NewOrg'
        assert db.session.get(Setting, 'CA_OU') is None
    admin_client.post('/settings/reset/CA_ORG')
    with app.app_context():
        assert get_setting('CA_ORG') == 'Homelab'
    admin_client.post('/settings/reset/NOT_A_SETTING')


def test_settings_admin_only(operator_client):
    assert operator_client.get('/settings/').headers['Location'] == '/dashboard'


def test_smtp_password_is_not_echoed(app, admin_client):
    admin_client.post('/settings/', data={'SMTP_PASSWORD': 'hunter2-very-secret'})
    html = admin_client.get('/settings/').get_data(as_text=True)
    assert 'hunter2-very-secret' not in html
    assert 'saved' in html
    # Saving with a blank password field keeps the stored one.
    admin_client.post('/settings/', data={'SMTP_PASSWORD': '', 'CA_ORG': 'X'})
    with app.app_context():
        assert get_setting('SMTP_PASSWORD') == 'hunter2-very-secret'


def _configure_smtp(app):
    with app.app_context():
        for k, v in {'SMTP_HOST': 'mail.home.local', 'SMTP_PORT': '587', 'SMTP_USER': 'ca',
                     'SMTP_PASSWORD': 'stored-pw', 'ALERT_EMAIL': 'ops@home.local'}.items():
            set_setting(k, v)


def test_test_email_with_saved_server_uses_stored_password(app, admin_client, sent):
    _configure_smtp(app)
    r = admin_client.post('/settings/test-email', data={}, follow_redirects=True)
    assert b'Test email sent' in r.data
    assert sent[0]['host'] == 'mail.home.local' and sent[0]['password'] == 'stored-pw'


def test_test_email_never_sends_stored_password_to_other_host(app, admin_client, sent):
    _configure_smtp(app)
    r = admin_client.post('/settings/test-email', data={'SMTP_HOST': 'attacker.example',
                                                        'SMTP_VERIFY_SSL': 'false'},
                          follow_redirects=True)
    assert b'Re-enter the SMTP password' in r.data
    assert sent == []
    r = admin_client.post('/settings/test-email', data={'SMTP_PORT': '2525'}, follow_redirects=True)
    assert sent == []


def test_test_email_other_host_with_typed_password(app, admin_client, sent):
    _configure_smtp(app)
    admin_client.post('/settings/test-email', data={'SMTP_HOST': 'other.local', 'SMTP_PASSWORD': 'typed'})
    assert sent[0]['host'] == 'other.local' and sent[0]['password'] == 'typed'


def test_test_email_requires_host_and_recipient(app):
    with app.app_context():
        ok, msg = mailer.send_test_email({})
    assert not ok and 'must be set' in msg


def test_test_email_errors_are_flashed(app, admin_client, monkeypatch):
    _configure_smtp(app)

    def boom(*args):
        raise OSError('connection refused')

    monkeypatch.setattr(mailer, '_send_mail', boom)
    r = admin_client.post('/settings/test-email', data={}, follow_redirects=True)
    assert b'connection refused' in r.data


def test_expiry_digest(app, sent):
    now = datetime.utcnow()
    with app.app_context():
        assert mailer.send_expiry_digest() == (False, 'SMTP_HOST and ALERT_EMAIL not configured')
    _configure_smtp(app)
    with app.app_context():
        db.session.add_all([
            Certificate(domain='soon.local', serial='01', status='valid', expires_at=now + timedelta(days=5)),
            Certificate(domain='later.local', serial='02', status='valid', expires_at=now + timedelta(days=200)),
            Certificate(domain='gone.local', serial='03', status='revoked', expires_at=now + timedelta(days=3)),
        ])
        db.session.commit()
        ok, msg = mailer.send_expiry_digest()
    assert ok and '1 cert' in msg
    assert 'soon.local' in sent[0]['body']
    assert 'later.local' not in sent[0]['body'] and 'gone.local' not in sent[0]['body']
    assert sent[0]['password'] == 'stored-pw'


def test_expiry_digest_nothing_expiring(app, sent):
    _configure_smtp(app)
    with app.app_context():
        ok, msg = mailer.send_expiry_digest()
    assert not ok and 'No certificates' in msg and sent == []
