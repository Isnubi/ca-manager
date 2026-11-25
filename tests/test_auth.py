import time

import pyotp
import pytest

from app import db
from app.blueprints.auth import safe_next_url, TOTP_PENDING_TTL
from app.models import User, AuditLog
from conftest import PASSWORD, create_user, login, csrf_token


# --- setup -----------------------------------------------------------------

def test_setup_creates_first_admin(app, client):
    response = client.post('/setup', data={'username': 'root', 'password': 'pw', 'password2': 'pw'})
    assert response.status_code == 302
    with app.app_context():
        user = User.query.one()
        assert user.username == 'root' and user.is_admin
        assert AuditLog.query.filter_by(action='user_create').count() == 1


def test_setup_validation(client):
    r = client.post('/setup', data={'username': '', 'password': 'pw', 'password2': 'pw'})
    assert b'required' in r.data
    r = client.post('/setup', data={'username': 'a', 'password': 'pw', 'password2': 'other'})
    assert b'do not match' in r.data


def test_setup_disabled_once_a_user_exists(app, client):
    create_user(app)
    r = client.post('/setup', data={'username': 'evil', 'password': 'pw', 'password2': 'pw'})
    assert r.status_code == 302
    with app.app_context():
        assert User.query.count() == 1


# --- login -------------------------------------------------------------------

def test_login_success_and_logout(app, client):
    create_user(app)
    r = login(client)
    assert r.status_code == 302 and r.headers['Location'] == '/dashboard'
    assert client.get('/dashboard').status_code == 200
    assert client.post('/logout').status_code == 302
    assert client.get('/dashboard').status_code == 302


def test_logout_requires_post(app, client):
    create_user(app)
    login(client)
    assert client.get('/logout').status_code == 405


def test_login_wrong_password(app, client):
    create_user(app)
    r = login(client, password='wrong')
    assert r.status_code == 200 and b'Invalid username or password' in r.data


def test_login_unknown_user(app, client):
    create_user(app)
    r = login(client, username='nobody')
    assert b'Invalid username or password' in r.data


@pytest.mark.parametrize('target, expected', [
    ('/cert/x.local', '/cert/x.local'),
    ('/users/?page=2', '/users/?page=2'),
    ('https://evil.example/', None),
    ('//evil.example/', None),
    ('/\\evil.example', None),
    ('\\\\evil.example', None),
    ('javascript:alert(1)', None),
    ('relative/path', None),
    ('/ok\r\nLocation: x', None),
    ('', None),
    (None, None),
])
def test_safe_next_url(target, expected):
    assert safe_next_url(target) == expected


def test_login_ignores_external_next(app, client):
    create_user(app)
    r = client.post('/login?next=https://evil.example/', data={'username': 'admin', 'password': PASSWORD})
    assert r.headers['Location'] == '/dashboard'


def test_login_follows_local_next(app, client):
    create_user(app)
    r = client.post('/login?next=/account/', data={'username': 'admin', 'password': PASSWORD})
    assert r.headers['Location'] == '/account/'


def test_lockout_after_repeated_failures(app, client):
    create_user(app)
    for _ in range(User.MAX_FAILED_LOGINS):
        login(client, password='wrong')
    r = login(client)  # correct password, but locked
    assert b'locked' in r.data
    assert client.get('/dashboard').status_code == 302
    with app.app_context():
        user = User.query.one()
        assert user.is_locked


def test_successful_login_resets_failures(app, client):
    create_user(app)
    login(client, password='wrong')
    login(client)
    with app.app_context():
        user = User.query.one()
        assert user.failed_login_count == 0 and user.last_login_at is not None


# --- CSRF --------------------------------------------------------------------

def test_csrf_token_required(csrf_app):
    client = csrf_app.test_client()
    r = client.post('/setup', data={'username': 'a', 'password': 'pw', 'password2': 'pw'})
    assert r.status_code == 400
    token = csrf_token(client, '/setup')
    r = client.post('/setup', data={'csrf_token': token, 'username': 'a', 'password': 'pw', 'password2': 'pw'})
    assert r.status_code == 302


def test_cross_site_user_creation_is_rejected(csrf_app):
    create_user(csrf_app)
    client = csrf_app.test_client()
    token = csrf_token(client, '/login')
    client.post('/login', data={'csrf_token': token, 'username': 'admin', 'password': PASSWORD})
    forged = {'username': 'evil', 'password': 'P', 'password2': 'P', 'role': 'admin'}
    assert client.post('/users/create', data=forged).status_code == 400
    with csrf_app.app_context():
        assert User.query.filter_by(username='evil').first() is None


def test_every_post_form_has_a_csrf_token(admin_client):
    import re
    for url in ['/account/', '/users/', '/users/create', '/settings/', '/users/1/change-password',
                '/users/1/totp/setup', '/account/totp/setup']:
        html = admin_client.get(url).get_data(as_text=True)
        forms = re.findall(r'<form\b[^>]*method="post"[^>]*>(.{0,200})', html, re.S)
        assert forms, url
        for body in forms:
            assert 'name="csrf_token"' in body, url


# --- TOTP --------------------------------------------------------------------

@pytest.fixture
def totp_user(app):
    secret = pyotp.random_base32()
    create_user(app, totp_secret=secret, totp_enabled=True)
    return secret


def test_totp_login(app, client, totp_user):
    r = login(client)
    assert r.headers['Location'] == '/totp-verify'
    assert client.get('/dashboard').status_code == 302
    r = client.post('/totp-verify', data={'code': pyotp.TOTP(totp_user).now()})
    assert r.headers['Location'] == '/dashboard'
    assert client.get('/dashboard').status_code == 200


def test_totp_keeps_safe_next(app, client, totp_user):
    client.post('/login?next=/account/', data={'username': 'admin', 'password': PASSWORD})
    r = client.post('/totp-verify', data={'code': pyotp.TOTP(totp_user).now()})
    assert r.headers['Location'] == '/account/'


def test_totp_wrong_code(app, client, totp_user):
    login(client)
    r = client.post('/totp-verify', data={'code': '000000' if pyotp.TOTP(totp_user).now() != '000000' else '111111'})
    assert b'Invalid code' in r.data


def test_totp_code_cannot_be_replayed(app, totp_user):
    code = pyotp.TOTP(totp_user).now()
    first = app.test_client()
    login(first)
    assert first.post('/totp-verify', data={'code': code}).headers['Location'] == '/dashboard'
    second = app.test_client()
    login(second)
    r = second.post('/totp-verify', data={'code': code})
    assert b'Invalid code' in r.data


def test_totp_brute_force_locks_account(app, client, totp_user):
    login(client)
    valid = pyotp.TOTP(totp_user).now()
    wrong = '000000' if valid != '000000' else '111111'
    for _ in range(User.MAX_FAILED_LOGINS):
        r = client.post('/totp-verify', data={'code': wrong})
    assert r.status_code == 302 and r.headers['Location'] == '/login'
    with app.app_context():
        assert User.query.one().is_locked


def test_pending_totp_login_expires(app, client, totp_user):
    login(client)
    with client.session_transaction() as sess:
        sess['_totp_started'] = int(time.time()) - TOTP_PENDING_TTL - 1
    r = client.post('/totp-verify', data={'code': pyotp.TOTP(totp_user).now()})
    assert r.headers['Location'] == '/login'
    assert client.get('/dashboard').status_code == 302


def test_totp_verify_without_pending_login(client):
    assert client.get('/totp-verify').headers['Location'] == '/login'


# --- sessions ----------------------------------------------------------------

def test_session_cookie_does_not_contain_user_id(app, client):
    create_user(app)
    login(client)
    with client.session_transaction() as sess:
        assert sess['_user_id'] != '1'
        assert len(sess['_user_id']) == 64


def test_password_change_revokes_other_sessions(app):
    create_user(app)
    a, b = app.test_client(), app.test_client()
    login(a)
    login(b)
    r = a.post('/account/change-password',
               data={'current_password': PASSWORD, 'password': 'new-pw', 'password2': 'new-pw'})
    assert r.status_code == 302
    assert a.get('/dashboard').status_code == 200
    assert b.get('/dashboard').status_code == 302


def test_forged_cookie_for_user_id_1_is_rejected(app, client):
    create_user(app)
    with client.session_transaction() as sess:
        sess['_user_id'] = '1'
        sess['_fresh'] = True
    assert client.get('/dashboard').status_code == 302


def test_remember_cookie_survives_session_loss(app, client):
    create_user(app)
    login(client)
    with client.session_transaction() as sess:
        sess.clear()
    assert client.get('/dashboard').status_code == 200
