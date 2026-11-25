import re

import pyotp

from app import db
from app.models import User, ApiKey
from conftest import PASSWORD, create_user, login


def secret_from(html):
    return re.search(r'user-select-all"[^>]*>([A-Z2-7]+)<', html).group(1)


# --- user management -----------------------------------------------------------

def test_create_user(app, admin_client):
    r = admin_client.post('/users/create', data={'username': 'bob', 'password': 'p', 'password2': 'p',
                                                 'role': 'operator'})
    assert r.headers['Location'] == '/users/'
    with app.app_context():
        assert User.query.filter_by(username='bob').one().role == 'operator'


def test_create_user_validation(app, admin_client):
    base = {'username': 'bob', 'password': 'p', 'password2': 'p', 'role': 'operator'}
    assert b'Invalid role' in admin_client.post('/users/create', data={**base, 'role': 'root'}).data
    assert b'do not match' in admin_client.post('/users/create', data={**base, 'password2': 'x'}).data
    assert b'already taken' in admin_client.post('/users/create', data={**base, 'username': 'admin'}).data


def test_users_pages_admin_only(operator_client):
    assert operator_client.get('/users/').headers['Location'] == '/dashboard'
    operator_client.post('/users/create', data={'username': 'x', 'password': 'p', 'password2': 'p',
                                                'role': 'admin'})


def test_delete_user(app, admin_client):
    uid = create_user(app, 'bob', 'viewer')
    admin_client.post(f'/users/{uid}/delete')
    with app.app_context():
        assert db.session.get(User, uid) is None


def test_cannot_delete_self(app, admin_client):
    admin_client.post('/users/1/delete')
    with app.app_context():
        assert db.session.get(User, 1) is not None


def test_users_list_builds_urls_server_side(app, admin_client):
    uid = create_user(app, 'bob', 'viewer')
    html = admin_client.get('/users/').get_data(as_text=True)
    assert f'data-delete-url="/users/{uid}/delete"' in html


def test_admin_changes_password_and_revokes_sessions(app, admin_client):
    uid = create_user(app, 'bob', 'viewer')
    bob = app.test_client()
    login(bob, 'bob')
    assert bob.get('/dashboard').status_code == 200
    admin_client.post(f'/users/{uid}/change-password', data={'password': 'new', 'password2': 'new'})
    assert bob.get('/dashboard').status_code == 302
    assert login(app.test_client(), 'bob', 'new').status_code == 302


def test_admin_totp_setup_uses_server_side_secret(app, admin_client):
    uid = create_user(app, 'bob', 'viewer')
    html = admin_client.get(f'/users/{uid}/totp/setup').get_data(as_text=True)
    assert 'name="secret"' not in html
    secret = secret_from(html)
    attacker = pyotp.random_base32()
    r = admin_client.post(f'/users/{uid}/totp/setup',
                          data={'secret': attacker, 'code': pyotp.TOTP(attacker).now()})
    assert b'Invalid code' in r.data
    r = admin_client.post(f'/users/{uid}/totp/setup', data={'code': pyotp.TOTP(secret).now()})
    assert r.headers['Location'] == '/users/'
    with app.app_context():
        user = db.session.get(User, uid)
        assert user.totp_enabled and user.totp_secret == secret
    admin_client.post(f'/users/{uid}/totp/disable')
    with app.app_context():
        assert not db.session.get(User, uid).totp_enabled


# --- own account -----------------------------------------------------------------

def test_change_own_password(app, admin_client):
    r = admin_client.post('/account/change-password',
                          data={'current_password': 'wrong', 'password': 'n', 'password2': 'n'})
    assert r.status_code == 302
    with app.app_context():
        assert User.query.one().check_password(PASSWORD)
    admin_client.post('/account/change-password',
                      data={'current_password': PASSWORD, 'password': 'n', 'password2': 'n'})
    with app.app_context():
        assert User.query.one().check_password('n')
    assert admin_client.get('/dashboard').status_code == 200


def test_self_totp_enrollment_ignores_form_secret(app, admin_client):
    html = admin_client.get('/account/totp/setup').get_data(as_text=True)
    assert 'name="secret"' not in html
    secret = secret_from(html)
    attacker = pyotp.random_base32()
    r = admin_client.post('/account/totp/setup', data={'secret': attacker, 'code': pyotp.TOTP(attacker).now()})
    assert b'Invalid code' in r.data
    r = admin_client.post('/account/totp/setup', data={'code': pyotp.TOTP(secret).now()})
    assert r.headers['Location'] == '/account/'
    with app.app_context():
        assert User.query.one().totp_secret == secret
    assert admin_client.get('/dashboard').status_code == 200


def test_reenrolling_totp_requires_password(app, admin_client):
    with app.app_context():
        user = User.query.one()
        user.totp_secret, user.totp_enabled = pyotp.random_base32(), True
        db.session.commit()
    secret = secret_from(admin_client.get('/account/totp/setup').get_data(as_text=True))
    r = admin_client.post('/account/totp/setup', data={'code': pyotp.TOTP(secret).now()})
    assert b'Current password is incorrect' in r.data
    r = admin_client.post('/account/totp/setup',
                          data={'code': pyotp.TOTP(secret).now(), 'current_password': PASSWORD})
    assert r.status_code == 302


def test_disable_own_totp_requires_password(app, admin_client):
    with app.app_context():
        user = User.query.one()
        user.totp_secret, user.totp_enabled = pyotp.random_base32(), True
        db.session.commit()
    admin_client.post('/account/totp/disable', data={'current_password': 'wrong'})
    with app.app_context():
        assert User.query.one().totp_enabled
    admin_client.post('/account/totp/disable', data={'current_password': PASSWORD})
    with app.app_context():
        assert not User.query.one().totp_enabled


def test_api_key_lifecycle(app, admin_client):
    admin_client.post('/account/api-keys/create', data={'name': 'ci'})
    page = admin_client.get('/account/').get_data(as_text=True)
    raw = re.search(r'\b([0-9a-f]{64})\b', page).group(1)
    with app.app_context():
        key = ApiKey.lookup(raw)
        assert key and key.name == 'ci'
        key_id = key.id
    assert f'data-delete-url="/account/api-keys/{key_id}/delete"' in page
    admin_client.post(f'/account/api-keys/{key_id}/delete')
    with app.app_context():
        assert ApiKey.query.count() == 0


def test_cannot_delete_someone_elses_api_key(app, admin_client):
    from conftest import create_api_key
    other = create_user(app, 'bob', 'viewer')
    create_api_key(app, other)
    with app.app_context():
        key_id = ApiKey.query.one().id
    assert admin_client.post(f'/account/api-keys/{key_id}/delete').status_code == 404


def test_api_key_name_required(app, admin_client):
    admin_client.post('/account/api-keys/create', data={'name': ''})
    with app.app_context():
        assert ApiKey.query.count() == 0
