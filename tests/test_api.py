import pytest

from app.models import Certificate, ApiKey
from conftest import create_user, create_api_key


@pytest.fixture
def keys(app):
    admin_id = create_user(app, 'admin', 'admin')
    op_id = create_user(app, 'op', 'operator')
    viewer_id = create_user(app, 'viewer', 'viewer')
    return {
        'admin': create_api_key(app, admin_id),
        'operator': create_api_key(app, op_id),
        'viewer': create_api_key(app, viewer_id),
    }


def h(key):
    return {'X-API-Key': key}


def test_missing_or_invalid_key(client, keys):
    assert client.get('/api/certs').status_code == 401
    assert client.get('/api/certs', headers=h('nope')).status_code == 401


def test_list_and_last_used(app, client, keys):
    r = client.get('/api/certs', headers=h(keys['viewer']))
    assert r.status_code == 200 and r.json == []
    with app.app_context():
        assert ApiKey.query.filter(ApiKey.last_used_at.isnot(None)).count() == 1


def test_issue_get_and_download(app, ca, client, keys):
    r = client.post('/api/certs', headers=h(keys['operator']),
                    json={'domain': 'Api.Home.Local', 'sans': ['10.1.1.1', 'alt.home.local'], 'notes': 'n'})
    assert r.status_code == 201, r.json
    assert r.json['domain'] == 'api.home.local'
    assert r.json['sans'] == ['DNS:api.home.local', 'IP:10.1.1.1', 'DNS:alt.home.local']

    r = client.get('/api/cert/api.home.local', headers=h(keys['viewer']))
    assert r.status_code == 200 and r.json['status'] == 'valid'
    assert b'BEGIN CERTIFICATE' in client.get('/api/cert/api.home.local/cert.pem', headers=h(keys['viewer'])).data
    chain = client.get('/api/cert/api.home.local/chain.pem', headers=h(keys['viewer'])).data
    assert chain.count(b'BEGIN CERTIFICATE') == 2

    r = client.post('/api/certs', headers=h(keys['operator']), json={'domain': 'api.home.local'})
    assert r.status_code == 409


def test_api_is_not_subject_to_csrf(csrf_app, ca):
    admin_id = create_user(csrf_app, 'admin', 'admin')
    key = create_api_key(csrf_app, admin_id)
    r = csrf_app.test_client().post('/api/certs', headers=h(key), json={'domain': 'csrf.home.local'})
    assert r.status_code == 201


def test_viewer_cannot_issue(ca, client, keys):
    r = client.post('/api/certs', headers=h(keys['viewer']), json={'domain': 'x.home.local'})
    assert r.status_code == 403


def test_issue_requires_initialized_ca(client, keys):
    r = client.post('/api/certs', headers=h(keys['admin']), json={'domain': 'x.home.local'})
    assert r.status_code == 409


@pytest.mark.parametrize('payload', [
    {},
    {'domain': ''},
    {'domain': '/app/app/static/k=v'},
    {'domain': '../escape'},
    {'domain': 'x.home.local', 'sans': ['y.home.local\nbasicConstraints=critical,CA:TRUE']},
    {'domain': 'x.home.local', 'sans': 'not-a-list'},
    {'domain': ['list']},
])
def test_issue_rejects_bad_input(app, ca, client, keys, payload):
    r = client.post('/api/certs', headers=h(keys['admin']), json=payload)
    assert r.status_code == 400
    with app.app_context():
        assert Certificate.query.count() == 0


def test_revoke_requires_admin(app, ca, client, keys):
    client.post('/api/certs', headers=h(keys['operator']), json={'domain': 'r.home.local'})
    assert client.post('/api/cert/r.home.local/revoke', headers=h(keys['operator'])).status_code == 403
    r = client.post('/api/cert/r.home.local/revoke', headers=h(keys['admin']))
    assert r.status_code == 200 and r.json['status'] == 'revoked'
    assert client.post('/api/cert/r.home.local/revoke', headers=h(keys['admin'])).status_code == 404


def test_reissue_through_api_records_revoked_history(app, ca, client, keys):
    client.post('/api/certs', headers=h(keys['admin']), json={'domain': 'r.home.local'})
    client.post('/api/cert/r.home.local/revoke', headers=h(keys['admin']))
    r = client.post('/api/certs', headers=h(keys['admin']), json={'domain': 'r.home.local'})
    assert r.status_code == 201
    from app.models import CertificateHistory
    with app.app_context():
        hist = CertificateHistory.query.one()
        assert hist.action == 'reissued' and hist.revoked_at is not None


def test_unknown_or_unsafe_names(ca, client, keys):
    assert client.get('/api/cert/nope.local', headers=h(keys['admin'])).status_code == 404
    assert client.get('/api/cert/rootCA/cert.pem', headers=h(keys['admin'])).status_code == 404
    assert client.get('/api/cert/rootCA/chain.pem', headers=h(keys['admin'])).status_code == 404
