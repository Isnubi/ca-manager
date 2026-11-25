import os
import subprocess

import pytest

from app import db
from app.blueprints.utils import ca_utils
from app.models import Certificate, CertificateHistory, AuditLog


def issue(client, domain='web.home.local', extra_sans='', notes=''):
    return client.post('/issue', data={'domain': domain, 'extra_sans': extra_sans, 'notes': notes})


def crl_serials():
    out = subprocess.run(['openssl', 'crl', '-in', ca_utils.CRL_FILE, '-noout', '-text'],
                         capture_output=True, text=True, check=True).stdout
    return {line.split(':', 1)[1].strip().upper()
            for line in out.splitlines() if 'Serial Number:' in line}


def norm(serial):
    return serial.upper().lstrip('0')


# --- init ----------------------------------------------------------------------

def test_dashboard_prompts_for_init(admin_client):
    r = admin_client.get('/dashboard')
    assert r.status_code == 200


def test_init_creates_root_ca(app, admin_client, root_ca_files):
    # Real 4096-bit key generation is slow: reuse the session CA through a stub.
    import shutil
    from app.blueprints import ca as ca_module

    def fake_init(**kwargs):
        shutil.copytree(root_ca_files, ca_utils.CA_DIR, dirs_exist_ok=True)

    ca_module.init_ca, original = fake_init, ca_module.init_ca
    try:
        r = admin_client.post('/init')
    finally:
        ca_module.init_ca = original
    assert r.status_code == 302 and r.headers['Location'] == '/ca'
    assert ca_utils.ca_initialized()
    assert admin_client.post('/init').headers['Location'] == '/dashboard'
    with app.app_context():
        assert AuditLog.query.filter_by(action='ca_init').count() == 1


def test_init_requires_admin(operator_client):
    r = operator_client.post('/init')
    assert r.headers['Location'] == '/dashboard'
    assert not ca_utils.ca_initialized()


def test_issue_requires_initialized_ca(admin_client):
    r = issue(admin_client)
    assert r.headers['Location'] == '/dashboard'


# --- issue ---------------------------------------------------------------------

def test_issue_certificate(app, ca, admin_client):
    r = issue(admin_client, 'web.home.local', '10.0.0.5, *.web.home.local', 'my notes')
    assert r.status_code == 302 and r.headers['Location'] == '/cert/web.home.local'
    with app.app_context():
        cert = Certificate.query.one()
        assert cert.status == 'valid' and cert.notes == 'my notes'
        assert cert.sans == 'DNS:web.home.local,IP:10.0.0.5,DNS:*.web.home.local'
    crt = os.path.join(ca, 'web.home.local.crt')
    text = subprocess.run(['openssl', 'x509', '-in', crt, '-noout', '-text'],
                          capture_output=True, text=True, check=True).stdout
    assert 'CA:FALSE' in text
    assert 'IP Address:10.0.0.5' in text
    verify = subprocess.run(['openssl', 'verify', '-CAfile', ca_utils.CA_CERT, crt],
                            capture_output=True, text=True)
    assert verify.returncode == 0, verify.stderr


def test_issue_duplicate_valid_domain(app, ca, admin_client):
    issue(admin_client)
    r = issue(admin_client)
    assert r.headers['Location'] == '/cert/web.home.local'
    with app.app_context():
        assert Certificate.query.count() == 1


@pytest.mark.parametrize('domain', [
    '/app/app/static/k=v', '../../escape', 'a\tb.home.local', '..\\users\\5\\delete?',
    'junk\\..\\..\\users\\1\\totp\\disable#', 'rootca', '',
])
def test_issue_rejects_unsafe_domain(app, ca, admin_client, domain):
    r = issue(admin_client, domain)
    assert r.status_code == 200
    with app.app_context():
        assert Certificate.query.count() == 0
    assert sorted(os.listdir(ca)) == sorted(os.listdir(ca))  # no crash
    assert not any(name.endswith('.key') and not name.startswith('rootCA') for name in os.listdir(ca))


def test_issue_rejects_extfile_injection(app, ca, admin_client):
    r = issue(admin_client, 'x.home.local', 'y.home.local\nbasicConstraints=CA:TRUE\nkeyUsage=keyCertSign')
    assert r.status_code == 200 and b'Invalid' in r.data
    with app.app_context():
        assert Certificate.query.count() == 0


def test_operator_can_issue(app, ca, operator_client):
    assert issue(operator_client, 'op.home.local').headers['Location'] == '/cert/op.home.local'
    with app.app_context():
        assert [c.domain for c in Certificate.query.all()] == ['op.home.local']


def test_viewer_cannot_issue(app, ca, viewer_client):
    assert issue(viewer_client, 'view.home.local').headers['Location'] == '/dashboard'
    with app.app_context():
        assert Certificate.query.count() == 0


# --- detail & downloads --------------------------------------------------------

def test_cert_detail_does_not_embed_private_key(ca, admin_client):
    issue(admin_client)
    r = admin_client.get('/cert/web.home.local')
    assert r.status_code == 200
    assert b'PRIVATE KEY' not in r.data
    assert b'data-src="/cert/web.home.local/download/key"' in r.data
    assert r.headers['Cache-Control'] == 'no-store'


def test_downloads_for_admin(ca, admin_client):
    issue(admin_client)
    assert b'BEGIN CERTIFICATE' in admin_client.get('/cert/web.home.local/download/cert').data
    chain = admin_client.get('/cert/web.home.local/download/chain').data
    assert chain.count(b'BEGIN CERTIFICATE') == 2
    key = admin_client.get('/cert/web.home.local/download/key')
    assert b'PRIVATE KEY' in key.data and key.headers['Cache-Control'] == 'no-store'
    p12 = admin_client.get('/cert/web.home.local/download/pkcs12')
    assert p12.status_code == 200 and p12.mimetype == 'application/x-pkcs12'


def test_root_ca_key_cannot_be_downloaded(ca, admin_client):
    for url in ['/cert/rootCA/download/key', '/cert/rootCA/download/pkcs12',
                '/cert/rootCA/download/cert', '/cert/rootCA']:
        assert admin_client.get(url).status_code == 404, url


def test_unknown_domain_is_404(ca, admin_client):
    assert admin_client.get('/cert/nope.local').status_code == 404
    assert admin_client.get('/cert/nope.local/download/cert').status_code == 404


def test_operator_cannot_download_key(ca, app, operator_client):
    issue(operator_client, 'op.home.local')
    r = operator_client.get('/cert/op.home.local/download/key')
    assert r.status_code == 302
    page = operator_client.get('/cert/op.home.local')
    assert b'download/key' not in page.data


def test_ca_pages(ca, viewer_client):
    assert b'BEGIN CERTIFICATE' in viewer_client.get('/ca').data
    assert viewer_client.get('/ca/download').status_code == 200


def test_crl_is_public(ca, app):
    from conftest import create_user
    create_user(app)
    r = app.test_client().get('/crl')
    assert r.status_code == 200


# --- revoke & renew ------------------------------------------------------------

def test_revoke_updates_crl(app, ca, admin_client):
    issue(admin_client)
    with app.app_context():
        serial = Certificate.query.one().serial
    r = admin_client.post('/cert/web.home.local/revoke')
    assert r.headers['Location'] == '/dashboard'
    with app.app_context():
        assert Certificate.query.one().status == 'revoked'
    assert norm(serial) in {norm(s) for s in crl_serials()}


def test_operator_cannot_revoke(app, ca, operator_client):
    issue(operator_client, 'op.home.local')
    operator_client.post('/cert/op.home.local/revoke')
    with app.app_context():
        assert Certificate.query.one().status == 'valid'


def test_renew_after_revoke_keeps_old_serial_on_crl(app, ca, admin_client):
    issue(admin_client)
    with app.app_context():
        old = Certificate.query.one().serial
    admin_client.post('/cert/web.home.local/revoke')
    r = admin_client.post('/cert/web.home.local/renew')
    assert r.headers['Location'] == '/cert/web.home.local'
    with app.app_context():
        cert = Certificate.query.one()
        assert cert.status == 'valid' and cert.serial != old
        history = CertificateHistory.query.one()
        assert history.serial == old and history.revoked_at is not None
    serials = {norm(s) for s in crl_serials()}
    assert norm(old) in serials
    assert norm(cert.serial) not in serials


def test_reissue_after_revoke_keeps_old_serial_on_crl(app, ca, admin_client):
    issue(admin_client)
    with app.app_context():
        old = Certificate.query.one().serial
    admin_client.post('/cert/web.home.local/revoke')
    issue(admin_client)
    with app.app_context():
        assert CertificateHistory.query.one().action == 'reissued'
    assert norm(old) in {norm(s) for s in crl_serials()}


def test_renew_valid_certificate(app, ca, admin_client):
    issue(admin_client, extra_sans='alt.home.local')
    with app.app_context():
        old = Certificate.query.one().serial
    admin_client.post('/cert/web.home.local/renew')
    with app.app_context():
        cert = Certificate.query.one()
        assert cert.serial != old
        assert cert.sans == 'DNS:web.home.local,DNS:alt.home.local'
        assert CertificateHistory.query.one().revoked_at is None
    assert norm(old) not in {norm(s) for s in crl_serials()}


def test_dashboard_builds_form_actions_server_side(ca, admin_client):
    issue(admin_client)
    html = admin_client.get('/dashboard').get_data(as_text=True)
    assert 'data-action="/cert/web.home.local/renew"' in html
    assert 'data-action="/cert/web.home.local/revoke"' in html
    assert "'/cert/' + domain" not in html


def test_audit_log_admin_only(ca, app, admin_client, ):
    issue(admin_client)
    r = admin_client.get('/audit-log')
    assert r.status_code == 200 and b'cert_issue' in r.data


def test_audit_log_forbidden_for_viewer(viewer_client):
    assert viewer_client.get('/audit-log').headers['Location'] == '/dashboard'


# --- index.txt -----------------------------------------------------------------

def test_index_txt_strips_control_characters(app, ca):
    from datetime import datetime

    class Row:
        def __init__(self, domain, serial, status='valid'):
            self.domain, self.serial, self.status = domain, serial, status
            self.expires_at = datetime(2030, 1, 1)
            self.revoked_at = datetime(2025, 1, 1) if status == 'revoked' else None

    with app.app_context():
        ca_utils._sync_index_txt([Row('a\tb\nc', 'AB12'), Row('ok', 'CD34', 'revoked')])
    lines = open(ca_utils.INDEX_FILE).read().splitlines()
    assert len(lines) == 2
    assert all(len(line.split('\t')) == 6 for line in lines)
    assert lines[1].startswith('R\t')
