"""Shared pytest fixtures.

CA_DIR is read once when ``app.blueprints.utils.ca_utils`` is imported, so it
is pointed at a session-wide temporary directory *before* the app is imported.
Each test gets an empty CA directory and its own SQLite database. Generating a
4096-bit root key is slow, so the root CA is created once per session and
copied in by the ``ca`` fixture.
"""
import os
import re
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

_SESSION_TMP = tempfile.mkdtemp(prefix='ca-manager-tests-')
CA_DIR = os.path.join(_SESSION_TMP, 'ca')
os.makedirs(CA_DIR, exist_ok=True)
os.environ['CA_DIR'] = CA_DIR
os.environ['DATA_DIR'] = os.path.join(_SESSION_TMP, 'data')
os.environ['SECRET_KEY'] = 'x' * 64
os.environ.pop('SESSION_COOKIE_SECURE', None)

from app import create_app, db  # noqa: E402
from app.models import User, ApiKey  # noqa: E402
from app.blueprints.utils import ca_utils  # noqa: E402

PASSWORD = 'correct horse battery staple'
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def _clear_dir(path):
    for name in os.listdir(path):
        full = os.path.join(path, name)
        if os.path.isdir(full):
            shutil.rmtree(full)
        else:
            os.unlink(full)


_ROOT_CA_CACHE = os.path.join(_SESSION_TMP, 'root-ca')


@pytest.fixture
def root_ca_files(app):
    """Create a root CA once per session and return the directory holding it."""
    if not os.path.exists(os.path.join(_ROOT_CA_CACHE, 'rootCA.key')):
        _clear_dir(CA_DIR)
        with app.app_context():
            ca_utils.init_ca('FR', 'Ile-de-France', 'Paris', 'Test Org', 3650)
        shutil.copytree(CA_DIR, _ROOT_CA_CACHE, dirs_exist_ok=True)
        _clear_dir(CA_DIR)
    return _ROOT_CA_CACHE


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    path = tmp_path / 'data'
    path.mkdir()
    monkeypatch.setenv('DATA_DIR', str(path))
    return path


@pytest.fixture
def make_app(data_dir):
    """Factory creating an app bound to the per-test data directory."""
    _clear_dir(CA_DIR)
    created = []

    def _make(**config):
        cfg = {'TESTING': True, 'SCHEDULER_ENABLED': False, 'WTF_CSRF_ENABLED': False}
        cfg.update(config)
        app = create_app(cfg)
        created.append(app)
        return app

    yield _make

    for app in created:
        with app.app_context():
            db.session.remove()
            db.engine.dispose()
    _clear_dir(CA_DIR)


@pytest.fixture
def app(make_app):
    return make_app()


@pytest.fixture
def csrf_app(make_app):
    return make_app(WTF_CSRF_ENABLED=True)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def ca(app, root_ca_files):
    """An initialized root CA in CA_DIR."""
    shutil.copytree(root_ca_files, CA_DIR, dirs_exist_ok=True)
    return CA_DIR


def create_user(app, username='admin', role='admin', password=PASSWORD, **fields):
    with app.app_context():
        user = User(username=username, role=role, **fields)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user.id


def login(client, username='admin', password=PASSWORD, **kwargs):
    return client.post('/login', data={'username': username, 'password': password}, **kwargs)


def csrf_token(client, url):
    response = client.get(url)
    match = CSRF_RE.search(response.get_data(as_text=True))
    assert match, f'no CSRF token on {url}'
    return match.group(1)


def create_api_key(app, user_id, name='test'):
    with app.app_context():
        raw, key_hash = ApiKey.generate()
        db.session.add(ApiKey(user_id=user_id, name=name, key_hash=key_hash))
        db.session.commit()
        return raw


@pytest.fixture
def admin_client(app, client):
    create_user(app, 'admin', 'admin')
    assert login(client).status_code == 302
    return client


def _role_client(app, role):
    create_user(app, 'admin', 'admin')
    create_user(app, role, role)
    c = app.test_client()
    assert login(c, role).status_code == 302
    return c


@pytest.fixture
def operator_client(app):
    return _role_client(app, 'operator')


@pytest.fixture
def viewer_client(app):
    return _role_client(app, 'viewer')
