from datetime import datetime, timedelta

from app import db
from app.models import User, ApiKey


def test_password_hashing_and_roles(app):
    with app.app_context():
        user = User(username='u', role='operator')
        user.set_password('pw')
        assert user.password_hash != 'pw'
        assert user.check_password('pw') and not user.check_password('nope')
        assert user.can_issue and user.is_operator and not user.is_admin
        assert not User(username='v', role='viewer').can_issue


def test_set_password_rotates_session_token(app):
    with app.app_context():
        user = User(username='u')
        user.set_password('a')
        first = user.get_id()
        user.set_password('b')
        assert user.get_id() != first and len(user.get_id()) == 64


def test_lockout_cycle(app):
    with app.app_context():
        user = User(username='u')
        user.set_password('a')
        db.session.add(user)
        for _ in range(User.MAX_FAILED_LOGINS - 1):
            user.register_failure()
        assert not user.is_locked
        user.register_failure()
        assert user.is_locked and user.failed_login_count == 0
        user.locked_until = datetime.utcnow() - timedelta(seconds=1)
        assert not user.is_locked
        user.register_success()
        assert user.locked_until is None and user.last_login_at is not None


def test_api_key_generate_and_lookup(app):
    with app.app_context():
        user = User(username='u')
        user.set_password('a')
        db.session.add(user)
        db.session.commit()
        raw, key_hash = ApiKey.generate()
        assert len(raw) == 64 and raw != key_hash
        db.session.add(ApiKey(user_id=user.id, name='k', key_hash=key_hash))
        db.session.commit()
        assert ApiKey.lookup(raw).name == 'k'
        assert ApiKey.lookup('wrong') is None
