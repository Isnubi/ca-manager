import logging
import os
import secrets
from datetime import timedelta
from flask import Flask, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()

logger = logging.getLogger(__name__)

# Values that have been published (source, README, .env.example) and must
# never be used to sign sessions.
KNOWN_PLACEHOLDER_KEYS = {
    'dev-secret-please-change',
    'change-this-to-a-long-random-secret',
}
MIN_SECRET_KEY_LENGTH = 32


def _load_secret_key(data_dir):
    """Return the session signing key.

    Uses SECRET_KEY from the environment when it is set to a strong, non-placeholder
    value. Otherwise a random key is generated once and persisted in DATA_DIR.
    """
    key = os.environ.get('SECRET_KEY', '')
    if key and key not in KNOWN_PLACEHOLDER_KEYS and len(key) >= MIN_SECRET_KEY_LENGTH:
        return key
    if key:
        logger.warning('SECRET_KEY is a known placeholder or shorter than %d characters; '
                       'ignoring it and using the persisted random key instead.',
                       MIN_SECRET_KEY_LENGTH)

    key_file = os.path.join(data_dir, 'secret_key')
    if os.path.exists(key_file):
        with open(key_file) as f:
            stored = f.read().strip()
        if len(stored) >= MIN_SECRET_KEY_LENGTH:
            return stored

    stored = secrets.token_hex(32)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(stored)
    logger.warning('No usable SECRET_KEY configured; generated a random key in %s.', key_file)
    return stored


def _env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ('1', 'true', 'yes', 'on')


def create_app(test_config=None):
    app = Flask(__name__, template_folder='templates', static_folder='static')

    from dotenv import load_dotenv
    load_dotenv()

    data_dir = os.environ.get('DATA_DIR', '/app/data')
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.environ.get('CA_DIR', '/opt/private-ca'), exist_ok=True)

    app.config['SECRET_KEY'] = _load_secret_key(data_dir)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{data_dir}/ca-manager.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Cookie hardening. Set SESSION_COOKIE_SECURE=true when served over HTTPS.
    secure_cookies = _env_flag('SESSION_COOKIE_SECURE')
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=secure_cookies,
        REMEMBER_COOKIE_HTTPONLY=True,
        REMEMBER_COOKIE_SAMESITE='Lax',
        REMEMBER_COOKIE_SECURE=secure_cookies,
        REMEMBER_COOKIE_DURATION=timedelta(days=30),
        WTF_CSRF_TIME_LIMIT=None,
        SCHEDULER_ENABLED=True,
    )

    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    csrf.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'

    from app.models import User

    @login_manager.user_loader
    def load_user(session_token):
        if not session_token:
            return None
        return User.query.filter_by(session_token=str(session_token)).first()

    @app.before_request
    def check_first_run():
        exempt = {'auth.setup', 'auth.login', 'auth.totp_verify', 'static'}
        if request.endpoint and request.endpoint not in exempt:
            if not db.session.query(User).count():
                return redirect(url_for('auth.setup'))

    @app.after_request
    def security_headers(response):
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'same-origin')
        if request.endpoint != 'static':
            # Pages and downloads can carry private keys: keep them out of caches.
            response.headers['Cache-Control'] = 'no-store'
            response.headers['Pragma'] = 'no-cache'
        return response

    from app.blueprints.auth import auth_bp
    from app.blueprints.ca import ca_bp
    from app.blueprints.users import users_bp
    from app.blueprints.settings import settings_bp
    from app.blueprints.account import account_bp
    from app.blueprints.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(ca_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(account_bp)
    app.register_blueprint(api_bp)
    # The API authenticates with the X-API-Key header, never with cookies,
    # so it is not exposed to CSRF.
    csrf.exempt(api_bp)

    with app.app_context():
        db.create_all()
        _migrate()

    if app.config.get('SCHEDULER_ENABLED'):
        from app.scheduler import init_scheduler
        init_scheduler(app)

    return app


def _migrate():
    """SQLite column migrations for fields added after the first release."""
    with db.engine.connect() as conn:
        for stmt in [
            'ALTER TABLE user ADD COLUMN totp_secret VARCHAR(32)',
            'ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0',
            'ALTER TABLE user ADD COLUMN last_login_at DATETIME',
            'ALTER TABLE user ADD COLUMN session_token VARCHAR(64)',
            'ALTER TABLE user ADD COLUMN failed_login_count INTEGER NOT NULL DEFAULT 0',
            'ALTER TABLE user ADD COLUMN locked_until DATETIME',
            'ALTER TABLE user ADD COLUMN totp_last_step INTEGER',
            'ALTER TABLE certificate ADD COLUMN sans VARCHAR(1000)',
            'ALTER TABLE certificate ADD COLUMN notes VARCHAR(500)',
            'ALTER TABLE certificate_history ADD COLUMN revoked_at DATETIME',
        ]:
            try:
                conn.execute(db.text(stmt))
                conn.commit()
            except Exception:
                conn.rollback()

        # A history row with action "reissued" always replaced a revoked
        # certificate (only revoked certificates can be reissued). Older
        # releases did not record the revocation time, so keep those serials
        # on the CRL using the best timestamp available.
        conn.execute(db.text(
            "UPDATE certificate_history SET revoked_at = COALESCE(issued_at, CURRENT_TIMESTAMP) "
            "WHERE action = 'reissued' AND revoked_at IS NULL"
        ))
        conn.commit()

    from app.models import User
    missing = User.query.filter(User.session_token.is_(None)).all()
    for user in missing:
        user.rotate_session_token()
    if missing:
        db.session.commit()
