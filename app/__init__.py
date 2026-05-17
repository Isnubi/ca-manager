import os
from flask import Flask, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    from dotenv import load_dotenv
    load_dotenv()

    data_dir = os.environ.get('DATA_DIR', '/app/data')
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.environ.get('CA_DIR', '/opt/private-ca'), exist_ok=True)

    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-please-change')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{data_dir}/ca-manager.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)

    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'warning'

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.before_request
    def check_first_run():
        exempt = {'auth.setup', 'auth.login', 'auth.totp_verify', 'static'}
        if request.endpoint and request.endpoint not in exempt:
            if not db.session.query(User).count():
                return redirect(url_for('auth.setup'))

    from app.blueprints.auth import auth_bp
    from app.blueprints.ca import ca_bp
    from app.blueprints.users import users_bp
    from app.blueprints.settings import settings_bp
    from app.blueprints.account import account_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(ca_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(settings_bp)
    app.register_blueprint(account_bp)

    with app.app_context():
        db.create_all()
        # SQLite column migrations for new fields
        with db.engine.connect() as conn:
            for stmt in [
                'ALTER TABLE user ADD COLUMN totp_secret VARCHAR(32)',
                'ALTER TABLE user ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0',
                'ALTER TABLE certificate ADD COLUMN sans VARCHAR(1000)',
            ]:
                try:
                    conn.execute(db.text(stmt))
                    conn.commit()
                except Exception:
                    pass

    return app
