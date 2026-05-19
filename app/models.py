import hashlib
import os
import secrets
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='viewer')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    last_login_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_operator(self):
        return self.role == 'operator'

    @property
    def can_issue(self):
        return self.role in ('admin', 'operator')


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), unique=True, nullable=False)
    serial = db.Column(db.String(40), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='valid')
    issued_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    issued_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    issued_by = db.relationship('User', backref='certificates')
    sans = db.Column(db.String(1000), nullable=True)
    notes = db.Column(db.String(500), nullable=True)


class CertificateHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False, index=True)
    serial = db.Column(db.String(40), nullable=False)
    issued_at = db.Column(db.DateTime, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    action = db.Column(db.String(20), nullable=False)


class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    owner = db.relationship('User', backref='api_keys')
    name = db.Column(db.String(100), nullable=False)
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used_at = db.Column(db.DateTime, nullable=True)

    @staticmethod
    def generate():
        raw = secrets.token_hex(32)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        return raw, key_hash

    @staticmethod
    def lookup(raw_key):
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        return ApiKey.query.filter_by(key_hash=key_hash).first()


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    actor = db.relationship('User', backref='audit_logs')
    action = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=True)
    detail = db.Column(db.String(500), nullable=True)


class Setting(db.Model):
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.String(500), nullable=False)


# Metadata for each configurable setting: label, default, help text
SETTING_DEFINITIONS = {
    'CA_COUNTRY': (
        'Country Code', 'FR',
        'Two-letter ISO country code (e.g. FR, US, DE).'
    ),
    'CA_STATE': (
        'State / Province', 'Ile-de-France',
        'Full state or province name.'
    ),
    'CA_LOCALITY': (
        'City', 'Alfortville',
        'Locality or city name.'
    ),
    'CA_ORG': (
        'Organization', 'Homelab',
        'Organization name used in certificate subjects.'
    ),
    'CA_OU': (
        'Organizational Unit', 'Services',
        'Department or unit name used in certificate subjects.'
    ),
    'DAYS_VALID_CERT': (
        'Certificate Validity (days)', '375',
        'Validity period for issued certificates (~1 year = 375).'
    ),
    'DAYS_VALID_ROOT': (
        'Root CA Validity (days)', '3650',
        'Validity period for the Root CA certificate (10 years = 3650). '
        'Only applies on next CA initialization.'
    ),
    'EXPIRY_WARN_DAYS': (
        'Expiry Warning (days)', '30',
        'Certificates expiring within this many days are flagged on the dashboard and included in email digests.'
    ),
    'SMTP_HOST': (
        'SMTP Host', '',
        'Hostname of the SMTP server for expiry alert emails (e.g. mail.home.local).'
    ),
    'SMTP_PORT': (
        'SMTP Port', '587',
        'SMTP port: 587 = STARTTLS, 465 = SSL/TLS, 25 = plain.'
    ),
    'SMTP_USER': (
        'SMTP Username', '',
        'Leave blank if the server requires no authentication.'
    ),
    'SMTP_PASSWORD': (
        'SMTP Password', '',
        'Leave blank if the server requires no authentication. Stored in the database.'
    ),
    'SMTP_VERIFY_SSL': (
        'Verify SSL Certificate', 'true',
        'Verify the SMTP server\'s SSL/TLS certificate. Set to "false" for self-signed certs.'
    ),
    'SMTP_FROM': (
        'From Address', '',
        'Sender email address (e.g. ca-manager@home.local).'
    ),
    'ALERT_EMAIL': (
        'Alert Recipient', '',
        'Email address to receive daily expiry digest emails.'
    ),
}


def get_setting(key):
    defaults = {k: v[1] for k, v in SETTING_DEFINITIONS.items()}
    row = db.session.get(Setting, key)
    if row:
        return row.value
    return os.environ.get(key, defaults.get(key, ''))


def set_setting(key, value):
    row = db.session.get(Setting, key)
    if row:
        row.value = value
    else:
        db.session.add(Setting(key=key, value=value))
    db.session.commit()
