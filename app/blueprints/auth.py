import time
from urllib.parse import urlparse

import pyotp
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app import db
from app.models import User, AuditLog

auth_bp = Blueprint('auth', __name__)

# Pending second-factor logins expire after this many seconds.
TOTP_PENDING_TTL = 300
TOTP_INTERVAL = 30

# Hash checked when the username does not exist, so that both paths take the
# same time and do not reveal which accounts exist.
_DUMMY_HASH = generate_password_hash('ca-manager-dummy-password')


def safe_next_url(target):
    """Return target if it is a local path, else None (prevents open redirects)."""
    if not target:
        return None
    target = target.strip()
    if '\\' in target or any(ord(ch) < 32 for ch in target):
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc:
        return None
    if not target.startswith('/') or target.startswith('//'):
        return None
    return target


def verify_totp(user, code):
    """Check a TOTP code for user, rejecting codes already used (replay)."""
    code = (code or '').strip()
    if not user.totp_secret or not code.isdigit() or len(code) != 6:
        return False
    totp = pyotp.TOTP(user.totp_secret)
    now_step = int(time.time()) // TOTP_INTERVAL
    for offset in (-1, 0, 1):
        step = now_step + offset
        if totp.at(step * TOTP_INTERVAL) == code:
            if user.totp_last_step is not None and step <= user.totp_last_step:
                return False
            user.totp_last_step = step
            return True
    return False


def _locked_error():
    return (f'Too many failed attempts. The account is locked for '
            f'{User.LOCKOUT_MINUTES} minutes.')


@auth_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    if db.session.query(User).count():
        return redirect(url_for('auth.login'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')

        if not username or not password:
            error = 'Username and password are required.'
        elif password != password2:
            error = 'Passwords do not match.'
        else:
            user = User(username=username, role='admin')
            user.set_password(password)
            db.session.add(user)
            db.session.flush()  # get user.id before commit
            db.session.add(AuditLog(action='user_create', target=username, detail='admin (setup)', user_id=user.id))
            db.session.commit()
            flash('Admin account created. Please log in.', 'success')
            return redirect(url_for('auth.login'))

    return render_template('auth/setup.html', error=error)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('ca.dashboard'))

    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()

        if user is None:
            check_password_hash(_DUMMY_HASH, password)
            error = 'Invalid username or password.'
        elif user.is_locked:
            check_password_hash(_DUMMY_HASH, password)
            error = _locked_error()
        elif user.check_password(password):
            next_url = safe_next_url(request.args.get('next'))
            if user.totp_enabled:
                session['_totp_user_id'] = user.id
                session['_totp_started'] = int(time.time())
                session['_totp_next'] = next_url
                return redirect(url_for('auth.totp_verify'))
            user.register_success()
            db.session.commit()
            login_user(user, remember=True)
            return redirect(next_url or url_for('ca.dashboard'))
        else:
            user.register_failure()
            db.session.commit()
            error = _locked_error() if user.is_locked else 'Invalid username or password.'

    return render_template('auth/login.html', error=error)


def _clear_pending_totp():
    for key in ('_totp_user_id', '_totp_started', '_totp_next'):
        session.pop(key, None)


@auth_bp.route('/totp-verify', methods=['GET', 'POST'])
def totp_verify():
    user_id = session.get('_totp_user_id')
    started = session.get('_totp_started') or 0
    if not user_id or time.time() - started > TOTP_PENDING_TTL:
        _clear_pending_totp()
        if user_id:
            flash('The login attempt expired. Please sign in again.', 'warning')
        return redirect(url_for('auth.login'))
    user = db.session.get(User, user_id)
    if not user or not user.totp_enabled:
        _clear_pending_totp()
        return redirect(url_for('auth.login'))
    if user.is_locked:
        _clear_pending_totp()
        flash(_locked_error(), 'danger')
        return redirect(url_for('auth.login'))

    error = None
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if verify_totp(user, code):
            next_url = safe_next_url(session.get('_totp_next'))
            _clear_pending_totp()
            user.register_success()
            db.session.commit()
            login_user(user, remember=True)
            return redirect(next_url or url_for('ca.dashboard'))
        user.register_failure()
        db.session.commit()
        if user.is_locked:
            _clear_pending_totp()
            flash(_locked_error(), 'danger')
            return redirect(url_for('auth.login'))
        error = 'Invalid code. Please try again.'

    return render_template('auth/totp_verify.html', error=error, username=user.username)


@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
