import pyotp
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, AuditLog

auth_bp = Blueprint('auth', __name__)


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
        if user and user.check_password(password):
            if user.totp_enabled:
                session['_totp_user_id'] = user.id
                return redirect(url_for('auth.totp_verify'))
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            return redirect(request.args.get('next') or url_for('ca.dashboard'))
        error = 'Invalid username or password.'

    return render_template('auth/login.html', error=error)


@auth_bp.route('/totp-verify', methods=['GET', 'POST'])
def totp_verify():
    user_id = session.get('_totp_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))
    user = db.session.get(User, user_id)
    if not user or not user.totp_enabled:
        session.pop('_totp_user_id', None)
        return redirect(url_for('auth.login'))

    error = None
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if pyotp.TOTP(user.totp_secret).verify(code, valid_window=1):
            session.pop('_totp_user_id', None)
            user.last_login_at = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('ca.dashboard'))
        error = 'Invalid code. Please try again.'

    return render_template('auth/totp_verify.html', error=error, username=user.username)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
