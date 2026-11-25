import pyotp
from flask import Blueprint, render_template, redirect, url_for, request, flash, abort, session
from flask_login import login_required, current_user, login_user
from app import db
from app.models import User
from app.blueprints.utils.utils import admin_required, log_action

users_bp = Blueprint('users', __name__, url_prefix='/users')

VALID_ROLES = ('admin', 'operator', 'viewer')


@users_bp.route('/')
@login_required
@admin_required
def list():
    all_users = User.query.order_by(User.created_at).all()
    return render_template('users/list.html', users=all_users)


@users_bp.route('/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        role = request.form.get('role', 'viewer')

        if not username or not password:
            error = 'Username and password are required.'
        elif role not in VALID_ROLES:
            error = 'Invalid role.'
        elif password != password2:
            error = 'Passwords do not match.'
        elif User.query.filter_by(username=username).first():
            error = f'Username "{username}" is already taken.'
        else:
            user = User(username=username, role=role)
            user.set_password(password)
            db.session.add(user)
            log_action('user_create', target=username, detail=role)
            db.session.commit()
            flash(f'User {username} created.', 'success')
            return redirect(url_for('users.list'))

    return render_template('users/create.html', error=error)


@users_bp.route('/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
    else:
        username = user.username
        log_action('user_delete', target=username)
        db.session.delete(user)
        db.session.commit()
        flash(f'User {username} deleted.', 'success')
    return redirect(url_for('users.list'))


@users_bp.route('/<int:user_id>/change-password', methods=['GET', 'POST'])
@login_required
@admin_required
def change_password(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        password2 = request.form.get('password2', '')
        if not password:
            error = 'Password is required.'
        elif password != password2:
            error = 'Passwords do not match.'
        else:
            user.set_password(password)  # also logs the user out everywhere
            log_action('user_password_change', target=user.username)
            db.session.commit()
            if user.id == current_user.id:
                login_user(user, remember=True)
            flash(f'Password for {user.username} updated.', 'success')
            return redirect(url_for('users.list'))

    return render_template('users/change_password.html', user=user, error=error)


@users_bp.route('/<int:user_id>/totp/setup', methods=['GET', 'POST'])
@login_required
@admin_required
def totp_setup(user_id):
    from app.blueprints.account import render_totp_qr

    user = db.session.get(User, user_id)
    if not user:
        abort(404)

    error = None
    # Pending secret is kept server-side in the signed session, per target user.
    pending_key = f'_totp_pending_{user.id}'
    secret = session.get(pending_key)

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if not secret:
            error = 'The enrollment expired. Please scan the new QR code and retry.'
        elif pyotp.TOTP(secret).verify(code, valid_window=1):
            session.pop(pending_key, None)
            user.totp_secret = secret
            user.totp_enabled = True
            user.totp_last_step = None
            user.rotate_session_token()
            log_action('totp_enable', target=user.username)
            db.session.commit()
            if user.id == current_user.id:
                login_user(user, remember=True)
            flash(f'TOTP enabled for {user.username}.', 'success')
            return redirect(url_for('users.list'))
        else:
            error = 'Invalid code — scan the QR code again and retry.'

    if not secret:
        secret = pyotp.random_base32()
        session[pending_key] = secret

    uri, qr_svg = render_totp_qr(secret, user.username)
    return render_template('users/totp_setup.html',
                           user=user, secret=secret, uri=uri, qr_svg=qr_svg, error=error)


@users_bp.route('/<int:user_id>/totp/disable', methods=['POST'])
@login_required
@admin_required
def totp_disable(user_id):
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    user.totp_secret = None
    user.totp_enabled = False
    user.totp_last_step = None
    user.rotate_session_token()
    log_action('totp_disable', target=user.username)
    db.session.commit()
    if user.id == current_user.id:
        login_user(user, remember=True)
    flash(f'TOTP disabled for {user.username}.', 'success')
    return redirect(url_for('users.list'))
