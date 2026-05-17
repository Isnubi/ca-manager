import io
import pyotp
import qrcode
import qrcode.image.svg
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
from app import db
from app.blueprints.utils.utils import log_action

account_bp = Blueprint('account', __name__, url_prefix='/account')


@account_bp.route('/')
@login_required
def index():
    return render_template('account/index.html')


@account_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_pw = request.form.get('current_password', '')
    new_pw = request.form.get('password', '')
    confirm_pw = request.form.get('password2', '')

    if not current_user.check_password(current_pw):
        flash('Current password is incorrect.', 'danger')
    elif not new_pw:
        flash('New password is required.', 'danger')
    elif new_pw != confirm_pw:
        flash('Passwords do not match.', 'danger')
    else:
        current_user.set_password(new_pw)
        log_action('user_password_change', target=current_user.username, detail='self')
        db.session.commit()
        flash('Password updated successfully.', 'success')

    return redirect(url_for('account.index'))


@account_bp.route('/totp/setup', methods=['GET', 'POST'])
@login_required
def totp_setup():
    error = None
    secret = None

    if request.method == 'POST':
        secret = request.form.get('secret', '').strip()
        code = request.form.get('code', '').strip()
        if not secret:
            error = 'Missing secret. Please reload and try again.'
        elif pyotp.TOTP(secret).verify(code, valid_window=1):
            current_user.totp_secret = secret
            current_user.totp_enabled = True
            log_action('totp_enable', target=current_user.username, detail='self')
            db.session.commit()
            flash('Two-factor authentication enabled.', 'success')
            return redirect(url_for('account.index'))
        else:
            error = 'Invalid code — scan the QR code again and retry.'

    if not secret:
        secret = pyotp.random_base32()

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username, issuer_name='CA Manager'
    )
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    qr_svg = buf.getvalue().decode('utf-8')
    if '<?xml' in qr_svg:
        qr_svg = qr_svg[qr_svg.index('<svg'):]

    return render_template('account/totp_setup.html',
                           secret=secret, uri=uri, qr_svg=qr_svg, error=error)


@account_bp.route('/totp/disable', methods=['POST'])
@login_required
def totp_disable():
    current_user.totp_secret = None
    current_user.totp_enabled = False
    log_action('totp_disable', target=current_user.username, detail='self')
    db.session.commit()
    flash('Two-factor authentication disabled.', 'success')
    return redirect(url_for('account.index'))
