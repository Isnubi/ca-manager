from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required
from app import db
from app.models import Setting, SETTING_DEFINITIONS, get_setting
from app.blueprints.utils.utils import admin_required, log_action
from app.blueprints.utils.mailer import send_test_email

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')

SMTP_KEYS = [
    'SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD',
    'SMTP_FROM', 'SMTP_VERIFY_SSL', 'ALERT_EMAIL',
]


@settings_bp.route('/', methods=['GET', 'POST'])
@login_required
@admin_required
def index():
    if request.method == 'POST':
        changed = 0
        for key, (label, default, _) in SETTING_DEFINITIONS.items():
            value = request.form.get(key, '').strip()
            if not value:
                continue
            row = db.session.get(Setting, key)
            if row:
                if row.value != value:
                    row.value = value
                    changed += 1
            else:
                db.session.add(Setting(key=key, value=value))
                changed += 1
        if changed:
            log_action('settings_save', detail=f'{changed} change{"s" if changed != 1 else ""}')
        db.session.commit()
        flash(f'Settings saved ({changed} change{"s" if changed != 1 else ""}).', 'success')
        return redirect(url_for('settings.index'))

    current_values = {key: get_setting(key) for key in SETTING_DEFINITIONS}
    return render_template('settings/index.html',
                           definitions=SETTING_DEFINITIONS,
                           current_values=current_values)


@settings_bp.route('/test-email', methods=['POST'])
@login_required
@admin_required
def test_email():
    overrides = {key: request.form.get(key, '').strip() for key in SMTP_KEYS}
    try:
        sent, message = send_test_email(overrides)
        flash(message, 'success' if sent else 'warning')
    except Exception as e:
        flash(f'Failed to send test email: {e}', 'danger')
    log_action('settings_test_email', detail=overrides.get('ALERT_EMAIL') or None)
    db.session.commit()
    return redirect(url_for('settings.index'))


@settings_bp.route('/reset/<key>', methods=['POST'])
@login_required
@admin_required
def reset(key):
    if key not in SETTING_DEFINITIONS:
        flash('Unknown setting.', 'danger')
        return redirect(url_for('settings.index'))
    row = db.session.get(Setting, key)
    if row:
        db.session.delete(row)
        db.session.commit()
        flash(f'{SETTING_DEFINITIONS[key][0]} reset to default.', 'success')
    return redirect(url_for('settings.index'))
