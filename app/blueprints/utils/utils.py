from functools import wraps
from flask import flash, redirect, url_for
from flask_login import current_user


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            flash('Administrator access required.', 'danger')
            return redirect(url_for('ca.dashboard'))
        return f(*args, **kwargs)
    return decorated


def issue_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.can_issue:
            flash('You do not have permission to issue certificates.', 'danger')
            return redirect(url_for('ca.dashboard'))
        return f(*args, **kwargs)
    return decorated


def log_action(action, target=None, detail=None):
    """Add an audit log entry to the current db session. Caller must commit."""
    from app import db
    from app.models import AuditLog
    user_id = current_user.id if current_user.is_authenticated else None
    db.session.add(AuditLog(action=action, target=target, detail=detail, user_id=user_id))
