"""
Shared email logic for the expiry digest and SMTP test emails.
Call send_expiry_digest() / send_test_email() from within an active app context.
Both return (sent: bool, message: str) and raise on SMTP errors.
"""
import smtplib
import ssl
from datetime import datetime, timedelta


def _setting(key, overrides):
    value = overrides.get(key)
    if value not in (None, ''):
        return value
    from app.models import get_setting
    return get_setting(key)


def _send_mail(smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from, verify_ssl, to_addr, msg):
    ssl_ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
    if smtp_port == 465:
        server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=ssl_ctx)
    else:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls(context=ssl_ctx)

    with server:
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_from, [to_addr], msg.as_string())


def send_expiry_digest():
    from app.models import Certificate, get_setting

    warn_days = int(get_setting('EXPIRY_WARN_DAYS') or 30)
    smtp_host = get_setting('SMTP_HOST')
    smtp_port = int(get_setting('SMTP_PORT') or 587)
    smtp_user = get_setting('SMTP_USER')
    smtp_pass = get_setting('SMTP_PASSWORD')
    smtp_from = get_setting('SMTP_FROM') or smtp_user or 'ca-manager@localhost'
    alert_email = get_setting('ALERT_EMAIL')
    verify_ssl = get_setting('SMTP_VERIFY_SSL') != 'false'

    if not smtp_host or not alert_email:
        return False, 'SMTP_HOST and ALERT_EMAIL not configured'

    now = datetime.utcnow()
    threshold = now + timedelta(days=warn_days)
    expiring = (
        Certificate.query
        .filter(
            Certificate.status == 'valid',
            Certificate.expires_at <= threshold,
            Certificate.expires_at > now,
        )
        .order_by(Certificate.expires_at)
        .all()
    )

    if not expiring:
        return False, f'No certificates expiring within {warn_days} days'

    lines = [
        f'CA Manager — Expiry Digest ({now.strftime("%Y-%m-%d")})',
        f'Certificates expiring within {warn_days} days: {len(expiring)}',
        '',
    ]
    for cert in expiring:
        days_left = (cert.expires_at - now).days
        lines.append(
            f'  {cert.domain:<45} expires {cert.expires_at.strftime("%Y-%m-%d")} ({days_left}d left)'
        )

    from email.mime.text import MIMEText
    body = '\n'.join(lines)
    msg = MIMEText(body)
    msg['Subject'] = f'[CA Manager] {len(expiring)} certificate(s) expiring soon'
    msg['From'] = smtp_from
    msg['To'] = alert_email

    _send_mail(smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from, verify_ssl, alert_email, msg)

    return True, f'Sent to {alert_email} ({len(expiring)} cert(s) listed)'


def send_test_email(overrides=None):
    overrides = overrides or {}

    smtp_host = _setting('SMTP_HOST', overrides)
    smtp_port = int(_setting('SMTP_PORT', overrides) or 587)
    smtp_user = _setting('SMTP_USER', overrides)
    smtp_pass = _setting('SMTP_PASSWORD', overrides)
    smtp_from = _setting('SMTP_FROM', overrides) or smtp_user or 'ca-manager@localhost'
    alert_email = _setting('ALERT_EMAIL', overrides)
    verify_ssl = _setting('SMTP_VERIFY_SSL', overrides) != 'false'

    if not smtp_host or not alert_email:
        return False, 'SMTP_HOST and Alert Recipient must be set to send a test email'

    from email.mime.text import MIMEText
    body = (
        'This is a test email from CA Manager.\n\n'
        'If you received this, your SMTP settings are configured correctly.'
    )
    msg = MIMEText(body)
    msg['Subject'] = '[CA Manager] Test Email'
    msg['From'] = smtp_from
    msg['To'] = alert_email

    _send_mail(smtp_host, smtp_port, smtp_user, smtp_pass, smtp_from, verify_ssl, alert_email, msg)

    return True, f'Test email sent to {alert_email}'
