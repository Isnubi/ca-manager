"""
Shared email logic for the expiry digest.
Call send_expiry_digest() from within an active app context.
Returns (sent: bool, message: str). Raises on SMTP errors.
"""
import smtplib
import ssl
from datetime import datetime, timedelta


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

    ssl_ctx = ssl.create_default_context() if verify_ssl else ssl._create_unverified_context()
    if smtp_port == 465:
        server = smtplib.SMTP_SSL(smtp_host, smtp_port, context=ssl_ctx)
    else:
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.starttls(context=ssl_ctx)

    with server:
        if smtp_user and smtp_pass:
            server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_from, [alert_email], msg.as_string())

    return True, f'Sent to {alert_email} ({len(expiring)} cert(s) listed)'
