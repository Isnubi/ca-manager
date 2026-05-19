import io
import ipaddress
import os
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, flash, send_file, abort, Response
from flask_login import login_required, current_user
from app import db
from app.models import Certificate, CertificateHistory, AuditLog, get_setting
from app.blueprints.utils.ca_utils import (
    CA_DIR, CA_CERT, CRL_FILE,
    ca_initialized, regen_crl, init_ca, issue_cert, cert_text,
    parse_sans_from_cert_text, gen_pkcs12,
)
from app.blueprints.utils.utils import admin_required, issue_required, log_action

ca_bp = Blueprint('ca', __name__)


def _san_entry(value):
    """Return 'IP:value' if value is a valid IP address, else 'DNS:value'."""
    try:
        ipaddress.ip_address(value)
        return f'IP:{value}'
    except ValueError:
        return f'DNS:{value}'


@ca_bp.route('/')
@login_required
def index():
    return redirect(url_for('ca.dashboard'))


@ca_bp.route('/dashboard')
@login_required
def dashboard():
    certs = Certificate.query.order_by(Certificate.issued_at.desc()).all()
    now = datetime.utcnow()
    expiry_threshold = int(get_setting('EXPIRY_WARN_DAYS') or 30)
    stats = {
        'total': len(certs),
        'valid': sum(1 for c in certs if c.status == 'valid'),
        'revoked': sum(1 for c in certs if c.status == 'revoked'),
        'expiring': sum(
            1 for c in certs
            if c.status == 'valid' and c.expires_at
            and 0 <= (c.expires_at - now).days <= expiry_threshold
        ),
    }
    return render_template('ca/dashboard.html',
                           certs=certs,
                           initialized=ca_initialized(),
                           now=now,
                           stats=stats,
                           expiry_threshold=expiry_threshold)


@ca_bp.route('/init', methods=['GET', 'POST'])
@login_required
@admin_required
def init():
    if ca_initialized():
        flash('CA is already initialized.', 'info')
        return redirect(url_for('ca.dashboard'))

    if request.method == 'POST':
        try:
            init_ca(
                subj_c=get_setting('CA_COUNTRY'),
                subj_st=get_setting('CA_STATE'),
                subj_l=get_setting('CA_LOCALITY'),
                subj_o=get_setting('CA_ORG'),
                days_valid_root=int(get_setting('DAYS_VALID_ROOT')),
            )
            log_action('ca_init')
            db.session.commit()
            flash(
                'Root CA initialized! Download the CA certificate and install it '
                'in your trusted root store.',
                'success',
            )
            return redirect(url_for('ca.show_ca'))
        except Exception as e:
            flash(f'Initialization failed: {e}', 'danger')

    return render_template('ca/init.html',
                           country=get_setting('CA_COUNTRY'),
                           state=get_setting('CA_STATE'),
                           locality=get_setting('CA_LOCALITY'),
                           org=get_setting('CA_ORG'),
                           days=get_setting('DAYS_VALID_ROOT'))


@ca_bp.route('/issue', methods=['GET', 'POST'])
@login_required
@issue_required
def issue():
    if not ca_initialized():
        flash('Please initialize the CA first.', 'warning')
        return redirect(url_for('ca.dashboard'))

    if request.method == 'POST':
        domain = request.form.get('domain', '').strip().lower()
        extra_raw = request.form.get('extra_sans', '').strip()
        notes = request.form.get('notes', '').strip() or None

        if not domain:
            flash('Domain is required.', 'danger')
            return render_template('ca/issue.html', days=get_setting('DAYS_VALID_CERT'))

        existing = Certificate.query.filter_by(domain=domain).first()
        if existing and existing.status == 'valid':
            flash(f'A valid certificate for {domain} already exists.', 'warning')
            return redirect(url_for('ca.cert_detail', domain=domain))

        try:
            sans = [_san_entry(domain)]
            for s in extra_raw.split(','):
                s = s.strip()
                if s:
                    entry = _san_entry(s)
                    if entry not in sans:
                        sans.append(entry)

            days = int(get_setting('DAYS_VALID_CERT'))
            serial = issue_cert(
                domain=domain,
                sans=sans,
                subj_c=get_setting('CA_COUNTRY'),
                subj_st=get_setting('CA_STATE'),
                subj_l=get_setting('CA_LOCALITY'),
                subj_o=get_setting('CA_ORG'),
                subj_ou=get_setting('CA_OU'),
                days_valid_cert=days,
            )

            now = datetime.utcnow()
            if existing:
                # Save history of the revoked cert being replaced
                db.session.add(CertificateHistory(
                    domain=domain,
                    serial=existing.serial,
                    issued_at=existing.issued_at,
                    expires_at=existing.expires_at,
                    action='reissued',
                ))
                existing.serial = serial
                existing.status = 'valid'
                existing.issued_at = now
                existing.expires_at = now + timedelta(days=days)
                existing.revoked_at = None
                existing.issued_by_id = current_user.id
                existing.sans = ','.join(sans)
                existing.notes = notes
            else:
                cert = Certificate(
                    domain=domain,
                    serial=serial,
                    status='valid',
                    issued_at=now,
                    expires_at=now + timedelta(days=days),
                    issued_by_id=current_user.id,
                    sans=','.join(sans),
                    notes=notes,
                )
                db.session.add(cert)

            log_action('cert_issue', target=domain, detail=','.join(sans))
            db.session.commit()
            flash(f'Certificate for {domain} issued successfully!', 'success')
            return redirect(url_for('ca.cert_detail', domain=domain))

        except Exception as e:
            flash(f'Failed to issue certificate: {e}', 'danger')

    return render_template('ca/issue.html', days=get_setting('DAYS_VALID_CERT'))


@ca_bp.route('/cert/<domain>/renew', methods=['POST'])
@login_required
@issue_required
def renew(domain):
    cert = Certificate.query.filter_by(domain=domain).first_or_404()

    try:
        # Resolve SANs: use stored value or parse from cert file
        if cert.sans:
            sans = cert.sans.split(',')
        else:
            ossl = cert_text(domain)
            sans = parse_sans_from_cert_text(ossl) or [_san_entry(domain)]

        old_serial = cert.serial
        old_issued_at = cert.issued_at
        old_expires_at = cert.expires_at
        days = int(get_setting('DAYS_VALID_CERT'))
        serial = issue_cert(
            domain=domain,
            sans=sans,
            subj_c=get_setting('CA_COUNTRY'),
            subj_st=get_setting('CA_STATE'),
            subj_l=get_setting('CA_LOCALITY'),
            subj_o=get_setting('CA_ORG'),
            subj_ou=get_setting('CA_OU'),
            days_valid_cert=days,
        )

        db.session.add(CertificateHistory(
            domain=domain,
            serial=old_serial,
            issued_at=old_issued_at,
            expires_at=old_expires_at,
            action='renewed',
        ))

        now = datetime.utcnow()
        cert.serial = serial
        cert.status = 'valid'
        cert.issued_at = now
        cert.expires_at = now + timedelta(days=days)
        cert.revoked_at = None
        cert.issued_by_id = current_user.id
        cert.sans = ','.join(sans)

        log_action('cert_renew', target=domain, detail=f'old serial {old_serial}')
        db.session.commit()
        regen_crl(Certificate.query.all())
        flash(f'Certificate for {domain} renewed successfully!', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Renewal failed: {e}', 'danger')

    return redirect(url_for('ca.cert_detail', domain=domain))


@ca_bp.route('/cert/<domain>')
@login_required
def cert_detail(domain):
    cert = Certificate.query.filter_by(domain=domain).first_or_404()
    crt_path = os.path.join(CA_DIR, f'{domain}.crt')
    key_path = os.path.join(CA_DIR, f'{domain}.key')

    cert_pem = open(crt_path).read() if os.path.exists(crt_path) else None
    key_pem = open(key_path).read() if (current_user.is_admin and os.path.exists(key_path)) else None
    ossl_text = cert_text(domain) if cert_pem else None

    # Resolve SANs for display
    if cert.sans:
        sans_list = cert.sans.split(',')
    else:
        sans_list = parse_sans_from_cert_text(ossl_text) if ossl_text else []

    history = (CertificateHistory.query
               .filter_by(domain=domain)
               .order_by(CertificateHistory.issued_at.desc())
               .all())

    return render_template('ca/cert_detail.html',
                           cert=cert,
                           cert_pem=cert_pem,
                           key_pem=key_pem,
                           cert_text=ossl_text,
                           sans_list=sans_list,
                           history=history,
                           now=datetime.utcnow())


@ca_bp.route('/cert/<domain>/download/cert')
@login_required
def download_cert(domain):
    path = os.path.join(CA_DIR, f'{domain}.crt')
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=f'{domain}.crt')


@ca_bp.route('/cert/<domain>/download/chain')
@login_required
def download_chain(domain):
    crt_path = os.path.join(CA_DIR, f'{domain}.crt')
    if not os.path.exists(crt_path) or not os.path.exists(CA_CERT):
        abort(404)
    chain = open(crt_path).read() + open(CA_CERT).read()
    return Response(
        chain,
        mimetype='application/x-pem-file',
        headers={'Content-Disposition': f'attachment; filename="{domain}-chain.pem"'},
    )


@ca_bp.route('/cert/<domain>/download/key')
@login_required
@admin_required
def download_key(domain):
    path = os.path.join(CA_DIR, f'{domain}.key')
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True, download_name=f'{domain}.key')


@ca_bp.route('/cert/<domain>/download/pkcs12')
@login_required
@admin_required
def download_pkcs12(domain):
    crt_path = os.path.join(CA_DIR, f'{domain}.crt')
    key_path = os.path.join(CA_DIR, f'{domain}.key')
    if not os.path.exists(crt_path) or not os.path.exists(key_path):
        abort(404)
    try:
        data = gen_pkcs12(domain)
    except Exception as e:
        flash(f'PKCS#12 generation failed: {e}', 'danger')
        return redirect(url_for('ca.cert_detail', domain=domain))
    return send_file(
        io.BytesIO(data),
        as_attachment=True,
        download_name=f'{domain}.p12',
        mimetype='application/x-pkcs12',
    )


@ca_bp.route('/cert/<domain>/revoke', methods=['POST'])
@login_required
@admin_required
def revoke(domain):
    cert = Certificate.query.filter_by(domain=domain, status='valid').first_or_404()
    try:
        cert.status = 'revoked'
        cert.revoked_at = datetime.utcnow()
        log_action('cert_revoke', target=domain)
        db.session.commit()
        regen_crl(Certificate.query.all())
        flash(f'Certificate for {domain} revoked and CRL updated.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Revocation failed: {e}', 'danger')
    return redirect(url_for('ca.dashboard'))


@ca_bp.route('/ca')
@login_required
def show_ca():
    ca_pem = open(CA_CERT).read() if os.path.exists(CA_CERT) else None
    return render_template('ca/show_ca.html',
                           ca_pem=ca_pem,
                           initialized=ca_initialized())


@ca_bp.route('/ca/download')
@login_required
def download_ca():
    if not os.path.exists(CA_CERT):
        abort(404)
    return send_file(CA_CERT, as_attachment=True, download_name='rootCA.pem')


@ca_bp.route('/crl')
def download_crl():
    if not os.path.exists(CRL_FILE):
        abort(404)
    return send_file(CRL_FILE, as_attachment=True, download_name='rootCA.crl')


@ca_bp.route('/audit-log')
@login_required
@admin_required
def audit_log():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(500).all()
    return render_template('ca/audit_log.html', logs=logs)
