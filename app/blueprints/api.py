import ipaddress
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify, g, send_file, Response
from app import db
from app.models import ApiKey, Certificate, CertificateHistory, AuditLog, get_setting
from app.blueprints.utils.ca_utils import (
    CA_DIR, CA_CERT, ca_initialized, issue_cert, regen_crl, parse_sans_from_cert_text,
)

api_bp = Blueprint('api', __name__, url_prefix='/api')


def _san_entry(value):
    try:
        ipaddress.ip_address(value)
        return f'IP:{value}'
    except ValueError:
        return f'DNS:{value}'


def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        raw_key = request.headers.get('X-API-Key', '')
        if not raw_key:
            return jsonify({'error': 'X-API-Key header required'}), 401
        api_key = ApiKey.lookup(raw_key)
        if not api_key:
            return jsonify({'error': 'Invalid API key'}), 401
        api_key.last_used_at = datetime.utcnow()
        db.session.commit()
        g.api_key = api_key
        return f(*args, **kwargs)
    return decorated


def _log(action, target=None, detail=None):
    db.session.add(AuditLog(
        action=action, target=target, detail=detail,
        user_id=g.api_key.user_id,
    ))


def _cert_json(cert):
    return {
        'domain': cert.domain,
        'serial': cert.serial,
        'status': cert.status,
        'issued_at': cert.issued_at.isoformat() if cert.issued_at else None,
        'expires_at': cert.expires_at.isoformat() if cert.expires_at else None,
        'revoked_at': cert.revoked_at.isoformat() if cert.revoked_at else None,
        'sans': cert.sans.split(',') if cert.sans else [],
        'notes': cert.notes,
    }


@api_bp.route('/certs')
@require_api_key
def list_certs():
    certs = Certificate.query.order_by(Certificate.issued_at.desc()).all()
    return jsonify([_cert_json(c) for c in certs])


@api_bp.route('/cert/<domain>')
@require_api_key
def get_cert(domain):
    cert = Certificate.query.filter_by(domain=domain).first()
    if not cert:
        return jsonify({'error': 'Certificate not found'}), 404
    return jsonify(_cert_json(cert))


@api_bp.route('/certs', methods=['POST'])
@require_api_key
def issue():
    owner = g.api_key.owner
    if not owner.can_issue:
        return jsonify({'error': 'Insufficient permissions'}), 403
    if not ca_initialized():
        return jsonify({'error': 'CA not initialized'}), 409

    data = request.get_json(silent=True) or {}
    domain = (data.get('domain') or '').strip().lower()
    if not domain:
        return jsonify({'error': 'domain is required'}), 400

    extra_sans = data.get('sans', [])
    notes = (data.get('notes') or '').strip() or None

    existing = Certificate.query.filter_by(domain=domain).first()
    if existing and existing.status == 'valid':
        return jsonify({'error': f'A valid certificate for {domain} already exists'}), 409

    sans = [_san_entry(domain)]
    for s in extra_sans:
        s = str(s).strip()
        if s:
            entry = _san_entry(s)
            if entry not in sans:
                sans.append(entry)

    try:
        days = int(get_setting('DAYS_VALID_CERT'))
        serial = issue_cert(
            domain=domain, sans=sans,
            subj_c=get_setting('CA_COUNTRY'),
            subj_st=get_setting('CA_STATE'),
            subj_l=get_setting('CA_LOCALITY'),
            subj_o=get_setting('CA_ORG'),
            subj_ou=get_setting('CA_OU'),
            days_valid_cert=days,
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 500

    now = datetime.utcnow()
    if existing:
        db.session.add(CertificateHistory(
            domain=domain, serial=existing.serial,
            issued_at=existing.issued_at, expires_at=existing.expires_at,
            action='reissued',
        ))
        existing.serial = serial
        existing.status = 'valid'
        existing.issued_at = now
        existing.expires_at = now + timedelta(days=days)
        existing.revoked_at = None
        existing.issued_by_id = owner.id
        existing.sans = ','.join(sans)
        existing.notes = notes
    else:
        cert = Certificate(
            domain=domain, serial=serial, status='valid',
            issued_at=now, expires_at=now + timedelta(days=days),
            issued_by_id=owner.id, sans=','.join(sans), notes=notes,
        )
        db.session.add(cert)

    _log('cert_issue', target=domain, detail=f'via API; {",".join(sans)}')
    db.session.commit()

    cert = Certificate.query.filter_by(domain=domain).first()
    return jsonify(_cert_json(cert)), 201


@api_bp.route('/cert/<domain>/revoke', methods=['POST'])
@require_api_key
def revoke(domain):
    if not g.api_key.owner.is_admin:
        return jsonify({'error': 'Admin permission required'}), 403
    cert = Certificate.query.filter_by(domain=domain, status='valid').first()
    if not cert:
        return jsonify({'error': 'No valid certificate found for this domain'}), 404
    cert.status = 'revoked'
    cert.revoked_at = datetime.utcnow()
    _log('cert_revoke', target=domain, detail='via API')
    db.session.commit()
    regen_crl(Certificate.query.all())
    return jsonify({'status': 'revoked', 'domain': domain})


@api_bp.route('/cert/<domain>/cert.pem')
@require_api_key
def download_cert(domain):
    path = os.path.join(CA_DIR, f'{domain}.crt')
    if not os.path.exists(path):
        return jsonify({'error': 'Certificate file not found'}), 404
    return send_file(path, as_attachment=True, download_name=f'{domain}.crt',
                     mimetype='application/x-pem-file')


@api_bp.route('/cert/<domain>/chain.pem')
@require_api_key
def download_chain(domain):
    crt_path = os.path.join(CA_DIR, f'{domain}.crt')
    if not os.path.exists(crt_path) or not os.path.exists(CA_CERT):
        return jsonify({'error': 'Certificate or CA file not found'}), 404
    chain = open(crt_path).read() + open(CA_CERT).read()
    return Response(
        chain,
        mimetype='application/x-pem-file',
        headers={'Content-Disposition': f'attachment; filename="{domain}-chain.pem"'},
    )
