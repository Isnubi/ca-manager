import ipaddress
import os
import re
import subprocess
import tempfile

CA_DIR = os.environ.get('CA_DIR', '/opt/private-ca')
CA_KEY = os.path.join(CA_DIR, 'rootCA.key')
CA_CERT = os.path.join(CA_DIR, 'rootCA.pem')
CRL_FILE = os.path.join(CA_DIR, 'rootCA.crl')
INDEX_FILE = os.path.join(CA_DIR, 'index.txt')
SERIAL_FILE = os.path.join(CA_DIR, 'serial')


# Hostname: dot-separated labels of letters, digits and inner hyphens,
# optionally prefixed by a single "*." wildcard label.
_LABEL = r'(?!-)[a-z0-9-]{1,63}(?<!-)'
_HOSTNAME_RE = re.compile(rf'^(\*\.)?{_LABEL}(\.{_LABEL})*$')
RESERVED_NAMES = {'rootca', 'index', 'serial', 'crlnumber'}


class InvalidNameError(ValueError):
    """Raised when a domain or SAN is not a plain hostname or IP address."""


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def validate_domain(value):
    """Return the normalized domain, or raise InvalidNameError.

    Only hostnames (optionally with a leading wildcard) and IP addresses are
    accepted. The value is used in file names, in the OpenSSL subject and
    extension file and in index.txt, so anything else is refused.
    """
    if not isinstance(value, str):
        raise InvalidNameError('Domain must be a string.')
    domain = value.strip().lower()
    if not domain:
        raise InvalidNameError('Domain is required.')
    if len(domain) > 253:
        raise InvalidNameError('Domain is too long.')
    if not (_is_ip(domain) or _HOSTNAME_RE.match(domain)):
        raise InvalidNameError(f'Invalid domain name: {value!r}')
    if domain.split('.')[0] in RESERVED_NAMES:
        raise InvalidNameError(f'Reserved name: {value!r}')
    return domain


def san_entry(value):
    """Validate one SAN value and return it as 'IP:x' or 'DNS:x'."""
    value = validate_domain(value)
    return f'IP:{value}' if _is_ip(value) else f'DNS:{value}'


def validate_san_entry(entry):
    """Validate an already-prefixed SAN ('DNS:x' / 'IP:x') and return it."""
    kind, sep, value = str(entry).strip().partition(':')
    if not sep or kind not in ('DNS', 'IP'):
        raise InvalidNameError(f'Invalid SAN entry: {entry!r}')
    if kind == 'IP':
        if not _is_ip(value):
            raise InvalidNameError(f'Invalid IP SAN: {entry!r}')
        return f'IP:{value}'
    return f'DNS:{validate_domain(value)}'


def build_sans(domain, extra):
    """Build the SAN list for a certificate from its domain and extra names."""
    sans = [san_entry(domain)]
    for s in extra:
        s = str(s).strip()
        if s:
            entry = san_entry(s)
            if entry not in sans:
                sans.append(entry)
    return sans


def cert_path(domain, ext):
    """Return CA_DIR/<domain>.<ext>, refusing any path that leaves CA_DIR."""
    base = os.path.realpath(CA_DIR)
    path = os.path.realpath(os.path.join(base, f'{domain}.{ext}'))
    if os.path.dirname(path) != base or os.path.basename(path).lower().startswith('rootca.'):
        raise InvalidNameError(f'Invalid certificate name: {domain!r}')
    return path


def ca_initialized():
    return os.path.exists(CA_KEY) and os.path.exists(CA_CERT)


def _openssl_conf():
    return (
        "[ ca ]\n"
        "default_ca = CA_default\n"
        "[ CA_default ]\n"
        f"database = {INDEX_FILE}\n"
        f"serial = {SERIAL_FILE}\n"
        "default_md = sha256\n"
        "default_crl_days = 365\n"
    )


def _sync_index_txt(certificates, revoked_history=()):
    """Rebuild index.txt from certificate records for CRL generation.

    ``revoked_history`` holds earlier, revoked serials of certificates that
    have since been renewed or reissued; they must stay on the CRL.
    """
    from app.models import get_setting
    c = get_setting('CA_COUNTRY')
    st = get_setting('CA_STATE')
    loc = get_setting('CA_LOCALITY')
    o = get_setting('CA_ORG')
    ou = get_setting('CA_OU')

    def _clean(value):
        # index.txt is tab/newline delimited: never let a field break it.
        return re.sub(r'[\x00-\x1f\x7f]', '', str(value))

    lines = []
    seen = set()

    def _add(revoked, expires_at, revoked_at, serial, domain):
        if serial in seen:
            return
        seen.add(serial)
        flag = 'R' if revoked else 'V'
        expiry = expires_at.strftime('%y%m%d%H%M%SZ') if expires_at else '991231235959Z'
        rev = revoked_at.strftime('%y%m%d%H%M%SZ') if (revoked and revoked_at) else ''
        if revoked and not rev:
            rev = expiry
        subj = _clean(f"/C={c}/ST={st}/L={loc}/O={o}/OU={ou}/CN={domain}")
        lines.append(f"{flag}\t{expiry}\t{rev}\t{_clean(serial)}\tunknown\t{subj}")

    # Revoked serials first, so a serial appearing twice is kept as revoked.
    for h in revoked_history:
        _add(True, h.expires_at, h.revoked_at, h.serial, h.domain)
    for cert in certificates:
        _add(cert.status != 'valid', cert.expires_at, cert.revoked_at, cert.serial, cert.domain)

    with open(INDEX_FILE, 'w') as f:
        f.write('\n'.join(lines))
        if lines:
            f.write('\n')


def regen_crl(certificates=None, revoked_history=None):
    """Regenerate the CRL.

    Called with no arguments it reads every certificate and every revoked
    history entry from the database (requires an app context).
    """
    if certificates is None or revoked_history is None:
        from app.models import Certificate, CertificateHistory
        if certificates is None:
            certificates = Certificate.query.all()
        if revoked_history is None:
            revoked_history = CertificateHistory.query.filter(
                CertificateHistory.revoked_at.isnot(None)).all()
    _sync_index_txt(certificates, revoked_history)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as cf:
        cf.write(_openssl_conf())
        conf_path = cf.name
    try:
        r = subprocess.run(
            ['openssl', 'ca', '-gencrl', '-keyfile', CA_KEY, '-cert', CA_CERT,
             '-out', CRL_FILE, '-config', conf_path],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr)
    finally:
        os.unlink(conf_path)


def init_ca(subj_c, subj_st, subj_l, subj_o, days_valid_root):
    os.makedirs(CA_DIR, exist_ok=True)
    open(INDEX_FILE, 'a').close()
    with open(SERIAL_FILE, 'w') as f:
        f.write('1000\n')

    root_subj = f"/C={subj_c}/ST={subj_st}/L={subj_l}/O={subj_o}/CN={subj_o} Root CA"

    r = subprocess.run(['openssl', 'genrsa', '-out', CA_KEY, '4096'], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)

    r = subprocess.run(
        ['openssl', 'req', '-x509', '-new', '-nodes', '-key', CA_KEY,
         '-sha256', '-days', str(days_valid_root), '-out', CA_CERT, '-subj', root_subj],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(r.stderr)

    regen_crl([], [])


def issue_cert(domain, sans, subj_c, subj_st, subj_l, subj_o, subj_ou, days_valid_cert):
    domain = validate_domain(domain)
    sans = [validate_san_entry(s) for s in sans]
    key_path = cert_path(domain, 'key')
    csr_path = cert_path(domain, 'csr')
    crt_path = cert_path(domain, 'crt')
    ext_path = cert_path(domain, 'ext')

    subj = f"/C={subj_c}/ST={subj_st}/L={subj_l}/O={subj_o}/OU={subj_ou}/CN={domain}"
    with open(ext_path, 'w') as f:
        f.write(
            "authorityKeyIdentifier=keyid,issuer\n"
            "basicConstraints=CA:FALSE\n"
            "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment\n"
            f"subjectAltName = {', '.join(sans)}\n"
        )

    for cmd in [
        ['openssl', 'genrsa', '-out', key_path, '2048'],
        ['openssl', 'req', '-new', '-key', key_path, '-out', csr_path, '-subj', subj],
        ['openssl', 'x509', '-req', '-in', csr_path, '-CA', CA_CERT, '-CAkey', CA_KEY,
         '-CAcreateserial', '-out', crt_path, '-days', str(days_valid_cert),
         '-sha256', '-extfile', ext_path],
    ]:
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr)

    r = subprocess.run(
        ['openssl', 'x509', '-in', crt_path, '-noout', '-serial'],
        capture_output=True, text=True, check=True,
    )
    return r.stdout.strip().split('=')[1]


def cert_text(domain):
    crt_path = cert_path(domain, 'crt')
    r = subprocess.run(
        ['openssl', 'x509', '-in', crt_path, '-noout', '-text'],
        capture_output=True, text=True,
    )
    return r.stdout


def parse_sans_from_cert_text(text):
    """Extract SANs from openssl x509 -text output, in DNS:/IP: extension format."""
    if not text:
        return []
    lines = text.split('\n')
    for i, line in enumerate(lines):
        if 'Subject Alternative Name' in line:
            if i + 1 < len(lines):
                san_line = lines[i + 1].strip()
                result = []
                for entry in san_line.split(','):
                    entry = entry.strip()
                    if entry.startswith('IP Address:'):
                        result.append('IP:' + entry[len('IP Address:'):])
                    elif entry:
                        result.append(entry)
                return result
    return []


def gen_pkcs12(domain):
    """Generate PKCS#12 bundle (no password) and return bytes."""
    crt_path = cert_path(domain, 'crt')
    key_path = cert_path(domain, 'key')
    with tempfile.NamedTemporaryFile(suffix='.p12', delete=False) as f:
        p12_path = f.name
    try:
        r = subprocess.run(
            ['openssl', 'pkcs12', '-export',
             '-out', p12_path,
             '-inkey', key_path,
             '-in', crt_path,
             '-certfile', CA_CERT,
             '-passout', 'pass:'],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr)
        with open(p12_path, 'rb') as f:
            return f.read()
    finally:
        os.unlink(p12_path)
