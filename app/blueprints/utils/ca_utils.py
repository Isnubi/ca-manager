import os
import subprocess
import tempfile

CA_DIR = os.environ.get('CA_DIR', '/opt/private-ca')
CA_KEY = os.path.join(CA_DIR, 'rootCA.key')
CA_CERT = os.path.join(CA_DIR, 'rootCA.pem')
CRL_FILE = os.path.join(CA_DIR, 'rootCA.crl')
INDEX_FILE = os.path.join(CA_DIR, 'index.txt')
SERIAL_FILE = os.path.join(CA_DIR, 'serial')


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


def _sync_index_txt(certificates):
    """Rebuild index.txt from certificate records for CRL generation."""
    from app.models import get_setting
    c = get_setting('CA_COUNTRY')
    st = get_setting('CA_STATE')
    loc = get_setting('CA_LOCALITY')
    o = get_setting('CA_ORG')
    ou = get_setting('CA_OU')

    lines = []
    for cert in certificates:
        flag = 'V' if cert.status == 'valid' else 'R'
        expiry = cert.expires_at.strftime('%y%m%d%H%M%SZ') if cert.expires_at else '991231235959Z'
        rev = cert.revoked_at.strftime('%y%m%d%H%M%SZ') if (cert.status == 'revoked' and cert.revoked_at) else ''
        subj = f"/C={c}/ST={st}/L={loc}/O={o}/OU={ou}/CN={cert.domain}"
        lines.append(f"{flag}\t{expiry}\t{rev}\t{cert.serial}\tunknown\t{subj}")

    with open(INDEX_FILE, 'w') as f:
        f.write('\n'.join(lines))
        if lines:
            f.write('\n')


def regen_crl(certificates):
    _sync_index_txt(certificates)
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

    regen_crl([])


def issue_cert(domain, sans, subj_c, subj_st, subj_l, subj_o, subj_ou, days_valid_cert):
    key_path = os.path.join(CA_DIR, f'{domain}.key')
    csr_path = os.path.join(CA_DIR, f'{domain}.csr')
    crt_path = os.path.join(CA_DIR, f'{domain}.crt')
    ext_path = os.path.join(CA_DIR, f'{domain}.ext')

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
    crt_path = os.path.join(CA_DIR, f'{domain}.crt')
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
    crt_path = os.path.join(CA_DIR, f'{domain}.crt')
    key_path = os.path.join(CA_DIR, f'{domain}.key')
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
