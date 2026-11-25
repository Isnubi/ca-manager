# CA Manager

A self-hosted private Certificate Authority manager built with Flask. Issue, renew, and revoke TLS certificates for your homelab services — no command-line required.

## Features

- **Root CA management** — initialize and manage your own Root CA
- **Certificate issuance** — 2048-bit RSA certificates with custom SANs (DNS and IP addresses)
- **Certificate renewal** — renew with one click, preserving all SANs
- **Certificate revocation** — with automatic CRL regeneration
- **Full-chain download** — certificate + Root CA concatenated (`.pem`)
- **PKCS#12 export** — bundled cert + key + CA (`.p12`, no password)
- **Role-based access** — admin, operator (can issue/renew), viewer (read-only)
- **Two-factor authentication** — TOTP per user (optional)
- **Audit log** — track all important actions
- **Dashboard search** — filter certificates by domain or status

## Quick start

### Docker Compose

```bash
cp .env.example .env   # optionally set SECRET_KEY (see below)
docker compose up -d
```

Open [http://localhost:5000](http://localhost:5000) and create your admin account on first launch.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(random, generated on first start)* | Session signing secret. If unset, shorter than 32 characters, or a published placeholder, a random key is generated and stored in `DATA_DIR/secret_key`. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`. |
| `SESSION_COOKIE_SECURE` | `false` | Set to `true` when the app is served over HTTPS, so session cookies are never sent in clear text. |
| `DATA_DIR` | `/app/data` | SQLite database location |
| `CA_DIR` | `/opt/private-ca` | CA keys and certificate files |

CA subject fields (Country, Org, etc.) are configurable in the Settings page after login.

### Security notes

- All forms are protected against CSRF; session cookies are `HttpOnly` and `SameSite=Lax`.
- Domains and SANs must be plain hostnames (optionally `*.` wildcard) or IP addresses.
- After 5 failed password or TOTP attempts an account is locked for 15 minutes.
- Changing a password or TOTP setting signs the user out of every other session.

## Roles

| Role | Issue | Renew | Revoke | Users | Settings |
|---|:---:|:---:|:---:|:---:|:---:|
| Admin | ✓ | ✓ | ✓ | ✓ | ✓ |
| Operator | ✓ | ✓ | — | — | — |
| Viewer | — | — | — | — | — |

All roles can view certificates and download the CA certificate. Admins can also download private keys and export PKCS#12 bundles.

## Trust setup

After initializing the CA, download `rootCA.pem` from the CA Certificate page and add it to your system/browser trust store:

**Linux:**
```bash
sudo cp rootCA.pem /usr/local/share/ca-certificates/homelab-ca.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rootCA.pem
```

**Windows:** Double-click the `.pem` file → Install Certificate → Local Machine → Trusted Root Certification Authorities.

## Data persistence

Two Docker volumes are used:

- `ca_data` → `/opt/private-ca` — CA key, certificate, and all issued cert/key files
- `app_data` → `/app/data` — SQLite database (users, cert records, settings, audit log)

Back these up regularly. The CA private key (`rootCA.key`) is the most sensitive file — treat it accordingly.

## Migrating from a script-managed CA

If you previously managed your CA with `ca-manager.sh` and want to move to this Docker application, see **[MIGRATION.md](MIGRATION.md)** for the full step-by-step guide.

The short version: archive your `/opt/private-ca` directory, inject it into the Docker volume, then run `python cli.py import-ca` — no certificates need to be reissued and clients do not need to re-import the Root CA.

## REST API

CA Manager exposes a JSON API at `/api/`. Authenticate every request with an `X-API-Key` header. Keys are generated per-user in **My Account → API Keys**.

See **[API.md](API.md)** for the full endpoint reference.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r app/requirements.txt
DATA_DIR=./data CA_DIR=./ca-files python start.py
```
