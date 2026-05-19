# CA Manager — REST API Reference

All endpoints are under `/api/`. Every request must include an `X-API-Key` header with a valid API key.

API keys are managed per-user in the web UI under **My Account → API Keys**. Keys are generated once and shown only at creation — store them securely.

---

## Authentication

```
X-API-Key: <your-api-key>
```

Missing or invalid key → `401 Unauthorized`.

Permission errors (e.g. a viewer key trying to issue) → `403 Forbidden`.

All responses are JSON.

---

## Endpoints

### List certificates

```
GET /api/certs
```

Returns all certificates ordered by issue date descending.

**Response `200`**

```json
[
  {
    "domain": "myservice.home.local",
    "serial": "4A3F1C2D...",
    "status": "valid",
    "issued_at": "2025-01-15T10:30:00",
    "expires_at": "2026-02-24T10:30:00",
    "revoked_at": null,
    "sans": ["DNS:myservice.home.local", "IP:192.168.1.10"],
    "notes": "nginx on web-01"
  }
]
```

---

### Get a certificate

```
GET /api/cert/<domain>
```

**Response `200`** — same object shape as above.

**Response `404`** — certificate not found.

---

### Issue a certificate

Requires **operator** or **admin** key.

```
POST /api/certs
Content-Type: application/json
```

**Request body**

| Field | Type | Required | Description |
|---|---|:---:|---|
| `domain` | string | yes | Primary domain (automatically added as a SAN) |
| `sans` | array of strings | no | Extra SANs — DNS names or IP addresses |
| `notes` | string | no | Free-text description |

IP addresses in `sans` are detected automatically and prefixed with `IP:`.

**Example**

```json
{
  "domain": "myservice.home.local",
  "sans": ["alt.home.local", "192.168.1.10"],
  "notes": "nginx on web-01"
}
```

**Response `201`** — the newly issued certificate object.

**Response `400`** — missing `domain`.

**Response `409`** — a valid certificate for this domain already exists, or the CA is not initialized.

---

### Revoke a certificate

Requires **admin** key.

```
POST /api/cert/<domain>/revoke
```

No request body needed.

**Response `200`**

```json
{
  "status": "revoked",
  "domain": "myservice.home.local"
}
```

**Response `404`** — no valid certificate found for this domain.

---

### Download certificate PEM

```
GET /api/cert/<domain>/cert.pem
```

Returns the certificate file as `application/x-pem-file`.

---

### Download full-chain PEM

```
GET /api/cert/<domain>/chain.pem
```

Returns the certificate concatenated with the Root CA as a single `application/x-pem-file`. Use this for most TLS configurations (nginx `ssl_certificate`, etc.).

---

## Example usage

```bash
API_KEY="your-key-here"
BASE="http://ca-manager.home.local:5000"

# List all certificates
curl -H "X-API-Key: $API_KEY" "$BASE/api/certs"

# Issue a certificate
curl -s -X POST "$BASE/api/certs" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain": "newservice.home.local", "sans": ["192.168.1.20"], "notes": "web server"}'

# Download the full-chain for nginx
curl -sO "$BASE/api/cert/newservice.home.local/chain.pem" \
  -H "X-API-Key: $API_KEY"

# Revoke a certificate
curl -s -X POST "$BASE/api/cert/newservice.home.local/revoke" \
  -H "X-API-Key: $API_KEY"
```

---

## Permissions summary

| Endpoint | Viewer | Operator | Admin |
|---|:---:|:---:|:---:|
| `GET /api/certs` | ✓ | ✓ | ✓ |
| `GET /api/cert/<domain>` | ✓ | ✓ | ✓ |
| `GET /api/cert/<domain>/cert.pem` | ✓ | ✓ | ✓ |
| `GET /api/cert/<domain>/chain.pem` | ✓ | ✓ | ✓ |
| `POST /api/certs` | — | ✓ | ✓ |
| `POST /api/cert/<domain>/revoke` | — | — | ✓ |
