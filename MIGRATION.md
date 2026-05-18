# Migration: script-managed CA → Docker web UI

This guide covers migrating an existing CA managed by `ca-manager.sh` (files in `/opt/private-ca` on a bare-metal host or LXC) to the CA Manager Docker application running on a new host.

Your CA files and issued certificates are preserved — no certificates need to be reissued and clients do not need to re-import the Root CA.

---

## Prerequisites

- The old host has `ca-manager.sh` with CA files in `/opt/private-ca`
- The new host has Docker and Docker Compose installed
- SSH access between the two hosts (or another file transfer method)

---

## Step 1 — Archive the CA files (old host)

```bash
tar -czf ca-backup.tar.gz -C /opt/private-ca .
```

This captures everything: `rootCA.key`, `rootCA.pem`, `rootCA.crl`, `index.txt`, `serial`, and all issued `*.crt` / `*.key` files.

---

## Step 2 — Transfer to the new host

```bash
scp ca-backup.tar.gz user@new-host:/tmp/
```

---

## Step 3 — Deploy the Docker application (new host)

```bash
git clone <your-repo-url> ca-manager
cd ca-manager
```

Edit `.env` — at minimum set a strong `SECRET_KEY`:

```bash
nano .env
```

Start the application:

```bash
docker compose up -d
```

Browse to `http://new-host-ip:5000`, create your **admin account**, then stop — do **not** click "Initialize CA". Your existing CA will be imported in the next steps.

---

## Step 4 — Inject the CA files into the Docker volume (new host)

The Docker volume `ca_data` is mounted at `/opt/private-ca` inside the container. Copy your archive into it:

```bash
docker compose cp /tmp/ca-backup.tar.gz ca-manager:/tmp/
docker compose exec ca-manager tar -xzf /tmp/ca-backup.tar.gz -C /opt/private-ca
```

Verify the files are in place:

```bash
docker compose exec ca-manager ls /opt/private-ca
```

Expected output includes `rootCA.key`, `rootCA.pem`, and your `<domain>.crt` / `<domain>.key` files.

---

## Step 5 — Import certificates into the database (new host)

The web application stores certificate metadata (domain, serial, expiry, status) in a SQLite database. Run the import command to populate it from your existing files:

```bash
docker compose exec ca-manager python cli.py import-ca
```

The command will:
- Scan all `*.crt` files in `/opt/private-ca`
- Read serial numbers and dates directly from each certificate
- Check `index.txt` to detect revoked certificates
- Parse Subject Alternative Names (SANs) and store them
- Skip any domain already present in the database (safe to re-run)

Example output:

```
Found 1 revoked serial(s) in index.txt
  import myservice.home.local   serial=4A3F1C2D...  [valid]
  import oldservice.home.local  serial=8B7E6D5C...  [revoked]

Done: 2 imported, 0 skipped, 0 errors.
```

---

## Step 6 — Verify (new host)

List all imported certificates from the CLI:

```bash
docker compose exec ca-manager python cli.py list
```

Then open the web dashboard — all certificates should appear with correct status, expiry dates, and SANs.

---

## After migration

- **Clients do not need to re-import the Root CA.** The CA key and certificate are identical.
- **Existing service certificates remain valid.** Replace them over time using the Renew button as they approach expiry.
- **Decommission the old host** once you have confirmed everything is working in the web UI.
- **Back up your Docker volumes regularly**, especially `ca_data` which contains the CA private key.

```bash
# Example backup of both volumes
docker compose exec ca-manager tar -czf /tmp/ca-data-backup.tar.gz -C /opt/private-ca .
docker compose cp ca-manager:/tmp/ca-data-backup.tar.gz ./backups/
```
