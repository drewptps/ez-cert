# EZ-CERT

A lightweight, self-hosted Certificate Authority manager. Create and manage a full PKI hierarchy — root CA, intermediate CA, and leaf certificates — through a simple web UI. No database, no cloud, no complexity.

## Quick Start

Create a `docker-compose.yml` and run it:

```yaml
services:
  ez-cert:
    image: ghcr.io/drewpetipas/ez-cert:latest  # or pin to a specific tag e.g. v1.0.0
    container_name: ez-cert
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ez-cert-data:/app/data

volumes:
  ez-cert-data:
```

```bash
docker compose up -d
```

Then open [http://localhost:8080](http://localhost:8080).

**First run:** you'll be prompted to set a password, then walk through initial PKI setup to create a root CA and intermediate CA.

## Features

- Full PKI hierarchy: root CA → intermediate CA → leaf certificates
- ECDSA (P-256, P-384, P-521) and RSA (2048, 3072, 4096) key types
- Certificate renewal in place
- Password-protected UI with audit log
- Export cert, private key, or full chain bundle as PEM files
- Copy-to-clipboard on PEM output blocks
- Dashboard showing certificate hierarchy with expiry status
- Email notifications for expiring certificates (SMTP)
- File-based storage — no database, easy to back up

## Expiry Notifications

EZ-CERT can send email alerts when certificates are approaching expiry. Configure SMTP under **Settings → Notifications** in the UI.

| Field | Description |
|---|---|
| SMTP Host | Your mail server hostname (e.g. `smtp.example.com`) |
| Port | Usually `587` (STARTTLS). Port `465` (SMTPS) is not supported. |
| Username / Password | SMTP auth credentials. Leave Password blank on save to keep the existing value. |
| From / To | Sender and recipient addresses for alert emails. |
| Notify when expiring within | Certificates expiring within this many days are included in alerts (default: 30). |
| Check interval | How often the background scheduler runs the check, in hours (default: 24). |

The scheduler runs automatically in the background and checks on the configured interval. It persists the last-run time to `data/notify_last_run` so the schedule stays consistent across server restarts. You can also trigger an immediate check at any time with the **Send Notification Now** button.

Alerts are only sent for certificates in "expiring soon" status — certificates that are already expired are not included.

## Data

All data lives in the Docker volume at `/app/data`:

| Path | Contents |
|---|---|
| `data/certs/` | One directory per certificate, containing `cert.pem`, `key.pem`, `description.txt` |
| `data/auth.hash` | bcrypt hash of the UI password |
| `data/audit.log` | Append-only log of all auth and certificate events |
| `data/smtp.json` | SMTP notification settings |
| `data/notify_last_run` | Timestamp of the last notification check |

Back up the volume to preserve everything. The root CA private key is **never stored** — save it somewhere secure when shown at creation time.

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `EZCERT_DATA_DIR` | `./data` | Path to the data directory |

## Updating

```bash
docker compose pull
docker compose up -d
```

## Building from Source

```bash
go build ./cmd/ez-cert
./ez-cert
```

Requires Go 1.24+.
