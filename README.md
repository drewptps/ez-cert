# EZ-CERT

A lightweight, self-hosted Certificate Authority manager. Create and manage a full PKI hierarchy — root CA, intermediate CA, and leaf certificates — through a simple web UI. No database, no cloud, no complexity.

## Quick Start

Create a `docker-compose.yml` and run it:

```yaml
services:
  ez-cert:
    image: ghcr.io/drewpetipas/ez-cert:latest
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
- File-based storage — no database, easy to back up

## Data

All data lives in the Docker volume at `/app/data`:

| Path | Contents |
|---|---|
| `data/certs/` | One directory per certificate, containing `cert.pem`, `key.pem`, `description.txt` |
| `data/auth.hash` | bcrypt hash of the UI password |
| `data/audit.log` | Append-only log of all auth and certificate events |

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
