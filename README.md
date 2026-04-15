# LAN Monitor — Defensive Home Network Monitoring

A self-hosted, defensive LAN monitoring system that discovers devices on your local network, ingests passive network logs, and flags suspicious behavior. No offensive features. Runs locally via Docker Compose.

## Features

- **Device Discovery** — Nmap-based scanning, DHCP lease tracking
- **Log Ingestion** — Zeek (conn/dns/http), Suricata (eve.json), router syslog
- **Suspicion Scoring** — 9 behavioral rules with configurable thresholds
- **Alert System** — Severity-based alerts with evidence linking
- **Behavioral Baselines** — Rolling z-score anomaly detection
- **Web Dashboard** — Streamlit frontend with 6 pages
- **REST API** — FastAPI backend with full OpenAPI docs

## Quick Start

### Option A — Docker Compose (recommended)

Requires: Docker + Docker Compose

#### 1. Configure

```bash
cp .env.example .env
# Edit .env — at minimum set SCAN_CIDR to your local subnet (e.g. 192.168.1.0/24)
```

#### 2. Start all services

```bash
docker compose up --build
```

- Frontend: http://localhost:8501
- Backend API: http://localhost:8000
- API docs: http://localhost:8000/docs

The frontend waits for the backend health check before starting.

#### 3. Seed with sample data (optional)

```bash
docker compose exec backend python scripts/seed_db.py
```

#### 4. Stop

```bash
docker compose down          # keep data volumes
docker compose down -v       # also delete DB and Ollama model volumes
```

---

### Option B — Run locally without Docker (quick start)

> For a full Ubuntu setup with Zeek + Suricata + Ollama, see [UBUNTU_SETUP.md](UBUNTU_SETUP.md).

Requires: Python 3.11+, `nmap` installed on the host (`apt install nmap` / `brew install nmap`)

#### 1. Configure

```bash
cp .env.example .env
# Edit .env — change DATABASE_URL to a local path, e.g.:
#   DATABASE_URL=sqlite:///./lan_monitor.db
# Set SCAN_CIDR to your local subnet
```

#### 2. Install backend dependencies

```bash
cd backend
pip install -r requirements.txt
```

#### 3. Run database migrations

```bash
cd backend
DATABASE_URL=sqlite:///./lan_monitor.db alembic upgrade head
```

> The `DATABASE_URL` override is required because `alembic.ini` defaults to the container path `/data/db/lan_monitor.db`. Use a relative `sqlite:///./` path so the DB file is created in `backend/`.

#### 4. Start both services (one command)

```bash
./start.sh
```

This runs migrations, starts the backend, waits for it to be healthy, then starts the frontend. Logs go to `logs/backend.log` and `logs/frontend.log`. Use `./stop.sh` to stop both.

Or start them manually:

```bash
cd backend
DATABASE_URL=sqlite:///./lan_monitor.db PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
```

Backend API available at http://localhost:8000 — docs at http://localhost:8000/docs.

#### 5. Install frontend dependencies (new terminal)

```bash
cd frontend
pip install -r requirements.txt
```

#### 6. Start the frontend

```bash
cd frontend
BACKEND_URL=http://localhost:8000 streamlit run app.py --server.port 8501
```

Frontend available at http://localhost:8501.

#### 7. Seed with sample data (optional)

```bash
cd backend
DATABASE_URL=sqlite:///./lan_monitor.db PYTHONPATH=. python scripts/seed_db.py
```

#### 8. Run tests

```bash
cd backend
PYTHONPATH=. python -m pytest tests/ -v
```

## Architecture

```
browser ──► Streamlit (8501) ──► FastAPI (8000) ──► SQLite
                                      │
                          ┌───────────┼───────────┐
                       Parsers    Scoring      APScheduler
                     (nmap/zeek   (rules +      (scan every
                    /suricata/    engine)        30 min,
                     router)                    ingest every
                                                5 min)
```

## Directory Structure

```
lan-monitor/
├── backend/
│   ├── app/
│   │   ├── main.py          # FastAPI entry point
│   │   ├── config.py        # Pydantic settings
│   │   ├── database.py      # SQLAlchemy + session
│   │   ├── models/          # ORM models
│   │   ├── schemas/         # Pydantic schemas
│   │   ├── api/             # Route handlers
│   │   ├── parsers/         # Log parsers
│   │   ├── scoring/         # Rules + engine
│   │   └── jobs/            # APScheduler jobs
│   ├── tests/               # pytest suite
│   └── data/sample/         # Synthetic test data
└── frontend/
    ├── app.py               # Streamlit entry point
    └── pages/               # Dashboard, Inventory, Alerts, ...
```

## Scoring Rules

| Rule | Description |
|------|-------------|
| `outbound_fanout` | Many unique dest IPs per hour (IoT ×1.5) |
| `sustained_upload` | High bytes uploaded per hour |
| `long_lived_sessions` | Multiple connections lasting > 1 hour |
| `high_dns_churn` | Many unique DNS queries per hour |
| `suspicious_domain_diversity` | Many NXDOMAINs or diverse TLDs |
| `geo_asn_spread` | Connections to many different network regions |
| `behavior_deviation` | Z-score anomaly vs rolling baseline |
| `exposed_proxy_service` | Open proxy ports (3128, 8080, 1080, 8888) |
| `suricata_alert_score` | Suricata IDS alerts mapped to score deltas |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/devices` | List all devices |
| GET | `/api/devices/{id}` | Device detail + ports + events |
| PATCH | `/api/devices/{id}` | Update category/tags/suppressed |
| GET | `/api/alerts` | List alerts (filter by severity/ack/device) |
| PATCH | `/api/alerts/{id}/acknowledge` | Acknowledge alert |
| GET | `/api/evidence/{device_id}` | Raw events for device |
| GET | `/api/config` | All thresholds |
| PUT | `/api/config` | Update thresholds |
| POST | `/api/scan/nmap` | Trigger Nmap scan |
| POST | `/api/ingest/{source}` | Trigger log ingest (zeek/suricata/router) |
| GET | `/api/stats` | Summary statistics |

## Log Integration

### Zeek
Mount Zeek log directory:
```yaml
volumes:
  - /var/log/zeek/current:/data/logs/zeek:ro
```
Set `ZEEK_LOG_DIR=/data/logs/zeek` in `.env`.

### Suricata
```yaml
volumes:
  - /var/log/suricata:/data/logs/suricata:ro
```
Set `SURICATA_LOG_PATH=/data/logs/suricata/eve.json`.

### Router Syslog
Forward syslog to a file and mount it:
```yaml
volumes:
  - /var/log/router:/data/logs/router:ro
```
Supports OpenWRT/dnsmasq, pfSense, and iptables formats.

## Configuration

All thresholds are configurable via the Config page or `PUT /api/config`:

| Key | Default | Description |
|-----|---------|-------------|
| `outbound_fanout_threshold` | 50 | Unique dest IPs/hour |
| `sustained_upload_threshold_mb` | 500 | MB uploaded/hour |
| `long_lived_session_threshold_sec` | 3600 | Session duration (s) |
| `dns_churn_threshold` | 100 | Unique DNS queries/hour |
| `domain_diversity_nxdomain_threshold` | 20 | NXDOMAIN count/hour |
| `geo_asn_spread_threshold` | 10 | Unique network regions/hour |
| `behavior_deviation_z_threshold` | 2.5 | Z-score for anomaly |
| `iot_weight_multiplier` | 1.5 | Score multiplier for IoT/TV |
| `alert_score_change_threshold` | 10.0 | Min delta to create alert |

## Notes

- This is a **defensive monitoring tool only**. It passively observes your network and flags anomalies.
- No traffic is generated except for periodic Nmap scans on your local subnet.
- SQLite is used for simplicity; for production use, consider PostgreSQL.
- GeoIP lookup via ip-api.com is used as fallback when MaxMind GeoLite2 DB is not available.
