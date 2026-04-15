# Project Context — LAN Monitor

This file exists so that a new Claude session on any machine can immediately understand the full state of this project without re-deriving it from the code.

---

## What This Is

A self-hosted defensive home network monitoring system. It discovers devices on a LAN, ingests passive network logs (Zeek, Suricata, router syslog), scores devices for suspicious behavior using 9 behavioral rules, raises alerts, and provides an LLM-powered plain-English analysis of flagged devices.

**Not offensive.** No traffic injection, no exploitation. Passive observation only.

---

## Repositories

| Remote | URL |
|--------|-----|
| GitHub (public) | https://github.com/salremi/lan-monitor |
| Gitea (local NAS) | http://192.168.50.229:3001/salremi/lan-monitor |

Push to both:
```bash
git push origin main   # GitHub
git push gitea main    # local Gitea
```

---

## Stack

| Component | Tech | Port |
|-----------|------|------|
| Backend API | FastAPI + SQLAlchemy + APScheduler + SQLite | 8000 |
| Frontend | Streamlit | 8501 |
| LLM (optional) | Ollama or LM Studio | 11434 / 1234 |

---

## Run Locally (no Docker)

```bash
# Install deps (first time)
pip install -r backend/requirements.txt
pip install -r frontend/requirements.txt

# Start both services
./start.sh

# Stop
./stop.sh
```

`start.sh` handles migrations, waits for backend health, then starts frontend.
Logs go to `logs/backend.log` and `logs/frontend.log`.

### Manual start (if needed)
```bash
cd backend
DATABASE_URL=sqlite:///./lan_monitor.db alembic upgrade head
DATABASE_URL=sqlite:///./lan_monitor.db PYTHONPATH=. uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1

cd ../frontend
BACKEND_URL=http://localhost:8000 streamlit run app.py --server.port 8501
```

### Run tests
```bash
cd backend && PYTHONPATH=. python3 -m pytest tests/ -v
```

### Seed sample data
```bash
cd backend && DATABASE_URL=sqlite:///./lan_monitor.db PYTHONPATH=. python scripts/seed_db.py
```

---

## Run with Docker
```bash
cp .env.example .env   # edit SCAN_CIDR to your subnet
docker compose up --build
```

---

## Key Config (`.env`)

```env
DATABASE_URL=sqlite:///./lan_monitor.db   # local path (not container path)
SCAN_CIDR=192.168.50.0/24                 # owner's LAN subnet
NMAP_ARGS=-sV --open -T4                  # -O removed (requires root)

# LLM (disabled until Ollama/LM Studio is running)
LLM_ENABLED=false
LLM_PROVIDER=ollama          # or lmstudio
LLM_BASE_URL=http://localhost:11434
LLM_MODEL=llama3.2
```

**Critical:** `config.py` reads `.env` from the project root via absolute path — no need to cd anywhere specific.

---

## Architecture

```
browser → Streamlit (8501) → FastAPI (8000) → SQLite
                                  │
                    ┌─────────────┼─────────────┐
                 Parsers       Scoring       APScheduler
              (nmap/zeek/    (9 rules +    (scan every 30min,
              suricata/       engine)       ingest every 5min)
               router)
                                  │
                              LLM Analyzer
                         (Ollama / LM Studio)
```

---

## Scoring Rules (all in `backend/app/scoring/rules.py`)

| Rule | Signal | Data needed |
|------|--------|-------------|
| `outbound_fanout` | Many unique dest IPs/hour | Zeek conn.log |
| `sustained_upload` | High bytes uploaded/hour | Zeek conn.log |
| `long_lived_sessions` | Persistent connections > 1hr | Zeek conn.log |
| `high_dns_churn` | Many unique DNS queries/hour | Zeek dns.log |
| `suspicious_domain_diversity` | Many NXDOMAINs / diverse TLDs | Zeek dns.log |
| `geo_asn_spread` | Connections to many network regions | Zeek conn.log |
| `behavior_deviation` | Z-score anomaly vs rolling baseline | Zeek conn.log |
| `exposed_proxy_service` | Open proxy ports (3128/8080/1080/8888) | nmap scan |
| `suricata_alert_score` | IDS alert severity mapping | Suricata eve.json |

Scores are 0.0 until log data is ingested. Use seed script to test with synthetic data.

---

## Network & Hardware Context

| Item | Detail |
|------|--------|
| LAN subnet | 192.168.50.0/24 |
| Gateway | 192.168.50.1 |
| Main router | ASUS GT-BE98 Pro (Asuswrt, no OpenWRT, no port mirroring) |
| Switch | TRENDnet TEG-S750 — **unmanaged**, no port mirroring |
| Spare router | Netgear RAX120 (could run OpenWRT or forward syslog) |
| NAS | Synology at 192.168.50.229 — runs Gitea on port 3001 |
| Planned purchase | TP-Link TL-SG108E managed switch (~$30) for port mirroring |

---

## What's Not Done Yet (Next Steps)

### High priority
1. **Buy TP-Link TL-SG108E** — plug it between ASUS router and devices, configure port mirroring to Ubuntu machine → Zeek/Suricata see all LAN traffic
2. **Set up Zeek + Suricata on Ubuntu** — follow `UBUNTU_SETUP.md` in this repo
3. **Enable LLM** — `LLM_ENABLED=true`, run `ollama pull llama3.2`, restart backend

### Medium priority
4. **Netgear RAX120 syslog** — enable syslog forwarding on RAX120 to Ubuntu → router parser gets DHCP + firewall events without needing a managed switch
5. **SSE log stream** — real-time backend log panel in frontend (planned, not built); currently check `logs/backend.log`

### Nice to have
6. **systemd service** — see `UBUNTU_SETUP.md` section 7 for auto-start on boot
7. **PostgreSQL** — SQLite is fine for home use; swap if load increases

---

## Ubuntu / DGX Spark Migration Checklist

- [ ] Clone repo: `git clone https://github.com/salremi/lan-monitor`
- [ ] Follow `UBUNTU_SETUP.md` for Zeek + Suricata install
- [ ] Copy `.env.example` → `.env`, set `SCAN_CIDR` and `DATABASE_URL`
- [ ] Run `./start.sh`
- [ ] Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh && ollama pull llama3.2`
- [ ] Set `LLM_ENABLED=true` in `.env`, restart backend
- [ ] Configure managed switch port mirroring once TP-Link TL-SG108E arrives

---

## Known Gotchas

- `alembic.ini` has a hardcoded container path — always pass `DATABASE_URL` env var when running alembic locally (already fixed in `migrations/env.py`)
- `NMAP_ARGS` must not include `-O` when running as non-root (removed from defaults)
- APScheduler runs nmap scan on startup after 30min — don't be surprised by nmap processes
- Parser `_offsets` dicts are module-level globals — reset between test runs (handled in `conftest.py`)
- `gh` CLI does not support Gitea — use `git push gitea main` directly
- `gh` binary installed at `~/.local/bin/gh` (no sudo available on workbench user)
