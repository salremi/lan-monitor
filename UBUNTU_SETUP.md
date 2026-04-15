# Ubuntu Setup Guide — LAN Monitor + Zeek + Suricata

This guide sets up the full stack on Ubuntu (22.04 or 24.04):
- LAN Monitor (backend + frontend)
- Zeek — network traffic analyzer
- Suricata — IDS/IPS

## Prerequisites

- Ubuntu 22.04 LTS or 24.04 LTS
- Connected to your LAN (wired recommended)
- `sudo` access
- Python 3.11+

Find your network interface name:
```bash
ip addr show
# Look for the interface with your 192.168.50.x address, e.g. eth0 or enp3s0
IFACE=eth0   # replace with yours
```

---

## 1. Install system dependencies

```bash
sudo apt update && sudo apt install -y \
  nmap python3 python3-pip python3-venv \
  curl git build-essential
```

---

## 2. Install Zeek

```bash
# Add Zeek repo
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
  | sudo tee /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null

sudo apt update && sudo apt install -y zeek

# Add zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc
```

> For Ubuntu 24.04 replace `xUbuntu_22.04` with `xUbuntu_24.04` in both URLs above.

### Configure Zeek

```bash
# Set the interface Zeek listens on
sudo nano /opt/zeek/etc/node.cfg
```

Change:
```ini
[zeek]
type=standalone
host=localhost
interface=eth0    # <-- replace with your interface (e.g. enp3s0)
```

```bash
# Deploy and start
sudo /opt/zeek/bin/zeekctl deploy
sudo /opt/zeek/bin/zeekctl start

# Verify it's running
sudo /opt/zeek/bin/zeekctl status
```

Zeek writes logs to `/opt/zeek/logs/current/` — conn.log, dns.log, http.log.

### Auto-restart Zeek on boot

```bash
sudo crontab -e
# Add:
@reboot /opt/zeek/bin/zeekctl start
```

---

## 3. Install Suricata

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update && sudo apt install -y suricata

# Update rules
sudo suricata-update
```

### Configure Suricata

```bash
sudo nano /etc/suricata/suricata.yaml
```

Find and set:
```yaml
af-packet:
  - interface: eth0    # <-- your interface

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
```

```bash
# Enable and start
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl status suricata

# Verify eve.json is being written
tail -f /var/log/suricata/eve.json
```

---

## 4. Install LAN Monitor

```bash
git clone <your-repo-url> lan-monitor
cd lan-monitor

# Backend dependencies
cd backend
python3 -m pip install -r requirements.txt
cd ..

# Frontend dependencies
cd frontend
python3 -m pip install -r requirements.txt
cd ..
```

### Configure .env

```bash
cp .env.example .env
nano .env
```

Key settings for Ubuntu:
```env
DATABASE_URL=sqlite:////home/<youruser>/lan-monitor/backend/lan_monitor.db
SCAN_CIDR=192.168.50.0/24

# Zeek logs
ZEEK_LOG_DIR=/opt/zeek/logs/current

# Suricata
SURICATA_LOG_PATH=/var/log/suricata/eve.json

# LLM (optional — configure after installing Ollama)
LLM_ENABLED=false
LLM_PROVIDER=ollama
LLM_BASE_URL=http://localhost:11434
LLM_MODEL=llama3.2
```

### Start LAN Monitor

```bash
cd lan-monitor
chmod +x start.sh stop.sh
./start.sh
```

- Frontend: http://localhost:8501
- Backend: http://localhost:8000

---

## 5. Ingest logs

Once Zeek and Suricata have been running for a few minutes, trigger ingestion from the Dashboard page or via API:

```bash
# Zeek
curl -X POST http://localhost:8000/api/ingest/zeek

# Suricata
curl -X POST http://localhost:8000/api/ingest/suricata
```

The scheduler also runs ingestion automatically every 5 minutes.

---

## 6. Install Ollama for AI analysis (optional)

```bash
curl -fsSL https://ollama.com/install.sh | sh

# Pull a model (llama3.2 is ~2GB)
ollama pull llama3.2

# Verify
ollama run llama3.2 "say hello"
```

Then in `.env`:
```env
LLM_ENABLED=true
LLM_PROVIDER=ollama
LLM_BASE_URL=http://localhost:11434
LLM_MODEL=llama3.2
```

Restart the backend (`./stop.sh && ./start.sh`) and use the **Analyze with AI** button on any device's detail page.

---

## 7. Run as a service (optional)

To have LAN Monitor start automatically on boot:

```bash
sudo nano /etc/systemd/system/lan-monitor.service
```

```ini
[Unit]
Description=LAN Monitor
After=network.target

[Service]
Type=forking
User=<youruser>
WorkingDirectory=/home/<youruser>/lan-monitor
ExecStart=/home/<youruser>/lan-monitor/start.sh
ExecStop=/home/<youruser>/lan-monitor/stop.sh
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable lan-monitor
sudo systemctl start lan-monitor
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Zeek not capturing traffic | Check interface name in `node.cfg`, run `sudo zeekctl deploy` |
| Suricata not writing eve.json | Check `sudo systemctl status suricata`, verify interface in `suricata.yaml` |
| Score stays 0.0 | Trigger ingest manually, check backend logs for parse errors |
| Ollama unreachable | Run `ollama serve`, check `LLM_BASE_URL` in `.env` |
| nmap needs root for OS scan | `-O` is removed from defaults; use `sudo ./start.sh` only if you re-add it |
| Backend log | `tail -f logs/backend.log` |
| Frontend log | `tail -f logs/frontend.log` |
