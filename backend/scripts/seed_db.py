#!/usr/bin/env python3
"""Seed database with synthetic sample data and run scoring engine."""
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.database import init_db, SessionLocal
from app.config import settings

# Override DB to local path for dev
os.environ.setdefault("DATABASE_URL", "sqlite:///./dev.db")

import importlib
import app.config as config_mod
config_mod.settings = config_mod.Settings()

from app.database import get_engine, SessionLocal as _SL
from sqlalchemy.orm import sessionmaker

# Use local dev DB
_engine = get_engine("sqlite:///./dev.db")
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)

from app.database import Base
Base.metadata.create_all(bind=_engine)

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")


def seed():
    from app.parsers.nmap_parser import parse_nmap_xml
    from app.parsers.zeek_parser import _ingest_conn_log, _ingest_dns_log, _ingest_http_log
    from app.parsers.suricata_parser import ingest_suricata_logs
    from app.parsers.router_parser import ingest_router_logs
    from app.scoring.engine import run_scoring_engine
    from app.scoring.baseline import compute_baselines
    from app.models.app_config import AppConfig

    db = SessionLocal()
    try:
        # Insert default config
        defaults = {
            "outbound_fanout_threshold": (5, "Unique dest IPs per hour threshold (lowered for demo)"),
            "sustained_upload_threshold_mb": (1.0, "MB uploaded per hour threshold (lowered for demo)"),
            "long_lived_session_threshold_sec": (1000, "Session duration seconds threshold (lowered for demo)"),
            "long_lived_session_count_threshold": (1, "Number of long sessions threshold"),
            "dns_churn_threshold": (5, "Unique DNS queries per hour threshold (lowered for demo)"),
            "domain_diversity_nxdomain_threshold": (3, "NXDOMAIN count threshold (lowered for demo)"),
            "geo_asn_spread_threshold": (3, "Unique network regions threshold (lowered for demo)"),
            "behavior_deviation_z_threshold": (2.5, "Z-score threshold"),
            "suricata_alert_low_delta": (5.0, "Score delta per low Suricata alert"),
            "suricata_alert_medium_delta": (15.0, "Score delta per medium Suricata alert"),
            "suricata_alert_high_delta": (30.0, "Score delta per high Suricata alert"),
            "suricata_alert_critical_delta": (50.0, "Score delta per critical Suricata alert"),
            "iot_weight_multiplier": (1.5, "Score multiplier for IoT/TV devices"),
            "alert_score_change_threshold": (5.0, "Minimum score change to generate alert"),
            "suppressed_ips": ([], "Suppressed IPs"),
        }
        for key, (value, description) in defaults.items():
            if not db.query(AppConfig).filter(AppConfig.key == key).first():
                db.add(AppConfig(key=key, value=value, description=description))
        db.commit()

        # 1. Parse nmap XML
        print("Parsing nmap sample XML...")
        nmap_path = os.path.join(SAMPLE_DIR, "nmap_sample.xml")
        with open(nmap_path) as f:
            xml_data = f.read()
        devices = parse_nmap_xml(xml_data, db)
        db.commit()
        print(f"  → {len(devices)} devices inserted/updated")

        # 2. Parse router syslog (creates devices from DHCP too)
        print("Parsing router syslog...")
        syslog_path = os.path.join(SAMPLE_DIR, "syslog_dhcp.log")
        ingest_router_logs(db, syslog_path)
        db.commit()
        print("  → Router log ingested")

        # 3. Parse Zeek logs
        print("Parsing Zeek conn.log...")
        conn_path = os.path.join(SAMPLE_DIR, "conn.log")
        _ingest_conn_log(db, conn_path, 0)
        db.commit()

        print("Parsing Zeek dns.log...")
        dns_path = os.path.join(SAMPLE_DIR, "dns.log")
        _ingest_dns_log(db, dns_path, 0)
        db.commit()

        print("Parsing Zeek http.log...")
        http_path = os.path.join(SAMPLE_DIR, "http.log")
        _ingest_http_log(db, http_path, 0)
        db.commit()
        print("  → Zeek logs ingested")

        # 4. Parse Suricata eve.json
        print("Parsing Suricata eve.json...")
        eve_path = os.path.join(SAMPLE_DIR, "eve.json")
        ingest_suricata_logs(db, eve_path)
        db.commit()
        print("  → Suricata events ingested")

        # 5. Compute baselines (limited data, but shows the flow)
        print("Computing baselines...")
        compute_baselines(db, window_hours=1)
        print("  → Baselines computed")

        # 6. Run scoring engine
        print("Running scoring engine...")
        run_scoring_engine(db)
        print("  → Scoring complete")

        # Print summary
        from app.models.device import Device
        from app.models.alert import Alert
        from app.models.event import NetworkEvent

        devices = db.query(Device).order_by(Device.suspicion_score.desc()).all()
        print("\n=== Device Summary ===")
        for d in devices:
            print(f"  {d.ip:18} {d.hostname or '':20} score={d.suspicion_score:5.1f}  category={d.category.value}")

        alerts = db.query(Alert).all()
        print(f"\n=== Alerts: {len(alerts)} ===")
        for a in alerts:
            print(f"  [{a.severity.value:8}] {a.title[:60]}")

        event_count = db.query(NetworkEvent).count()
        print(f"\nTotal network events: {event_count}")

    finally:
        db.close()


if __name__ == "__main__":
    seed()
