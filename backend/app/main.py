from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.database import init_db, get_db
from app.api import devices, alerts, evidence, config, ingest
from app.jobs.scheduler import start_scheduler, stop_scheduler
from app.llm.api import router as llm_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    _insert_default_config()
    start_scheduler()
    yield
    stop_scheduler()


def _insert_default_config():
    from app.database import SessionLocal
    from app.models.app_config import AppConfig
    from app.config import settings

    defaults = {
        "outbound_fanout_threshold": (settings.outbound_fanout_threshold, "Unique dest IPs per hour to trigger fanout rule"),
        "sustained_upload_threshold_mb": (settings.sustained_upload_threshold_mb, "MB uploaded per hour threshold"),
        "long_lived_session_threshold_sec": (settings.long_lived_session_threshold_sec, "Session duration seconds to flag"),
        "long_lived_session_count_threshold": (settings.long_lived_session_count_threshold, "Number of long sessions to trigger rule"),
        "dns_churn_threshold": (settings.dns_churn_threshold, "Unique DNS queries per hour threshold"),
        "domain_diversity_nxdomain_threshold": (settings.domain_diversity_nxdomain_threshold, "NXDOMAIN count threshold"),
        "geo_asn_spread_threshold": (settings.geo_asn_spread_threshold, "Unique dest countries/ASNs threshold"),
        "behavior_deviation_z_threshold": (settings.behavior_deviation_z_threshold, "Z-score threshold for behavior deviation"),
        "suricata_alert_low_delta": (settings.suricata_alert_low_delta, "Score delta per low Suricata alert"),
        "suricata_alert_medium_delta": (settings.suricata_alert_medium_delta, "Score delta per medium Suricata alert"),
        "suricata_alert_high_delta": (settings.suricata_alert_high_delta, "Score delta per high Suricata alert"),
        "suricata_alert_critical_delta": (settings.suricata_alert_critical_delta, "Score delta per critical Suricata alert"),
        "iot_weight_multiplier": (settings.iot_weight_multiplier, "Score multiplier for IoT/TV devices"),
        "alert_score_change_threshold": (settings.alert_score_change_threshold, "Minimum score change to generate alert"),
        "suppressed_ips": ([], "List of IPs to suppress from scoring"),
    }

    db = SessionLocal()
    try:
        for key, (value, description) in defaults.items():
            existing = db.query(AppConfig).filter(AppConfig.key == key).first()
            if not existing:
                db.add(AppConfig(key=key, value=value, description=description))
        db.commit()
    finally:
        db.close()


app = FastAPI(title="LAN Monitor", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(evidence.router, prefix="/api")
app.include_router(config.router, prefix="/api")
app.include_router(ingest.router, prefix="/api")
app.include_router(llm_router)

@app.get("/api/stats")
def get_stats(db: Session = Depends(get_db)):
    from app.models.device import Device
    from app.models.alert import Alert, AlertSeverity

    device_count = db.query(Device).count()
    alert_counts = {}
    for sev in AlertSeverity:
        alert_counts[sev.value] = (
            db.query(Alert)
            .filter(Alert.severity == sev, Alert.acknowledged == False)  # noqa: E712
            .count()
        )
    top_device = (
        db.query(Device)
        .filter(Device.suppressed == False)  # noqa: E712
        .order_by(Device.suspicion_score.desc())
        .first()
    )
    return {
        "device_count": device_count,
        "alert_counts": alert_counts,
        "top_suspicious_device": {
            "id": top_device.id,
            "ip": top_device.ip,
            "hostname": top_device.hostname,
            "score": top_device.suspicion_score,
        } if top_device else None,
    }
