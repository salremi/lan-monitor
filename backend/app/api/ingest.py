import logging
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks, HTTPException
from typing import Literal

from app.config import settings

logger = logging.getLogger(__name__)
router = APIRouter(tags=["ingest"])

# In-memory scan status — persists for the lifetime of the process
_scan_status: dict = {
    "running": False,
    "last_started": None,
    "last_finished": None,
    "last_device_count": None,
    "last_error": None,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_nmap_scan():
    global _scan_status
    from app.database import SessionLocal
    from app.parsers.nmap_parser import run_nmap_scan

    _scan_status["running"] = True
    _scan_status["last_started"] = _now_iso()
    _scan_status["last_error"] = None

    db = SessionLocal()
    try:
        devices = run_nmap_scan(db, settings.scan_cidr, settings.nmap_args)
        db.commit()
        _scan_status["last_device_count"] = len(devices)
    except Exception:
        logger.exception("Nmap scan failed")
        _scan_status["last_error"] = "Scan failed — check backend logs"
        db.rollback()
    finally:
        db.close()
        _scan_status["running"] = False
        _scan_status["last_finished"] = _now_iso()


def _run_ingest(source: str):
    from app.database import SessionLocal
    from app.parsers.zeek_parser import ingest_zeek_logs
    from app.parsers.suricata_parser import ingest_suricata_logs
    from app.parsers.router_parser import ingest_router_logs
    from app.scoring.engine import run_scoring_engine

    db = SessionLocal()
    try:
        if source == "zeek":
            ingest_zeek_logs(db, settings.zeek_log_dir)
        elif source == "suricata":
            ingest_suricata_logs(db, settings.suricata_log_path)
        elif source == "router":
            ingest_router_logs(db, settings.router_syslog_path)
        db.commit()
        run_scoring_engine(db)
    except Exception:
        logger.exception("Ingest failed for source=%s", source)
        db.rollback()
    finally:
        db.close()


@router.post("/scan/nmap")
def trigger_nmap_scan(background_tasks: BackgroundTasks):
    if _scan_status["running"]:
        raise HTTPException(status_code=409, detail="A scan is already running")
    background_tasks.add_task(_run_nmap_scan)
    return {"status": "queued", "message": "Nmap scan started in background"}


@router.get("/scan/status")
def get_scan_status():
    """Return the status of the last (or current) nmap scan."""
    return {
        "running": _scan_status["running"],
        "last_started": _scan_status["last_started"],
        "last_finished": _scan_status["last_finished"],
        "last_device_count": _scan_status["last_device_count"],
        "last_error": _scan_status["last_error"],
    }


@router.post("/ingest/{source}")
def trigger_ingest(
    source: Literal["zeek", "suricata", "router"],
    background_tasks: BackgroundTasks,
):
    background_tasks.add_task(_run_ingest, source)
    return {"status": "queued", "source": source}
