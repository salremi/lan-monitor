"""APScheduler background jobs for scanning, ingestion, and scoring."""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.cron import CronTrigger

from app.config import settings
from app.jobs.enhanced_monitoring import run_enhanced_monitoring

logger = logging.getLogger(__name__)
_scheduler: BackgroundScheduler | None = None


def _job_nmap_scan():
    from app.database import SessionLocal
    from app.parsers.nmap_parser import run_nmap_scan
    db = SessionLocal()
    try:
        logger.info("Scheduled nmap scan starting")
        run_nmap_scan(db, settings.scan_cidr, settings.nmap_args)
        db.commit()
        logger.info("Scheduled nmap scan complete")
    except Exception:
        logger.exception("Scheduled nmap scan failed")
        db.rollback()
    finally:
        db.close()


def _job_ingest_zeek():
    from app.database import SessionLocal
    from app.parsers.zeek_parser import ingest_zeek_logs
    db = SessionLocal()
    try:
        ingest_zeek_logs(db, settings.zeek_log_dir)
        db.commit()
    except Exception:
        logger.exception("Zeek ingest failed")
        db.rollback()
    finally:
        db.close()


def _job_ingest_suricata():
    from app.database import SessionLocal
    from app.parsers.suricata_parser import ingest_suricata_logs
    db = SessionLocal()
    try:
        ingest_suricata_logs(db, settings.suricata_log_path)
        db.commit()
    except Exception:
        logger.exception("Suricata ingest failed")
        db.rollback()
    finally:
        db.close()


def _job_ingest_router():
    from app.database import SessionLocal
    from app.parsers.router_parser import ingest_router_logs
    db = SessionLocal()
    try:
        ingest_router_logs(db, settings.router_syslog_path)
        db.commit()
    except Exception:
        logger.exception("Router ingest failed")
        db.rollback()
    finally:
        db.close()


def _job_run_scoring():
    from app.database import SessionLocal
    from app.scoring.engine import run_scoring_engine
    db = SessionLocal()
    try:
        run_scoring_engine(db)
    except Exception:
        logger.exception("Scoring engine failed")
    finally:
        db.close()


def _job_compute_baselines():
    from app.database import SessionLocal
    from app.scoring.baseline import compute_baselines
    db = SessionLocal()
    try:
        compute_baselines(db)
    except Exception:
        logger.exception("Baseline computation failed")
    finally:
        db.close()


def _job_enhanced_monitoring():
    """Job for running enhanced network monitoring."""
    try:
        run_enhanced_monitoring()
    except Exception:
        logger.exception("Enhanced monitoring job failed")


def start_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        return

    _scheduler = BackgroundScheduler(timezone="UTC")

    _scheduler.add_job(
        _job_nmap_scan,
        trigger=IntervalTrigger(minutes=settings.scan_interval_minutes),
        id="nmap_scan",
        replace_existing=True,
        misfire_grace_time=60,
    )

    _scheduler.add_job(
        _job_ingest_zeek,
        trigger=IntervalTrigger(minutes=5),
        id="ingest_zeek",
        replace_existing=True,
        misfire_grace_time=30,
    )

    _scheduler.add_job(
        _job_ingest_suricata,
        trigger=IntervalTrigger(minutes=5),
        id="ingest_suricata",
        replace_existing=True,
        misfire_grace_time=30,
    )

    _scheduler.add_job(
        _job_ingest_router,
        trigger=IntervalTrigger(minutes=5),
        id="ingest_router",
        replace_existing=True,
        misfire_grace_time=30,
    )

    _scheduler.add_job(
        _job_run_scoring,
        trigger=IntervalTrigger(minutes=10),
        id="run_scoring",
        replace_existing=True,
        misfire_grace_time=60,
    )

    _scheduler.add_job(
        _job_compute_baselines,
        trigger=CronTrigger(hour=2, minute=0),  # daily at 02:00 UTC
        id="compute_baselines",
        replace_existing=True,
        misfire_grace_time=300,
    )

    _scheduler.add_job(
        _job_enhanced_monitoring,
        trigger=IntervalTrigger(minutes=1),
        id="enhanced_monitoring",
        replace_existing=True,
        misfire_grace_time=30,
    )

    _scheduler.start()
    logger.info("Scheduler started with %d jobs", len(_scheduler.get_jobs()))


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler and _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")
