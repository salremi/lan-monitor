"""Compute and store device behavior baselines."""
import math
import logging
from datetime import datetime, timedelta
from sqlalchemy.orm import Session

from app.models.device import Device
from app.models.event import NetworkEvent
from app.models.baseline import Baseline
from app.config import settings

logger = logging.getLogger(__name__)


def _compute_stats(values: list[float]) -> tuple[float, float]:
    """Return (mean, stddev) for a list of floats."""
    if not values:
        return 0.0, 1.0
    n = len(values)
    mean = sum(values) / n
    if n < 2:
        return mean, 1.0
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    stddev = math.sqrt(variance) if variance > 0 else 1.0
    return mean, stddev


def compute_baselines(db: Session, window_hours: int | None = None) -> None:
    """Compute rolling baselines for all non-suppressed devices."""
    window = window_hours or settings.baseline_window_hours
    cutoff = datetime.utcnow() - timedelta(hours=window)
    now = datetime.utcnow()

    devices = db.query(Device).filter(Device.suppressed == False).all()  # noqa: E712
    for device in devices:
        _compute_device_baseline(db, device, cutoff, window, now)

    db.commit()
    logger.info("Computed baselines for %d devices", len(devices))


def _compute_device_baseline(
    db: Session,
    device: Device,
    cutoff: datetime,
    window_hours: int,
    now: datetime,
) -> None:
    events = (
        db.query(NetworkEvent)
        .filter(
            NetworkEvent.device_id == device.id,
            NetworkEvent.ts >= cutoff,
        )
        .all()
    )

    if not events:
        return

    # Bucket events by hour
    hour_buckets: dict[int, dict[str, set | int]] = {}
    for e in events:
        hour_key = int((e.ts - cutoff).total_seconds() // 3600)
        if hour_key not in hour_buckets:
            hour_buckets[hour_key] = {
                "conn_count": 0,
                "dest_ips": set(),
                "dns_count": 0,
            }
        b = hour_buckets[hour_key]
        if e.event_type == "conn":
            b["conn_count"] = b["conn_count"] + 1  # type: ignore
            if e.dest_ip:
                b["dest_ips"].add(e.dest_ip)  # type: ignore
        elif e.event_type == "dns":
            b["dns_count"] = b["dns_count"] + 1  # type: ignore

    hourly_conn = [float(b["conn_count"]) for b in hour_buckets.values()]  # type: ignore
    hourly_dest = [float(len(b["dest_ips"])) for b in hour_buckets.values()]  # type: ignore
    hourly_dns = [float(b["dns_count"]) for b in hour_buckets.values()]  # type: ignore

    metrics = [
        ("hourly_conn_count", hourly_conn),
        ("unique_dest_ips", hourly_dest),
        ("dns_query_count", hourly_dns),
    ]

    for metric_name, values in metrics:
        if not values:
            continue
        mean, stddev = _compute_stats(values)
        existing = (
            db.query(Baseline)
            .filter(Baseline.device_id == device.id, Baseline.metric == metric_name)
            .first()
        )
        if existing:
            existing.mean = mean
            existing.stddev = stddev
            existing.window_hours = window_hours
            existing.computed_at = now
        else:
            db.add(Baseline(
                device_id=device.id,
                metric=metric_name,
                mean=mean,
                stddev=stddev,
                window_hours=window_hours,
                computed_at=now,
            ))
