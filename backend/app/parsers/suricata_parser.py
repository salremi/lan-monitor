"""Parse Suricata eve.json NDJSON log file."""
import json
import logging
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from app.models.device import Device
from app.models.event import NetworkEvent

logger = logging.getLogger(__name__)

_offsets: dict[str, int] = {}


def _get_device_id(db: Session, ip: str) -> int | None:
    device = db.query(Device).filter(Device.ip == ip).first()
    return device.id if device else None


def _parse_ts(ts_str: str) -> datetime:
    try:
        ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return datetime.utcnow()


def ingest_suricata_logs(db: Session, log_path: str) -> None:
    global _offsets
    p = Path(log_path)
    if not p.exists():
        logger.warning("Suricata eve.json not found: %s", log_path)
        return

    offset = _offsets.get(log_path, 0)
    count = 0

    with open(log_path, "r") as f:
        lines = f.readlines()

    new_lines = lines[offset:]
    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Skipping malformed Suricata line: %s", line[:80])
            continue

        ev_type = event.get("event_type", "")
        if ev_type not in ("alert", "flow"):
            continue

        src_ip = event.get("src_ip") or event.get("flow", {}).get("src_ip")
        if not src_ip:
            continue

        dest_ip = event.get("dest_ip") or event.get("flow", {}).get("dest_ip")
        ts = _parse_ts(event.get("timestamp", ""))
        device_id = _get_device_id(db, src_ip)

        mapped_type = "suricata_alert" if ev_type == "alert" else "conn"

        raw: dict = {}
        if ev_type == "alert":
            alert_data = event.get("alert", {})
            raw = {
                "signature": alert_data.get("signature", ""),
                "category": alert_data.get("category", ""),
                "severity": alert_data.get("severity", 3),
                "signature_id": alert_data.get("signature_id", 0),
                "proto": event.get("proto", ""),
            }
        elif ev_type == "flow":
            flow = event.get("flow", {})
            raw = {
                "proto": event.get("proto", ""),
                "bytes_toserver": flow.get("bytes_toserver", 0),
                "bytes_toclient": flow.get("bytes_toclient", 0),
                "pkts_toserver": flow.get("pkts_toserver", 0),
                "pkts_toclient": flow.get("pkts_toclient", 0),
            }

        db.add(NetworkEvent(
            device_id=device_id,
            source_ip=src_ip,
            dest_ip=dest_ip,
            event_type=mapped_type,
            source="suricata",
            ts=ts,
            raw=raw,
        ))
        count += 1

    _offsets[log_path] = offset + len(new_lines)
    logger.info("Ingested %d Suricata events from %s", count, log_path)
