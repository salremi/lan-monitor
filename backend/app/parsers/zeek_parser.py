"""Parse Zeek TSV log files: conn.log, dns.log, http.log."""
import logging
import os
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from app.models.device import Device
from app.models.event import NetworkEvent

logger = logging.getLogger(__name__)

# Track file read offsets between runs
_offsets: dict[str, int] = {}


def _get_device_id(db: Session, ip: str) -> int | None:
    device = db.query(Device).filter(Device.ip == ip).first()
    return device.id if device else None


def _parse_zeek_tsv(filepath: str) -> tuple[list[str], list[dict]]:
    """Parse a Zeek TSV log file. Returns (field_names, list_of_row_dicts)."""
    fields = []
    rows = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif fields:
                    parts = line.split("\t")
                    if len(parts) == len(fields):
                        row = dict(zip(fields, parts))
                        rows.append(row)
    except FileNotFoundError:
        logger.warning("Zeek log not found: %s", filepath)
    except Exception:
        logger.exception("Error parsing Zeek log: %s", filepath)
    return fields, rows


def _parse_ts(ts_str: str) -> datetime:
    try:
        return datetime.utcfromtimestamp(float(ts_str))
    except (ValueError, OSError):
        return datetime.utcnow()


def _ingest_conn_log(db: Session, filepath: str, offset: int) -> int:
    _, rows = _parse_zeek_tsv(filepath)
    rows = rows[offset:]
    count = 0
    for row in rows:
        try:
            src_ip = row.get("id.orig_h", "-")
            dst_ip = row.get("id.resp_h", "-")
            if src_ip == "-":
                continue
            ts = _parse_ts(row.get("ts", "0"))
            device_id = _get_device_id(db, src_ip)
            raw = {
                "proto": row.get("proto", ""),
                "src_port": row.get("id.orig_p", ""),
                "dst_port": row.get("id.resp_p", ""),
                "duration": row.get("duration", ""),
                "bytes_orig": row.get("orig_bytes", "0"),
                "bytes_resp": row.get("resp_bytes", "0"),
                "conn_state": row.get("conn_state", ""),
            }
            db.add(NetworkEvent(
                device_id=device_id,
                source_ip=src_ip,
                dest_ip=dst_ip if dst_ip != "-" else None,
                event_type="conn",
                source="zeek",
                ts=ts,
                raw=raw,
            ))
            count += 1
        except Exception:
            logger.debug("Skipping malformed conn.log row: %s", row)
    logger.info("Ingested %d conn events from %s", count, filepath)
    return offset + len(rows)


def _ingest_dns_log(db: Session, filepath: str, offset: int) -> int:
    _, rows = _parse_zeek_tsv(filepath)
    rows = rows[offset:]
    count = 0
    for row in rows:
        try:
            src_ip = row.get("id.orig_h", "-")
            if src_ip == "-":
                continue
            ts = _parse_ts(row.get("ts", "0"))
            device_id = _get_device_id(db, src_ip)
            raw = {
                "query": row.get("query", ""),
                "qtype_name": row.get("qtype_name", ""),
                "rcode_name": row.get("rcode_name", ""),
                "answers": row.get("answers", ""),
            }
            db.add(NetworkEvent(
                device_id=device_id,
                source_ip=src_ip,
                dest_ip=row.get("id.resp_h") or None,
                event_type="dns",
                source="zeek",
                ts=ts,
                raw=raw,
            ))
            count += 1
        except Exception:
            logger.debug("Skipping malformed dns.log row: %s", row)
    logger.info("Ingested %d dns events from %s", count, filepath)
    return offset + len(rows)


def _ingest_http_log(db: Session, filepath: str, offset: int) -> int:
    _, rows = _parse_zeek_tsv(filepath)
    rows = rows[offset:]
    count = 0
    for row in rows:
        try:
            src_ip = row.get("id.orig_h", "-")
            if src_ip == "-":
                continue
            ts = _parse_ts(row.get("ts", "0"))
            device_id = _get_device_id(db, src_ip)
            raw = {
                "method": row.get("method", ""),
                "host": row.get("host", ""),
                "uri": row.get("uri", ""),
                "user_agent": row.get("user_agent", ""),
                "status_code": row.get("status_code", ""),
            }
            db.add(NetworkEvent(
                device_id=device_id,
                source_ip=src_ip,
                dest_ip=row.get("id.resp_h") or None,
                event_type="http",
                source="zeek",
                ts=ts,
                raw=raw,
            ))
            count += 1
        except Exception:
            logger.debug("Skipping malformed http.log row: %s", row)
    logger.info("Ingested %d http events from %s", count, filepath)
    return offset + len(rows)


def ingest_zeek_logs(db: Session, log_dir: str) -> None:
    """Ingest all Zeek log files from log_dir, tracking offsets."""
    global _offsets
    log_path = Path(log_dir)

    for log_name, ingest_fn in [
        ("conn.log", _ingest_conn_log),
        ("dns.log", _ingest_dns_log),
        ("http.log", _ingest_http_log),
    ]:
        filepath = str(log_path / log_name)
        offset = _offsets.get(filepath, 0)
        new_offset = ingest_fn(db, filepath, offset)
        _offsets[filepath] = new_offset
