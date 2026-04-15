"""Parse router syslog files: DHCP leases, DNS queries, firewall events."""
import logging
import re
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session

from app.models.device import Device, DeviceCategory
from app.models.event import NetworkEvent

logger = logging.getLogger(__name__)

_offsets: dict[str, int] = {}

# Regex patterns for common router syslog formats
DHCP_PATTERNS = [
    # OpenWRT / dnsmasq: DHCPACK(br-lan) 192.168.1.10 aa:bb:cc:dd:ee:ff hostname
    re.compile(
        r"DHCP(?:ACK|OFFER|REQUEST|DISCOVER)(?:\(\S+\))?\s+([\d.]+)\s+([\da-fA-F:]+)(?:\s+(\S+))?"
    ),
    # OpenWRT: dnsmasq-dhcp[1234]: 12345 aa:bb:cc:dd:ee:ff 192.168.1.10 hostname
    re.compile(
        r"dnsmasq-dhcp\[\d+\]:\s+\d+\s+([\da-fA-F:]+)\s+([\d.]+)(?:\s+(\S+))?"
    ),
]

FIREWALL_PATTERNS = [
    # iptables/kernel: DROP/ACCEPT ... SRC=x DST=y (action may appear before SRC)
    re.compile(r"(DROP|ACCEPT|REJECT)\s+.*?SRC=([\d.]+)\s+DST=([\d.]+)", re.IGNORECASE),
    # iptables: SRC=x DST=y (action after)
    re.compile(r"SRC=([\d.]+)\s+DST=([\d.]+)", re.IGNORECASE),
    # pfSense: filterlog: ... src:x, dst:y
    re.compile(r"src:([\d.]+),\s*dst:([\d.]+)", re.IGNORECASE),
]

DNS_QUERY_PATTERN = re.compile(
    r"dnsmasq\[\d+\]:\s+query\[(\w+)\]\s+(\S+)\s+from\s+([\d.]+)"
)

TIMESTAMP_PATTERNS = [
    # ISO: 2024-01-01T12:00:00
    re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"),
    # Syslog: Jan  1 12:00:00
    re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
]


def _parse_timestamp(line: str) -> datetime:
    for pattern in TIMESTAMP_PATTERNS:
        m = pattern.search(line)
        if m:
            ts_str = m.group(1)
            try:
                return datetime.fromisoformat(ts_str)
            except ValueError:
                try:
                    # Syslog format – assume current year
                    return datetime.strptime(f"2024 {ts_str}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    pass
    return datetime.utcnow()


def _upsert_device_from_dhcp(db: Session, ip: str, mac: str, hostname: str | None) -> int | None:
    device = db.query(Device).filter(Device.mac == mac).first()
    if device is None:
        device = db.query(Device).filter(Device.ip == ip).first()
    now = datetime.utcnow()
    if device is None:
        device = Device(
            ip=ip,
            mac=mac,
            hostname=hostname,
            first_seen=now,
            last_seen=now,
            category=DeviceCategory.unknown,
            tags=[],
            suppressed=False,
            suspicion_score=0.0,
            score_reasons=[],
        )
        db.add(device)
        db.flush()
    else:
        device.ip = ip
        device.last_seen = now
        if hostname and not device.hostname:
            device.hostname = hostname
    return device.id


def _get_device_id(db: Session, ip: str) -> int | None:
    device = db.query(Device).filter(Device.ip == ip).first()
    return device.id if device else None


def _process_line(db: Session, line: str) -> bool:
    """Process a single syslog line. Returns True if an event was created."""
    ts = _parse_timestamp(line)

    # Check DHCP
    for pattern in DHCP_PATTERNS:
        m = pattern.search(line)
        if m:
            groups = m.groups()
            # Determine if first group is IP or MAC
            if re.match(r"[\d.]+", groups[0]):
                ip, mac = groups[0], groups[1]
            else:
                mac, ip = groups[0], groups[1]
            hostname = groups[2] if len(groups) > 2 else None
            if hostname in ("-", "*", None):
                hostname = None
            device_id = _upsert_device_from_dhcp(db, ip, mac, hostname)
            db.add(NetworkEvent(
                device_id=device_id,
                source_ip=ip,
                dest_ip=None,
                event_type="dhcp",
                source="router",
                ts=ts,
                raw={"ip": ip, "mac": mac, "hostname": hostname, "raw_line": line[:200]},
            ))
            return True

    # Check DNS query
    m = DNS_QUERY_PATTERN.search(line)
    if m:
        qtype, query, src_ip = m.group(1), m.group(2), m.group(3)
        device_id = _get_device_id(db, src_ip)
        db.add(NetworkEvent(
            device_id=device_id,
            source_ip=src_ip,
            dest_ip=None,
            event_type="dns",
            source="router",
            ts=ts,
            raw={"query": query, "qtype": qtype},
        ))
        return True

    # Check firewall
    for pattern in FIREWALL_PATTERNS:
        m = pattern.search(line)
        if m:
            groups = m.groups()
            if len(groups) == 2:
                src_ip, dst_ip = groups
                action = "DROP" if "drop" in line.lower() or "block" in line.lower() else "ACCEPT"
            else:
                action, src_ip, dst_ip = groups
            device_id = _get_device_id(db, src_ip)
            db.add(NetworkEvent(
                device_id=device_id,
                source_ip=src_ip,
                dest_ip=dst_ip,
                event_type="firewall",
                source="router",
                ts=ts,
                raw={"action": action, "raw_line": line[:200]},
            ))
            return True

    return False


def ingest_router_logs(db: Session, log_path: str) -> None:
    global _offsets
    p = Path(log_path)
    if not p.exists():
        logger.warning("Router syslog not found: %s", log_path)
        return

    offset = _offsets.get(log_path, 0)
    count = 0

    with open(log_path, "r", errors="replace") as f:
        lines = f.readlines()

    new_lines = lines[offset:]
    for line in new_lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        try:
            if _process_line(db, line):
                count += 1
        except Exception:
            logger.debug("Skipping malformed syslog line: %s", line[:80])

    _offsets[log_path] = offset + len(new_lines)
    logger.info("Ingested %d router events from %s", count, log_path)
