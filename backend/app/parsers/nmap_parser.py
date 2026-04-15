"""Parse Nmap XML output and upsert Device + DevicePort rows."""
import logging
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.device import Device, DevicePort, DeviceCategory

logger = logging.getLogger(__name__)

# Minimal OUI prefix → vendor table (first 3 bytes of MAC, upper-cased, no colons)
OUI_TABLE = {
    "000C29": "VMware",
    "001A11": "Google",
    "B827EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Ltd",
    "001E06": "Neterion",
    "ACDE48": "Apple",
    "3C5AB4": "Google",
    "001B21": "Intel",
    "E4E749": "Samsung",
    "F0D2F1": "Samsung",
}

CATEGORY_HINTS = {
    "raspberry": DeviceCategory.IoT,
    "arduino": DeviceCategory.IoT,
    "espressif": DeviceCategory.IoT,
    "google": DeviceCategory.TV,
    "apple": DeviceCategory.phone,
    "samsung": DeviceCategory.phone,
    "synology": DeviceCategory.NAS,
    "qnap": DeviceCategory.NAS,
    "cisco": DeviceCategory.router,
    "ubiquiti": DeviceCategory.router,
    "mikrotik": DeviceCategory.router,
    "openwrt": DeviceCategory.router,
}


def _oui_lookup(mac: str) -> str | None:
    if not mac:
        return None
    key = mac.replace(":", "").replace("-", "").upper()[:6]
    return OUI_TABLE.get(key)


def _guess_category(vendor: str | None, hostname: str | None) -> DeviceCategory:
    text = ((vendor or "") + " " + (hostname or "")).lower()
    for hint, cat in CATEGORY_HINTS.items():
        if hint in text:
            return cat
    return DeviceCategory.unknown


def parse_nmap_xml(xml_data: str, db: Session) -> list[Device]:
    """Parse Nmap XML string, upsert devices, return list of Device objects."""
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        logger.error("Failed to parse Nmap XML: %s", e)
        return []

    devices = []
    now = datetime.utcnow()

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        mac = None
        for addr in host.findall("address"):
            atype = addr.get("addrtype")
            if atype == "ipv4":
                ip = addr.get("addr")
            elif atype == "mac":
                mac = addr.get("addr")

        if not ip:
            continue

        hostname_el = host.find(".//hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        vendor = _oui_lookup(mac) if mac else None
        category = _guess_category(vendor, hostname)

        # Upsert by MAC or IP
        device = None
        if mac:
            device = db.query(Device).filter(Device.mac == mac).first()
        if device is None:
            device = db.query(Device).filter(Device.ip == ip).first()

        if device is None:
            device = Device(
                ip=ip,
                mac=mac,
                hostname=hostname,
                vendor=vendor,
                category=category,
                tags=[],
                first_seen=now,
                last_seen=now,
                suppressed=False,
                suspicion_score=0.0,
                score_reasons=[],
            )
            db.add(device)
            db.flush()
        else:
            device.ip = ip
            device.last_seen = now
            if mac and not device.mac:
                device.mac = mac
            if hostname and not device.hostname:
                device.hostname = hostname
            if vendor and not device.vendor:
                device.vendor = vendor

        # Parse ports
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                portnum = int(port_el.get("portid", 0))
                proto = port_el.get("protocol", "tcp")
                service_el = port_el.find("service")
                service = service_el.get("name") if service_el is not None else None
                banner = service_el.get("product") if service_el is not None else None

                # Upsert port
                existing_port = (
                    db.query(DevicePort)
                    .filter(
                        DevicePort.device_id == device.id,
                        DevicePort.port == portnum,
                        DevicePort.protocol == proto,
                    )
                    .first()
                )
                if existing_port is None:
                    db.add(
                        DevicePort(
                            device_id=device.id,
                            port=portnum,
                            protocol=proto,
                            service=service,
                            banner=banner,
                            discovered_at=now,
                        )
                    )

        devices.append(device)

    logger.info("Nmap parse: %d devices processed", len(devices))
    return devices


def run_nmap_scan(db: Session, cidr: str, nmap_args: str) -> list[Device]:
    """Run nmap subprocess, parse XML output, upsert devices."""
    cmd = ["nmap"] + nmap_args.split() + ["-oX", "-", cidr]
    logger.info("Running nmap: %s", " ".join(cmd))
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            logger.error("nmap error: %s", result.stderr)
            return []
        return parse_nmap_xml(result.stdout, db)
    except FileNotFoundError:
        logger.error("nmap not found. Install nmap to use scan feature.")
        return []
    except subprocess.TimeoutExpired:
        logger.error("nmap timed out after 300 seconds")
        return []
