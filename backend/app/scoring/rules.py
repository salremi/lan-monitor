"""Scoring rules for LAN Monitor. Each rule returns a RuleResult."""
import math
from collections import namedtuple
from datetime import datetime, timedelta

from app.models.device import Device, DeviceCategory
from app.models.event import NetworkEvent

RuleResult = namedtuple("RuleResult", ["score_delta", "explanation", "evidence_ids"])

_IOT_CATEGORIES = {DeviceCategory.IoT, DeviceCategory.TV}
_PROXY_PORTS = {3128, 8080, 1080, 8888}


def _iot_weight(device: Device, config: dict) -> float:
    if device.category in _IOT_CATEGORIES:
        return float(config.get("iot_weight_multiplier", 1.5))
    return 1.0


def _conn_events_last_hour(events: list[NetworkEvent]) -> list[NetworkEvent]:
    cutoff = datetime.utcnow() - timedelta(hours=1)
    return [e for e in events if e.event_type == "conn" and e.ts >= cutoff]


def rule_outbound_fanout(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Unique dest IPs in last hour > threshold."""
    threshold = int(config.get("outbound_fanout_threshold", 50))
    conn_events = _conn_events_last_hour(events)
    unique_dests = {e.dest_ip for e in conn_events if e.dest_ip}
    count = len(unique_dests)
    if count <= threshold:
        return RuleResult(0.0, "", [])
    weight = _iot_weight(device, config)
    delta = min(20.0, (count - threshold) / threshold * 15.0) * weight
    evidence_ids = [e.id for e in conn_events if e.dest_ip in unique_dests][:20]
    return RuleResult(
        round(delta, 2),
        f"Outbound fanout: {count} unique dest IPs in last hour (threshold: {threshold})",
        evidence_ids,
    )


def rule_sustained_upload(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Total bytes_sent in last hour > threshold for IoT/TV."""
    threshold_mb = float(config.get("sustained_upload_threshold_mb", 500.0))
    threshold_bytes = threshold_mb * 1024 * 1024
    conn_events = _conn_events_last_hour(events)
    total_bytes = 0
    evidence_ids = []
    for e in conn_events:
        try:
            b = int(e.raw.get("bytes_orig", 0) or 0)
            total_bytes += b
            if b > 0:
                evidence_ids.append(e.id)
        except (ValueError, TypeError):
            pass
    if total_bytes <= threshold_bytes:
        return RuleResult(0.0, "", [])
    weight = _iot_weight(device, config)
    ratio = total_bytes / threshold_bytes
    delta = min(25.0, (ratio - 1.0) * 10.0) * weight
    return RuleResult(
        round(delta, 2),
        f"Sustained upload: {total_bytes / 1e6:.1f} MB in last hour (threshold: {threshold_mb} MB)",
        evidence_ids[:20],
    )


def rule_long_lived_sessions(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Connections with duration > threshold seconds, count > count_threshold."""
    duration_threshold = int(config.get("long_lived_session_threshold_sec", 3600))
    count_threshold = int(config.get("long_lived_session_count_threshold", 3))
    long_sessions = []
    for e in events:
        if e.event_type != "conn":
            continue
        try:
            dur = float(e.raw.get("duration", 0) or 0)
            if dur > duration_threshold:
                long_sessions.append(e)
        except (ValueError, TypeError):
            pass
    count = len(long_sessions)
    if count <= count_threshold:
        return RuleResult(0.0, "", [])
    delta = min(20.0, (count - count_threshold) * 4.0)
    return RuleResult(
        round(delta, 2),
        f"Long-lived sessions: {count} connections > {duration_threshold}s (threshold: {count_threshold})",
        [e.id for e in long_sessions[:20]],
    )


def rule_high_dns_churn(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Unique queried domains per hour > threshold."""
    threshold = int(config.get("dns_churn_threshold", 100))
    cutoff = datetime.utcnow() - timedelta(hours=1)
    dns_events = [e for e in events if e.event_type == "dns" and e.ts >= cutoff]
    unique_domains = {e.raw.get("query", "") for e in dns_events if e.raw.get("query")}
    count = len(unique_domains)
    if count <= threshold:
        return RuleResult(0.0, "", [])
    delta = min(15.0, (count - threshold) / threshold * 12.0)
    return RuleResult(
        round(delta, 2),
        f"High DNS churn: {count} unique domains queried in last hour (threshold: {threshold})",
        [e.id for e in dns_events[:20]],
    )


def rule_suspicious_domain_diversity(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Many NXDOMAINs or many different TLDs in short window."""
    nxdomain_threshold = int(config.get("domain_diversity_nxdomain_threshold", 20))
    cutoff = datetime.utcnow() - timedelta(hours=1)
    dns_events = [e for e in events if e.event_type == "dns" and e.ts >= cutoff]

    nxdomains = [e for e in dns_events if e.raw.get("rcode_name", "") == "NXDOMAIN"]
    nxcount = len(nxdomains)

    # Count unique TLDs
    tlds = set()
    for e in dns_events:
        query = e.raw.get("query", "")
        if query and "." in query:
            tlds.add(query.rsplit(".", 1)[-1].lower())

    score_delta = 0.0
    explanation_parts = []
    evidence_ids = []

    if nxcount > nxdomain_threshold:
        delta = min(20.0, (nxcount - nxdomain_threshold) / nxdomain_threshold * 15.0)
        score_delta += delta
        explanation_parts.append(f"{nxcount} NXDOMAINs in last hour (threshold: {nxdomain_threshold})")
        evidence_ids.extend(e.id for e in nxdomains[:20])

    if len(tlds) > 10:
        score_delta += min(10.0, (len(tlds) - 10) * 1.0)
        explanation_parts.append(f"{len(tlds)} unique TLDs queried")

    if not explanation_parts:
        return RuleResult(0.0, "", [])
    return RuleResult(
        round(score_delta, 2),
        "Suspicious domain diversity: " + "; ".join(explanation_parts),
        list(set(evidence_ids))[:20],
    )


def rule_geo_asn_spread(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Unique dest countries/ASNs in short window > threshold."""
    threshold = int(config.get("geo_asn_spread_threshold", 10))
    cutoff = datetime.utcnow() - timedelta(hours=1)
    conn_events = [e for e in events if e.event_type == "conn" and e.ts >= cutoff and e.dest_ip]

    # Extract stored geo info from raw if present, else count unique /24 subnets as a proxy
    geo_info = set()
    for e in conn_events:
        country = e.raw.get("country")
        asn = e.raw.get("asn")
        if country:
            geo_info.add(f"country:{country}")
        elif asn:
            geo_info.add(f"asn:{asn}")
        elif e.dest_ip:
            # Use /16 subnet as a rough geographic proxy
            parts = e.dest_ip.split(".")
            if len(parts) >= 2:
                geo_info.add(f"prefix:{parts[0]}.{parts[1]}")

    count = len(geo_info)
    if count <= threshold:
        return RuleResult(0.0, "", [])
    delta = min(15.0, (count - threshold) / threshold * 10.0)
    evidence_ids = [e.id for e in conn_events[:20]]
    return RuleResult(
        round(delta, 2),
        f"Geo/ASN spread: {count} unique network regions in last hour (threshold: {threshold})",
        evidence_ids,
    )


def rule_behavior_deviation(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Z-score of current metric vs stored baseline > threshold."""
    from app.models.baseline import Baseline
    z_threshold = float(config.get("behavior_deviation_z_threshold", 2.5))

    # Get baselines from device's baselines relationship
    baselines = getattr(device, "baselines", [])
    if not baselines:
        return RuleResult(0.0, "", [])

    cutoff = datetime.utcnow() - timedelta(hours=1)
    conn_events = [e for e in events if e.event_type == "conn" and e.ts >= cutoff]
    dns_events = [e for e in events if e.event_type == "dns" and e.ts >= cutoff]

    current_metrics = {
        "hourly_conn_count": float(len(conn_events)),
        "unique_dest_ips": float(len({e.dest_ip for e in conn_events if e.dest_ip})),
        "dns_query_count": float(len(dns_events)),
    }

    max_z = 0.0
    worst_metric = ""
    evidence_ids = []

    for bl in baselines:
        metric = bl.metric
        if metric not in current_metrics:
            continue
        if bl.stddev <= 0:
            continue
        current = current_metrics[metric]
        z = (current - bl.mean) / bl.stddev
        if z > max_z:
            max_z = z
            worst_metric = metric

    if max_z <= z_threshold:
        return RuleResult(0.0, "", [])

    delta = min(20.0, (max_z - z_threshold) * 4.0)
    return RuleResult(
        round(delta, 2),
        f"Behavior deviation: z-score={max_z:.2f} on {worst_metric} (threshold: {z_threshold})",
        evidence_ids[:20],
    )


def rule_exposed_proxy_service(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Open ports 3128, 8080, 1080, 8888 with non-standard banners."""
    ports = getattr(device, "ports", [])
    suspicious_ports = []
    for port in ports:
        if port.port in _PROXY_PORTS:
            banner = (port.banner or "").lower()
            service = (port.service or "").lower()
            # Flag if service looks like a proxy or banner is blank/unusual
            is_suspicious = (
                "proxy" in service or "proxy" in banner or
                "squid" in banner or "socks" in service or
                port.port == 1080 or
                (port.port == 3128 and "squid" not in banner) or
                (port.port == 8888 and "http" in service and "standard" not in banner)
            )
            if is_suspicious:
                suspicious_ports.append(port)

    if not suspicious_ports:
        return RuleResult(0.0, "", [])

    delta = min(30.0, len(suspicious_ports) * 10.0)
    port_list = ", ".join(str(p.port) for p in suspicious_ports)
    return RuleResult(
        round(delta, 2),
        f"Exposed proxy service on port(s): {port_list}",
        [],
    )


def rule_suricata_alert_score(device: Device, events: list[NetworkEvent], config: dict) -> RuleResult:
    """Each Suricata alert severity maps to score delta."""
    severity_map = {
        1: float(config.get("suricata_alert_high_delta", 30.0)),
        2: float(config.get("suricata_alert_medium_delta", 15.0)),
        3: float(config.get("suricata_alert_low_delta", 5.0)),
    }

    cutoff = datetime.utcnow() - timedelta(hours=24)
    alert_events = [
        e for e in events
        if e.event_type == "suricata_alert" and e.ts >= cutoff
    ]

    total_delta = 0.0
    evidence_ids = []
    for e in alert_events:
        sev = int(e.raw.get("severity", 3))
        total_delta += severity_map.get(sev, 5.0)
        evidence_ids.append(e.id)

    if total_delta <= 0:
        return RuleResult(0.0, "", [])

    # Cap contribution
    capped = min(40.0, total_delta)
    return RuleResult(
        round(capped, 2),
        f"Suricata alerts: {len(alert_events)} alert(s) in last 24h (raw delta: {total_delta:.1f})",
        evidence_ids[:20],
    )


ALL_RULES = [
    rule_outbound_fanout,
    rule_sustained_upload,
    rule_long_lived_sessions,
    rule_high_dns_churn,
    rule_suspicious_domain_diversity,
    rule_geo_asn_spread,
    rule_behavior_deviation,
    rule_exposed_proxy_service,
    rule_suricata_alert_score,
]
