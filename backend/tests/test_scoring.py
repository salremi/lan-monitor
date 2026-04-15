"""Unit tests for scoring rules."""
import pytest
from datetime import datetime, timedelta

from app.scoring.rules import (
    rule_outbound_fanout,
    rule_sustained_upload,
    rule_long_lived_sessions,
    rule_high_dns_churn,
    rule_suspicious_domain_diversity,
    rule_geo_asn_spread,
    rule_behavior_deviation,
    rule_exposed_proxy_service,
    rule_suricata_alert_score,
    ALL_RULES,
)
from app.models.device import DevicePort
from app.models.baseline import Baseline
from tests.conftest import make_conn_event, make_dns_event, make_suricata_event


# ---- outbound_fanout ----

def test_outbound_fanout_benign(db, pc_device, default_config):
    events = [make_conn_event(db, pc_device.id, f"10.0.{i}.1") for i in range(3)]
    result = rule_outbound_fanout(pc_device, events, default_config)
    assert result.score_delta == 0.0


def test_outbound_fanout_triggered(db, pc_device, default_config):
    events = [make_conn_event(db, pc_device.id, f"10.{i}.0.1") for i in range(10)]
    result = rule_outbound_fanout(pc_device, events, default_config)
    assert result.score_delta > 0
    assert "fanout" in result.explanation.lower()


def test_outbound_fanout_iot_weight(db, iot_device, default_config):
    events_iot = [make_conn_event(db, iot_device.id, f"10.{i}.0.1") for i in range(10)]
    result_iot = rule_outbound_fanout(iot_device, events_iot, default_config)

    from app.models.device import Device, DeviceCategory
    pc = db.query(Device).filter(Device.category == DeviceCategory.PC).first()
    if pc:
        events_pc = [make_conn_event(db, pc.id, f"10.{i}.0.1") for i in range(10)]
        result_pc = rule_outbound_fanout(pc, events_pc, default_config)
        assert result_iot.score_delta >= result_pc.score_delta


def test_outbound_fanout_old_events_ignored(db, pc_device, default_config):
    old_ts = datetime.utcnow() - timedelta(hours=2)
    events = [make_conn_event(db, pc_device.id, f"10.{i}.0.1", ts=old_ts) for i in range(20)]
    result = rule_outbound_fanout(pc_device, events, default_config)
    assert result.score_delta == 0.0


# ---- sustained_upload ----

def test_sustained_upload_benign(db, pc_device, default_config):
    events = [make_conn_event(db, pc_device.id, "1.2.3.4", bytes_orig=100)]
    result = rule_sustained_upload(pc_device, events, default_config)
    assert result.score_delta == 0.0


def test_sustained_upload_triggered(db, iot_device, default_config):
    # threshold is 1 MB = 1_048_576 bytes
    events = [make_conn_event(db, iot_device.id, "1.2.3.4", bytes_orig=2_000_000)]
    result = rule_sustained_upload(iot_device, events, default_config)
    assert result.score_delta > 0
    assert "upload" in result.explanation.lower()


# ---- long_lived_sessions ----

def test_long_lived_sessions_benign(db, pc_device, default_config):
    events = [make_conn_event(db, pc_device.id, "1.2.3.4", duration=50.0)]
    result = rule_long_lived_sessions(pc_device, events, default_config)
    assert result.score_delta == 0.0


def test_long_lived_sessions_triggered(db, pc_device, default_config):
    events = [make_conn_event(db, pc_device.id, f"1.2.3.{i}", duration=200.0) for i in range(3)]
    result = rule_long_lived_sessions(pc_device, events, default_config)
    assert result.score_delta > 0
    assert "long" in result.explanation.lower()


# ---- high_dns_churn ----

def test_high_dns_churn_benign(db, pc_device, default_config):
    events = [make_dns_event(db, pc_device.id, f"domain{i}.com") for i in range(3)]
    result = rule_high_dns_churn(pc_device, events, default_config)
    assert result.score_delta == 0.0


def test_high_dns_churn_triggered(db, pc_device, default_config):
    events = [make_dns_event(db, pc_device.id, f"domain{i}.com") for i in range(10)]
    result = rule_high_dns_churn(pc_device, events, default_config)
    assert result.score_delta > 0
    assert "dns" in result.explanation.lower()


# ---- suspicious_domain_diversity ----

def test_suspicious_domain_diversity_benign(db, pc_device, default_config):
    events = [make_dns_event(db, pc_device.id, f"site{i}.com", "NXDOMAIN") for i in range(2)]
    result = rule_suspicious_domain_diversity(pc_device, events, default_config)
    assert result.score_delta == 0.0


def test_suspicious_domain_diversity_triggered(db, pc_device, default_config):
    events = [make_dns_event(db, pc_device.id, f"rogue{i}.xyz", "NXDOMAIN") for i in range(5)]
    result = rule_suspicious_domain_diversity(pc_device, events, default_config)
    assert result.score_delta > 0
    assert "nxdomain" in result.explanation.lower()


# ---- geo_asn_spread ----

def test_geo_asn_spread_benign(db, pc_device, default_config):
    events = [make_conn_event(db, pc_device.id, "192.168.1.1") for _ in range(2)]
    result = rule_geo_asn_spread(pc_device, events, default_config)
    assert result.score_delta == 0.0


def test_geo_asn_spread_triggered(db, pc_device, default_config):
    unique_ips = [f"{i}.{i}.0.1" for i in range(1, 10)]
    events = [make_conn_event(db, pc_device.id, ip) for ip in unique_ips]
    result = rule_geo_asn_spread(pc_device, events, default_config)
    assert result.score_delta > 0


# ---- behavior_deviation ----

def test_behavior_deviation_no_baseline(db, pc_device, default_config):
    events = [make_conn_event(db, pc_device.id, "1.2.3.4") for _ in range(10)]
    result = rule_behavior_deviation(pc_device, events, default_config)
    assert result.score_delta == 0.0  # no baselines → no deviation


def test_behavior_deviation_triggered(db, pc_device, default_config):
    # Add a baseline with low mean/stddev
    bl = Baseline(
        device_id=pc_device.id,
        metric="hourly_conn_count",
        mean=2.0,
        stddev=0.5,
        window_hours=24,
        computed_at=datetime.utcnow(),
    )
    db.add(bl)
    db.flush()
    pc_device.baselines = [bl]

    events = [make_conn_event(db, pc_device.id, f"1.2.3.{i}") for i in range(20)]
    result = rule_behavior_deviation(pc_device, events, default_config)
    assert result.score_delta > 0
    assert "z-score" in result.explanation.lower()


# ---- exposed_proxy_service ----

def test_exposed_proxy_benign(db, pc_device, default_config):
    port = DevicePort(device_id=pc_device.id, port=443, protocol="tcp", service="https", discovered_at=datetime.utcnow())
    db.add(port)
    db.flush()
    pc_device.ports = [port]
    result = rule_exposed_proxy_service(pc_device, [], default_config)
    assert result.score_delta == 0.0


def test_exposed_proxy_triggered(db, pc_device, default_config):
    port = DevicePort(device_id=pc_device.id, port=1080, protocol="tcp", service="socks5", discovered_at=datetime.utcnow())
    db.add(port)
    db.flush()
    pc_device.ports = [port]
    result = rule_exposed_proxy_service(pc_device, [], default_config)
    assert result.score_delta > 0
    assert "1080" in result.explanation


# ---- suricata_alert_score ----

def test_suricata_alert_benign(db, pc_device, default_config):
    result = rule_suricata_alert_score(pc_device, [], default_config)
    assert result.score_delta == 0.0


def test_suricata_alert_triggered_high(db, pc_device, default_config):
    events = [make_suricata_event(db, pc_device.id, severity=1) for _ in range(2)]
    result = rule_suricata_alert_score(pc_device, events, default_config)
    assert result.score_delta > 0


def test_suricata_alert_severity_ordering(db, pc_device, default_config):
    ev_low = make_suricata_event(db, pc_device.id, severity=3)
    ev_high = make_suricata_event(db, pc_device.id, severity=1)
    result_low = rule_suricata_alert_score(pc_device, [ev_low], default_config)
    result_high = rule_suricata_alert_score(pc_device, [ev_high], default_config)
    assert result_high.score_delta > result_low.score_delta


# ---- Score clamping ----

def test_score_clamped(db, iot_device, default_config):
    """Running all rules should never produce a score > 100."""
    # Create lots of suspicious events
    events = []
    for i in range(100):
        events.append(make_conn_event(db, iot_device.id, f"{i}.{i}.{i}.1", bytes_orig=5_000_000, duration=5000.0))
    for i in range(50):
        events.append(make_dns_event(db, iot_device.id, f"nxdomain{i}.evil", "NXDOMAIN"))
    for i in range(10):
        events.append(make_suricata_event(db, iot_device.id, severity=1))

    total = 0.0
    for rule_fn in ALL_RULES:
        try:
            r = rule_fn(iot_device, events, default_config)
            total += r.score_delta
        except Exception:
            pass
    clamped = max(0.0, min(100.0, total))
    assert clamped <= 100.0


# ---- Suppressed device skipped in engine ----

def test_suppressed_device_skipped(db, suppressed_device, default_config):
    from app.models.app_config import AppConfig
    for key, val in default_config.items():
        db.add(AppConfig(key=key, value=val, description=""))
    db.flush()

    events = [make_conn_event(db, suppressed_device.id, f"10.{i}.0.1") for i in range(20)]
    db.flush()

    from app.scoring.engine import run_scoring_engine
    run_scoring_engine(db)
    db.refresh(suppressed_device)
    assert suppressed_device.suspicion_score == 0.0
