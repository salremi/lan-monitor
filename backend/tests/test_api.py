"""FastAPI route integration tests."""
import pytest
from datetime import datetime

from app.models.device import Device, DeviceCategory
from app.models.alert import Alert, AlertSeverity
from app.models.event import NetworkEvent
from app.models.app_config import AppConfig


# ---- Helper to seed data ----

def _seed_device(db, ip="192.168.1.10", score=25.0) -> Device:
    device = Device(
        ip=ip,
        mac=f"AA:BB:CC:DD:{ip.split('.')[-1].zfill(2)}:01",
        hostname=f"device-{ip}",
        category=DeviceCategory.PC,
        tags=["test"],
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        suppressed=False,
        suspicion_score=score,
        score_reasons=[],
    )
    db.add(device)
    db.flush()
    return device


def _seed_alert(db, device_id, severity=AlertSeverity.medium) -> Alert:
    alert = Alert(
        device_id=device_id,
        severity=severity,
        title="Test Alert",
        reason="Test reason",
        evidence=[],
        created_at=datetime.utcnow(),
        acknowledged=False,
    )
    db.add(alert)
    db.flush()
    return alert


def _seed_config(db):
    for key, val in {
        "outbound_fanout_threshold": 50,
        "dns_churn_threshold": 100,
    }.items():
        if not db.query(AppConfig).filter(AppConfig.key == key).first():
            db.add(AppConfig(key=key, value=val, description="test"))
    db.flush()


# ---- GET /api/devices ----

def test_list_devices_empty(client, db):
    response = client.get("/api/devices")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_list_devices_returns_seeded(client, db):
    _seed_device(db, "192.168.1.11", score=42.0)
    db.commit()
    response = client.get("/api/devices")
    assert response.status_code == 200
    data = response.json()
    ips = [d["ip"] for d in data]
    assert "192.168.1.11" in ips


def test_list_devices_score_in_response(client, db):
    _seed_device(db, "192.168.1.12", score=77.0)
    db.commit()
    response = client.get("/api/devices")
    assert response.status_code == 200
    device = next((d for d in response.json() if d["ip"] == "192.168.1.12"), None)
    assert device is not None
    assert device["suspicion_score"] == 77.0


# ---- GET /api/devices/{id} ----

def test_get_device_detail(client, db):
    device = _seed_device(db, "192.168.1.20")
    db.commit()
    response = client.get(f"/api/devices/{device.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["ip"] == "192.168.1.20"
    assert "ports" in data


def test_get_device_not_found(client, db):
    response = client.get("/api/devices/99999")
    assert response.status_code == 404


# ---- PATCH /api/devices/{id} ----

def test_patch_device_category(client, db):
    device = _seed_device(db, "192.168.1.21")
    db.commit()
    response = client.patch(f"/api/devices/{device.id}", json={"category": "IoT"})
    assert response.status_code == 200
    assert response.json()["category"] == "IoT"


def test_patch_device_tags(client, db):
    device = _seed_device(db, "192.168.1.22")
    db.commit()
    response = client.patch(f"/api/devices/{device.id}", json={"tags": ["camera", "iot"]})
    assert response.status_code == 200
    assert "camera" in response.json()["tags"]


def test_patch_device_suppressed(client, db):
    device = _seed_device(db, "192.168.1.23")
    db.commit()
    response = client.patch(f"/api/devices/{device.id}", json={"suppressed": True})
    assert response.status_code == 200
    assert response.json()["suppressed"] is True


def test_patch_device_not_found(client, db):
    response = client.patch("/api/devices/99999", json={"category": "IoT"})
    assert response.status_code == 404


# ---- GET /api/alerts ----

def test_list_alerts_empty(client, db):
    response = client.get("/api/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_list_alerts_filter_severity(client, db):
    device = _seed_device(db, "192.168.1.30")
    _seed_alert(db, device.id, AlertSeverity.high)
    _seed_alert(db, device.id, AlertSeverity.low)
    db.commit()
    response = client.get("/api/alerts?severity=high")
    assert response.status_code == 200
    for a in response.json():
        assert a["severity"] == "high"


def test_list_alerts_filter_ack(client, db):
    device = _seed_device(db, "192.168.1.31")
    _seed_alert(db, device.id)
    db.commit()
    response = client.get("/api/alerts?ack=false")
    assert response.status_code == 200
    for a in response.json():
        assert not a["acknowledged"]


def test_list_alerts_filter_device_id(client, db):
    device1 = _seed_device(db, "192.168.1.32")
    device2 = _seed_device(db, "192.168.1.33")
    _seed_alert(db, device1.id)
    _seed_alert(db, device2.id)
    db.commit()
    response = client.get(f"/api/alerts?device_id={device1.id}")
    assert response.status_code == 200
    for a in response.json():
        assert a["device_id"] == device1.id


# ---- PATCH /api/alerts/{id}/acknowledge ----

def test_acknowledge_alert(client, db):
    device = _seed_device(db, "192.168.1.40")
    alert = _seed_alert(db, device.id)
    db.commit()
    response = client.patch(f"/api/alerts/{alert.id}/acknowledge")
    assert response.status_code == 200
    data = response.json()
    assert data["acknowledged"] is True
    assert data["ack_at"] is not None


def test_acknowledge_alert_not_found(client, db):
    response = client.patch("/api/alerts/99999/acknowledge")
    assert response.status_code == 404


# ---- GET /api/evidence/{device_id} ----

def test_get_evidence(client, db):
    device = _seed_device(db, "192.168.1.50")
    ev = NetworkEvent(
        device_id=device.id,
        source_ip="192.168.1.50",
        dest_ip="1.2.3.4",
        event_type="conn",
        source="zeek",
        ts=datetime.utcnow(),
        raw={"bytes_orig": "1024"},
    )
    db.add(ev)
    db.commit()
    response = client.get(f"/api/evidence/{device.id}")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["source_ip"] == "192.168.1.50"


# ---- GET /api/config ----

def test_get_config(client, db):
    _seed_config(db)
    db.commit()
    response = client.get("/api/config")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    keys = {item["key"] for item in data}
    assert "outbound_fanout_threshold" in keys


# ---- PUT /api/config ----

def test_update_config(client, db):
    _seed_config(db)
    db.commit()
    response = client.put("/api/config", json={"values": {"outbound_fanout_threshold": 99}})
    assert response.status_code == 200
    assert "outbound_fanout_threshold" in response.json()["updated"]


# ---- GET /api/stats ----

def test_get_stats(client, db):
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "device_count" in data
    assert "alert_counts" in data
    assert isinstance(data["alert_counts"], dict)
