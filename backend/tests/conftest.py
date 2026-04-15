"""Pytest fixtures for LAN Monitor tests."""
import os
import pytest
from datetime import datetime
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Must be set before any app imports so the module-level engine uses in-memory SQLite
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from fastapi.testclient import TestClient

# Import after env var is set
from app.database import Base, get_db
from app.main import app
from app.models.device import Device, DeviceCategory, DevicePort
from app.models.event import NetworkEvent
from app.models.alert import Alert, AlertSeverity
from app.models.baseline import Baseline
from app.models.app_config import AppConfig


# One shared in-memory engine with StaticPool so all connections share the same DB
_TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(_TEST_ENGINE, "connect")
def _set_pragma(dbapi_conn, _):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


Base.metadata.create_all(bind=_TEST_ENGINE)

TestSession = sessionmaker(autocommit=False, autoflush=False, bind=_TEST_ENGINE)

# Patch app.database so lifespan's init_db() + _insert_default_config() use the test engine
import app.database as _appdb
_appdb.engine = _TEST_ENGINE
_appdb.SessionLocal = TestSession


@pytest.fixture()
def db():
    """Return a test DB session; truncates all tables after each test."""
    session = TestSession()
    try:
        yield session
    finally:
        session.rollback()
        for table in reversed(Base.metadata.sorted_tables):
            session.execute(table.delete())
        session.commit()
        session.close()


@pytest.fixture()
def client(db):
    """FastAPI test client backed by the shared in-memory DB session."""
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def default_config() -> dict:
    return {
        "outbound_fanout_threshold": 5,
        "sustained_upload_threshold_mb": 1.0,
        "long_lived_session_threshold_sec": 100,
        "long_lived_session_count_threshold": 1,
        "dns_churn_threshold": 5,
        "domain_diversity_nxdomain_threshold": 3,
        "geo_asn_spread_threshold": 3,
        "behavior_deviation_z_threshold": 2.5,
        "suricata_alert_low_delta": 5.0,
        "suricata_alert_medium_delta": 15.0,
        "suricata_alert_high_delta": 30.0,
        "suricata_alert_critical_delta": 50.0,
        "iot_weight_multiplier": 1.5,
        "alert_score_change_threshold": 5.0,
    }


@pytest.fixture()
def pc_device(db) -> Device:
    device = Device(
        ip="192.168.1.10",
        mac="AA:BB:CC:DD:EE:01",
        hostname="test-pc",
        category=DeviceCategory.PC,
        tags=[],
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        suppressed=False,
        suspicion_score=0.0,
        score_reasons=[],
    )
    db.add(device)
    db.flush()
    return device


@pytest.fixture()
def iot_device(db) -> Device:
    device = Device(
        ip="192.168.1.30",
        mac="B8:27:EB:12:34:56",
        hostname="rpi-sensor",
        category=DeviceCategory.IoT,
        tags=[],
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        suppressed=False,
        suspicion_score=0.0,
        score_reasons=[],
    )
    db.add(device)
    db.flush()
    return device


@pytest.fixture()
def suppressed_device(db) -> Device:
    device = Device(
        ip="192.168.1.99",
        mac="FF:FF:FF:FF:FF:FF",
        hostname="suppressed",
        category=DeviceCategory.PC,
        tags=[],
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        suppressed=True,
        suspicion_score=0.0,
        score_reasons=[],
    )
    db.add(device)
    db.flush()
    return device


def make_conn_event(db, device_id, dest_ip, bytes_orig=1024, duration=1.0, ts=None) -> NetworkEvent:
    e = NetworkEvent(
        device_id=device_id,
        source_ip="192.168.1.10",
        dest_ip=dest_ip,
        event_type="conn",
        source="zeek",
        ts=ts or datetime.utcnow(),
        raw={"bytes_orig": str(bytes_orig), "bytes_resp": "512", "duration": str(duration)},
    )
    db.add(e)
    db.flush()
    return e


def make_dns_event(db, device_id, query, rcode="NOERROR", ts=None) -> NetworkEvent:
    e = NetworkEvent(
        device_id=device_id,
        source_ip="192.168.1.10",
        dest_ip="8.8.8.8",
        event_type="dns",
        source="zeek",
        ts=ts or datetime.utcnow(),
        raw={"query": query, "rcode_name": rcode, "qtype_name": "A"},
    )
    db.add(e)
    db.flush()
    return e


def make_suricata_event(db, device_id, severity=2, ts=None) -> NetworkEvent:
    e = NetworkEvent(
        device_id=device_id,
        source_ip="192.168.1.10",
        dest_ip="1.2.3.4",
        event_type="suricata_alert",
        source="suricata",
        ts=ts or datetime.utcnow(),
        raw={"severity": severity, "signature": "ET TEST Alert", "category": "test"},
    )
    db.add(e)
    db.flush()
    return e
