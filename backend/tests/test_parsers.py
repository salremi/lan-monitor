"""Parser unit tests with synthetic fixture files."""
import os
import pytest

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "sample")


# ---- Nmap parser ----

def test_nmap_parse_devices(db):
    from app.parsers.nmap_parser import parse_nmap_xml
    from app.models.device import Device

    nmap_path = os.path.join(SAMPLE_DIR, "nmap_sample.xml")
    with open(nmap_path) as f:
        xml_data = f.read()

    devices = parse_nmap_xml(xml_data, db)
    db.commit()

    assert len(devices) == 8
    ips = {d.ip for d in devices}
    assert "192.168.1.1" in ips
    assert "192.168.1.70" in ips


def test_nmap_parse_ports(db):
    from app.parsers.nmap_parser import parse_nmap_xml
    from app.models.device import DevicePort

    nmap_path = os.path.join(SAMPLE_DIR, "nmap_sample.xml")
    with open(nmap_path) as f:
        xml_data = f.read()

    parse_nmap_xml(xml_data, db)
    db.commit()

    ports = db.query(DevicePort).all()
    assert len(ports) > 0
    port_nums = {p.port for p in ports}
    assert 22 in port_nums or 80 in port_nums


def test_nmap_parse_malformed(db):
    from app.parsers.nmap_parser import parse_nmap_xml

    devices = parse_nmap_xml("<invalid xml >>>", db)
    assert devices == []


def test_nmap_parse_empty(db):
    from app.parsers.nmap_parser import parse_nmap_xml

    xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
    devices = parse_nmap_xml(xml, db)
    assert devices == []


def test_nmap_upsert_existing(db):
    from app.parsers.nmap_parser import parse_nmap_xml
    from app.models.device import Device

    nmap_path = os.path.join(SAMPLE_DIR, "nmap_sample.xml")
    with open(nmap_path) as f:
        xml_data = f.read()

    parse_nmap_xml(xml_data, db)
    db.commit()
    count_first = db.query(Device).count()

    # Parse again — should upsert, not create duplicates
    parse_nmap_xml(xml_data, db)
    db.commit()
    count_second = db.query(Device).count()
    assert count_second == count_first


# ---- Zeek parser ----

def test_zeek_conn_log(db):
    from app.parsers.zeek_parser import _ingest_conn_log
    from app.models.event import NetworkEvent

    conn_path = os.path.join(SAMPLE_DIR, "conn.log")
    _ingest_conn_log(db, conn_path, 0)
    db.commit()

    events = db.query(NetworkEvent).filter(NetworkEvent.event_type == "conn").all()
    assert len(events) > 0
    # Check some source IPs
    src_ips = {e.source_ip for e in events}
    assert "192.168.1.10" in src_ips or "192.168.1.30" in src_ips


def test_zeek_dns_log(db):
    from app.parsers.zeek_parser import _ingest_dns_log
    from app.models.event import NetworkEvent

    dns_path = os.path.join(SAMPLE_DIR, "dns.log")
    _ingest_dns_log(db, dns_path, 0)
    db.commit()

    events = db.query(NetworkEvent).filter(NetworkEvent.event_type == "dns").all()
    assert len(events) > 0
    queries = {e.raw.get("query") for e in events}
    assert "example.com" in queries


def test_zeek_http_log(db):
    from app.parsers.zeek_parser import _ingest_http_log
    from app.models.event import NetworkEvent

    http_path = os.path.join(SAMPLE_DIR, "http.log")
    _ingest_http_log(db, http_path, 0)
    db.commit()

    events = db.query(NetworkEvent).filter(NetworkEvent.event_type == "http").all()
    assert len(events) > 0


def test_zeek_nonexistent_file(db):
    from app.parsers.zeek_parser import _ingest_conn_log

    new_offset = _ingest_conn_log(db, "/nonexistent/path/conn.log", 0)
    assert new_offset == 0  # offset unchanged


def test_zeek_malformed_line_skipped(db, tmp_path):
    from app.parsers.zeek_parser import _ingest_conn_log
    from app.models.event import NetworkEvent

    log = tmp_path / "conn.log"
    log.write_text(
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\n"
        "NOT_A_TIMESTAMP\tinvalid\n"
        "1704067200.0\tCabc\t192.168.1.5\t12345\t8.8.8.8\t53\tudp\tdns\t0.001\t44\t60\tSF\tT\tF\t0\tDd\t1\t72\t1\t88\t-\n"
    )
    _ingest_conn_log(db, str(log), 0)
    db.commit()
    events = db.query(NetworkEvent).filter(NetworkEvent.source_ip == "192.168.1.5").all()
    assert len(events) >= 1  # valid line parsed


# ---- Suricata parser ----

def test_suricata_parse(db):
    from app.parsers.suricata_parser import ingest_suricata_logs
    from app.models.event import NetworkEvent

    eve_path = os.path.join(SAMPLE_DIR, "eve.json")
    ingest_suricata_logs(db, eve_path)
    db.commit()

    events = db.query(NetworkEvent).filter(
        NetworkEvent.event_type == "suricata_alert"
    ).all()
    assert len(events) > 0


def test_suricata_malformed_line(db, tmp_path):
    from app.parsers.suricata_parser import ingest_suricata_logs

    eve = tmp_path / "eve.json"
    eve.write_text(
        'INVALID JSON\n'
        '{"timestamp":"2024-01-01T12:00:00+0000","event_type":"alert","src_ip":"10.0.0.1","dest_ip":"1.2.3.4","proto":"TCP","alert":{"signature":"TEST","severity":2}}\n'
    )
    ingest_suricata_logs(db, str(eve))
    db.commit()  # Should not raise


def test_suricata_nonexistent(db):
    from app.parsers.suricata_parser import ingest_suricata_logs
    ingest_suricata_logs(db, "/nonexistent/eve.json")
    # Should not raise


# ---- Router parser ----

def test_router_parse_dhcp(db):
    import app.parsers.router_parser as rp
    from app.models.event import NetworkEvent

    syslog_path = os.path.join(SAMPLE_DIR, "syslog_dhcp.log")
    rp._offsets.pop(syslog_path, None)  # reset offset for this test
    rp.ingest_router_logs(db, syslog_path)
    db.commit()

    dhcp_events = db.query(NetworkEvent).filter(NetworkEvent.event_type == "dhcp").all()
    assert len(dhcp_events) > 0


def test_router_parse_firewall(db):
    import app.parsers.router_parser as rp
    from app.models.event import NetworkEvent

    syslog_path = os.path.join(SAMPLE_DIR, "syslog_dhcp.log")
    rp._offsets.pop(syslog_path, None)  # reset offset for this test
    rp.ingest_router_logs(db, syslog_path)
    db.commit()

    fw_events = db.query(NetworkEvent).filter(NetworkEvent.event_type == "firewall").all()
    assert len(fw_events) > 0


def test_router_malformed_line(db, tmp_path):
    from app.parsers.router_parser import ingest_router_logs

    log = tmp_path / "syslog"
    log.write_text("This is a completely unrecognized line with no pattern match\n")
    ingest_router_logs(db, str(log))
    db.commit()  # Should not raise
