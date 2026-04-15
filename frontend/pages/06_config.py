"""Config page — threshold sliders and suppression list."""
import streamlit as st
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_client import get_config, update_config, get_devices, trigger_nmap_scan, trigger_ingest

st.set_page_config(page_title="Config — LAN Monitor", layout="wide")
st.title("⚙️ Configuration")

try:
    config_entries = get_config()
    devices = get_devices()
except Exception as e:
    st.error(f"Cannot connect to backend: {e}")
    st.stop()

config = {e["key"]: e["value"] for e in config_entries}
config_desc = {e["key"]: e.get("description", "") for e in config_entries}

st.subheader("Detection Thresholds")

with st.form("config_form"):
    new_values = {}

    col1, col2 = st.columns(2)
    with col1:
        new_values["outbound_fanout_threshold"] = st.number_input(
            "Outbound Fanout Threshold (unique dest IPs/hr)",
            min_value=1, max_value=500,
            value=int(config.get("outbound_fanout_threshold", 50)),
            help=config_desc.get("outbound_fanout_threshold"),
        )
        new_values["dns_churn_threshold"] = st.number_input(
            "DNS Churn Threshold (unique queries/hr)",
            min_value=1, max_value=1000,
            value=int(config.get("dns_churn_threshold", 100)),
            help=config_desc.get("dns_churn_threshold"),
        )
        new_values["long_lived_session_threshold_sec"] = st.number_input(
            "Long-lived Session Threshold (seconds)",
            min_value=60, max_value=86400,
            value=int(config.get("long_lived_session_threshold_sec", 3600)),
            help=config_desc.get("long_lived_session_threshold_sec"),
        )
        new_values["long_lived_session_count_threshold"] = st.number_input(
            "Long-lived Session Count Threshold",
            min_value=1, max_value=100,
            value=int(config.get("long_lived_session_count_threshold", 3)),
        )
        new_values["behavior_deviation_z_threshold"] = st.slider(
            "Behavior Deviation Z-score Threshold",
            min_value=1.0, max_value=5.0,
            value=float(config.get("behavior_deviation_z_threshold", 2.5)),
            step=0.1,
            help=config_desc.get("behavior_deviation_z_threshold"),
        )

    with col2:
        new_values["sustained_upload_threshold_mb"] = st.number_input(
            "Sustained Upload Threshold (MB/hr)",
            min_value=1.0, max_value=10000.0,
            value=float(config.get("sustained_upload_threshold_mb", 500.0)),
            step=10.0,
        )
        new_values["domain_diversity_nxdomain_threshold"] = st.number_input(
            "NXDOMAIN Count Threshold",
            min_value=1, max_value=200,
            value=int(config.get("domain_diversity_nxdomain_threshold", 20)),
        )
        new_values["geo_asn_spread_threshold"] = st.number_input(
            "Geo/ASN Spread Threshold",
            min_value=1, max_value=100,
            value=int(config.get("geo_asn_spread_threshold", 10)),
        )
        new_values["iot_weight_multiplier"] = st.slider(
            "IoT/TV Weight Multiplier",
            min_value=1.0, max_value=3.0,
            value=float(config.get("iot_weight_multiplier", 1.5)),
            step=0.1,
        )
        new_values["alert_score_change_threshold"] = st.slider(
            "Alert Score Change Threshold",
            min_value=1.0, max_value=50.0,
            value=float(config.get("alert_score_change_threshold", 10.0)),
            step=1.0,
        )

    st.subheader("Suricata Alert Score Deltas")
    col3, col4 = st.columns(2)
    with col3:
        new_values["suricata_alert_low_delta"] = st.number_input("Low severity delta", 0.0, 50.0, float(config.get("suricata_alert_low_delta", 5.0)))
        new_values["suricata_alert_medium_delta"] = st.number_input("Medium severity delta", 0.0, 50.0, float(config.get("suricata_alert_medium_delta", 15.0)))
    with col4:
        new_values["suricata_alert_high_delta"] = st.number_input("High severity delta", 0.0, 100.0, float(config.get("suricata_alert_high_delta", 30.0)))
        new_values["suricata_alert_critical_delta"] = st.number_input("Critical severity delta", 0.0, 100.0, float(config.get("suricata_alert_critical_delta", 50.0)))

    submitted = st.form_submit_button("💾 Save Configuration")
    if submitted:
        try:
            result = update_config(new_values)
            st.success(f"Updated: {', '.join(result.get('updated', []))}")
        except Exception as e:
            st.error(f"Failed to save: {e}")

st.divider()

# --- Suppressed Devices ---
st.subheader("Suppressed Devices")
all_ips = [f"{d['ip']} ({d.get('hostname') or '—'})" for d in devices]
suppressed = [d for d in devices if d.get("suppressed")]
suppressed_labels = [f"{d['ip']} ({d.get('hostname') or '—'})" for d in suppressed]

selected_suppressed = st.multiselect(
    "Select devices to suppress (removes them from scoring)",
    options=all_ips,
    default=suppressed_labels,
)

if st.button("Apply Suppression"):
    from api_client import update_device
    selected_ips = {label.split(" ")[0] for label in selected_suppressed}
    for d in devices:
        should_suppress = d["ip"] in selected_ips
        if d.get("suppressed") != should_suppress:
            try:
                update_device(d["id"], suppressed=should_suppress)
            except Exception as e:
                st.error(f"Failed for {d['ip']}: {e}")
    st.success("Suppression updated!")
    st.rerun()

st.divider()

# --- Manual Triggers ---
st.subheader("Manual Operations")
col1, col2, col3 = st.columns(3)
with col1:
    if st.button("🔍 Run Nmap Scan"):
        try:
            trigger_nmap_scan()
            st.success("Nmap scan queued!")
        except Exception as e:
            st.error(f"Failed: {e}")
with col2:
    if st.button("📥 Ingest Zeek Logs"):
        try:
            trigger_ingest("zeek")
            st.success("Zeek ingest queued!")
        except Exception as e:
            st.error(f"Failed: {e}")
with col3:
    if st.button("📥 Ingest Suricata Logs"):
        try:
            trigger_ingest("suricata")
            st.success("Suricata ingest queued!")
        except Exception as e:
            st.error(f"Failed: {e}")
