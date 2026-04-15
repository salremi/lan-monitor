"""Evidence page — raw network events per device."""
import streamlit as st
import pandas as pd
import json
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_client import get_devices, get_evidence

st.set_page_config(page_title="Evidence — LAN Monitor", layout="wide")
st.title("🔎 Evidence")

try:
    devices = get_devices()
except Exception as e:
    st.error(f"Cannot connect to backend: {e}")
    st.stop()

if not devices:
    st.info("No devices found.")
    st.stop()

col1, col2, col3 = st.columns(3)
with col1:
    device_options = {f"{d['ip']} ({d.get('hostname') or '—'})": d["id"] for d in devices}
    selected_label = st.selectbox("Device", list(device_options.keys()))
    device_id = device_options[selected_label]

with col2:
    event_types = ["All", "conn", "dns", "http", "suricata_alert", "dhcp", "firewall"]
    ev_type = st.selectbox("Event Type", event_types)

with col3:
    limit = st.slider("Max events", 10, 500, 100, step=10)

ev_type_param = None if ev_type == "All" else ev_type

try:
    events = get_evidence(device_id, limit=limit, event_type=ev_type_param)
except Exception as e:
    st.error(f"Failed to load evidence: {e}")
    st.stop()

st.caption(f"{len(events)} event(s)")

for ev in events:
    ts = ev.get("ts", "")[:19]
    ev_type_label = ev.get("event_type", "").upper()
    src = ev.get("source_ip", "")
    dst = ev.get("dest_ip") or "—"
    src_label = ev.get("source", "")
    label = f"`{ts}` **{ev_type_label}** ({src_label}) — {src} → {dst}"

    with st.expander(label):
        raw = ev.get("raw") or {}
        if raw:
            st.json(raw)
        else:
            st.info("No raw data.")
