"""Dashboard page — overview stats and top suspicious devices."""
import streamlit as st
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_client import get_stats, get_devices, get_alerts, trigger_nmap_scan, get_scan_status, trigger_ingest

st.set_page_config(page_title="Dashboard — LAN Monitor", layout="wide")
st.title("📊 Dashboard")

try:
    stats = get_stats()
    devices = get_devices()
    alerts = get_alerts(ack=False)
except Exception as e:
    st.error(f"Cannot connect to backend: {e}")
    st.stop()

# --- Metric Cards ---
col1, col2, col3, col4 = st.columns(4)
alert_counts = stats.get("alert_counts", {})
col1.metric("Devices", stats.get("device_count", 0))
col2.metric("Critical Alerts", alert_counts.get("critical", 0), delta_color="inverse")
col3.metric("High Alerts", alert_counts.get("high", 0), delta_color="inverse")
col4.metric("Total Unacked Alerts", sum(alert_counts.values()), delta_color="inverse")

st.divider()

# --- Alert severity bar chart ---
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("Unacknowledged Alerts by Severity")
    severity_order = ["critical", "high", "medium", "low"]
    sev_data = {s: alert_counts.get(s, 0) for s in severity_order}
    df_sev = pd.DataFrame({"Severity": list(sev_data.keys()), "Count": list(sev_data.values())})
    df_sev = df_sev[df_sev["Count"] > 0]
    if not df_sev.empty:
        st.bar_chart(df_sev.set_index("Severity"))
    else:
        st.info("No unacknowledged alerts.")

with col_right:
    st.subheader("Top Suspicious Devices")
    top = stats.get("top_suspicious_device")
    if top:
        st.markdown(f"**Most suspicious:** `{top['ip']}` ({top.get('hostname', 'unknown')})")
        st.metric("Score", f"{top['score']:.1f} / 100")

    top_devices = sorted(devices, key=lambda d: d["suspicion_score"], reverse=True)[:5]
    if top_devices:
        rows = []
        for d in top_devices:
            rows.append({
                "IP": d["ip"],
                "Hostname": d.get("hostname") or "—",
                "Category": d["category"],
                "Score": f"{d['suspicion_score']:.1f}",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

st.divider()
st.subheader("Recent Alerts")
if alerts:
    rows = []
    for a in alerts[:20]:
        rows.append({
            "Severity": a["severity"].upper(),
            "Device": a["device_id"],
            "Title": a["title"][:60],
            "Created": a["created_at"][:19],
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
else:
    st.success("No unacknowledged alerts!")

st.divider()

# --- Scan Controls & Status ---
st.subheader("Scan & Ingest")

try:
    scan_status = get_scan_status()
    if scan_status["running"]:
        st.warning(f"Nmap scan running... (started {scan_status['last_started']})")
    else:
        cols = st.columns(4)
        with cols[0]:
            if st.button("Scan Network"):
                try:
                    trigger_nmap_scan()
                    st.success("Scan queued!")
                    st.rerun()
                except Exception as e:
                    st.error(str(e))
        with cols[1]:
            if st.button("Ingest Zeek"):
                trigger_ingest("zeek")
                st.success("Zeek ingest queued!")
        with cols[2]:
            if st.button("Ingest Suricata"):
                trigger_ingest("suricata")
                st.success("Suricata ingest queued!")
        with cols[3]:
            if st.button("Ingest Router"):
                trigger_ingest("router")
                st.success("Router ingest queued!")

        if scan_status["last_finished"]:
            parts = [f"Last scan finished: {scan_status['last_finished']}"]
            if scan_status["last_device_count"] is not None:
                parts.append(f"{scan_status['last_device_count']} devices found")
            if scan_status["last_error"]:
                parts.append(f"Error: {scan_status['last_error']}")
            st.caption(" — ".join(parts))
except Exception:
    pass

if st.button("🔄 Refresh"):
    st.rerun()
