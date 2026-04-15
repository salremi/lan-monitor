"""Alerts page — filterable table with acknowledge button."""
import streamlit as st
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_client import get_alerts, acknowledge_alert

st.set_page_config(page_title="Alerts — LAN Monitor", layout="wide")
st.title("🚨 Alerts")

# Filters
col1, col2, col3 = st.columns(3)
with col1:
    sev_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
with col2:
    ack_filter = st.selectbox("Status", ["Unacknowledged", "Acknowledged", "All"])
with col3:
    device_filter = st.text_input("Device ID (optional)", "")

ack_param = None
if ack_filter == "Unacknowledged":
    ack_param = False
elif ack_filter == "Acknowledged":
    ack_param = True

sev_param = None if sev_filter == "All" else sev_filter
device_id_param = int(device_filter) if device_filter.strip().isdigit() else None

try:
    alerts = get_alerts(severity=sev_param, ack=ack_param, device_id=device_id_param)
except Exception as e:
    st.error(f"Cannot connect to backend: {e}")
    st.stop()

st.caption(f"{len(alerts)} alert(s)")

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

for alert in alerts:
    icon = SEV_ICON.get(alert["severity"], "⚪")
    acked = alert.get("acknowledged", False)
    status = "✅ Acknowledged" if acked else "🔔 Active"

    with st.expander(f"{icon} [{alert['severity'].upper()}] {alert['title'][:70]}  —  {status}"):
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown(f"**Device ID:** {alert['device_id']}")
            st.markdown(f"**Created:** {alert['created_at'][:19]}")
            st.markdown(f"**Reason:** {alert['reason']}")
            evidence = alert.get("evidence") or []
            if evidence:
                st.markdown(f"**Evidence ({len(evidence)} events):**")
                rows = [
                    {"Time": ev.get("ts", "")[:19], "Type": ev.get("type"), "Src": ev.get("src"), "Dst": ev.get("dst")}
                    for ev in evidence[:10]
                ]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        with col2:
            if not acked:
                if st.button("✅ Acknowledge", key=f"ack_{alert['id']}"):
                    try:
                        acknowledge_alert(alert["id"])
                        st.success("Acknowledged!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed: {e}")
            else:
                st.markdown(f"_Acked at {(alert.get('ack_at') or '')[:19]}_")

if not alerts:
    st.success("No alerts matching current filters.")
