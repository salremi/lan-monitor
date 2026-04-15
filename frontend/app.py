"""LAN Monitor — Streamlit multi-page app entry point."""
import streamlit as st

st.set_page_config(
    page_title="LAN Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.sidebar.title("🛡️ LAN Monitor")
st.sidebar.markdown("Defensive home network monitoring")
st.sidebar.divider()

st.title("Welcome to LAN Monitor")
st.markdown("""
Use the sidebar to navigate between pages:

- **Dashboard** — Overview stats and top suspicious devices
- **Inventory** — Full device list with search and filters
- **Device Detail** — Per-device score breakdown and event timeline
- **Alerts** — View and acknowledge security alerts
- **Evidence** — Raw network events per device
- **Config** — Adjust detection thresholds
- **LLM Analysis** — AI-powered threat analysis
""")
