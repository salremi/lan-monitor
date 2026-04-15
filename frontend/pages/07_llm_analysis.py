"""LLM Analysis page — analyze any device with Ollama or LM Studio."""
import streamlit as st
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_client import get_devices, get_llm_health, analyze_device_llm

st.set_page_config(page_title="AI Analysis — LAN Monitor", layout="wide")
st.title("AI Analysis")

# LLM health check
try:
    health = get_llm_health()
except Exception as e:
    st.error(f"Cannot connect to backend: {e}")
    st.stop()

status = health.get("status")
if status == "disabled":
    st.warning("LLM analysis is disabled. Set `LLM_ENABLED=true` in `.env` and restart the backend.")
    st.code("LLM_ENABLED=true\nLLM_PROVIDER=ollama\nLLM_BASE_URL=http://localhost:11434\nLLM_MODEL=llama3.2")
    st.stop()
elif status == "unreachable":
    st.error(f"LLM provider unreachable: {health.get('error', '')}")
    st.info("Make sure Ollama is running (`ollama serve`) or LM Studio is open with a model loaded.")
    st.stop()
else:
    st.success(f"Provider: **{health.get('provider')}** — Model: **{health.get('model')}**")

st.divider()

# Device selector
try:
    devices = get_devices()
except Exception as e:
    st.error(f"Failed to load devices: {e}")
    st.stop()

if not devices:
    st.info("No devices found. Run an nmap scan first.")
    st.stop()

# Sort by suspicion score descending so high-risk devices appear first
devices = sorted(devices, key=lambda d: d["suspicion_score"], reverse=True)

def score_icon(score):
    if score >= 75: return "🔴"
    if score >= 50: return "🟠"
    if score >= 25: return "🟡"
    return "🟢"

device_options = {
    f"{score_icon(d['suspicion_score'])} {d['ip']} ({d.get('hostname') or '—'})  score: {d['suspicion_score']:.1f}": d["id"]
    for d in devices
}

selected_label = st.selectbox("Select a device to analyze", list(device_options.keys()))
device_id = device_options[selected_label]

if st.button("Analyze with AI", type="primary"):
    with st.spinner("Asking LLM — this may take 10-30 seconds..."):
        try:
            result = analyze_device_llm(device_id)
            st.markdown("### Assessment")
            st.markdown(result["analysis"])
            st.caption(f"Model: {result.get('model')} via {result.get('provider')}")
        except Exception as e:
            st.error(f"Analysis failed: {e}")
