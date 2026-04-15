"""Device Detail page — score gauge, port table, event timeline."""
import streamlit as st
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_client import get_devices, get_device, get_evidence, analyze_device_llm, get_llm_health

st.set_page_config(page_title="Device Detail — LAN Monitor", layout="wide")
st.title("🔍 Device Detail")

# Device selector
try:
    devices = get_devices()
except Exception as e:
    st.error(f"Cannot connect to backend: {e}")
    st.stop()

if not devices:
    st.info("No devices found.")
    st.stop()

params = st.query_params
default_idx = 0
if "device_id" in params:
    try:
        target_id = int(params["device_id"])
        ids = [d["id"] for d in devices]
        if target_id in ids:
            default_idx = ids.index(target_id)
    except (ValueError, KeyError):
        pass

device_options = {f"{d['ip']} ({d.get('hostname') or '—'})": d["id"] for d in devices}
selected_label = st.selectbox("Select device", list(device_options.keys()), index=default_idx)
device_id = device_options[selected_label]

try:
    detail = get_device(device_id)
    events = get_evidence(device_id, limit=200)
except Exception as e:
    st.error(f"Failed to load device: {e}")
    st.stop()

score = detail["suspicion_score"]

# --- Header ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("IP Address", detail["ip"])
col2.metric("Hostname", detail.get("hostname") or "—")
col3.metric("Category", detail["category"])
col4.metric("Suspicion Score", f"{score:.1f} / 100")

# Visual score bar
if score >= 75:
    level, color = "CRITICAL", "🔴"
elif score >= 50:
    level, color = "HIGH", "🟠"
elif score >= 25:
    level, color = "MEDIUM", "🟡"
else:
    level, color = "LOW", "🟢"
st.markdown(f"**Risk Level:** {color} {level}")
st.progress(int(score))

st.divider()

# --- Score Breakdown ---
col_left, col_right = st.columns(2)
with col_left:
    st.subheader("Score Breakdown")
    reasons = detail.get("score_reasons") or []
    if reasons:
        rows = [{"Rule": r["rule"], "Delta": f"+{r['delta']:.1f}", "Explanation": r["explanation"]} for r in reasons]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No score contributions.")

with col_right:
    st.subheader("Open Ports")
    ports = detail.get("ports") or []
    if ports:
        rows = [{"Port": f"{p['port']}/{p['protocol']}", "Service": p.get("service") or "—", "Banner": p.get("banner") or "—"} for p in ports]
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No ports discovered.")

st.divider()

# --- Event Timeline ---
st.subheader("Event Timeline")
if events:
    df = pd.DataFrame([
        {
            "Time": e["ts"][:19],
            "Type": e["event_type"],
            "Source": e["source"],
            "Src IP": e["source_ip"],
            "Dst IP": e.get("dest_ip") or "—",
        }
        for e in events
    ])
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Event type distribution
    type_counts = df["Type"].value_counts()
    st.subheader("Event Distribution")
    st.bar_chart(type_counts)
else:
    st.info("No events recorded for this device.")

# --- LLM Analysis ---
st.divider()
st.subheader("AI Analysis")

try:
    llm_health = get_llm_health()
    llm_enabled = llm_health.get("status") not in ("disabled", "unreachable")
except Exception:
    llm_health = {"status": "unreachable"}
    llm_enabled = False

if llm_health.get("status") == "disabled":
    st.info("LLM analysis is disabled. Set `LLM_ENABLED=true` in `.env` and restart the backend.")
elif llm_health.get("status") == "unreachable":
    st.warning(f"LLM provider unreachable. Is Ollama or LM Studio running? ({llm_health.get('error', '')})")
else:
    st.caption(f"Provider: {llm_health.get('provider')} — Model: {llm_health.get('model')}")
    if st.button("Analyze with AI"):
        with st.spinner("Asking LLM..."):
            try:
                result = analyze_device_llm(device_id)
                st.markdown(result["analysis"])
            except Exception as e:
                st.error(f"Analysis failed: {e}")

# Device metadata
with st.expander("Device Metadata"):
    st.json({
        "id": detail["id"],
        "mac": detail.get("mac"),
        "vendor": detail.get("vendor"),
        "tags": detail.get("tags"),
        "first_seen": detail.get("first_seen"),
        "last_seen": detail.get("last_seen"),
        "suppressed": detail.get("suppressed"),
    })
