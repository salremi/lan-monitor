"""Inventory page — device table with search, filter, score color."""
import streamlit as st
import pandas as pd
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from api_client import get_devices, update_device

st.set_page_config(page_title="Inventory — LAN Monitor", layout="wide")
st.title("📋 Device Inventory")

try:
    devices = get_devices()
except Exception as e:
    st.error(f"Cannot connect to backend: {e}")
    st.stop()

# --- Filters ---
col1, col2, col3 = st.columns(3)
with col1:
    search = st.text_input("Search IP / Hostname", "")
with col2:
    categories = ["All"] + sorted({d["category"] for d in devices})
    cat_filter = st.selectbox("Category", categories)
with col3:
    show_suppressed = st.checkbox("Show suppressed devices", value=False)

filtered = devices
if search:
    q = search.lower()
    filtered = [d for d in filtered if q in d["ip"] or q in (d.get("hostname") or "").lower()]
if cat_filter != "All":
    filtered = [d for d in filtered if d["category"] == cat_filter]
if not show_suppressed:
    filtered = [d for d in filtered if not d["suppressed"]]

st.caption(f"Showing {len(filtered)} of {len(devices)} devices")

# --- Color-coded score ---
def score_color(score: float) -> str:
    if score >= 75:
        return "🔴"
    if score >= 50:
        return "🟠"
    if score >= 25:
        return "🟡"
    return "🟢"

rows = []
for d in filtered:
    rows.append({
        "": score_color(d["suspicion_score"]),
        "IP": d["ip"],
        "Hostname": d.get("hostname") or "—",
        "MAC": d.get("mac") or "—",
        "Vendor": d.get("vendor") or "—",
        "Category": d["category"],
        "Score": f"{d['suspicion_score']:.1f}",
        "Tags": ", ".join(d.get("tags") or []) or "—",
        "Suppressed": "✓" if d["suppressed"] else "",
        "Last Seen": (d.get("last_seen") or "")[:19],
        "ID": d["id"],
    })

df = pd.DataFrame(rows)
if not df.empty:
    st.dataframe(df.drop(columns=["ID"]), use_container_width=True, hide_index=True)

st.divider()
st.subheader("Update Device")
if filtered:
    device_options = {f"{d['ip']} ({d.get('hostname') or '—'})": d["id"] for d in filtered}
    selected_label = st.selectbox("Select device", list(device_options.keys()))
    selected_id = device_options[selected_label]
    selected_device = next(d for d in filtered if d["id"] == selected_id)

    col1, col2, col3 = st.columns(3)
    with col1:
        new_cat = st.selectbox(
            "Category",
            ["PC", "phone", "TV", "IoT", "NAS", "router", "unknown"],
            index=["PC", "phone", "TV", "IoT", "NAS", "router", "unknown"].index(selected_device["category"]),
        )
    with col2:
        tags_str = st.text_input("Tags (comma-separated)", ", ".join(selected_device.get("tags") or []))
    with col3:
        suppressed = st.checkbox("Suppressed", value=selected_device.get("suppressed", False))

    if st.button("💾 Save"):
        tags = [t.strip() for t in tags_str.split(",") if t.strip()]
        try:
            update_device(selected_id, category=new_cat, tags=tags, suppressed=suppressed)
            st.success("Device updated!")
            st.rerun()
        except Exception as e:
            st.error(f"Update failed: {e}")
