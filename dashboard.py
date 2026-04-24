"""
EvilTwin-Detector — Brutal Neon Streamlit Dashboard
Author: @btwvitznaresh
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import json
import os
import time
from datetime import datetime, timedelta
import random

# ─── Page Config ─────────────────────────────────────
st.set_page_config(
    page_title="EvilTwin Detector",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Brutal Neon CSS ─────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=Orbitron:wght@400;700;900&display=swap');

/* Base */
html, body, [class*="css"] {
    font-family: 'Space Mono', monospace !important;
    background-color: #0a0a0f !important;
    color: #e0e0ff !important;
}

/* Hide Streamlit branding */
#MainMenu, footer, header { visibility: hidden; }

/* Main bg */
.stApp { background: #0a0a0f; }
.main .block-container { padding: 1.5rem 2rem; max-width: 100%; }

/* Sidebar */
[data-testid="stSidebar"] {
    background: #0d0d1a !important;
    border-right: 1px solid #7B2FBE44;
}
[data-testid="stSidebar"] * { color: #c0b8ff !important; }

/* Title */
.detector-title {
    font-family: 'Orbitron', monospace !important;
    font-size: 1.8rem;
    font-weight: 900;
    background: linear-gradient(90deg, #00FFFF, #BF00FF, #00FFFF);
    background-size: 200% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    animation: shimmer 3s linear infinite;
    letter-spacing: 3px;
}
@keyframes shimmer {
    to { background-position: 200% center; }
}

/* Metric cards */
[data-testid="metric-container"] {
    background: #0d0d1a !important;
    border: 1px solid #7B2FBE55 !important;
    border-radius: 8px !important;
    padding: 1rem !important;
}
[data-testid="metric-container"] label {
    color: #8888aa !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.7rem !important;
    letter-spacing: 2px !important;
    text-transform: uppercase !important;
}
[data-testid="metric-container"] [data-testid="stMetricValue"] {
    font-family: 'Orbitron', monospace !important;
    font-size: 2rem !important;
    font-weight: 700 !important;
}

/* Dataframe */
[data-testid="stDataFrame"] {
    border: 1px solid #7B2FBE44 !important;
    border-radius: 8px !important;
}

/* Buttons */
.stButton button {
    background: transparent !important;
    border: 1px solid #00FFFF55 !important;
    color: #00FFFF !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.75rem !important;
    letter-spacing: 2px !important;
    border-radius: 4px !important;
    transition: all 0.2s !important;
}
.stButton button:hover {
    background: #00FFFF22 !important;
    border-color: #00FFFF !important;
    box-shadow: 0 0 12px #00FFFF44 !important;
}

/* Alert boxes */
.alert-high {
    background: #1a0505;
    border: 1px solid #ff2222;
    border-left: 4px solid #ff2222;
    border-radius: 6px;
    padding: 1rem 1.2rem;
    margin: 0.5rem 0;
    font-family: 'Space Mono', monospace;
    font-size: 0.8rem;
}
.alert-medium {
    background: #1a1200;
    border: 1px solid #ffaa00;
    border-left: 4px solid #ffaa00;
    border-radius: 6px;
    padding: 1rem 1.2rem;
    margin: 0.5rem 0;
    font-family: 'Space Mono', monospace;
    font-size: 0.8rem;
}
.alert-safe {
    background: #001a0d;
    border: 1px solid #00ff88;
    border-left: 4px solid #00ff88;
    border-radius: 6px;
    padding: 1rem 1.2rem;
    margin: 0.5rem 0;
    font-family: 'Space Mono', monospace;
    font-size: 0.8rem;
}

/* Section headers */
.section-head {
    font-family: 'Orbitron', monospace;
    font-size: 0.9rem;
    letter-spacing: 3px;
    color: #00FFFF;
    text-transform: uppercase;
    border-bottom: 1px solid #00FFFF33;
    padding-bottom: 0.4rem;
    margin-bottom: 1rem;
}

/* Tabs */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    background: #0d0d1a !important;
    border-bottom: 1px solid #7B2FBE44 !important;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    color: #8888aa !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.75rem !important;
    letter-spacing: 1px !important;
}
[data-testid="stTabs"] [aria-selected="true"] {
    color: #00FFFF !important;
    border-bottom: 2px solid #00FFFF !important;
}

/* Selectbox */
[data-testid="stSelectbox"] * {
    background: #0d0d1a !important;
    color: #c0b8ff !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.8rem !important;
}
</style>
""", unsafe_allow_html=True)

# ─── Plotly Theme ─────────────────────────────────────
PLOTLY_LAYOUT = dict(
    paper_bgcolor="#0a0a0f",
    plot_bgcolor="#0d0d1a",
    font=dict(family="Space Mono", color="#c0b8ff", size=11),
    xaxis=dict(gridcolor="rgba(255, 255, 255, 0.05)", linecolor="rgba(123, 47, 190, 0.27)"),
    yaxis=dict(gridcolor="rgba(255, 255, 255, 0.05)", linecolor="rgba(123, 47, 190, 0.27)"),
    margin=dict(l=40, r=20, t=40, b=40),
)

# ─── Mock Data ───────────────────────────────────────
def mock_scan():
    return [
        {"ssid": "CafeNet", "bssid": "AA:BB:CC:00:11:22", "vendor": "TP-Link",
         "channel": 6, "rssi": -55, "encryption": "WPA2", "risk": "SAFE", "confidence": 5},
        {"ssid": "CafeNet", "bssid": "FF:EE:DD:CC:BB:AA", "vendor": "UNKNOWN",
         "channel": 11, "rssi": -38, "encryption": "OPEN", "risk": "HIGH", "confidence": 94},
        {"ssid": "HomeRouter", "bssid": "11:22:33:44:55:66", "vendor": "Netgear",
         "channel": 1, "rssi": -47, "encryption": "WPA3", "risk": "SAFE", "confidence": 2},
        {"ssid": "GuestWifi", "bssid": "DE:AD:BE:EF:00:01", "vendor": "Cisco",
         "channel": 6, "rssi": -61, "encryption": "WPA2", "risk": "MEDIUM", "confidence": 52},
        {"ssid": "GuestWifi", "bssid": "DE:AD:BE:EF:00:02", "vendor": "Cisco",
         "channel": 6, "rssi": -63, "encryption": "WPA2", "risk": "MEDIUM", "confidence": 48},
    ]

def mock_rssi_history():
    now = datetime.now()
    rows = []
    for ssid in ["CafeNet (legit)", "CafeNet (TWIN)", "HomeRouter"]:
        base = {"CafeNet (legit)": -55, "CafeNet (TWIN)": -38, "HomeRouter": -47}[ssid]
        for i in range(20):
            t = now - timedelta(minutes=20-i)
            noise = random.randint(-4, 4)
            spike = 10 if (ssid == "CafeNet (TWIN)" and i > 12) else 0
            rows.append({"time": t, "ssid": ssid, "rssi": base + noise - spike})
    return pd.DataFrame(rows)

def mock_alerts():
    return [
        {"timestamp": "2024-01-15 14:32:01", "ssid": "CafeNet", "bssid": "FF:EE:DD:CC:BB:AA",
         "threat_type": "Security Mismatch + Signal Anomaly", "risk": "HIGH", "confidence": 94},
        {"timestamp": "2024-01-15 13:11:44", "ssid": "GuestWifi", "bssid": "DE:AD:BE:EF:00:01",
         "threat_type": "SSID Duplication", "risk": "MEDIUM", "confidence": 52},
        {"timestamp": "2024-01-14 09:05:22", "ssid": "FreeAirport", "bssid": "00:11:AA:BB:CC:FF",
         "threat_type": "Beacon Interval Anomaly", "risk": "HIGH", "confidence": 88},
    ]

# ─── Sidebar ─────────────────────────────────────────
with st.sidebar:
    st.markdown('<p class="detector-title">⚡ ET</p>', unsafe_allow_html=True)
    st.markdown("---")
    st.markdown('<p class="section-head">Controls</p>', unsafe_allow_html=True)
    scan_interval = st.slider("Scan interval (s)", 10, 120, 30)
    auto_refresh  = st.toggle("Auto-refresh", value=False)
    st.markdown("---")
    st.markdown('<p class="section-head">Filters</p>', unsafe_allow_html=True)
    risk_filter = st.multiselect("Risk level", ["HIGH", "MEDIUM", "SAFE"], default=["HIGH", "MEDIUM", "SAFE"])
    st.markdown("---")
    if st.button("▶  RUN SCAN"):
        st.toast("Scanning...", icon="⚡")
    if st.button("⊕  BUILD BASELINE"):
        st.toast("Building baseline profile", icon="📡")
    st.markdown("---")
    st.markdown('<p style="font-size:0.65rem;color:#444466;letter-spacing:1px;">EVILTWIN-DETECTOR v1.0.0<br>@btwvitznaresh</p>', unsafe_allow_html=True)

# ─── Header ──────────────────────────────────────────
st.markdown('<h1 class="detector-title">EVILTWIN DETECTOR</h1>', unsafe_allow_html=True)
st.markdown('<p style="color:#8888aa;font-size:0.75rem;letter-spacing:2px;margin-top:-0.5rem;">ROGUE ACCESS POINT MONITOR  ·  DEFENSIVE SECURITY</p>', unsafe_allow_html=True)

networks = mock_scan()
alerts   = mock_alerts()
filtered = [n for n in networks if n["risk"] in risk_filter]

# ─── Metrics ─────────────────────────────────────────
m1, m2, m3, m4, m5 = st.columns(5)
high_count = sum(1 for n in networks if n["risk"] == "HIGH")
med_count  = sum(1 for n in networks if n["risk"] == "MEDIUM")
safe_count = sum(1 for n in networks if n["risk"] == "SAFE")

m1.metric("🔴 HIGH",   high_count,  delta="⚠ THREAT" if high_count else None, delta_color="inverse")
m2.metric("🟡 MEDIUM", med_count)
m3.metric("🟢 SAFE",   safe_count)
m4.metric("📡 TOTAL",  len(networks))
m5.metric("🕐 LAST SCAN", datetime.now().strftime("%H:%M:%S"))

st.markdown("<br>", unsafe_allow_html=True)

# ─── Tabs ─────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["  LIVE SCAN  ", "  RSSI TIMELINE  ", "  ALERT HISTORY  ", "  BASELINE  "])

# ── Tab 1: Live Scan ──────────────────────────────────
with tab1:
    st.markdown('<p class="section-head">Nearby Access Points</p>', unsafe_allow_html=True)

    for net in filtered:
        risk = net["risk"]
        css_class = {"HIGH": "alert-high", "MEDIUM": "alert-medium"}.get(risk, "alert-safe")
        icon = {"HIGH": "⚠", "MEDIUM": "~", "SAFE": "●"}.get(risk, "●")
        color = {"HIGH": "#ff4444", "MEDIUM": "#ffaa00", "SAFE": "#00ff88"}.get(risk, "#00FFFF")

        st.markdown(f"""
        <div class="{css_class}">
          <span style="color:{color};font-weight:700;">{icon} {risk}</span>
          <span style="color:#8888aa;font-size:0.7rem;float:right;">confidence: {net['confidence']}/100</span><br>
          <span style="color:#00FFFF;">{net['ssid']}</span>
          <span style="color:#666688;margin-left:1rem;">{net['bssid']}</span>
          <span style="color:#8888aa;margin-left:1rem;">{net['vendor']}</span><br>
          <span style="color:#8888aa;font-size:0.7rem;">
            CH {net['channel']}  ·  {net['rssi']} dBm  ·  {net['encryption']}
          </span>
        </div>""", unsafe_allow_html=True)

# ── Tab 2: RSSI Timeline ──────────────────────────────
with tab2:
    st.markdown('<p class="section-head">RSSI Over Time</p>', unsafe_allow_html=True)
    df_rssi = mock_rssi_history()

    colors = {"CafeNet (legit)": "#00FFFF", "CafeNet (TWIN)": "#FF2222", "HomeRouter": "#BF00FF"}
    fig = go.Figure()
    for ssid in df_rssi["ssid"].unique():
        d = df_rssi[df_rssi["ssid"] == ssid]
        fig.add_trace(go.Scatter(
            x=d["time"], y=d["rssi"], mode="lines+markers",
            name=ssid,
            line=dict(color=colors.get(ssid, "#ffffff"), width=2),
            marker=dict(size=4),
        ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Signal Strength (dBm) — Sudden spike = Evil Twin", font=dict(color="#00FFFF", size=12)),
        legend=dict(bgcolor="#0d0d1a", bordercolor="rgba(123, 47, 190, 0.27)"),
        height=380,
    )
    fig.add_hline(y=-50, line_dash="dot", line_color="rgba(255, 68, 68, 0.27)",
                  annotation_text="Anomaly threshold", annotation_font_color="#ff4444", annotation_font_size=10)
    st.plotly_chart(fig, use_container_width=True)

# ── Tab 3: Alert History ──────────────────────────────
with tab3:
    st.markdown('<p class="section-head">Alert History</p>', unsafe_allow_html=True)
    risk_sel = st.selectbox("Filter by risk", ["ALL", "HIGH", "MEDIUM", "LOW"])
    filtered_alerts = alerts if risk_sel == "ALL" else [a for a in alerts if a["risk"] == risk_sel]

    for a in filtered_alerts:
        risk    = a["risk"]
        css     = {"HIGH": "alert-high", "MEDIUM": "alert-medium"}.get(risk, "alert-safe")
        color   = {"HIGH": "#ff4444", "MEDIUM": "#ffaa00"}.get(risk, "#00ff88")
        st.markdown(f"""
        <div class="{css}">
          <span style="color:{color};font-weight:700;">{risk}</span>
          <span style="color:#666688;font-size:0.7rem;float:right;">{a['timestamp']}</span><br>
          <span style="color:#00FFFF;">{a['ssid']}</span>
          <span style="color:#666688;margin-left:1rem;font-size:0.75rem;">{a['bssid']}</span><br>
          <span style="color:#8888aa;font-size:0.7rem;">{a['threat_type']}  ·  confidence: {a['confidence']}/100</span>
        </div>""", unsafe_allow_html=True)

    df_alerts = pd.DataFrame(filtered_alerts)
    if not df_alerts.empty:
        st.download_button("⬇  EXPORT CSV", df_alerts.to_csv(index=False).encode('utf-8'),
                           "alerts.csv", "text/csv")

# ── Tab 4: Baseline ───────────────────────────────────
with tab4:
    st.markdown('<p class="section-head">Trusted Network Baseline</p>', unsafe_allow_html=True)
    baseline = [
        {"ssid": "HomeRouter", "bssid": "11:22:33:44:55:66", "channel": 1,
         "rssi_min": -52, "rssi_max": -44, "encryption": "WPA3", "trusted": True},
    ]
    df_base = pd.DataFrame(baseline)
    st.dataframe(df_base, use_container_width=True, hide_index=True)

    col1, col2 = st.columns(2)
    with col1:
        new_bssid = st.text_input("Add trusted BSSID", placeholder="AA:BB:CC:DD:EE:FF")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("⊕  WHITELIST"):
            if new_bssid:
                st.success(f"✓ {new_bssid} added to whitelist")

if auto_refresh:
    time.sleep(scan_interval)
    st.rerun()
