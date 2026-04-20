import streamlit as st
import pandas as pd
import plotly.express as px
import time
import json
import yaml
import sys
from pathlib import Path
from datetime import datetime

# Adjust Python Path to link `src` modules dynamically.
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

try:
    from src.scanner import WifiScanner
    from src.analyzer import ThreatAnalyzer
    from src.baseline import BaselineManager
except ImportError as e:
    st.error(f"Module linking failed. Ensure `dashboard.py` sits at project root outside of `/src`. Error: {e}")
    st.stop()

# Environment Hooks
ALERTS_FILE = BASE_DIR / "logs/alerts.json"
CONFIG_FILE = BASE_DIR / "config.yaml"
BASELINE_FILE = BASE_DIR / "logs/baseline.json"

# === STREAMLIT CONFIGURATION ===
st.set_page_config(
    page_title="EvilTwin Dashboard",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# === CYBERSECURITY STYLING (DARK PALETTE) ===
st.markdown("""
<style>
    /* Dark Terminal Override */
    [data-testid="stAppViewContainer"] {
        background-color: #0A0A0A;
        color: #00FF41; 
    }
    [data-testid="stSidebar"] {
        background-color: #121212;
        border-right: 1px solid #00FF41;
    }
    h1, h2, h3 {
        color: #00FF41 !important;
        font-family: 'Courier New', Courier, monospace;
    }
    /* Typography Overrides */
    p, span, div.stMarkdown {
        font-family: 'Consolas', monospace;
    }
    /* DataFrame Native Overrides */
    .stDataFrame {
        font-family: 'Consolas', Courier, monospace;
    }
    /* Buttons */
    .stButton>button {
        background-color: #121212;
        color: #00FF41;
        border: 1px solid #00FF41;
    }
    .stButton>button:hover {
        background-color: #00FF41;
        color: #000000;
    }
</style>
""", unsafe_allow_html=True)

# === SHARED DATA LOADERS ===
@st.cache_data(ttl=2)
def get_alerts():
    if not ALERTS_FILE.exists():
        return []
    try:
        with open(ALERTS_FILE, 'r') as f:
             content = f.read()
             return json.loads(content) if content.strip() else []
    except Exception:
        return []

def load_config():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}

def save_config(config_data):
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config_data, f, default_flow_style=False)

# === TOP THREAT BADGES ===
alerts_cache = get_alerts()
high_count = sum(1 for a in alerts_cache if a.get("risk_level") == "HIGH")
med_count = sum(1 for a in alerts_cache if a.get("risk_level") == "MEDIUM")
low_count = sum(1 for a in alerts_cache if a.get("risk_level") == "LOW")

st.markdown(f"""
<div style='display:flex; justify-content:space-around; margin-bottom: 2rem; margin-top: -3rem;'>
    <div style='background-color:#2a0808; padding:15px; border-radius:8px; border:2px solid #FF3B30; width:30%; text-align:center; box-shadow: 0px 0px 10px #FF3B3055;'>
        <h2 style='margin:0; color:#FF3B30; font-size: 28px;'>🔴 HIGH Lvl: {high_count}</h2>
    </div>
    <div style='background-color:#2a2a08; padding:15px; border-radius:8px; border:2px solid #FFCC00; width:30%; text-align:center; box-shadow: 0px 0px 10px #FFCC0055;'>
        <h2 style='margin:0; color:#FFCC00; font-size: 28px;'>🟡 MED Lvl: {med_count}</h2>
    </div>
    <div style='background-color:#082a15; padding:15px; border-radius:8px; border:2px solid #34C759; width:30%; text-align:center; box-shadow: 0px 0px 10px #34C75955;'>
        <h2 style='margin:0; color:#34C759; font-size: 28px;'>🟢 LOW Lvl: {low_count}</h2>
    </div>
</div>
""", unsafe_allow_html=True)


# === NAVIGATION ===
page = st.sidebar.radio("Navigation Protocol", ["Live Scan", "RSSI Timeline", "Alert History", "Baseline Manager"])


# === PAGE: LIVE SCAN ===
if page == "Live Scan":
    st.subheader("📡 Live Network Sweep")
    auto_refresh = st.checkbox("Enable Auto-Refresh Sequence (10s lock)")
    
    # Session state mappings
    if 'history_log' not in st.session_state:
        st.session_state.history_log = []

    def run_sweep():
        scanner = WifiScanner()
        analyzer = ThreatAnalyzer()
        baseline = BaselineManager()
        
        # Pull active layer directly for GUI speeds
        active = scanner.scan(timeout=3)
        res_list = []
        for bssid, data_map in active.items():
            anom, _ = baseline.is_anomaly(data_map)
            data_map["Risk"] = "UNKNOWN"
            if anom:
                data_map["Risk"] = "MEDIUM"
            res_list.append(data_map)
            
        threat_data = analyzer.analyze(active)
        
        # Isolate specific AP risks hooking into analyzer matrix
        bssid_risk = {}
        for a in threat_data:
             rl = a["risk_level"]
             r_val = 3 if rl == "HIGH" else (2 if rl == "MEDIUM" else 1)
             affected = a.get("affected_APs", [a.get("bssid", "")])
             for ap in affected:
                 if ap not in bssid_risk or bssid_risk[ap][0] < r_val:
                     bssid_risk[ap] = (r_val, rl)
                     
        for row in res_list:
             if row["BSSID"] in bssid_risk:
                 row["Risk"] = bssid_risk[row["BSSID"]][1]
             if row["Risk"] == "UNKNOWN":
                 row["Risk"] = "SAFE"
                 
        return res_list
        
    def highlight_dataframe_rows(row):
        """Native pandas styler hooking red/yellow alerts."""
        if row['Risk'] == 'HIGH':
            return ['background-color: #4a0000; color: #ff6666'] * len(row)
        elif row['Risk'] == 'MEDIUM':
            return ['background-color: #4a4a00; color: #ffff66'] * len(row)
        return [''] * len(row)

    if st.button("Initialize Deep Scan") or auto_refresh:
        with st.spinner("{ System Scanning Active Matrices }"):
             res = run_sweep()
             
             # Map timelines outwards over RSSI hook loops
             now = datetime.now()
             for r in res:
                 st.session_state.history_log.append({
                     "Timestamp": now,
                     "SSID": r.get("SSID", "<Hidden>"),
                     "BSSID": r["BSSID"],
                     "RSSI": r["RSSI"]
                 })
                 
             df = pd.DataFrame(res)
             if not df.empty:
                 display_df = df[["SSID", "BSSID", "vendor_oui", "channel", "RSSI", "encryption", "Risk"]]
                 st.dataframe(display_df.style.apply(highlight_dataframe_rows, axis=1), use_container_width=True)
             else:
                 st.warning("No targets locked. Signal clean.")
                 
    if auto_refresh:
         time.sleep(10)
         st.rerun()

# === PAGE: RSSI TIMELINE ===
elif page == "RSSI Timeline":
    st.subheader("📈 RSSI Telemetry Log")
    if 'history_log' in st.session_state and st.session_state.history_log:
        df_hist = pd.DataFrame(st.session_state.history_log)
        
        ssids = df_hist["SSID"].unique()
        selected_ssid = st.selectbox("Select Access Point SSID Focus Array:", ssids)
        filtered = df_hist[df_hist["SSID"] == selected_ssid]
        
        # Inject standard dark mode mappings natively.
        fig = px.line(filtered, x="Timestamp", y="RSSI", color="BSSID", markers=True, title=f"Raw RSSI Topology: {selected_ssid}")
        fig.update_layout(template="plotly_dark", paper_bgcolor="#0A0A0A", plot_bgcolor="#111111", font=dict(family="Courier New", color="#00FF41"))
        fig.update_traces(line=dict(width=3), marker=dict(size=8))
        
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("[/] Array empty. Execute 'Live Scan' sequence previously to buffer session telemetry.")

# === PAGE: ALERT HISTORY ===
elif page == "Alert History":
    st.subheader("☠️ Threat Log History")
    
    if alerts_cache:
        df_alerts = pd.DataFrame(alerts_cache)
        df_alerts['Date'] = pd.to_datetime(df_alerts['timestamp']).dt.date
        
        col_f1, col_f2 = st.columns(2)
        risk_filter = col_f1.multiselect("Severity Lock:", options=["HIGH", "MEDIUM", "LOW"], default=["HIGH", "MEDIUM", "LOW"])
        dates = df_alerts['Date'].unique()
        date_filter = col_f2.multiselect("Chronological Filter:", options=dates, default=dates)
        
        filtered_df = df_alerts[df_alerts['risk_level'].isin(risk_filter) & df_alerts['Date'].isin(date_filter)]
        
        def highlight_alert_history(row):
             if row['risk_level'] == 'HIGH':
                 return ['background-color: #3b0a0a; color: #ff6666'] * len(row)
             elif row['risk_level'] == 'MEDIUM':
                 return ['background-color: #3b3b0a; color: #ffff66'] * len(row)
             return [''] * len(row)
             
        if not filtered_df.empty:
            st.dataframe(filtered_df.drop(columns=['Date'], errors='ignore').style.apply(highlight_alert_history, axis=1), use_container_width=True)
        else:
            st.warning("Filters blocked results.")
    else:
        st.info("No recorded security breaks in cache structure.")

# === PAGE: BASELINE MANAGER ===
elif page == "Baseline Manager":
    st.subheader("🔒 Topology Baselining & Trust Bounds")
    
    config = load_config()
    whitelist = config.get("whitelist_bssids", [])
    
    st.write("### Root Identity Whitelist")
    with st.form("whitelist_add_form"):
        colA, colB = st.columns([3, 1])
        new_bssid = colA.text_input("Push secure MAC (BSSID) identity override (e.g. 00:11...):")
        submitted = colB.form_submit_button("Grant Trust Matrix")
        
        if submitted and new_bssid:
            safe_bssid = new_bssid.upper()
            if safe_bssid not in whitelist:
                whitelist.append(safe_bssid)
                config["whitelist_bssids"] = whitelist
                save_config(config)
                st.success(f"Deployed {safe_bssid} upwards to trusted roots.")
                time.sleep(1)
                st.rerun()
            else:
                st.warning("Identity previously vaulted.")
                
    if whitelist:
        st.markdown("**(Currently Handled Permissions:)**")
        for w in whitelist:
             cols = st.columns([4, 1])
             cols[0].code(w)
             if cols[1].button("Revoke Security", key=f"del_{w}"):
                 whitelist.remove(w)
                 config["whitelist_bssids"] = whitelist
                 save_config(config)
                 st.rerun()
                 
    st.markdown("---")
    st.write("### Network Baseline Profiles Extracted Array")
    if BASELINE_FILE.exists():
        with open(BASELINE_FILE, 'r') as f:
            st.json(json.load(f), expanded=False)
    else:
        st.info("No network shape baseline snapshot generated. Deploy `python src/cli.py --baseline` over terminal arrays.")
