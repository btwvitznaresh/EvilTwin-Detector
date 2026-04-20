from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys
import yaml
import json
import time
from datetime import datetime
from pathlib import Path

# Fix relative references
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Ensure required libraries and internal modules load successfully
try:
    from src.scanner import WifiScanner
    from src.analyzer import ThreatAnalyzer
    from src.baseline import BaselineManager
except ImportError as e:
    raise RuntimeError(f"Critical module hook failed securely: {e}")

app = FastAPI(
    title="EvilTwin Detector API",
    description="RESTful JSON bridge translating raw detector matrices into SIEM tools like Splunk or Wazuh.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Inject dynamic CORS integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

CONFIG_FILE = BASE_DIR / "config.yaml"
ALERTS_FILE = BASE_DIR / "logs/alerts.json"
BASELINE_FILE = BASE_DIR / "logs/baseline.json"

# In-Memory Tracking Data
SERVER_START_TIME = time.time()
LAST_SCAN_TIME = None

class WhitelistReq(BaseModel):
    bssid: str

def load_config():
    """Hook config structures."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}

def save_config(config_data):
    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config_data, f, default_flow_style=False)

@app.get("/scan", summary="Trigger Logical Grid Scan", tags=["Scanning & Detection"])
def trigger_scan():
    """
    Kicks off an active & passive sweep across the interface locking in anomalous packets directly.
    Returns complete array parameters fitting for SIEM aggregators.
    """
    global LAST_SCAN_TIME
    try:
        scanner = WifiScanner()
        analyzer = ThreatAnalyzer()
        baseline = BaselineManager()

        # Live Execute
        active = scanner.scan(timeout=3)
        passive = scanner.capture_beacons(timeout=3)
        
        merged = {**active}
        for b, data in passive.items():
             if b not in merged:
                 merged[b] = data
             else:
                 if data.get("beacon_interval"): merged[b]["beacon_interval"] = data["beacon_interval"]
                 if data.get("encryption") and data.get("encryption") != "Open": merged[b]["encryption"] = data["encryption"]
                 
        alerts = analyzer.analyze(merged)
        
        # Merge highest risk flags down to network parameters dynamically.
        bssid_risk = {}
        for a in alerts:
             rl = a["risk_level"]
             r_val = 3 if rl == "HIGH" else (2 if rl == "MEDIUM" else 1)
             affected = a.get("affected_APs", [a.get("bssid", "")])
             for ap in affected:
                 if ap not in bssid_risk or bssid_risk[ap][0] < r_val:
                     bssid_risk[ap] = (r_val, rl)

        results = []
        for bssid, data in merged.items():
            anom, _ = baseline.is_anomaly(data)
            
            data["risk_level"] = "SAFE"
            if anom:
                 data["risk_level"] = "SUSPICIOUS"
            
            if bssid in bssid_risk:
                 data["risk_level"] = bssid_risk[bssid][1]
                 
            results.append(data)

        LAST_SCAN_TIME = time.time()
        
        return {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "networks_detected": len(results),
            "threats_detected": len(alerts),
            "results": results,
            "alerts": alerts
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/alerts", summary="Poll Raw Threat Log Cache", tags=["Data Extraction"])
def get_alerts(risk_level: str = Query(None, description="Optional: STRICT search filter for 'HIGH', 'MEDIUM', or 'LOW'.")):
    """Extracts internal array alerts directly outwards into JSON."""
    if not ALERTS_FILE.exists():
         return {"total": 0, "alerts": []}
         
    try:
        with open(ALERTS_FILE, 'r') as f:
            content = f.read()
            alerts = json.loads(content) if content.strip() else []
            
        if risk_level:
             alerts = [a for a in alerts if a.get("risk_level", "").upper() == risk_level.upper()]
             
        # Newest alerts first for standard tail logic
        return {"total": len(alerts), "alerts": alerts[::-1]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Log structural fail: {e}")

@app.get("/baseline", summary="Poll Topological Standards Bound", tags=["Data Extraction"])
def get_baseline():
    """Poll recorded normal operational frequencies mapped locally dynamically."""
    if not BASELINE_FILE.exists():
        raise HTTPException(status_code=404, detail="Baseline JSON is empty/not found. Hook `cli.py --baseline` initially.")
        
    try:
         with open(BASELINE_FILE, 'r') as f:
             return json.load(f)
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))

@app.post("/whitelist", summary="Push Config Identifiers", tags=["Configuration Handling"])
def add_whitelist(req: WhitelistReq):
    """SIEM endpoints hook here natively allowing remote network approval loops over suspicious arrays."""
    try:
        bssid = req.bssid.upper()
        config = load_config()
        bssids = config.get("whitelist_bssids", [])
        
        if bssid not in bssids:
            bssids.append(bssid)
            config["whitelist_bssids"] = bssids
            save_config(config)
            return {"status": "success", "message": f"{bssid} approved into global bounds."}
        else:
            return {"status": "skipped", "message": f"{bssid} authorization pre-existing locally."}
            
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))


@app.get("/status", summary="Ping Detector Health Node", tags=["Network Status"])
def get_status():
    """Returns quick boolean properties reflecting live processing integrity limits."""
    uptime = time.time() - SERVER_START_TIME
    
    last_scan = "Never"
    if LAST_SCAN_TIME:
        last_scan = datetime.fromtimestamp(LAST_SCAN_TIME).isoformat()
        
    return {
        "status": "online",
        "uptime_seconds": round(uptime, 2),
        "last_scan": last_scan,
        "config_loaded": CONFIG_FILE.exists()
    }
