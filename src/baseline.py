import json
import yaml
import time
import logging
from datetime import datetime
from pathlib import Path

# Important: ensure scanner exists in the identical module
try:
    from .scanner import WifiScanner
except ImportError:
    from scanner import WifiScanner

logger = logging.getLogger(__name__)

class BaselineManager:
    def __init__(self, config_path=None, baseline_path="logs/baseline.json"):
        project_root = Path(__file__).resolve().parent.parent
        self.baseline_path = project_root / baseline_path
        self.config_path = config_path or project_root / "config.yaml"
        
        self.whitelist = self._load_whitelist()
        self.baseline_data = self._load_baseline()

    def _load_whitelist(self):
        """Load globally trusted MAC addresses from config.yaml"""
        if not self.config_path.exists():
            return []
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
                # Return BSSIDs properly standardized to upper-case
                return [b.upper() for b in config.get('whitelist_bssids', [])]
        except Exception as e:
            logger.error(f"Error loading config whitelist: {e}")
            return []

    def _load_baseline(self):
        """Load historical baseline snapshot from JSON log."""
        if not self.baseline_path.exists():
            return {}
        try:
            with open(self.baseline_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading baseline JSON: {e}")
            return {}

    def save_baseline(self):
        """Export current memory structure to JSON."""
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self.baseline_path, 'w') as f:
                json.dump(self.baseline_data, f, indent=4)
            logger.info(f"Baseline saved successfully to {self.baseline_path}")
        except Exception as e:
            logger.error(f"Error saving baseline: {e}")

    def get_time_bucket(self):
        """Assign current time to morning, afternoon, or night."""
        hour = datetime.now().hour
        if 6 <= hour < 12:
            return "morning"
        elif 12 <= hour < 18:
            return "afternoon"
        else:
            return "night"

    def build_baseline(self, num_scans=10, duration_mins=5, target_ssid=None):
        """
        Execute iterative scans mapping out trusted network topography.
        Combines Scapy Passive + System Active mapping modes.
        """
        logger.info(f"Starting baseline build: {num_scans} scans over {duration_mins} minutes...")
        scanner = WifiScanner()
        delay_seconds = (duration_mins * 60) / num_scans
        
        # Intermediate holder: ssid -> bssid -> list of metrics
        raw_data = {}
        
        for i in range(num_scans):
            logger.info(f"Capturing Baseline state [{i+1}/{num_scans}]...")
            
            # Combine methods: Capture explicit info with PyWiFi/Iwlist, grab deeper intervals with Beacons
            active = scanner.scan(timeout=3)
            passive = scanner.capture_beacons(timeout=5)
            
            merged = {**active}
            for bssid, data in passive.items():
                if bssid not in merged:
                    merged[bssid] = data
                else:
                    if data.get("beacon_interval") is not None:
                        merged[bssid]["beacon_interval"] = data["beacon_interval"]
                    if data.get("encryption") not in [None, "Open"]: 
                        merged[bssid]["encryption"] = data["encryption"]
            
            for bssid, data in merged.items():
                ssid = data.get("SSID")
                if not ssid:
                     continue
                if target_ssid and ssid != target_ssid:
                     continue
                     
                if ssid not in raw_data:
                    raw_data[ssid] = {}
                if bssid not in raw_data[ssid]:
                    raw_data[ssid][bssid] = []
                    
                raw_data[ssid][bssid].append({
                    "rssi": data.get("RSSI"),
                    "channel": data.get("channel"),
                    "encryption": data.get("encryption"),
                    "beacon_interval": data.get("beacon_interval"),
                    "bucket": self.get_time_bucket()
                })
            
            if i < num_scans - 1:
                logger.info(f"Sleeping for {delay_seconds:.1f}s until next block...")
                time.sleep(delay_seconds)
                
        # Transform intermediate recordings into constrained baseline limits
        for ssid, bssids in raw_data.items():
            if ssid not in self.baseline_data:
                self.baseline_data[ssid] = {
                    "trusted_bssids": [],
                    "expected_channels": [],
                    "encryption_type": None,
                    "profiles": {
                        "morning": {},
                        "afternoon": {},
                        "night": {}
                    }
                }
            
            ref = self.baseline_data[ssid]
            for bssid, entries in bssids.items():
                if bssid not in ref["trusted_bssids"]:
                    ref["trusted_bssids"].append(bssid)
                
                for entry in entries:
                    if entry["channel"] and entry["channel"] not in ref["expected_channels"]:
                        ref["expected_channels"].append(entry["channel"])
                    
                    if entry["encryption"] and not ref["encryption_type"]:
                         ref["encryption_type"] = entry["encryption"]
                         
                    bucket = entry["bucket"]
                    if bssid not in ref["profiles"][bucket]:
                        # Default high/low bounds inverted safely
                        ref["profiles"][bucket][bssid] = {
                            "rssi_min": 100, "rssi_max": -150,
                            "bi_min": 9999, "bi_max": 0
                        }
                    
                    prof = ref["profiles"][bucket][bssid]
                    
                    if entry["rssi"] is not None:
                        prof["rssi_min"] = min(prof["rssi_min"], entry["rssi"])
                        prof["rssi_max"] = max(prof["rssi_max"], entry["rssi"])
                        
                    if entry["beacon_interval"] is not None:
                        prof["bi_min"] = min(prof["bi_min"], entry["beacon_interval"])
                        prof["bi_max"] = max(prof["bi_max"], entry["beacon_interval"])
                        
        self.save_baseline()
        logger.info("Baseline process comprehensively compiled.")

    def is_anomaly(self, ap_data):
        """
        Live-scan hook. Given a current AP packet, compares it against its baseline standard.
        Returns: `(is_anomalous: bool, reason: str)`
        """
        ssid = ap_data.get("SSID")
        bssid = ap_data.get("BSSID")
        channel = ap_data.get("channel")
        rssi = ap_data.get("RSSI")
        encryption = ap_data.get("encryption")
        bi = ap_data.get("beacon_interval")
        
        # Ignore unsupported / unregistered networks
        if not ssid or ssid not in self.baseline_data:
            return False, "Not Baselined"
            
        base = self.baseline_data[ssid]
        
        # 1. Config.yaml Manual Whitelist Bypass
        if bssid in self.whitelist:
            return False, "Globally Whitelisted BSSID"
            
        # 2. Trusted Topology Mismatch (Attackers simulating names)
        if bssid not in base["trusted_bssids"]:
            return True, f"Unrecognized Identity: BSSID {bssid} not registered in topology for '{ssid}'"
            
        # 3. Encryption Security Down-grade Attempts
        if encryption and base["encryption_type"]:
            # Primary logic flags Open/Encrypted clashes, softer differences (WPA vs WPA2) are sometimes natural.
            if "Open" in encryption and "Encrypted" in base["encryption_type"]:
                return True, f"Security Disparity: Legitimate {ssid} is encrypted, but detected as {encryption}"
                
        # 4. Unknown Frequency Jumps
        if channel is not None and base["expected_channels"]:
            if channel not in base["expected_channels"]:
                return True, f"Channel Displacement: Network is operating on freq {channel}, differing from expected {base['expected_channels']}"
                
        # 5. Temporal Parameter Analysis
        bucket = self.get_time_bucket()
        profile = base["profiles"].get(bucket, {}).get(bssid)
        if profile:
            # RSSI bounds (+/- 15 dBm situational tolerance)
            if rssi is not None and profile["rssi_max"] != -150:
                if rssi < profile["rssi_min"] - 15 or rssi > profile["rssi_max"] + 15:
                    return True, f"Signal Rupture: RSSI {rssi} sits sharply outside {bucket} bounds [{profile['rssi_min']-15}, {profile['rssi_max']+15}]"
            
            # Beacon Interval (+/- 5 TU clock tolerance) 
            if bi is not None and profile["bi_min"] != 9999:
                 if bi < profile["bi_min"] - 5 or bi > profile["bi_max"] + 5:
                     return True, f"Interval Skew: Beacon ({bi} TU) mismatched to baseline footprint."
                     
        return False, "Normal"


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    bm = BaselineManager()
    
    # Mock behavior block to verify engine
    bm.baseline_data["MyHomeNetwork"] = {
        "trusted_bssids": ["00:11:22:33:44:55"],
        "expected_channels": [6],
        "encryption_type": "Encrypted",
        "profiles": {
            bm.get_time_bucket(): {
                "00:11:22:33:44:55": {
                    "rssi_min": -70, "rssi_max": -50,
                    "bi_min": 100, "bi_max": 100
                }
            }
        }
    }
    
    # Validation
    safe_data = {"SSID": "MyHomeNetwork", "BSSID": "00:11:22:33:44:55", "channel": 6, "RSSI": -55, "encryption": "Encrypted", "beacon_interval": 100}
    bad_channel_data = {"SSID": "MyHomeNetwork", "BSSID": "00:11:22:33:44:55", "channel": 1, "RSSI": -55, "encryption": "Encrypted"}
    bad_mac_data = {"SSID": "MyHomeNetwork", "BSSID": "AA:BB:CC:DD:EE:FF", "channel": 6, "RSSI": -55, "encryption": "Encrypted"}
    bad_rssi_data = {"SSID": "MyHomeNetwork", "BSSID": "00:11:22:33:44:55", "channel": 6, "RSSI": -30, "encryption": "Encrypted"}
    
    print("Test 1 (Safe):", bm.is_anomaly(safe_data))
    print("Test 2 (Rogue Channel):", bm.is_anomaly(bad_channel_data))
    print("Test 3 (Rogue MAC):", bm.is_anomaly(bad_mac_data))
    print("Test 4 (Sudden Proximity Spike):", bm.is_anomaly(bad_rssi_data))
