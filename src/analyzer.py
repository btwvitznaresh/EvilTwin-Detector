import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

class ThreatAnalyzer:
    def __init__(self, config=None):
        self.config = config or {}
        # Load configuration or defaults
        self.whitelist_bssids = set(self.config.get("whitelist_bssids", []))
        self.risk_thresholds = self.config.get("risk_thresholds", {
            "signal_strength_diff": 10,
            "open_network_penalty": 50,
            "max_risk_score_allowed": 75
        })
        
        # historical data for signal profiling
        # Maps BSSID -> list of historical RSSI values
        self.history = defaultdict(list)

    def update_history(self, scan_results):
        """Update historical RSSI data for baseline profiling."""
        for bssid, data in scan_results.items():
            if data.get("RSSI") is not None:
                self.history[bssid].append(data["RSSI"])
                # Limit history size to the last 50 data points per AP to control memory usage
                if len(self.history[bssid]) > 50:
                    self.history[bssid].pop(0)

    def analyze(self, scan_results):
        """
        Analyze current scan results against models and historical datelines.
        Returns a list of alerts formatted with threat_type, risk_level, confidence, and reason.
        """
        self.update_history(scan_results)
        alerts = []

        # Sub-group APs by SSID to analyze networks that span multiple Access Points
        ssid_groups = defaultdict(list)
        for bssid, data in scan_results.items():
            ssid = data.get("SSID")
            if not ssid: 
                continue  # Skip hidden networks or unparsed SSIDs for these correlative checks
            ssid_groups[ssid].append(data)

        # 1. Group-based checks (SSID Duplication, Channel Conflict, Security Mismatch)
        for ssid, aps in ssid_groups.items():
            if len(aps) > 1:
                alerts.extend(self._check_ssid_duplication(ssid, aps))
                alerts.extend(self._check_channel_conflict(ssid, aps))
                alerts.extend(self._check_security_mismatch(ssid, aps))

        # 2. Individual AP checks (Signal anomaly, Beacon Intervals)
        for bssid, data in scan_results.items():
            if bssid in self.whitelist_bssids:
                logger.debug(f"BSSID {bssid} is whitelisted. Skipping anomaly checks.")
                continue
            
            alerts.extend(self._check_signal_anomaly(bssid, data))
            alerts.extend(self._check_beacon_interval(bssid, data))

        return alerts

    def _check_ssid_duplication(self, ssid, aps):
        """Method 1: SSID Duplication - same SSID, different BSSID"""
        alerts = []
        vendors = {ap.get("vendor_oui") for ap in aps if ap.get("vendor_oui")}
        
        # False positive handling: if all APs have the same vendor OUI, it's likely a legitimate corporate/mesh network.
        if len(vendors) == 1 and list(vendors)[0] not in [None, "Unknown"]:
            risk_level = "LOW"
            confidence = 30
            reason = f"Multiple BSSIDs for '{ssid}', but share identical Vendor OUI ({list(vendors)[0]}). Likely a legitimate mesh/corporate network."
        else:
            risk_level = "HIGH"
            confidence = 85
            reason = f"Multiple BSSIDs found for '{ssid}' with differing Vendor OUIs ({', '.join(filter(None, vendors))}). Strong Evil Twin indicator."
        
        # Additional Context: if a spoofed AP attempts to clone a whitelisted SSID but doesn't have a whitelisted BSSID.
        whitelisted_ap_count = sum(1 for ap in aps if ap.get("BSSID") in self.whitelist_bssids)
        if 0 < whitelisted_ap_count < len(aps):
             risk_level = "HIGH"
             confidence = 95
             reason = f"Rogue AP detected broadcasting whitelisted SSID '{ssid}' with an unauthorized MAC Address."

        alerts.append({
            "threat_type": "SSID_DUPLICATION",
            "risk_level": risk_level,
            "confidence_score": confidence,
            "reason": reason,
            "ssid": ssid,
            "affected_APs": [ap.get("BSSID") for ap in aps]
        })
        
        return alerts

    def _check_signal_anomaly(self, bssid, data):
        """Method 2: Signal Anomaly - RSSI spike vs baseline profile"""
        alerts = []
        rssi = data.get("RSSI")
        
        # We need historical data to baseline
        if rssi is None or len(self.history[bssid]) < 5:
            return alerts

        # Calculate a simple average baseline (excluding the most recent value)
        historical_values = self.history[bssid][:-1]
        baseline_avg = sum(historical_values) / len(historical_values)
        
        # A positive spike (e.g. from -70 to -40 implies it suddenly got much closer or stronger)
        diff = rssi - baseline_avg
        anomaly_threshold = self.risk_thresholds.get("signal_strength_diff", 10)
        
        if diff > anomaly_threshold:
            conf = min(100, 50 + int(diff * 1.5))
            alerts.append({
                "threat_type": "SIGNAL_ANOMALY",
                "risk_level": "MEDIUM" if diff < (anomaly_threshold + 15) else "HIGH",
                "confidence_score": conf,
                "reason": f"Sudden RSSI spike detected for BSSID {bssid}. Historical average: {baseline_avg:.1f} dBm, Current: {rssi} dBm. Potential proximity attack.",
                "bssid": bssid
            })
            
        return alerts

    def _check_channel_conflict(self, ssid, aps):
        """Method 3: Channel Conflict - same SSID on different channels"""
        alerts = []
        channels = {ap.get("channel") for ap in aps if ap.get("channel") is not None}
        
        # While mesh networks DO broadcast on different channels, coupled with SSID Duplication risk, it serves as metadata.
        if len(channels) > 1:
            alerts.append({
                "threat_type": "CHANNEL_CONFLICT",
                "risk_level": "MEDIUM",
                "confidence_score": 60,
                "reason": f"SSID '{ssid}' is overlapping on multiple active channels: {', '.join(map(str, channels))}.",
                "ssid": ssid
            })
            
        return alerts

    def _check_security_mismatch(self, ssid, aps):
        """Method 4: Security Mismatch - same SSID, different encryption"""
        alerts = []
        encryptions = {ap.get("encryption") for ap in aps if ap.get("encryption") is not None}
        
        if len(encryptions) > 1:
            if "Open" in encryptions or "OFF" in encryptions:
                alerts.append({
                    "threat_type": "SECURITY_MISMATCH",
                    "risk_level": "HIGH",
                    "confidence_score": 100,
                    "reason": f"Critical mismatch: Fake AP creating an open portal for '{ssid}'. Mixed encryption types observed ({', '.join(encryptions)}).",
                    "ssid": ssid
                })
            else:
                 alerts.append({
                    "threat_type": "SECURITY_MISMATCH",
                    "risk_level": "MEDIUM",
                    "confidence_score": 75,
                    "reason": f"Varying encryption states detected for SSID '{ssid}': {', '.join(encryptions)}.",
                    "ssid": ssid
                })
                 
        return alerts

    def _check_beacon_interval(self, bssid, data):
        """Method 5: Beacon Interval Anomaly - irregular beacon timing"""
        alerts = []
        bi = data.get("beacon_interval")
        
        if bi is None:
            return alerts
            
        # The 802.11 standard defaults Beacon Interval to 100 Time Units (102.4ms).
        # We flag values wildly outside typical manufacturing boundaries as they indicate software emulated APs.
        if bi < 50 or bi > 500:
            alerts.append({
                "threat_type": "BEACON_INTERVAL_ANOMALY",
                "risk_level": "LOW" if bi > 500 else "MEDIUM",
                "confidence_score": 70,
                "reason": f"Suspicious MAC Beacon Interval ({bi} TU) detected for BSSID {bssid}. Often associated with software-defined Rogue APs.",
                "bssid": bssid
            })
            
        return alerts

if __name__ == "__main__":
    # Test script execution
    logging.basicConfig(level=logging.INFO)
    analyzer = ThreatAnalyzer(config={"whitelist_bssids": ["00:11:22:33:44:55"]})
    
    mock_scan_data = {
        "AA:BB:CC:DD:EE:FF": {
            "SSID": "Corporate_Wifi", "BSSID": "AA:BB:CC:DD:EE:FF", 
            "channel": 1, "RSSI": -75, "encryption": "Encrypted", "vendor_oui": "Cisco", "beacon_interval": 100
        },
        # Evil Twin simulating the Corporate network
        "AA:BB:CC:DD:EE:FE": {
            "SSID": "Corporate_Wifi", "BSSID": "AA:BB:CC:DD:EE:FE", 
            "channel": 6, "RSSI": -40, "encryption": "Open", "vendor_oui": "Unknown", "beacon_interval": 20
        }
    }
    
    # Load history to simulate a previous scan where the good AP was further away
    analyzer.history["AA:BB:CC:DD:EE:FF"] = [-80, -82, -81, -85, -78]
    
    results = analyzer.analyze(mock_scan_data)
    for alert in results:
        print(f"[{alert['risk_level']}] {alert['threat_type']} (Conf: {alert['confidence_score']}): {alert['reason']}")
