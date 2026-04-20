import pytest
import sys
from pathlib import Path

# Fix relative module imports
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.analyzer import ThreatAnalyzer

@pytest.fixture
def analyzer():
    """Initializes the ThreatAnalyzer hooked onto isolated test limits and configs."""
    return ThreatAnalyzer(config={
        "risk_thresholds": {
             "signal_strength_diff": 10,
             "open_network_penalty": 50,
             "max_risk_score_allowed": 75
        },
        "whitelist_bssids": ["00:11:22:AA:BB:CC"]
    })

def test_normal_home_network(analyzer):
    """Assert normal networking yields entirely blank anomaly arrays."""
    mock_scan = {
        "AA:BB:CC:DD:EE:FF": {
            "SSID": "Standard_Home_Network",
            "BSSID": "AA:BB:CC:DD:EE:FF",
            "channel": 6,
            "RSSI": -65,
            "encryption": "Encrypted",
            "beacon_interval": 100,
            "vendor_oui": "Asus"
        }
    }
    alerts = analyzer.analyze(mock_scan)
    
    assert len(alerts) == 0
    assert len([a for a in alerts if a["risk_level"] == "HIGH"]) == 0

def test_ssid_duplication_detected(analyzer):
    """Assert mimicking AP hardware MAC mappings without corporate OUIs triggers HIGH threat bounds."""
    mock_scan = {
        "AA:BB:CC:DD:EE:FF": {
            "SSID": "Local_CoffeeShop",
            "BSSID": "AA:BB:CC:DD:EE:FF",
            "channel": 6,
            "vendor_oui": "Cisco"
        },
        "AA:BB:CC:DD:EE:EE": {
            "SSID": "Local_CoffeeShop",
            "BSSID": "AA:BB:CC:DD:EE:EE",
            "channel": 11,
            "vendor_oui": "Unknown" # Rogue Twin mimicking without hardware signature
        }
    }
    
    alerts = analyzer.analyze(mock_scan)
    dup_alerts = [a for a in alerts if a["threat_type"] == "SSID_DUPLICATION"]
    
    assert len(dup_alerts) == 1
    assert dup_alerts[0]["risk_level"] == "HIGH"
    assert dup_alerts[0]["ssid"] == "Local_CoffeeShop"
    assert "differing Vendor OUIs" in dup_alerts[0]["reason"]

def test_corporate_mesh_forgiveness(analyzer):
    """Assert large mesh grids broadcasting multiple MACs with identical Vendors downgrade flags effectively."""
    mock_scan = {
        "AA:BB:CC:DD:11:11": {
            "SSID": "CorpNet",
            "BSSID": "AA:BB:CC:DD:11:11",
            "vendor_oui": "Aruba"
        },
        "AA:BB:CC:DD:22:22": {
            "SSID": "CorpNet",
            "BSSID": "AA:BB:CC:DD:22:22",
            "vendor_oui": "Aruba"
        }
    }
    
    alerts = analyzer.analyze(mock_scan)
    dup_alerts = [a for a in alerts if a["threat_type"] == "SSID_DUPLICATION"]
    
    assert len(dup_alerts) == 1
    assert dup_alerts[0]["risk_level"] == "LOW"

def test_security_mismatch_wpa2_vs_open(analyzer):
    """Assert OPEN interfaces attempting to counterfeit Encrypted architectures triggers critical flags."""
    mock_scan = {
        "AA:BB:CC:00:11:22": {
            "SSID": "Enterprise_Secure",
            "BSSID": "AA:BB:CC:00:11:22",
            "encryption": "Encrypted",
        },
        "AA:BB:CC:00:11:33": {
            "SSID": "Enterprise_Secure",
            "BSSID": "AA:BB:CC:00:11:33",
            "encryption": "Open", # Attacker stripping locks
        }
    }
    
    alerts = analyzer.analyze(mock_scan)
    sec_alert = [a for a in alerts if a["threat_type"] == "SECURITY_MISMATCH"]
    
    assert len(sec_alert) == 1
    assert sec_alert[0]["risk_level"] == "HIGH"
    assert sec_alert[0]["confidence_score"] == 100

def test_minor_security_mismatch(analyzer):
    """Assert differing but locked encryption states generate softer warnings dynamically."""
    mock_scan = {
        "11:22:33:44:55:66": {
             "SSID": "Corp_A", "BSSID": "11:22:33:44:55:66", "encryption": "WPA2"
        },
        "11:22:33:44:55:77": {
             "SSID": "Corp_A", "BSSID": "11:22:33:44:55:77", "encryption": "WPA3"
        }
    }
    alerts = analyzer.analyze(mock_scan)
    sec_alert = [a for a in alerts if a["threat_type"] == "SECURITY_MISMATCH"]
    
    assert len(sec_alert) == 1
    assert sec_alert[0]["risk_level"] == "MEDIUM"

def test_beacon_interval_anomaly(analyzer):
    """Assert intervals escaping Standard IEEE bounds automatically trigger analysis hits."""
    mock_scan = {
        "BB:CC:DD:EE:FF:00": {
            "SSID": "Hacker_AP",
            "BSSID": "BB:CC:DD:EE:FF:00",
            "beacon_interval": 30, # Severely truncated packet limits (standard is 100 TU)
        }
    }
    
    alerts = analyzer.analyze(mock_scan)
    bi_alert = [a for a in alerts if a["threat_type"] == "BEACON_INTERVAL_ANOMALY"]
    
    assert len(bi_alert) == 1
    assert bi_alert[0]["risk_level"] == "MEDIUM"

def test_channel_hopping_conflict(analyzer):
    """Assert same network hopping across multiple distinct frequency bands generates overlapping warnings."""
    mock_scan = {
         "11:22:33:AA:BB:CC": {"SSID": "WIFI_NAME", "BSSID": "11:22:33:AA:BB:CC", "channel": 1},
         "11:22:33:AA:BB:DD": {"SSID": "WIFI_NAME", "BSSID": "11:22:33:AA:BB:DD", "channel": 8}
    }
    
    alerts = analyzer.analyze(mock_scan)
    chan_alerts = [a for a in alerts if a["threat_type"] == "CHANNEL_CONFLICT"]
    
    assert len(chan_alerts) == 1
    assert chan_alerts[0]["risk_level"] == "MEDIUM"

def test_signal_strength_proximity_spike(analyzer):
    """Assert sudden overwhelming strength bursts relative to cached histories trips physical boundary attacks."""
    analyzer.history["AA:BB:CC:DD:EE:FF"] = [-80, -82, -81, -85, -78] # Safe ambient noise caching
    
    mock_scan = {
         "AA:BB:CC:DD:EE:FF": {
             "SSID": "Far_Target",
             "BSSID": "AA:BB:CC:DD:EE:FF",
             "RSSI": -30 # Target explodes physically next to system bounds
         }
    }
    
    alerts = analyzer.analyze(mock_scan)
    sig_alert = [a for a in alerts if a["threat_type"] == "SIGNAL_ANOMALY"]
    
    assert len(sig_alert) == 1
    assert sig_alert[0]["risk_level"] == "HIGH"
    
def test_whitelisted_bssid_bypasses(analyzer):
    """Assert configurations actively dodge processing limits mapping heavily skewed results."""
    # "00:11:22:AA:BB:CC" is vaulted intrinsically globally across our setup hook 
    mock_scan = {
        "00:11:22:AA:BB:CC": {
            "SSID": "DevNet",
            "BSSID": "00:11:22:AA:BB:CC",
            "beacon_interval": 20, # Explicit anomaly bounds
            "RSSI": -20
        }
    }
    alerts = analyzer.analyze(mock_scan)
    # Whitelisting overrides beacon and raw anomaly scans internally completely.
    bi_alert = [a for a in alerts if a["threat_type"] == "BEACON_INTERVAL_ANOMALY"]
    assert len(bi_alert) == 0

def test_whitelisted_spoof_detection(analyzer):
    """Assert spoof attempts copying securely configured SSIDs but lacking authorized MAC hashes fail spectacularly."""
    mock_scan = {
         "00:11:22:AA:BB:CC": { # Trusted Safe Route 
              "SSID": "Private_Corp_WIFI", "BSSID": "00:11:22:AA:BB:CC", "vendor_oui": "Cisco"
         },
         "AA:BB:CC:DD:EE:FF": { # Unknown Rogue Twin Attack Vector
              "SSID": "Private_Corp_WIFI", "BSSID": "AA:BB:CC:DD:EE:FF", "vendor_oui": "Unknown"
         }
    }
    
    alerts = analyzer.analyze(mock_scan)
    dup_alert = [a for a in alerts if a["threat_type"] == "SSID_DUPLICATION"]
    
    assert len(dup_alert) == 1
    assert dup_alert[0]["risk_level"] == "HIGH"
    assert dup_alert[0]["confidence_score"] == 95 # Specifically bumps up confidence natively over mimic overlaps
    assert "unauthorized MAC" in dup_alert[0]["reason"]
