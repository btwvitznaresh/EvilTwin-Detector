import time
import json
import yaml
import sys
import logging
import requests
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.text import Text
except ImportError:
    pass # Managed gracefully within init

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self, config_path=None, alerts_file="logs/alerts.json"):
        project_root = Path(__file__).resolve().parent.parent
        self.config_path = config_path or project_root / "config.yaml"
        self.alerts_file = project_root / alerts_file
        
        # Ensure target logging directory exists
        self.alerts_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Rich dependency check
        try:
            self.console = Console()
        except NameError:
            self.console = None
            logger.warning("Rich library not loaded. Falling back to standard print.")
            
        self.webhook_url = self._load_config_webhook()
        
        # BSSID -> last_timestamp logic cache. Time constraint to limit fatigue.
        # Deduplicates consecutive alerts for identical AP sources within 5 minutes.
        self.last_alert_times = {}

    def _load_config_webhook(self):
        """Extracts the generic Webhook destination from the project config parameters."""
        if not self.config_path.exists():
            return None
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f) or {}
                return config.get('alert_webhook_url')
        except Exception as e:
            logger.error(f"Error loading webhook endpoint from config: {e}")
            return None

    def trigger_beep(self):
        """Cross-platform built-in terminal bell for high-acuity risks."""
        try:
            sys.stdout.write('\a')
            sys.stdout.flush()
        except:
            pass

    def send_webhook(self, alert_data):
        """Fires network payload containing formatted alert data to designated webhooks (e.g. Telegram/Slack/Discord via IFTTT)."""
        if not self.webhook_url or not self.webhook_url.startswith("http"):
             return
             
        try:
             # Formulates standard payload natively understandable by most bot integrations.
             msg = (f"🚨 HIGH RISK EVIL TWIN ALERT 🚨\n"
                    f"**SSID:** {alert_data['SSID']} | **BSSID:** {alert_data['BSSID']}\n"
                    f"**Threat:** {alert_data['threat_type']} (Conf: {alert_data['confidence_score']}%)\n"
                    f"**Reason:** {alert_data['reason']}")
             
             # Typical format structure
             payload = {"text": msg, "content": msg}
             
             # Add low-latency connection constraint so networking issues don't throttle the program
             requests.post(self.webhook_url, json=payload, timeout=3)
        except Exception as e:
             logger.error(f"Webhook dispatch failed dynamically: {e}")

    def save_alert(self, alert_data):
        """Persists structural findings inside logs module preserving historical metadata arrays."""
        alerts_list = []
        
        # Pull history securely.
        if self.alerts_file.exists():
             try:
                 with open(self.alerts_file, 'r') as f:
                     content = f.read()
                     if content.strip():
                         alerts_list = json.loads(content)
             except Exception as e:
                 logger.error(f"Error parsing historic alerts JSON logic limit: {e}")
                 # Force fallback empty array state to prevent cascading crashes.
                 alerts_list = []
        
        # Append and dump.
        alerts_list.append(alert_data)
        
        try:
            with open(self.alerts_file, 'w') as f:
                json.dump(alerts_list, f, indent=4)
        except Exception as e:
            logger.error(f"Error overwriting/saving combined alert architecture to JSON: {e}")

    def process_alerts(self, analyzer_alerts):
        """
        Takes raw dictionary inputs from the core Analyzer ruleset hooks. 
        Filters thresholds -> prints with high coloration -> invokes system hooks for Webhooks and Terminal warnings.
        """
        now = time.time()
        
        for alert in analyzer_alerts:
            # ThreatAnalyzer groupings may map the string format to individual "bssid" handles
            # OR as an array called "affected_APs" containing all MAC endpoints correlated to an attack geometry.
            bssid = str(alert.get("bssid", "")) or str(alert.get("affected_APs", "unknown_bssid"))
            
            # Deduplication Check (Blocks redundant processing inside 5m window intervals ~ 300 seconds)
            if bssid in self.last_alert_times:
                 if (now - self.last_alert_times[bssid]) < 300:
                     continue
            
            # Unlocked! Stamp the update constraint
            self.last_alert_times[bssid] = now
            
            # Build payload
            timestamp = datetime.now().isoformat()
            formatted_alert = {
                "timestamp": timestamp,
                "SSID": alert.get("ssid", "Unknown"),
                "BSSID": bssid,
                "threat_type": alert["threat_type"],
                "risk_level": alert["risk_level"],
                "confidence_score": alert["confidence_score"],
                "reason": alert["reason"]
            }
            
            # Flush alert physically to disk cache log.
            self.save_alert(formatted_alert)
            
            # Manage Rich Colorization UI hooks
            risk = alert["risk_level"]
            if self.console:
                color = "green"
                if risk == "HIGH":
                    color = "bold red"
                elif risk == "MEDIUM":
                    color = "bold yellow"
                    
                log_text = Text()
                log_text.append(f"[{timestamp}] ")
                log_text.append(f"[{risk}] ", style=color)
                log_text.append(f"{alert['threat_type']} (Conf {alert['confidence_score']}%): ")
                log_text.append(f"{alert['reason']}")
                self.console.print(log_text)
            else:
                 # Standard native python printing map for headless/non-rich environments
                 print(f"[{timestamp}] [{risk}] {alert['threat_type']} - {alert['reason']}")
            
            # Execute physical hardware bindings and external webhooks exclusively on high criticality.
            if risk == "HIGH":
                self.trigger_beep()
                self.send_webhook(formatted_alert)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    am = AlertManager()
    
    # Validation Simulator
    mock_high_alert = {
        "threat_type": "SECURITY_MISMATCH",
        "risk_level": "HIGH",
        "confidence_score": 100,
        "reason": "Different encryption states detected imitating SSID boundaries.",
        "ssid": "MyHomeNet",
        "bssid": "AA:BB:CC:DD:EE:FE"
    }
    mock_low_alert = {
        "threat_type": "SSID_DUPLICATION",
        "risk_level": "LOW",
        "confidence_score": 30,
        "reason": "Legitimate enterprise mesh nodes observed switching identical BSSID tokens.",
        "ssid": "MyHomeNet",
        "bssid": "AB:BC:CD:DE:EF:FF"
    }
    
    print("\n[!] Emitting Simulated Alerts...")
    am.process_alerts([mock_high_alert, mock_low_alert])
    print("[!] Testing Dedup. Re-emitting the same High Priority Alert. It should be blocked and remain silent.")
    am.process_alerts([mock_high_alert])
