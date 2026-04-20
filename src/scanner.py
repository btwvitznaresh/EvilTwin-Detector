import os
import sys
import time
import logging
import subprocess
import requests
from pathlib import Path

# Try importing the required third-party libraries gracefully
try:
    from scapy.all import sniff
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
except ImportError:
    logging.warning("Scapy is not installed. Beacon frame capturing will be unavailable.")

try:
    import pywifi
except ImportError:
    logging.warning("Pywifi is not installed. Standard scanning might fail on Windows/Mac.")

logger = logging.getLogger(__name__)

OUI_URL = "http://standards-oui.ieee.org/oui/oui.txt"
OUI_FILE = Path(__file__).parent.parent / "assets" / "oui.txt"


class WifiScanner:
    def __init__(self, interface=None):
        self.interface = interface
        self.oui_db = self._load_oui_database()

    def _load_oui_database(self):
        """Load the IEEE OUI database from the local file to resolve vendor names."""
        db = {}
        if not OUI_FILE.exists():
            logger.warning(f"OUI file not found at {OUI_FILE}. IEEE lookup will be limited.")
            return db

        try:
            with open(OUI_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if "(hex)" in line:
                        parts = line.split("(hex)")
                        mac_prefix = parts[0].strip().replace("-", ":").upper()
                        vendor = parts[1].strip()
                        db[mac_prefix] = vendor
            logger.info(f"Successfully loaded {len(db)} OUI records.")
        except Exception as e:
            logger.error(f"Error reading OUI database: {e}")
            
        return db

    def get_vendor_from_bssid(self, bssid):
        """Lookup BSSID vendor from OUI database."""
        if not bssid:
            return "Unknown"
        
        # BSSID format expected: XX:XX:XX:XX:XX:XX
        prefix = bssid[:8].upper()
        return self.oui_db.get(prefix, "Unknown")
        
    def download_oui_db(self):
        """Helper to download the OUI database if missing."""
        logger.info(f"Downloading IEEE OUI database to {OUI_FILE}...")
        try:
            OUI_FILE.parent.mkdir(parents=True, exist_ok=True)
            response = requests.get(OUI_URL, timeout=30)
            response.raise_for_status()
            
            with open(OUI_FILE, 'w', encoding='utf-8') as f:
                f.write(response.text)
            logger.info("Successfully downloaded OUI database.")
            self.oui_db = self._load_oui_database() # Reload it
        except Exception as e:
            logger.error(f"Failed to download OUI database: {e}")

    def scan(self, timeout=10):
        """Main method to map active scans based on operating system."""
        results = {}
        try:
            if sys.platform.startswith('linux'):
                results = self._scan_linux()
            else:
                results = self._scan_pywifi(timeout)
        except Exception as e:
            logger.error(f"Error during active scanning: {e}")
            
        return results
        
    def _scan_pywifi(self, timeout=10):
        """Fallback active scan implementation using pywifi (Windows / macOS)."""
        logger.info("Scanning using pywifi (Windows/macOS fallback)...")
        results = {}
        
        if 'pywifi' not in sys.modules:
            logger.error("Cannot perform pywifi scan: pywifi module not loaded.")
            return results

        try:
            wifi = pywifi.PyWiFi()
            ifaces = wifi.interfaces()
            if not ifaces:
                logger.error("No Wi-Fi interfaces found by pywifi.")
                return results
                
            iface = ifaces[0]
            if self.interface:
                for i in ifaces:
                    if i.name() == self.interface:
                        iface = i
                        break

            iface.scan()
            time.sleep(timeout)
            scan_results = iface.scan_results()

            for ap in scan_results:
                bssid = ap.bssid
                if isinstance(bssid, str):
                    bssid = bssid.upper()
                    if len(bssid) == 12:
                        bssid = ":".join(bssid[i:i+2] for i in range(0, 12, 2))

                results[bssid] = {
                    "SSID": ap.ssid,
                    "BSSID": bssid,
                    "channel": ap.freq, 
                    "RSSI": ap.signal,
                    "encryption": ap.akm, 
                    "beacon_interval": None, # Usually hard to get via PyWiFi exactly
                    "vendor_oui": self.get_vendor_from_bssid(bssid),
                    "source": "pywifi"
                }

        except Exception as e:
            logger.error(f"pywifi scanning failed: {e}")
            
        return results

    def _scan_linux(self):
        """Primary active scan implementation using iwlist for Linux environments."""
        logger.info("Scanning using iwlist (Linux)...")
        results = {}
        iface = self.interface or "wlan0"
        
        try:
            # Note: sudo may require passwordless sudo setup
            cmd = ["sudo", "iwlist", iface, "scan"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            
            current_ap = {}
            for line in output.split('\n'):
                line = line.strip()
                if line.startswith("Cell"):
                    if current_ap and 'BSSID' in current_ap:
                        results[current_ap['BSSID']] = current_ap
                    current_ap = {"source": "iwlist"}
                    parts = line.split("Address:")
                    if len(parts) > 1:
                        bssid = parts[1].strip().upper()
                        current_ap['BSSID'] = bssid
                        current_ap['vendor_oui'] = self.get_vendor_from_bssid(bssid)
                elif "ESSID:" in line:
                    current_ap['SSID'] = line.split("ESSID:")[1].strip().strip('"')
                elif "Channel:" in line:
                    current_ap['channel'] = int(line.split("Channel:")[1].strip())
                elif "Signal level=" in line:
                    current_ap['RSSI'] = int(line.split("Signal level=")[1].split(" ")[0].strip())
                elif "Encryption key:" in line:
                    enc = line.split("Encryption key:")[1].strip()
                    current_ap['encryption'] = "ON" if enc == "on" else "OFF"
                    
            if current_ap and 'BSSID' in current_ap:
                results[current_ap['BSSID']] = current_ap
                
        except Exception as e:
            logger.error(f"iwlist scanning failed: {e}")
            
        return results

    def capture_beacons(self, timeout=10):
        """Listen passively for 802.11 beacon frames using Scapy to detect hidden networks and raw headers."""
        logger.info(f"Capturing 802.11 beacon frames using scapy for {timeout} seconds...")
        results = {}
        
        if 'scapy.all' not in sys.modules:
             logger.error("Scapy is not loaded. Cannot capture beacon frames.")
             return results
        
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                try:
                    bssid = pkt[Dot11].addr2
                    if not bssid:
                        return
                    
                    bssid = bssid.upper()
                    if bssid not in results:
                        ssid = ""
                        
                        if pkt.haslayer(Dot11Elt):
                            # Try to extract SSID
                            elt = pkt[Dot11Elt]
                            while isinstance(elt, Dot11Elt):
                                if elt.ID == 0:  # SSID
                                    ssid = elt.info.decode('utf-8', errors='ignore')
                                    break
                                elt = elt.payload if hasattr(elt, 'payload') else None

                        # Extract channel
                        channel = None
                        elt = pkt[Dot11Elt]
                        while isinstance(elt, Dot11Elt):
                            if elt.ID == 3:  # DS Parameter Set (Channel)
                                if len(elt.info) > 0:
                                    channel = elt.info[0]
                                break
                            elt = elt.payload if hasattr(elt, 'payload') else None

                        # Extract Beacon Interval
                        beacon_interval = pkt[Dot11Beacon].beacon_interval
                        
                        # Extract RSSI via RadioTap
                        rssi = None
                        if pkt.haslayer(RadioTap):
                            rt = pkt[RadioTap]
                            if hasattr(rt, "dBm_AntSignal"):
                                rssi = rt.dBm_AntSignal

                        # Basic encryption check
                        capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
                        encryption = "Open"
                        if "privacy" in capability:
                            encryption = "Encrypted"
                            
                        results[bssid] = {
                            "SSID": ssid,
                            "BSSID": bssid,
                            "channel": channel,
                            "RSSI": rssi,
                            "encryption": encryption,
                            "beacon_interval": beacon_interval,
                            "vendor_oui": self.get_vendor_from_bssid(bssid),
                            "source": "scapy"
                        }
                except Exception as e:
                    logger.debug(f"Error parsing beacon packet: {e}")

        try:
            iface_kwargs = {"iface": self.interface} if self.interface else {}
            # NOTE: For scapy sniffing to work effectively, Windows needs Npcap. 
            # Linux requires the wireless interface to be in Monitor Mode.
            sniff(timeout=timeout, prn=packet_handler, store=0, **iface_kwargs)
        except Exception as e:
            logger.error(f"Scapy sniffing failed: {e}")
            
        return results

if __name__ == "__main__":
    # Test script execution
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    scanner = WifiScanner()
    if not scanner.oui_db:
        scanner.download_oui_db()
        
    print("\n--- Active Scan ---")
    active_results = scanner.scan(timeout=3)
    for b, data in active_results.items():
        print(f"AP: {data.get('SSID') or '<Hidden>'} | BSSID: {b} | Vendor: {data.get('vendor_oui')} | RSSI: {data.get('RSSI')}")

    print("\n--- Passive Scan (Beacons) ---")
    passive_results = scanner.capture_beacons(timeout=5)
    for b, data in passive_results.items():
         print(f"AP: {data.get('SSID') or '<Hidden>'} | BSSID: {b} | Vendor: {data.get('vendor_oui')} | RSSI: {data.get('RSSI')} | BI: {data.get('beacon_interval')}")
