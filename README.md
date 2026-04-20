# 📡 EvilTwin-Detector
<!-- Badges -->
![Python Version](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Win%20%7C%20Mac-lightgrey)
![GitHub stars](https://img.shields.io/github/stars/YourCorp/EvilTwin-Detector?style=social)

## Overview & What is an Evil Twin?

An **Evil Twin attack** is a malicious Wi-Fi spoofing technique where an attacker deploys a rogue access point (AP) perfectly mimicking a legitimate, trusted network (like your corporate Wi-Fi or local coffee shop's open hotspot). Because devices historically connect to the strongest signal matching a recognizable SSID, hackers physically reposition themselves close to the target to ensure their signal overpowers the legitimate router in the immediate area.

Once a victim device auto-connects to the Evil Twin, the attacker functions as a "Man in the Middle" (MitM). From this position, they can inject malicious code, strip encryption layers, steal credentials via captive portal overlays, and quietly harvest vast amounts of private data before passing traffic along to the legitimate internet—leaving the victim completely unaware that their session is compromised.

## 🏗 System Architecture

```text
  [Active Scanning]                [Passive Beacons]
   (iwlist/pywifi)                  (Scapy Sniffing)
         |                                 |
         +------------+--------------------+
                      |
              [ 📡 WifiScanner ] ────────────── [ 🌐 OUI Database ]
                      |
              [ 🧠 ThreatAnalyzer ] ─────────── [ 📉 Baseline Profiler ]
                      |                                (logs/baseline.json)
         +------------+------------+
         |                         |
 [ CLI Terminal ]          [ AlertManager ]
 (src/cli.py)             (logs/alerts.json)
         |                         |
   +-----+---------------+---------+--------+
   |                     |                  |
[ Streamlit GUI ]  [ FastAPI Server ] ── [ SIEM / Webhooks ]
(dashboard.py)     (src/api.py)
```

## 🔍 Five-Layer Detection Matrix
1. **SSID Duplication**: Identifies overlapping networks sharing identical SSIDs but utilizing contrasting vendor hardware MAC configurations.
2. **Signal Anomaly**: Compares real-time RSSI signal strengths against locally cached historical topography to spot severe proximity injections.
3. **Channel Conflict**: Checks active meshes for abnormal local channel-hopping arrays overlapping legitimate bands.
4. **Security Mismatch**: Critical threat flagging mapping OPEN portals directly attempting to spoof verified WPA2/WPA3 domains. 
5. **Beacon Interval Anomaly**: Decompiles Scapy telemetry monitoring IEEE 802.11 bounds targeting irregular packet transmission timings associated natively with software AP frameworks (like `airbase-ng` or `hostapd`).

## 🚀 Installation & Quick Start

**1. Clone the Source**:
```bash
git clone https://github.com/YourCorp/EvilTwin-Detector.git
cd EvilTwin-Detector
```

**2. Deploy Virtual Environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # (Linux/Mac)
# venv\Scripts\activate   # (Windows)
```

**3. Install Dependencies**:
```bash
pip install -e .
# Note: Linux platforms require local `iw` and `wireless-tools` configurations. 
# Windows requires `npcap` for Scapy tracing. 
```

## ⚙️ CLI Usage

Standard terminal commands interact natively via `src/cli.py`:

```bash
# Map localized telemetry to compile safe 'normal' boundary arrays (5 minutes). 
python src/cli.py --baseline  

# Snap active snapshot mapping live alerts
python src/cli.py --scan

# Kickoff indefinite interval checking
python src/cli.py --monitor

# Output historical telemetry bounds to forensics CSV
python src/cli.py --export csv 

# Push specific BSSID boundaries into explicit trust arrays safely
python src/cli.py --whitelist "00:11:22:AA:BB:CC"
```

## 🖥 The Streamlit Dashboard
Launch the dynamic visualization UI directly integrating with all backend mechanisms:
```bash
streamlit run dashboard.py
```
![Dashboard Screenshot Placeholder](assets/dashboard_screenshot.png)

## ⚠️ Limitations & Hardware Nuances
- **Hardware Privileges**: Scapy telemetry tracing requires **Root/Monitor Mode** on Linux bounds, or **Npcap installed** natively across Windows endpoints.
- **Mesh Architectures**: Highly complex enterprise Mesh configurations broadcasting wildly disparate MAC sequences without cohesive OUIs can occasionally trigger low-level confidence false positives natively.
- **WPA3 Encryptions**: Frame telemetry limits may vary across modern PMF (Protected Management Frames) blocking some passive data gathering depending deeply on driver stability.

## 🛤 Roadmap
- [ ] Implement Automated De-authentication (Deauth) injection countermeasures.
- [ ] Connect GPS/Location frameworks correlating physical network mappings downwards.
- [ ] Extend API hook bindings downwards directly towards Cloudflare/Splunk bounds natively.

## 🤝 Contributing
Submit pull requests mapping new analyzer configurations directly towards the `src/analyzer.py` matrices. Provide testing blocks passing >90% boundary marks internally. 

## ⚖️ Legal Disclaimer
**FOR EDUCATIONAL AND DEFENSIVE PURPOSES ONLY.** Intercepting or interacting maliciously with wireless boundaries belonging to third parties directly violates international and federal cyber-telemetry laws. The developers explicitly deny any overarching liability mapping towards offensive hardware usages internally. 
