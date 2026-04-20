# Penetration Array: Core Detection Logic

This document isolates the detailed mathematics and architectural logic executed sequentially by the `ThreatAnalyzer` mapping sequences internally.

## 1. SSID Duplication Matrix
Attackers spoof standard networks globally. By grouping identical SSIDs, we compare associated Vendor OUIs natively.
- **False Positive Handling**: If multiple BSSIDs share the exact exact organizational OUI (e.g. Cisco/Aruba), they likely represent an Enterprise Mesh network extending signal ranges. We drop `risk_level` strictly to `LOW`.
- **Rogue Identifiers**: If differing OUI topologies overlap (e.g., matching SSIDs where one contains an Asus identifier and the other explicitly shows `Unknown`), it yields immediate `HIGH` confidence flags internally. 
- **Configuration Hijacking**: If it mimics an SSID vaulted actively inside the `config.yaml` array but without possessing the specific whitelist BSSID hash, confidence scales vertically towards 95% certainty. 

## 2. Signal Spike Boundaries (RSSI Anomaly)
Traditional defense measures overlook spatial positioning. We log standard environmental dBm strengths iteratively. 
- **The Attack**: Hackers physically manipulate proximity bounds attempting to overpower native access point routing hardware natively.
- **Detection**: The code isolates current outputs comparing it directly backward against an averaged subset mapping historic RSSI blocks (last 50 reads). If arrays suddenly skew `> 10 dBm` (default interval limit) stronger unexpectedly without gradual ramping, it actively trips `SIGNAL_ANOMALY` limits structurally. 

## 3. Topographical Conflict Flags (Channel Interference)
SSID spoof operations usually utilize non-overlapping broadcast channels (like jumping explicitly from Channel 1 towards 11) reducing destructive interference natively against the victim router. This trigger operates predominantly combining metadata. If overlapping channels are combined simultaneously tracking dual SSID topologies upwards, this alerts analysts internally towards spatial collision risks bounding `MEDIUM` values. 

## 4. Encryption Truncation (Security Downgrades)
Attackers frequently strip WPA2/WPA3 structural locking sequences completely away mapping towards Open, Captive portals specifically.
- **Algorithm Check**: The scanner checks if an unencrypted node explicitly mimics a secured network boundary safely. If an identical SSID hashes both `"Open"` and `"Encrypted"` internally, this breaks protocol boundaries immediately asserting massive `HIGH` Risk parameters returning 100% Assurance limits securely. 

## 5. Software Clock Skews (Beacon Interval Tracing)
Raw IEEE 802.11 management frames naturally enforce standard timing mechanisms internally bounding typically to `100 TIME_UNITS` (which translates physically converting exactly to 102.4ms). 
- **Hack Indicators**: Malicious implementations structurally executed via frameworks like Kali Linux's `airbase-ng` / `hostapd` occasionally contain flawed interval parameters heavily truncated (like 25ms hooks) generating severe timeline collisions bounding explicit `BEACON_INTERVAL_ANOMALY` warnings inwards.
