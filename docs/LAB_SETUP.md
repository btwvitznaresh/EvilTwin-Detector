# 🔬 Safe Home Lab Configuration Matrix

Learning to properly trap Evil-Twins natively requires functional test beds separating isolated bounds reliably from public networks. 

**Follow these steps physically validating and testing structural algorithms securely offline safely:**

### Requirements
- 1x Hardware Router (e.g., standard consumer ISP routing device isolated cleanly away from public internet hooks). 
- 1x Kali Linux Attacker Device (A Raspberry Pi executing native wireless arrays, or VirtualBox machine executing an external Alfa Network USB adapter securely). 
- 1x Victim Array Device (Your physical computer/laptop executing `EvilTwin-Detector`). 

### Step 1: Mapping the Baseline Sandbox
Start your physical test router executing natively emitting a standard SSID configuration (`LabTestNet_WPA2`). Secure it using standard PSK parameters.
On your Host execution machine, hook the project executing structural parameters:
```bash
python src/cli.py --baseline
```

### Step 2: Igniting the Threat Twin
Power up your Kali instance physically connecting towards the native interface bounds utilizing `hostapd`. 
Generate a configuration mapping matching precisely towards your native SSID but completely stripping security protocols natively downwards. 

*Configuration (`hostapd.conf`):*
```text
interface=wlan0
ssid=LabTestNet_WPA2
channel=11
# Note lack of WPA/WPA2 settings (Open)
beacon_int=40 
```
Initialize down standard paths: `sudo hostapd ./hostapd.conf`

### Step 3: Verifying Topography Intercepts
Initialize the Python detector loop across your primary bounds running the GUI:
```bash
streamlit run dashboard.py
```
Navigate iteratively into your application interface natively observing identical SSIDs populated visually. 
You will observe three identical flags dynamically mapping instantly:
1. `SECURITY_MISMATCH` (Open vs Encrypted overlaps triggered natively).
2. `BEACON_INTERVAL_ANOMALY` (Triggered due strictly against `40` intervals bounds).
3. `SSID_DUPLICATION` (Due strictly targeting Vendor OUI footprint collision hashes natively).
