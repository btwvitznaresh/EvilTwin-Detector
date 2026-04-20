# Docker Setup for EvilTwin-Detector

This overview serves as standard documentation to initialize and deploy the comprehensive EvilTwin-Detector suite using Docker matrices.

## Prerequisites
- Docker alongside `docker-compose` deployed natively.
- (Linux Specifically) Standard `sudo` or root system permissions. 
- A physical Wi-Fi interface connected directly to the execution node.

## ⚠️ Important Note on Wi-Fi Hardware Execution Limits (Linux)
Containerized applications are traditionally routed through virtual software bridges. These localized bridges **do not have explicit access** to your physical network hardware or antennas. 

To permit Python layer detection commands (`iwlist`, `scapy`, `pywifi`) functional hooks inwards to your hardware interfaces natively, apply the following steps safely:

1. **Docker Compose Deployments**: The embedded `docker-compose.yml` contains strict bindings overriding traditional safety rails: `network_mode: "host"` alongside `privileged: true` specifically inside the API tracking service natively!
2. **Standalone Docker Core**: If spinning nodes downwards via raw manual commands, you **must append** the `--net=host` functionality safely bypassing virtual walls. Example:
   ```bash
   docker run -it --net=host --privileged eviltwin-detector
   ```

## Deployment Overview

### 1. Build and Mount using Compose

Drill down to the overarching directory path structure and initiate construction bounds:
```bash
docker-compose up --build
```

This automation accomplishes the following:
- Bootstraps natively around a custom `python:3.11-slim` architecture importing explicit Linux system hooks (`iwlist`, `wireless-tools`, `libpcap`).
- Starts your **FastAPI Web Bridge** natively pointing back across `0.0.0.0:8000`.
- Generates the interactive **Streamlit Dashboard Matrix** on port `8501`.
- Links `.yaml` models alongside localized log bindings keeping array history seamlessly synchronized across container life cycles.

### 2. Connect into Operational Architectures

- **Streamlit GUI Control Hub**: Deploy browsers strictly to [http://localhost:8501](http://localhost:8501).
- **FastAPI Endpoint Integrator**: Swagger hooks dynamically sit loaded facing inwards at [http://localhost:8000/docs](http://localhost:8000/docs).

### 3. Termination Hooks

Disconnect limits and close Docker daemon bounds safely wrapping down active memory links by executing:
```bash
docker-compose down
```
