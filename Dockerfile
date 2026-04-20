FROM python:3.11-slim

# Hook critical system-level dependencies for Wi-Fi tracking (Linux bindings)
RUN apt-get update && apt-get install -y \
    wireless-tools \
    iw \
    sudo \
    net-tools \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Push constraints and install dependencies
COPY requirements.txt .

# Enforce explicit uvicorn installation backing the FastAPI node internally
RUN pip install --no-cache-dir -r requirements.txt uvicorn

# Map functional app layer
COPY . .

# Expose architectural GUI and API hook limits
EXPOSE 8501 8000

# CLI fallback mechanism (Overwritten largely by compose services)
CMD ["python", "src/cli.py", "--help"]
