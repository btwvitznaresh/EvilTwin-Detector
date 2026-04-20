import os
import sys
import yaml
import json
import csv
import time
import argparse
from pathlib import Path

# Ensures modules can cross-import dependencies safely when executed natively.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from rich.console import Console
from rich.table import Table
from rich.text import Text

from scanner import WifiScanner
from analyzer import ThreatAnalyzer
from baseline import BaselineManager
from alert import AlertManager

console = Console()

BANNER = """[bold red]
███████╗██╗   ██╗██╗██╗     ████████╗███╗   ██╗██╗███╗   ██╗
██╔════╝██║   ██║██║██║     ╚══██╔══╝████╗  ██║██║████╗  ██║
█████╗  ██║   ██║██║██║        ██║   ██╔██╗ ██║██║██╔██╗ ██║
██╔══╝  ╚██╗ ██╔╝██║██║        ██║   ██║╚██╗██║██║██║╚██╗██║
███████╗ ╚████╔╝ ██║███████╗   ██║   ██║ ╚████║██║██║ ╚████║
╚══════╝  ╚═══╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝
                      [bold yellow]Detector & Analyzer v0.1.0[/]
"""

def get_config():
    """Reads system config."""
    config_path = Path(__file__).resolve().parent.parent / "config.yaml"
    if config_path.exists():
        with open(config_path, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}

def update_whitelist(bssid):
    """Safely injects designated hardware MAC identities into trusted list directly bypassing alerts."""
    config_path = Path(__file__).resolve().parent.parent / "config.yaml"
    config = get_config()
    bssids = config.get("whitelist_bssids", [])
    
    bssid_upper = bssid.upper()
    if bssid_upper not in bssids:
        bssids.append(bssid_upper)
        config["whitelist_bssids"] = bssids
        with open(config_path, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        console.print(f"[bold green]Successfully vaulted '{bssid_upper}' natively to trusted whitelist protocols.[/]")
    else:
        console.print(f"[yellow]{bssid_upper} already registered inside whitelist boundaries.[/]")

def export_csv():
    """Parses structural JSON cache, flattening it downwards into standardized forensic CSV tables."""
    alerts_path = Path(__file__).resolve().parent.parent / "logs/alerts.json"
    csv_path = Path(__file__).resolve().parent.parent / "logs/alerts.csv"
    
    if not alerts_path.exists():
        console.print("[red]Critical logic: JSON Array structure mapping failed. No alerts.json framework established.[/]")
        return
        
    try:
        with open(alerts_path, "r") as f:
             content = f.read()
             alerts = json.loads(content) if content.strip() else []
            
        if not alerts:
            console.print("[yellow]Event log holds NO anomaly configurations dynamically mapped.[/]")
            return
            
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "SSID", "BSSID", "Threat Type", "Risk", "Confidence", "Reason"])
            for a in alerts:
                writer.writerow([
                    a.get("timestamp", ""), a.get("SSID", ""), a.get("BSSID", ""),
                    a.get("threat_type", ""), a.get("risk_level", ""),
                    a.get("confidence_score", ""), a.get("reason", "")
                ])
        console.print(f"[bold green]Cross-compiled export sequence successful. Dumped {len(alerts)} alerts -> {csv_path}[/]")
    except Exception as e:
        console.print(f"[bold red]Forensic CSV payload failed compilation limits: {e}[/]")

def perform_scan():
    """Executes single-stage visual GUI mapping containing structural layout outputs."""
    console.print(BANNER)
    
    scanner = WifiScanner()
    analyzer = ThreatAnalyzer(config=get_config())
    alert_mgr = AlertManager()
    baseline = BaselineManager() 

    with console.status("[bold green]Executing deep-layer active and passive networking scans...[/]", spinner="arc"):
        # Combine mechanisms logically yielding higher hit rates.
        active = scanner.scan(timeout=3)
        passive = scanner.capture_beacons(timeout=3)
        
        merged_results = {**active}
        for b, data in passive.items():
            if b not in merged_results:
                merged_results[b] = data
            else:
                if data.get("beacon_interval"): merged_results[b]["beacon_interval"] = data["beacon_interval"]
                if data.get("encryption") and data.get("encryption") != "Open": merged_results[b]["encryption"] = data["encryption"]

        # Run analysis 
        alerts = analyzer.analyze(merged_results)
        
        # Risk colorization map
        bssid_risk = {}
        for alert in alerts:
            r_val = 3 if alert["risk_level"] == "HIGH" else (2 if alert["risk_level"] == "MEDIUM" else 1)
            
            # Identify correlated AP elements internally. 
            affected = alert["affected_APs"] if "affected_APs" in alert else [alert.get("bssid", "")]
            for ap in affected:
                if ap not in bssid_risk or bssid_risk[ap][0] < r_val:
                    bssid_risk[ap] = (r_val, alert["risk_level"])

    table = Table(title="Live Detected Wireless Grid")
    table.add_column("SSID", style="cyan")
    table.add_column("BSSID", style="magenta")
    table.add_column("Vendor", style="white")
    table.add_column("Channel", justify="right", style="blue")
    table.add_column("RSSI", justify="right", style="green")
    table.add_column("Encryption", style="yellow")
    table.add_column("Risk", justify="center")

    for bssid, data in merged_results.items():
        ssid = data.get("SSID", "<Hidden>")
        vendor = data.get("vendor_oui", "Unknown")
        ch = str(data.get("channel", "?"))
        rssi = str(data.get("RSSI", "?"))
        enc = str(data.get("encryption", "?"))
        
        anom, _ = baseline.is_anomaly(data)
        r_str = "[bold green]NONE[/]"
        
        if anom:
            r_str = "[bold yellow]SUSPICIOUS[/]"
            
        if bssid in bssid_risk:
            risk = bssid_risk[bssid][1]
            if risk == "HIGH": r_str = "[bold red]HIGH[/]"
            elif risk == "MEDIUM": r_str = "[bold yellow]MEDIUM[/]"
            elif risk == "LOW": r_str = "[bold blue]LOW[/]"

        table.add_row(ssid, bssid, vendor, ch, rssi, enc, r_str)

    console.print(table)
    
    if alerts:
        console.print("\n[bold red][!] Anomalous Threats Evaluated [/]")
        alert_mgr.process_alerts(alerts)

def monitor_mode():
    """Runs infinite cyclical interval tests utilizing deduplication algorithms silently reporting drops."""
    console.print(BANNER)
    config = get_config()
    interval = config.get("scan_interval", 10)
    
    scanner = WifiScanner()
    analyzer = ThreatAnalyzer(config=config)
    alert_mgr = AlertManager()
    
    console.print(f"[bold blue]Initiated Continuous Live Surveillance Protocol (Cycle Limit: {interval}s)[/]")
    console.print("[dim]Press Ctrl+C to disconnect daemon...[/]\n")
    
    try:
        while True:
            with console.status(f"[bold green]Running continuous network sweep mapping loops... (Cycle restarts every {interval}s)[/]", spinner="dots"):
                # Active scan is faster preventing interval bottlenecks compared to mixing passives.
                results = scanner.scan(timeout=3)
                alerts = analyzer.analyze(results)
                
            if alerts:
                # Let AlertManager handle JSON write deduplication bindings.
                alert_mgr.process_alerts(alerts)
                
            time.sleep(interval)
            
    except KeyboardInterrupt:
        console.print("\n[bold red]Continuous surveillance process terminated successfully.[/]")

def run_baseline():
    """Hooks standard baseline protocol iterations."""
    console.print(BANNER)
    console.print("[bold yellow]Initializing Network Topography Profiler...[/]")
    baseline = BaselineManager()
    
    with console.status("[bold cyan]Constructing standard array bounds... (Scanning sequences require time...)[/]", spinner="bouncingBar"):
        baseline.build_baseline(num_scans=10, duration_mins=5)
        
    console.print("[bold green]Comprehensive Baseline Compiled. Tolerances strictly saved.[/]")

def main():
    parser = argparse.ArgumentParser(description="EvilTwin-Detector Surveillance Suite")
    parser.add_argument("--scan", action="store_true", help="Initiates logic mapping producing structural GUI tables.")
    parser.add_argument("--monitor", action="store_true", help="Fires contiguous looped polling sequences monitoring active state.")
    parser.add_argument("--baseline", action="store_true", help="Scrapes local frequency bindings logging normal ranges natively.")
    parser.add_argument("--export", metavar="FORMAT", choices=["csv"], help="Extract alert arrays translating into forensics CSV.")
    parser.add_argument("--whitelist", metavar="BSSID", help="Push global hardware MAC authorizations safely dodging protocol blocks.")

    args = parser.parse_args()

    # Pre-warm OUI mapping securely avoiding silent logging drops
    scanner = WifiScanner()
    if not scanner.oui_db:
         # Trigger silent background API fetch loading vendor arrays correctly
         scanner.download_oui_db()

    if args.whitelist:
        update_whitelist(args.whitelist)
    elif args.export:
        export_csv()
    elif args.baseline:
        run_baseline()
    elif args.monitor:
        monitor_mode()
    elif args.scan:
        perform_scan()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
