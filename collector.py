"""
CTI Feed Collector
Pulls IOCs from AlienVault OTX, AbuseIPDB, and URLhaus
Author: Mohamed Ibrahim H
"""

import requests
import json
import csv
import os
from datetime import datetime, timezone

# ─── CONFIG ────────────────────────────────────────────────────────────────────
OTX_API_KEY    = os.getenv("OTX_API_KEY", "YOUR_OTX_API_KEY")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_API_KEY", "YOUR_ABUSEIPDB_KEY")
OUTPUT_DIR     = os.path.join(os.path.dirname(__file__), "..", "data")
IOC_FILE       = os.path.join(OUTPUT_DIR, "iocs.json")
SUMMARY_FILE   = os.path.join(OUTPUT_DIR, "feed_summary.json")

HEADERS = {"User-Agent": "CTI-Automation-Platform/1.0"}

# ─── HELPERS ───────────────────────────────────────────────────────────────────
def now_utc():
    return datetime.now(timezone.utc).isoformat()

def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved → {path}")

# ─── FEED 1: AlienVault OTX ────────────────────────────────────────────────────
def fetch_otx_pulses(limit=5):
    """Fetch recent threat pulses from AlienVault OTX."""
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    headers = {**HEADERS, "X-OTX-API-KEY": OTX_API_KEY}
    iocs = []

    try:
        resp = requests.get(url, headers=headers, params={"limit": limit}, timeout=15)
        resp.raise_for_status()
        pulses = resp.json().get("results", [])

        for pulse in pulses:
            for ind in pulse.get("indicators", []):
                iocs.append({
                    "source":      "AlienVault OTX",
                    "type":        ind.get("type"),
                    "value":       ind.get("indicator"),
                    "threat_name": pulse.get("name"),
                    "tlp":         pulse.get("TLP", "white"),
                    "tags":        pulse.get("tags", []),
                    "fetched_at":  now_utc()
                })

        print(f"[OTX] Collected {len(iocs)} IOCs from {len(pulses)} pulses")
    except Exception as e:
        print(f"[OTX][ERROR] {e}")

    return iocs

# ─── FEED 2: AbuseIPDB ─────────────────────────────────────────────────────────
def fetch_abuseipdb_blacklist(confidence=90, limit=100):
    """Fetch high-confidence malicious IPs from AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {**HEADERS, "Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    iocs = []

    try:
        resp = requests.get(
            url,
            headers=headers,
            params={"confidenceMinimum": confidence, "limit": limit},
            timeout=15
        )
        resp.raise_for_status()
        entries = resp.json().get("data", [])

        for entry in entries:
            iocs.append({
                "source":      "AbuseIPDB",
                "type":        "IPv4",
                "value":       entry.get("ipAddress"),
                "threat_name": "Malicious IP",
                "confidence":  entry.get("abuseConfidenceScore"),
                "country":     entry.get("countryCode"),
                "reports":     entry.get("totalReports"),
                "fetched_at":  now_utc()
            })

        print(f"[AbuseIPDB] Collected {len(iocs)} malicious IPs")
    except Exception as e:
        print(f"[AbuseIPDB][ERROR] {e}")

    return iocs

# ─── FEED 3: URLhaus (no key needed) ──────────────────────────────────────────
def fetch_urlhaus_recent(limit=100):
    """Fetch recent malicious URLs from URLhaus (free, no API key)."""
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    iocs = []

    try:
        resp = requests.post(url, data={"limit": limit}, timeout=15)
        resp.raise_for_status()
        urls = resp.json().get("urls", [])

        for entry in urls:
            if entry.get("url_status") == "online":
                iocs.append({
                    "source":      "URLhaus",
                    "type":        "URL",
                    "value":       entry.get("url"),
                    "threat_name": entry.get("threat", "malware_download"),
                    "tags":        entry.get("tags") or [],
                    "host":        entry.get("host"),
                    "date_added":  entry.get("date_added"),
                    "fetched_at":  now_utc()
                })

        print(f"[URLhaus] Collected {len(iocs)} active malicious URLs")
    except Exception as e:
        print(f"[URLhaus][ERROR] {e}")

    return iocs

# ─── DEMO DATA (when no API keys) ─────────────────────────────────────────────
def generate_demo_iocs():
    """Generate realistic sample IOCs for demo/testing."""
    return [
        {"source":"AlienVault OTX","type":"IPv4","value":"185.220.101.47","threat_name":"Tor Exit Node - C2","tlp":"white","tags":["tor","c2","botnet"],"fetched_at":now_utc()},
        {"source":"AlienVault OTX","type":"domain","value":"malware-c2.ru","threat_name":"Emotet C2 Domain","tlp":"green","tags":["emotet","banking-trojan"],"fetched_at":now_utc()},
        {"source":"AlienVault OTX","type":"FileHash-SHA256","value":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","threat_name":"Ransomware Payload","tlp":"amber","tags":["ransomware","lockbit"],"fetched_at":now_utc()},
        {"source":"AbuseIPDB","type":"IPv4","value":"45.142.212.100","threat_name":"Malicious IP","confidence":97,"country":"RU","reports":1843,"fetched_at":now_utc()},
        {"source":"AbuseIPDB","type":"IPv4","value":"194.165.16.11","threat_name":"Malicious IP","confidence":100,"country":"NL","reports":5621,"fetched_at":now_utc()},
        {"source":"AbuseIPDB","type":"IPv4","value":"91.92.248.105","threat_name":"Malicious IP","confidence":95,"country":"DE","reports":312,"fetched_at":now_utc()},
        {"source":"URLhaus","type":"URL","value":"http://update-service.xyz/payload.exe","threat_name":"malware_download","tags":["exe","dropper"],"host":"update-service.xyz","fetched_at":now_utc()},
        {"source":"URLhaus","type":"URL","value":"http://cdn-static.cf/files/rat.bin","threat_name":"malware_download","tags":["rat","asyncrat"],"host":"cdn-static.cf","fetched_at":now_utc()},
        {"source":"AlienVault OTX","type":"IPv4","value":"10.0.0.55","threat_name":"Internal Recon Detected","tlp":"red","tags":["lateral-movement","internal"],"fetched_at":now_utc()},
        {"source":"AbuseIPDB","type":"IPv4","value":"222.187.239.109","threat_name":"Malicious IP","confidence":100,"country":"CN","reports":9204,"fetched_at":now_utc()},
    ]

# ─── MAIN ─────────────────────────────────────────────────────────────────────
def run_collection(demo_mode=True):
    print("\n" + "="*60)
    print("  CTI FEED COLLECTOR  |  Mohamed Ibrahim H")
    print("="*60)

    all_iocs = []

    if demo_mode:
        print("[*] Running in DEMO MODE (no API keys required)")
        all_iocs = generate_demo_iocs()
    else:
        all_iocs += fetch_otx_pulses()
        all_iocs += fetch_abuseipdb_blacklist()
        all_iocs += fetch_urlhaus_recent()

    # Dedup by value
    seen = set()
    unique = []
    for ioc in all_iocs:
        if ioc["value"] not in seen:
            seen.add(ioc["value"])
            unique.append(ioc)

    save_json(IOC_FILE, unique)

    summary = {
        "last_run":    now_utc(),
        "total_iocs":  len(unique),
        "by_source": {
            "AlienVault OTX": sum(1 for i in unique if i["source"] == "AlienVault OTX"),
            "AbuseIPDB":      sum(1 for i in unique if i["source"] == "AbuseIPDB"),
            "URLhaus":        sum(1 for i in unique if i["source"] == "URLhaus"),
        },
        "by_type": {
            "IPv4":   sum(1 for i in unique if i.get("type") == "IPv4"),
            "URL":    sum(1 for i in unique if i.get("type") == "URL"),
            "domain": sum(1 for i in unique if i.get("type") == "domain"),
            "hash":   sum(1 for i in unique if "hash" in (i.get("type") or "").lower()),
        }
    }
    save_json(SUMMARY_FILE, summary)

    print(f"\n[✓] Total unique IOCs: {len(unique)}")
    print(f"[✓] Summary saved → {SUMMARY_FILE}")
    return unique

if __name__ == "__main__":
    run_collection(demo_mode=True)
