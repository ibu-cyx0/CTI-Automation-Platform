"""
CTI Automation Platform - IOC Harvester
Author: Mohamed Ibrahim H
Description: Automatically collects Indicators of Compromise (IOCs) from
             public threat intelligence feeds (AlienVault OTX, AbuseIPDB)
"""

import requests
import json
import csv
import os
import hashlib
import time
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("logs/harvester.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ─── CONFIG ──────────────────────────────────────────────────────────────────

OTX_API_KEY    = os.getenv("OTX_API_KEY", "YOUR_OTX_API_KEY_HERE")
ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY", "YOUR_ABUSEIPDB_KEY_HERE")
OUTPUT_DIR     = "data/iocs"
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs("logs", exist_ok=True)


# ─── ALIENVALUT OTX FEED ─────────────────────────────────────────────────────

class OTXHarvester:
    """Pulls IOCs from AlienVault Open Threat Exchange."""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        self.headers = {"X-OTX-API-KEY": api_key}

    def get_recent_pulses(self, days: int = 1) -> List[Dict]:
        """Fetch pulses updated within the last N days."""
        since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        url = f"{self.BASE_URL}/pulses/subscribed?modified_since={since}&limit=50"
        try:
            resp = requests.get(url, headers=self.headers, timeout=15)
            resp.raise_for_status()
            pulses = resp.json().get("results", [])
            logger.info(f"[OTX] Fetched {len(pulses)} pulses")
            return pulses
        except requests.RequestException as e:
            logger.error(f"[OTX] Request failed: {e}")
            return []

    def extract_iocs(self, pulses: List[Dict]) -> List[Dict]:
        """Extract IP, domain, URL, hash IOCs from pulses."""
        iocs = []
        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                iocs.append({
                    "type":        indicator.get("type"),
                    "value":       indicator.get("indicator"),
                    "source":      "AlienVault OTX",
                    "pulse_name":  pulse.get("name"),
                    "tlp":         pulse.get("tlp", "white"),
                    "tags":        ", ".join(pulse.get("tags", [])),
                    "timestamp":   indicator.get("created", datetime.utcnow().isoformat()),
                    "id":          hashlib.md5(indicator.get("indicator", "").encode()).hexdigest()
                })
        logger.info(f"[OTX] Extracted {len(iocs)} IOCs")
        return iocs

    def harvest(self, days: int = 1) -> List[Dict]:
        pulses = self.get_recent_pulses(days)
        return self.extract_iocs(pulses)


# ─── ABUSEIPDB FEED ──────────────────────────────────────────────────────────

class AbuseIPDBHarvester:
    """Pulls blacklisted IPs from AbuseIPDB."""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.headers = {
            "Key": api_key,
            "Accept": "application/json"
        }

    def get_blacklist(self, confidence_minimum: int = 90, limit: int = 500) -> List[Dict]:
        """Fetch IPs with abuse confidence score above threshold."""
        url = f"{self.BASE_URL}/blacklist"
        params = {
            "confidenceMinimum": confidence_minimum,
            "limit": limit
        }
        try:
            resp = requests.get(url, headers=self.headers, params=params, timeout=15)
            resp.raise_for_status()
            data = resp.json().get("data", [])
            logger.info(f"[AbuseIPDB] Fetched {len(data)} blacklisted IPs")
            return data
        except requests.RequestException as e:
            logger.error(f"[AbuseIPDB] Request failed: {e}")
            return []

    def harvest(self) -> List[Dict]:
        raw = self.get_blacklist()
        iocs = []
        for entry in raw:
            iocs.append({
                "type":        "IPv4",
                "value":       entry.get("ipAddress"),
                "source":      "AbuseIPDB",
                "pulse_name":  "Blacklist",
                "tlp":         "white",
                "tags":        ", ".join(entry.get("usageType", "").split()),
                "confidence":  entry.get("abuseConfidenceScore"),
                "country":     entry.get("countryCode"),
                "timestamp":   entry.get("lastReportedAt", datetime.utcnow().isoformat()),
                "id":          hashlib.md5(entry.get("ipAddress", "").encode()).hexdigest()
            })
        return iocs


# ─── URLHAUS FEED (no key needed) ────────────────────────────────────────────

class URLHausHarvester:
    """Pulls malicious URLs from URLhaus (abuse.ch) — no API key required."""

    FEED_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    def harvest(self, limit: int = 100) -> List[Dict]:
        try:
            resp = requests.post(self.FEED_URL, data={"limit": limit}, timeout=15)
            resp.raise_for_status()
            urls = resp.json().get("urls", [])
            iocs = []
            for entry in urls:
                if entry.get("url_status") == "online":
                    iocs.append({
                        "type":       "URL",
                        "value":      entry.get("url"),
                        "source":     "URLhaus",
                        "pulse_name": entry.get("threat", "malware"),
                        "tlp":        "white",
                        "tags":       entry.get("tags") or "",
                        "timestamp":  entry.get("date_added", datetime.utcnow().isoformat()),
                        "id":         hashlib.md5(entry.get("url", "").encode()).hexdigest()
                    })
            logger.info(f"[URLhaus] Fetched {len(iocs)} active malicious URLs")
            return iocs
        except requests.RequestException as e:
            logger.error(f"[URLhaus] Request failed: {e}")
            return []


# ─── IOC DEDUPLICATION & STORAGE ─────────────────────────────────────────────

class IOCStore:
    """Stores, deduplicates, and exports IOCs."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.seen_ids = set()
        self._load_existing()

    def _load_existing(self):
        if os.path.exists(self.filepath):
            with open(self.filepath, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.seen_ids.add(row.get("id", ""))

    def save(self, iocs: List[Dict]):
        new_iocs = [i for i in iocs if i.get("id") not in self.seen_ids]
        if not new_iocs:
            logger.info("No new IOCs to save.")
            return 0

        file_exists = os.path.exists(self.filepath)
        fieldnames = ["id", "type", "value", "source", "pulse_name",
                      "tlp", "tags", "confidence", "country", "timestamp"]

        with open(self.filepath, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            if not file_exists:
                writer.writeheader()
            writer.writerows(new_iocs)

        for ioc in new_iocs:
            self.seen_ids.add(ioc["id"])

        logger.info(f"Saved {len(new_iocs)} new IOCs to {self.filepath}")
        return len(new_iocs)

    def export_json(self, out_path: str):
        iocs = []
        if os.path.exists(self.filepath):
            with open(self.filepath, "r") as f:
                reader = csv.DictReader(f)
                iocs = list(reader)
        with open(out_path, "w") as f:
            json.dump(iocs, f, indent=2)
        logger.info(f"Exported {len(iocs)} IOCs to {out_path}")


# ─── MAIN ORCHESTRATOR ───────────────────────────────────────────────────────

def run_harvest():
    logger.info("=" * 60)
    logger.info("CTI Automation Platform — IOC Harvest Started")
    logger.info(f"Timestamp: {datetime.utcnow().isoformat()} UTC")
    logger.info("=" * 60)

    all_iocs = []

    # 1. AlienVault OTX
    otx = OTXHarvester(OTX_API_KEY)
    all_iocs.extend(otx.harvest(days=1))
    time.sleep(1)

    # 2. AbuseIPDB
    abuse = AbuseIPDBHarvester(ABUSEIPDB_KEY)
    all_iocs.extend(abuse.harvest())
    time.sleep(1)

    # 3. URLhaus (no key needed)
    urlhaus = URLHausHarvester()
    all_iocs.extend(urlhaus.harvest(limit=200))

    # Store & deduplicate
    today = datetime.utcnow().strftime("%Y-%m-%d")
    store = IOCStore(f"{OUTPUT_DIR}/iocs_{today}.csv")
    new_count = store.save(all_iocs)

    # Export JSON for dashboard
    store.export_json(f"{OUTPUT_DIR}/iocs_latest.json")

    logger.info("=" * 60)
    logger.info(f"Harvest complete. {new_count} new IOCs added.")
    logger.info("=" * 60)
    return new_count


if __name__ == "__main__":
    run_harvest()
