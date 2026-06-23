"""
CTI Automation Platform - Splunk Correlator
Author: Mohamed Ibrahim H
Description: Correlates harvested IOCs against Splunk logs to detect
             active threats hitting your monitored network.
"""

import requests
import json
import csv
import os
import time
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
from urllib.parse import urljoin

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("logs/correlator.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ─── CONFIG ──────────────────────────────────────────────────────────────────

SPLUNK_HOST     = os.getenv("SPLUNK_HOST", "https://localhost:8089")
SPLUNK_USER     = os.getenv("SPLUNK_USER", "admin")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "changeme")
IOC_FILE        = "data/iocs/iocs_latest.json"
ALERTS_FILE     = "data/alerts/alerts_latest.json"
os.makedirs("data/alerts", exist_ok=True)
os.makedirs("logs", exist_ok=True)


# ─── SPLUNK CLIENT ───────────────────────────────────────────────────────────

class SplunkClient:
    """Lightweight Splunk REST API client."""

    def __init__(self, host: str, username: str, password: str):
        self.host     = host
        self.username = username
        self.password = password
        self.session  = requests.Session()
        self.session.verify = False  # self-signed cert in lab env
        self.token    = None
        self._authenticate()

    def _authenticate(self):
        url = urljoin(self.host, "/services/auth/login")
        resp = self.session.post(url, data={
            "username": self.username,
            "password": self.password,
            "output_mode": "json"
        })
        resp.raise_for_status()
        self.token = resp.json()["sessionKey"]
        self.session.headers.update({"Authorization": f"Splunk {self.token}"})
        logger.info("[Splunk] Authenticated successfully")

    def search(self, spl_query: str, earliest: str = "-24h", latest: str = "now") -> List[Dict]:
        """Run a blocking SPL search and return results."""
        # Create search job
        url = urljoin(self.host, "/services/search/jobs")
        resp = self.session.post(url, data={
            "search":       f"search {spl_query}",
            "earliest_time": earliest,
            "latest_time":   latest,
            "output_mode":   "json"
        })
        resp.raise_for_status()
        sid = resp.json()["sid"]

        # Poll until done
        status_url = urljoin(self.host, f"/services/search/jobs/{sid}")
        for _ in range(30):
            time.sleep(2)
            r = self.session.get(status_url, params={"output_mode": "json"})
            state = r.json()["entry"][0]["content"]["dispatchState"]
            if state == "DONE":
                break

        # Fetch results
        results_url = urljoin(self.host, f"/services/search/jobs/{sid}/results")
        r = self.session.get(results_url, params={"output_mode": "json", "count": 10000})
        results = r.json().get("results", [])
        logger.info(f"[Splunk] Query returned {len(results)} results")
        return results


# ─── IOC CORRELATOR ──────────────────────────────────────────────────────────

class IOCCorrelator:
    """Matches IOCs against Splunk log data."""

    def __init__(self, splunk: SplunkClient, ioc_file: str):
        self.splunk = splunk
        self.iocs   = self._load_iocs(ioc_file)

    def _load_iocs(self, filepath: str) -> List[Dict]:
        if not os.path.exists(filepath):
            logger.warning(f"IOC file not found: {filepath}")
            return []
        with open(filepath) as f:
            data = json.load(f)
        logger.info(f"[Correlator] Loaded {len(data)} IOCs")
        return data

    def _chunk(self, lst: List, size: int):
        for i in range(0, len(lst), size):
            yield lst[i:i + size]

    def correlate_ips(self) -> List[Dict]:
        """Search Splunk for any log events containing blacklisted IPs."""
        ip_iocs = [i for i in self.iocs if i["type"] in ("IPv4", "IPv6")]
        if not ip_iocs:
            return []

        alerts = []
        for chunk in self._chunk(ip_iocs, 50):
            ip_values = " OR ".join([f'"{i["value"]}"' for i in chunk])
            # Search across common log sourcetypes
            query = (
                f'index=* ({ip_values}) '
                f'| eval ioc_type="IP" '
                f'| stats count by src_ip, dest_ip, sourcetype, host '
                f'| where count > 0'
            )
            results = self.splunk.search(query)
            for result in results:
                matched_ioc = next(
                    (i for i in chunk if i["value"] in str(result)), None
                )
                alerts.append({
                    "alert_id":   f"CTI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    "ioc_type":   "IP",
                    "ioc_value":  result.get("src_ip") or result.get("dest_ip"),
                    "source":     matched_ioc["source"] if matched_ioc else "Unknown",
                    "pulse_name": matched_ioc["pulse_name"] if matched_ioc else "",
                    "tags":       matched_ioc["tags"] if matched_ioc else "",
                    "log_host":   result.get("host"),
                    "sourcetype": result.get("sourcetype"),
                    "event_count": result.get("count"),
                    "severity":   "HIGH",
                    "timestamp":  datetime.utcnow().isoformat(),
                    "status":     "OPEN"
                })
        logger.info(f"[Correlator] IP correlation found {len(alerts)} hits")
        return alerts

    def correlate_domains(self) -> List[Dict]:
        """Search Splunk DNS logs for IOC domains."""
        domain_iocs = [i for i in self.iocs if i["type"] in ("domain", "hostname")]
        if not domain_iocs:
            return []

        alerts = []
        for chunk in self._chunk(domain_iocs, 30):
            domain_values = " OR ".join([f'"{i["value"]}"' for i in chunk])
            query = (
                f'index=* sourcetype=dns ({domain_values}) '
                f'| stats count by query, src_ip, host '
                f'| where count > 0'
            )
            results = self.splunk.search(query)
            for result in results:
                matched_ioc = next(
                    (i for i in chunk if i["value"] in str(result.get("query", ""))), None
                )
                alerts.append({
                    "alert_id":    f"CTI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    "ioc_type":    "Domain",
                    "ioc_value":   result.get("query"),
                    "source":      matched_ioc["source"] if matched_ioc else "Unknown",
                    "pulse_name":  matched_ioc["pulse_name"] if matched_ioc else "",
                    "tags":        matched_ioc["tags"] if matched_ioc else "",
                    "log_host":    result.get("host"),
                    "src_ip":      result.get("src_ip"),
                    "event_count": result.get("count"),
                    "severity":    "MEDIUM",
                    "timestamp":   datetime.utcnow().isoformat(),
                    "status":      "OPEN"
                })
        logger.info(f"[Correlator] Domain correlation found {len(alerts)} hits")
        return alerts

    def correlate_hashes(self) -> List[Dict]:
        """Search Splunk endpoint logs for file hash IOCs."""
        hash_iocs = [i for i in self.iocs if i["type"] in ("FileHash-MD5", "FileHash-SHA256")]
        if not hash_iocs:
            return []

        alerts = []
        for chunk in self._chunk(hash_iocs, 20):
            hash_values = " OR ".join([f'"{i["value"]}"' for i in chunk])
            query = (
                f'index=* sourcetype=sysmon ({hash_values}) '
                f'| stats count by Hashes, Image, ComputerName '
                f'| where count > 0'
            )
            results = self.splunk.search(query)
            for result in results:
                matched_ioc = next(
                    (i for i in chunk if i["value"] in str(result.get("Hashes", ""))), None
                )
                alerts.append({
                    "alert_id":    f"CTI-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
                    "ioc_type":    "FileHash",
                    "ioc_value":   result.get("Hashes"),
                    "source":      matched_ioc["source"] if matched_ioc else "Unknown",
                    "pulse_name":  matched_ioc["pulse_name"] if matched_ioc else "",
                    "tags":        matched_ioc["tags"] if matched_ioc else "",
                    "log_host":    result.get("ComputerName"),
                    "process":     result.get("Image"),
                    "event_count": result.get("count"),
                    "severity":    "CRITICAL",
                    "timestamp":   datetime.utcnow().isoformat(),
                    "status":      "OPEN"
                })
        logger.info(f"[Correlator] Hash correlation found {len(alerts)} hits")
        return alerts

    def run_all(self) -> List[Dict]:
        """Run all correlation checks and return combined alerts."""
        all_alerts = []
        all_alerts.extend(self.correlate_ips())
        all_alerts.extend(self.correlate_domains())
        all_alerts.extend(self.correlate_hashes())
        return all_alerts


# ─── ALERT WRITER ────────────────────────────────────────────────────────────

def save_alerts(alerts: List[Dict], filepath: str):
    with open(filepath, "w") as f:
        json.dump(alerts, f, indent=2)
    logger.info(f"[Alerts] Saved {len(alerts)} alerts to {filepath}")


# ─── SPLUNK SPL QUERIES REFERENCE ────────────────────────────────────────────

SPL_CHEATSHEET = """
# ── CTI Correlation SPL Queries ──────────────────────────────────────────────

# 1. Detect blacklisted IPs in firewall/network logs
index=network sourcetype=firewall
| lookup ioc_lookup.csv value AS src_ip OUTPUT ioc_type, source AS threat_source
| where isnotnull(threat_source)
| table _time, src_ip, dest_ip, action, threat_source, ioc_type

# 2. Detect IOC domains in DNS logs
index=dns
| lookup ioc_lookup.csv value AS query OUTPUT ioc_type, source AS threat_source
| where isnotnull(threat_source)
| stats count by query, src_ip, threat_source

# 3. Brute force + IOC IP combo (chained detection)
index=windows sourcetype=WinEventLog EventCode=4625
| stats count by src_ip, user
| where count > 10
| lookup ioc_lookup.csv value AS src_ip OUTPUT source AS threat_source
| where isnotnull(threat_source)

# 4. Threat intel dashboard summary
index=* tag=threat
| eval age_hours=round((now()-_time)/3600,1)
| stats count by ioc_type, severity, source
| sort -count

# 5. IOC hit rate over time (for trending chart)
index=* tag=threat earliest=-7d
| timechart span=1h count by ioc_type
"""

if __name__ == "__main__":
    # Save SPL cheatsheet
    os.makedirs("docs", exist_ok=True)
    with open("docs/splunk_spl_queries.txt", "w") as f:
        f.write(SPL_CHEATSHEET)
    logger.info("SPL cheatsheet saved to docs/splunk_spl_queries.txt")

    # Run correlation
    try:
        client = SplunkClient(SPLUNK_HOST, SPLUNK_USER, SPLUNK_PASSWORD)
        correlator = IOCCorrelator(client, IOC_FILE)
        alerts = correlator.run_all()
        save_alerts(alerts, ALERTS_FILE)
        logger.info(f"Correlation complete. Total alerts: {len(alerts)}")
    except Exception as e:
        logger.error(f"Correlation failed: {e}")
        logger.info("Tip: Make sure Splunk is running and env vars are set.")
