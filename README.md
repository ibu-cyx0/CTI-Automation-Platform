# 🛡️ CTI Automation Platform

> **Automated Cyber Threat Intelligence Pipeline with Live Threat Dashboard**  
> *AlienVault OTX · AbuseIPDB · URLhaus · Splunk Correlator*

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-SIEM-green?logo=splunk&logoColor=white)
![Threat Intel](https://img.shields.io/badge/Threat%20Intel-CTI-red)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## 📌 Overview

A fully automated **Cyber Threat Intelligence (CTI) pipeline** that:

1. **Collects IOCs** (Indicators of Compromise) from 3 live threat intelligence feeds
2. **Correlates** them against Splunk security logs to detect active threats
3. **Visualizes** everything on a real-time dark-themed threat dashboard

Built to demonstrate **SOC Tier 2** and **CTI Analyst** level skills for enterprise blue team environments.

---

## 🎯 Features

| Feature | Description |
|---|---|
| 🔗 Multi-Feed Collection | Pulls IOCs from OTX, AbuseIPDB, URLhaus simultaneously |
| 🔍 Splunk Correlation | Matches IOCs against real Splunk log events via REST API |
| 📊 Live Dashboard | Real-time threat feed with severity classification |
| 🌐 Threat Origin Map | Visualizes attacker geographic distribution |
| ⚡ Auto Severity | Classifies alerts as CRITICAL / HIGH / MEDIUM / LOW |
| 🔄 Demo Mode | Works fully offline without API keys |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│              CTI AUTOMATION PLATFORM                 │
├──────────────┬──────────────┬───────────────────────┤
│ AlienVault   │  AbuseIPDB   │       URLhaus          │
│    OTX       │  Blacklist   │   Malicious URLs       │
└──────┬───────┴──────┬───────┴──────────┬────────────┘
       │              │                  │
       └──────────────▼──────────────────┘
                 feeds/collector.py
                 (IOC Aggregator + Deduplication)
                        │
                        ▼
              data/iocs.json  ◄──── Stored IOCs
                        │
                        ▼
          correlator/splunk_correlator.py
          (Splunk REST API / Offline Correlation)
                        │
                        ▼
           data/correlation_hits.json
                        │
                        ▼
            dashboard/index.html
         (Live Threat Intelligence Dashboard)
```

---

## 📁 Project Structure

```
CTI-Automation-Platform/
├── collector.py                 # IOC collection from 3 threat feeds
├── ioc_harvester.py             # IOC harvesting helper
├── splunk_correlator.py         # Splunk REST API correlation engine
├── main.py                      # Main orchestrator
├── index.html                   # Live dark-themed threat dashboard
├── cti_dashboard_preview.html   # Dashboard preview page
├── iocs.json                    # Collected IOCs (auto-generated)
├── correlation_hits.json        # Alert matches (auto-generated)
├── feed_summary.json            # Feed summary data (auto-generated)
├── requirements.txt             # Python dependencies
├── LICENSE
└── README.md
```

---

## ⚙️ Setup & Installation

### Prerequisites
- Python 3.10+
- Splunk Enterprise (optional — demo mode works without it)

### 1. Clone the repository
```bash
git clone https://github.com/ibu-cyx0/CTI-Automation-Platform
cd CTI-Automation-Platform
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API keys (optional for live mode)
```bash
export OTX_API_KEY="your_otx_key_here"
export ABUSEIPDB_API_KEY="your_abuseipdb_key_here"
# URLhaus requires no API key
```

### 4. Run
```bash
# Demo mode (no API keys needed)
python main.py

# Live mode (with API keys + Splunk)
export SPLUNK_HOST="localhost"
export SPLUNK_USER="admin"
export SPLUNK_PASS="yourpassword"
python main.py
```

### 5. Open the Dashboard
```
Open index.html in your browser
```

---

## 🔐 Threat Feeds Used

| Feed | Type | Data | API Required |
|---|---|---|---|
| [AlienVault OTX](https://otx.alienvault.com) | Community | IPs, Domains, Hashes, URLs | ✅ Free |
| [AbuseIPDB](https://www.abuseipdb.com) | Crowd-sourced | Malicious IPs with confidence score | ✅ Free |
| [URLhaus](https://urlhaus.abuse.ch) | Malware | Active malware delivery URLs | ❌ No key |

---

## 🔍 Sample SPL Queries Used

```spl
# Detect IOC match in firewall logs
index=firewall (src_ip="185.220.101.47" OR dest_ip="185.220.101.47")
| table _time, src_ip, dest_ip, action, host

# Correlate all blocked IPs against IOC list
index=* action=blocked
| lookup ioc_lookup ip AS src_ip OUTPUT threat_name, severity
| where isnotnull(threat_name)
| stats count BY src_ip, threat_name, severity

# Detect outbound connections to known C2 domains
index=proxy_logs
| rex field=url "(?P<domain>[^/]+)"
| lookup ioc_lookup domain AS domain OUTPUT threat_name
| where isnotnull(threat_name)
| table _time, src_ip, url, threat_name
```

---

## 📊 Dashboard Features

- **Live IOC Feed Table** — streams new threats every second
- **Severity Donut Chart** — CRITICAL / HIGH / MEDIUM / LOW breakdown  
- **Source Bar Chart** — IOC count by threat feed
- **Threat Origin Map** — geographic attacker distribution
- **System Log Terminal** — real-time event logging
- **Auto-refresh** — repeats every 30 seconds

---

## 🛠️ Tech Stack

- **Python** — feed collection, correlation logic
- **Splunk REST API** — log correlation (`/services/search/jobs/export`)
- **AlienVault OTX API** — threat pulse + IOC collection
- **AbuseIPDB API** — malicious IP blacklist
- **URLhaus API** — active malware URL feed
- **HTML/CSS/JS** — live threat intelligence dashboard

---

## 🗺️ Roadmap

- [ ] MISP integration for threat sharing
- [ ] Automated email alerting (SMTP)
- [ ] Elasticsearch support
- [ ] STIX/TAXII feed support
- [ ] ML-based IOC prioritization

---

## 👤 Author

**Mohamed Ibrahim H**  
EC-Council Certified SOC Analyst (CSA) | Splunk Core Certified User | Cisco Cyber Ops Associate

- GitHub: [@ibu-cyx0](https://github.com/ibu-cyx0)
- TryHackMe: [@IbrahimCyb3r4](https://tryhackme.com/p/IbrahimCyb3r4)
- Email: ibrahim.cybrx@gmail.com

---

## 📄 License

MIT License — free to use, modify, and distribute.
