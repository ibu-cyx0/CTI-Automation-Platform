"""
CTI Automation Platform - Main Runner
Orchestrates: Feed Collection → Splunk Correlation → Dashboard Launch
Author: Mohamed Ibrahim H
"""

import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from feeds.collector import run_collection
from correlator.splunk_correlator import run_correlation

def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║        CTI AUTOMATION PLATFORM  v1.0                        ║
║        Cyber Threat Intelligence | Mohamed Ibrahim H         ║
╚══════════════════════════════════════════════════════════════╝
    """)

    # Step 1: Collect IOCs
    print("► STEP 1: Collecting IOCs from threat feeds...")
    iocs = run_collection(demo_mode=True)

    # Step 2: Correlate with logs
    print("\n► STEP 2: Correlating IOCs against log events...")
    hits = run_correlation(demo_mode=True)

    # Step 3: Launch dashboard
    print("\n► STEP 3: Launching threat intelligence dashboard...")
    print("    Open dashboard/index.html in your browser\n")

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  ✓  IOCs Collected  : {len(iocs):<5}                               ║
║  ✓  Alerts Fired    : {len(hits):<5}                               ║
║  ✓  Dashboard       : dashboard/index.html                  ║
╚══════════════════════════════════════════════════════════════╝
    """)

if __name__ == "__main__":
    main()
