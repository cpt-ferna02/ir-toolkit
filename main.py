"""
=============================================================
  Incident Response Toolkit — main.py
  Entry point. Runs the collector, passes data to the
  report generator, then opens the finished HTML report.
=============================================================
"""

import os
import sys
import webbrowser
from datetime import datetime
from collector import collect_all
from report import generate_report


def main():
    print("=" * 50)
    print("   INCIDENT RESPONSE TOOLKIT")
    print("   Forensic Evidence Collector")
    print("=" * 50)
    print()

    # ── 1. Collect all forensic data ────────────────────
    data = collect_all()

    # ── 2. Build output filename with timestamp ──────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    hostname = data["system_info"].get("hostname", "unknown")
    output_file = f"IR_Report_{hostname}_{ts}.html"

    # ── 3. Generate the HTML report ──────────────────────
    print("\n[*] Generating HTML report...")
    generate_report(data, output_file)

    # ── 4. Confirm and open ──────────────────────────────
    abs_path = os.path.abspath(output_file)
    print(f"\n[✓] Report saved to: {abs_path}")
    print("[*] Opening report in browser...")

    webbrowser.open(f"file:///{abs_path}")

    print("\n[✓] Done. Stay safe out there.\n")


if __name__ == "__main__":
    main()