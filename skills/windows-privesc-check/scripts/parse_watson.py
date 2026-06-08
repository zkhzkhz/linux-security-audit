#!/usr/bin/env python3
"""
Watson Output Parser

Parses Watson kernel vulnerability scanner output and extracts CVE findings.

Usage:
    python parse_watson.py <watson_raw.txt> --out <output.json>
"""

import re
import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any


def parse_watson(content: str) -> List[Dict[str, Any]]:
    """Parse Watson output and extract kernel vulnerability findings."""
    findings = []

    lines = content.split("\n")

    # Watson typically outputs lines like:
    # CVE-2019-0836: Exploitable
    # CVE-2019-1388: Vulnerable

    cve_pattern = re.compile(r"(CVE-\d{4}-\d+)")
    status_pattern = re.compile(r"(Vulnerable|Exploitable|Not Vulnerable|Not Found|Appears Vulnerable)", re.IGNORECASE)

    for i, line in enumerate(lines):
        cve_match = cve_pattern.search(line)
        status_match = status_pattern.search(line)

        if cve_match:
            cve = cve_match.group(1)
            status = status_match.group(1).lower() if status_match else "unknown"

            # Determine severity based on status
            severity = "medium"
            if "vulnerable" in status.lower() or "exploitable" in status.lower():
                severity = "high"

            # Common Windows kernel CVEs and their descriptions
            cve_descriptions = {
                "CVE-2019-0836": "Windows Privilege Escalation Vulnerability",
                "CVE-2019-1388": "Windows Certificate Dialog Elevation of Privilege",
                "CVE-2020-0787": "Windows Background Intelligent Transfer Service Elevation of Privilege",
                "CVE-2020-0788": "Windows Background Intelligent Transfer Service Elevation of Privilege",
                "CVE-2020-1048": "Windows Print Spooler Elevation of Privilege",
                "CVE-2021-1675": "Windows Print Spooler Elevation of Privilege (PrintNightmare)",
                "CVE-2021-34527": "Windows Print Spooler Remote Code Execution (PrintNightmare)",
                "CVE-2021-36934": "Windows LSA Spoofing Vulnerability",
                "CVE-2021-44228": "Apache Log4j Remote Code Execution (Log4Shell)",
                "CVE-2022-21882": "Windows Win32k Elevation of Privilege",
                "CVE-2022-26923": "Windows Active Directory Domain Services Elevation of Privilege",
            }

            description = cve_descriptions.get(cve, "Kernel vulnerability")
            note = f"{status} - {description}"

            findings.append({
                "severity": severity,
                "title": f"kernel-cve-{cve}",
                "where": "kernel",
                "note": note
            })

    # Also check for KB (Knowledge Base) mentions
    kb_pattern = re.compile(r"KB(\d+)")
    for i, line in enumerate(lines):
        kb_match = kb_pattern.search(line)
        if kb_match and "missing" in line.lower():
            kb = kb_match.group(1)
            findings.append({
                "severity": "medium",
                "title": f"missing-kb-{kb}",
                "where": "kernel",
                "note": f"Missing security update KB{kb}"
            })

    return findings


def main():
    parser = argparse.ArgumentParser(description="Parse Watson output")
    parser.add_argument("input", help="Watson raw output file")
    parser.add_argument("--out", "-o", required=True, help="Output JSON file")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    content = input_path.read_text(encoding="utf-8", errors="replace")
    findings = parse_watson(content)

    # Count by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f["severity"].lower()
        if sev in counts:
            counts[sev] += 1

    # Determine overall status
    if counts["critical"] > 0:
        status = "critical"
    elif counts["high"] > 0:
        status = "warn"
    else:
        status = "ok"

    result = {
        "module": "watson",
        "status": status,
        "counts": counts,
        "findings": findings
    }

    output_path = Path(args.out)
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))

    print(f"Parsed {len(findings)} kernel vulnerabilities from Watson")
    print(f"  High: {counts['high']}, Medium: {counts['medium']}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
