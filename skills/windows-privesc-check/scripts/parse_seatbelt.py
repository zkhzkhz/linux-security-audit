#!/usr/bin/env python3
"""
Seatbelt Output Parser

Parses Seatbelt security enumeration output and extracts security findings.

Usage:
    python parse_seatbelt.py <seatbelt_raw.txt> --out <output.json>
"""

import re
import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any


def parse_seatbelt(content: str) -> List[Dict[str, Any]]:
    """Parse Seatbelt output and extract security findings."""
    findings = []

    lines = content.split("\n")

    # High severity patterns
    high_patterns = [
        (r"AntiVirus.*not found|No AV installed", "no-antivirus", "No antivirus software detected"),
        (r"Windows Defender.*disabled|Defender is disabled", "defender-disabled", "Windows Defender is disabled"),
        (r"UAC.*disabled|EnableLUA.*=.*0", "uac-disabled", "UAC is disabled"),
        (r"PowerShell.*v2|PowerShell 2.0 installed", "powershell-v2", "PowerShell v2 is installed (deprecated, attack surface)"),
        (r"WSUS.*http://|WSUS using HTTP", "wsus-http", "WSUS using unencrypted HTTP"),
        (r"Credential Guard.*not enabled|CredentialGuard.*Disabled", "credential-guard-disabled", "Credential Guard is not enabled"),
        (r"LAPS.*not installed|LAPS not found", "laps-missing", "LAPS is not installed"),
        (r"BitLocker.*not enabled|BitLocker.*Disabled|No encrypted volumes", "bitlocker-disabled", "BitLocker is not enabled"),
    ]

    # Medium severity patterns
    medium_patterns = [
        (r"RDP.*enabled|Terminal Services.*enabled", "rdp-enabled", "RDP is enabled"),
        (r"Remote Registry.*running", "remote-registry", "Remote Registry service is running"),
        (r"SMB.*enabled|SMB v1 enabled", "smb-enabled", "SMB is enabled"),
        (r"PSRemoting.*enabled|WinRM.*running", "psremoting-enabled", "PowerShell remoting is enabled"),
        (r"LmCompatibilityLevel.*=.*[0-2]", "lm-compatibility", "Weak LM compatibility level"),
        (r"AutoLogon.*enabled|AutoAdminLogon.*=.*1", "autologon-enabled", "AutoLogon is enabled"),
        (r"Firewall.*disabled|Firewall Status.*Disabled", "firewall-disabled", "Windows Firewall is disabled"),
        (r"AppLocker.*not configured|AppLocker.*not enforced", "applocker-disabled", "AppLocker is not configured"),
        (r"Guest.*enabled|Guest account.*enabled", "guest-enabled", "Guest account is enabled"),
        (r"Administrator.*enabled|Admin account.*enabled", "admin-enabled", "Administrator account is enabled"),
    ]

    # Low severity patterns (informational)
    low_patterns = [
        (r"OS Version|Windows version", "os-version", "Operating system version"),
        (r"Architecture|System type", "arch-info", "System architecture"),
        (r"Domain|Workgroup", "domain-info", "Domain/Workgroup membership"),
        (r"Hotfix.*installed|KB[0-9]+", "hotfix", "Installed hotfixes"),
        (r"LastBootUpTime|Boot time", "boot-time", "Last boot time"),
    ]

    def check_patterns(line: str, patterns: list, severity: str):
        for pattern, title, note in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return {
                    "severity": severity,
                    "title": title,
                    "where": f"seatbelt:{title}",
                    "note": note
                }
        return None

    for i, line in enumerate(lines):
        # Check high patterns first
        f = check_patterns(line, high_patterns, "high")
        if f:
            findings.append(f)
            continue

        # Check medium patterns
        f = check_patterns(line, medium_patterns, "medium")
        if f:
            findings.append(f)
            continue

    # Deduplicate by title
    seen = set()
    unique_findings = []
    for f in findings:
        if f["title"] not in seen:
            seen.add(f["title"])
            unique_findings.append(f)

    return unique_findings


def main():
    parser = argparse.ArgumentParser(description="Parse Seatbelt output")
    parser.add_argument("input", help="Seatbelt raw output file")
    parser.add_argument("--out", "-o", required=True, help="Output JSON file")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    content = input_path.read_text(encoding="utf-8", errors="replace")
    findings = parse_seatbelt(content)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f["severity"].lower()
        if sev in counts:
            counts[sev] += 1

    status = "warn" if counts["high"] > 0 else "ok"

    result = {
        "module": "seatbelt",
        "status": status,
        "counts": counts,
        "findings": findings
    }

    output_path = Path(args.out)
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))

    print(f"Parsed {len(findings)} findings from Seatbelt")
    print(f"  High: {counts['high']}, Medium: {counts['medium']}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
