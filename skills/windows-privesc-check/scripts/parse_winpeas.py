#!/usr/bin/env python3
"""
WinPEAS Output Parser

Parses WinPEAS output and extracts privilege escalation vectors into structured JSON.

Usage:
    python parse_winpeas.py <winpeas_raw.txt> --out <output.json>
"""

import re
import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any

# Severity patterns
CRITICAL_PATTERNS = [
    (r"AdminPrivs|You have Admin privileges", "admin-privileges", "Current user has admin privileges"),
    (r"SystemPrivs|You have SYSTEM privileges", "system-privileges", "Current user has SYSTEM privileges"),
    (r"TokenElevation|Token is elevated", "elevated-token", "Process has elevated token"),
]

HIGH_PATTERNS = [
    (r"AlwaysInstallElevated.*=.*1|AlwaysInstallElevated is enabled", "alwaysinstallelevated", "AlwaysInstallElevated is enabled - MSI can run as SYSTEM"),
    (r"Unquoted Service Path|Unquoted Service Path found", "unquoted-service-path", "Unquoted service path allows privilege escalation"),
    (r"Modifiable Service|You can modify the service", "modifiable-service", "Service can be modified"),
    (r"Writable Service|Service with write permissions", "writable-service", "Service binary is writable"),
    (r"DLL Hijacking|DLL hijacking possible", "dll-hijacking", "DLL hijacking opportunity found"),
    (r"Credential.*found|Credential in", "credential-found", "Credential found in file"),
    (r"Saved Credential|Saved credential found", "saved-credential", "Saved Windows credential found"),
    (r"AutoLogon.*Password|DefaultPassword.*=", "autologon-password", "AutoLogon password found"),
    (r"RunAs.*saved|runas /savecred", "runas-savecred", "RunAs with saved credentials available"),
    (r"Sensitive file|Sensitive.*found", "sensitive-file", "Sensitive file accessible"),
]

MEDIUM_PATTERNS = [
    (r"HKCU.*Write|Write access to HKCU", "registry-write-hkcu", "Write access to HKCU registry"),
    (r"HKLM.*Write|Write access to HKLM", "registry-write-hklm", "Write access to HKLM registry"),
    (r"Startup folder|Startup.*writable", "startup-folder", "Startup folder is writable"),
    (r"Scheduled Task.*writable|Task.*write", "writable-task", "Scheduled task is writable"),
    (r"Service.*not quoted|Service path contains space", "service-space-path", "Service path contains space (potential unquoted)"),
    (r"Group.*Membership|Member of", "group-membership", "User has special group membership"),
    (r"Privilege.*SeDebug|SeDebugPrivilege", "sedebug-privilege", "SeDebugPrivilege present"),
    (r"Privilege.*SeLoadDriver|SeLoadDriverPrivilege", "seloaddriver-privilege", "SeLoadDriverPrivilege present"),
    (r"Unattended.*xml|Unattended install", "unattended-file", "Unattended install file found"),
    (r"SYSVOL.*Group|GPP password", "gpp-password", "GPP password might be in SYSVOL"),
]

LOW_PATTERNS = [
    (r"System Info|OS Version", "system-info", "System information"),
    (r"Hotfix|Patch|KB[0-9]+", "patch-info", "Patch information"),
    (r"User.*Info|Current User", "user-info", "User information"),
    (r"Network Info|Interface", "network-info", "Network information"),
]


def parse_winpeas(content: str) -> List[Dict[str, Any]]:
    """Parse WinPEAS output and extract findings."""
    findings = []

    def add_finding(severity: str, title: str, location: str, note: str):
        findings.append({
            "severity": severity,
            "title": title,
            "where": location[:200],
            "note": note[:300]
        })

    lines = content.split("\n")

    # Process each line
    current_section = ""
    for i, line in enumerate(lines):
        # Track current section
        if line.strip().startswith("&&&&&&&&") or line.strip().startswith("====="):
            current_section = line.strip()

        # Check critical patterns
        for pattern, title, note in CRITICAL_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                add_finding("critical", title, f"line:{i+1}", note)
                break

        # Check high patterns
        for pattern, title, note in HIGH_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                add_finding("high", title, f"line:{i+1}", note)
                break

        # Check medium patterns
        for pattern, title, note in MEDIUM_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                add_finding("medium", title, f"line:{i+1}", note)
                break

    # Deduplicate findings by title
    seen = set()
    unique_findings = []
    for f in findings:
        key = f["title"]
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    return unique_findings


def main():
    parser = argparse.ArgumentParser(description="Parse WinPEAS output")
    parser.add_argument("input", help="WinPEAS raw output file")
    parser.add_argument("--out", "-o", required=True, help="Output JSON file")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    content = input_path.read_text(encoding="utf-8", errors="replace")
    findings = parse_winpeas(content)

    # Count by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f["severity"].lower()
        if sev in counts:
            counts[sev] += 1

    result = {
        "module": "winpeas",
        "status": "warn" if counts["critical"] > 0 or counts["high"] > 0 else "ok",
        "counts": counts,
        "findings": findings
    }

    output_path = Path(args.out)
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))

    print(f"Parsed {len(findings)} findings from WinPEAS")
    print(f"  Critical: {counts['critical']}, High: {counts['high']}, Medium: {counts['medium']}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
