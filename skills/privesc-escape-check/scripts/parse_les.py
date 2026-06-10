#!/usr/bin/env python3
"""Parse Linux Exploit Suggester output."""

import json
import re
import sys
from pathlib import Path


def parse_les_output(raw_text: str) -> list[dict]:
    """Parse linux-exploit-suggester.sh output."""
    findings = []
    lines = raw_text.splitlines()

    current_exploit = {}
    in_exploit = False

    for line in lines:
        line = line.strip()

        # Match CVE header like "[1] CVE-2022-0847" or "CVE-2022-0847"
        cve_match = re.match(r'(?:\[\d+\]\s*)?(CVE-\d{4}-\d+)', line)
        if cve_match:
            # Save previous exploit
            if current_exploit and current_exploit.get("cve"):
                findings.append(make_finding(current_exploit))

            current_exploit = {"cve": cve_match.group(1)}
            in_exploit = True
            continue

        # Match exploit details
        if in_exploit and line:
            # Name: DirtyPipe
            if line.startswith("Name:"):
                current_exploit["name"] = line.split(":", 1)[1].strip()
            # Requires: kernel >= 5.8
            elif line.startswith(("Requires:", "Requisites:", "Requirements:")):
                current_exploit["requires"] = line.split(":", 1)[1].strip()
            # Tags: ubuntu=...
            elif line.startswith("Tags:"):
                current_exploit["tags"] = line.split(":", 1)[1].strip()
            # Source URL
            elif line.startswith(("Source:", "Url:", "URL:")):
                current_exploit["source"] = line.split(":", 1)[1].strip()
            # Use: ./exploit
            elif line.startswith("Use:"):
                current_exploit["use"] = line.split(":", 1)[1].strip()
            # Comments/Details
            elif line.startswith(("Comments:", "Details:")):
                current_exploit["note"] = line.split(":", 1)[1].strip()

    # Save last exploit
    if current_exploit and current_exploit.get("cve"):
        findings.append(make_finding(current_exploit))

    return findings


def make_finding(exploit: dict) -> dict:
    """Convert exploit dict to finding."""
    cve = exploit.get("cve", "unknown")
    name = exploit.get("name", "")
    requires = exploit.get("requires", "")
    tags = exploit.get("tags", "")
    note = exploit.get("note", "")

    title = f"kernel-cve-{cve}"
    if name:
        title = f"kernel-{name.lower().replace(' ', '-')}"

    note_parts = []
    if name:
        note_parts.append(f"Name: {name}")
    if requires:
        note_parts.append(f"Requires: {requires}")
    if tags:
        note_parts.append(f"Tags: {tags}")
    if note:
        note_parts.append(note)

    return {
        "severity": "medium",
        "title": title,
        "where": "host",
        "note": " | ".join(note_parts) or cve,
        "cve": cve
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: parse_les.py <input.log> <output.json>")
        sys.exit(1)

    raw_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    if not raw_path.exists():
        print(f"Error: {raw_path} not found")
        sys.exit(1)

    raw_text = raw_path.read_text()
    findings = parse_les_output(raw_text)

    # Build result
    counts = {}
    for f in findings:
        sev = f.get("severity", "medium")
        counts[sev] = counts.get(sev, 0) + 1

    status = "warn" if counts.get("medium", 0) > 0 else "ok"
    summary = f"{len(findings)} potential kernel exploits" if findings else "no kernel exploits found"

    result = {
        "module": "linux-exploit-suggester",
        "status": status,
        "summary": summary,
        "counts": counts,
        "findings": findings
    }

    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"Parsed {len(findings)} findings -> {out_path}")


if __name__ == "__main__":
    main()
