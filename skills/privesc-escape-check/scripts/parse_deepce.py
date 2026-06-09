#!/usr/bin/env python3
"""Parse Deepce output files into structured JSON findings."""
import json
import os
import re
import sys
from pathlib import Path

SEVERITY_MAP = {
    "Docker Sock": ("critical", "docker socket accessible - full escape"),
    "Privileged Mode": ("critical", "container runs in privileged mode"),
    "docker.sock": ("critical", "docker socket mount detected"),
    "CAP_SYS_ADMIN": ("high", "dangerous capability enables escape"),
    "CAP_SYS_PTRACE": ("high", "can attach to host processes"),
    "CAP_NET_ADMIN": ("high", "can manipulate network stack"),
    "CAP_DAC_READ_SEARCH": ("high", "can read any file bypassing permissions"),
    "CAP_DAC_OVERRIDE": ("medium", "can bypass file permission checks"),
    "sensitive mount": ("high", "host filesystem mounted"),
    "/root": ("high", "host /root accessible"),
    "namespace": ("medium", "shared namespace with host"),
    "K8S Service Account": ("medium", "kubernetes SA token found"),
    "metadata": ("medium", "cloud metadata may be reachable"),
    "CAP_NET_RAW": ("low", "can craft raw packets"),
    "AppArmor": ("low", "no AppArmor profile"),
    "Seccomp": ("low", "seccomp not enforcing"),
}

# Patterns that indicate false positives or non-issues
FALSE_POSITIVE_PATTERNS = [
    r'/etc\s+(is|appears|seems)\s+(ok|normal|default)',
    r'/etc\s+not\s+(mounted|found|accessible)',
    r'no\s+(sensitive|host)\s+mounts?\s+found',
    r'privileged.*false',
    r'privileged.*no',
    r'privileged.*disabled',
    r'docker\s*sock.*not\s+(found|mounted|accessible)',
    r'no\s+docker\s+sock',
]


def is_false_positive(line):
    """Check if line matches known false positive patterns."""
    for pattern in FALSE_POSITIVE_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


def parse_deepce_output(text, container_name):
    findings = []
    lines = text.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue

        # Skip known false positives
        if is_false_positive(stripped):
            continue

        for pattern, (severity, note) in SEVERITY_MAP.items():
            if pattern.lower() in stripped.lower():
                # Additional check: "not found" or "no" prefix often indicates absence
                if "not found" in stripped.lower():
                    continue
                # Skip lines that start with "No" (indicating absence)
                if stripped.lower().startswith("no "):
                    continue

                # Special handling for /etc - only flag if it's explicitly a host mount
                if pattern == "/etc":
                    # Look for indicators that this is actually a host /etc mount
                    if "host" not in stripped.lower() and "mount" not in stripped.lower():
                        continue

                findings.append({
                    "severity": severity,
                    "title": f"deepce-{pattern.lower().replace(' ', '-').replace('/', '')}",
                    "where": f"{container_name}:container",
                    "note": note + f" | {stripped[:120]}",
                })
                break

    seen = set()
    deduped = []
    for f in findings:
        key = (f["title"], f["where"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def main():
    if len(sys.argv) < 2:
        print("Usage: parse_deepce.py <deepce-output-dir>", file=sys.stderr)
        sys.exit(2)

    out_dir = Path(sys.argv[1])
    all_findings = []

    for txt_file in sorted(out_dir.glob("*.txt")):
        container_name = txt_file.stem
        text = txt_file.read_text(errors="replace")
        findings = parse_deepce_output(text, container_name)
        all_findings.extend(findings)

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    all_findings.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)

    sev_counts = {}
    for f in all_findings:
        s = f["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    status = "warn" if sev_counts.get("critical", 0) + sev_counts.get("high", 0) > 0 else "ok"
    summary = ", ".join(f"{k}:{v}" for k, v in sev_counts.items()) if sev_counts else "no findings"

    result = {
        "module": "privesc-escape-check.deepce",
        "status": status,
        "summary": summary,
        "counts": sev_counts,
        "findings": all_findings,
    }

    result_path = out_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"deepce: {summary}")


if __name__ == "__main__":
    main()
