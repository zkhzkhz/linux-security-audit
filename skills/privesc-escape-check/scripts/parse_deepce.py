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
    "sensitive mount": ("high", "host filesystem mounted"),
    "/etc": ("high", "host /etc accessible"),
    "/root": ("high", "host /root accessible"),
    "namespace": ("medium", "shared namespace with host"),
    "K8S Service Account": ("medium", "kubernetes SA token found"),
    "metadata": ("medium", "cloud metadata may be reachable"),
    "CAP_NET_RAW": ("low", "can craft raw packets"),
    "AppArmor": ("low", "no AppArmor profile"),
    "Seccomp": ("low", "seccomp not enforcing"),
}


def parse_deepce_output(text, container_name):
    findings = []
    lines = text.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        for pattern, (severity, note) in SEVERITY_MAP.items():
            if pattern.lower() in stripped.lower():
                if "not found" in stripped.lower() or "no" == stripped.lower()[:2]:
                    continue
                findings.append({
                    "severity": severity,
                    "title": f"deepce-{pattern.lower().replace(' ', '-').replace('/', '')}",
                    "where": f"{container_name}",
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
