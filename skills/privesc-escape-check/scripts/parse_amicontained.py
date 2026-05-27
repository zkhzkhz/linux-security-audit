#!/usr/bin/env python3
"""Parse amicontained output files into structured JSON findings."""
import json
import re
import sys
from pathlib import Path

DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN": ("critical", "full escape possible via mount/cgroup"),
    "CAP_SYS_PTRACE": ("high", "can attach to host processes"),
    "CAP_NET_ADMIN": ("high", "can manipulate network/iptables"),
    "CAP_DAC_READ_SEARCH": ("high", "can read any file"),
    "CAP_DAC_OVERRIDE": ("medium", "can bypass file permissions"),
    "CAP_NET_RAW": ("low", "can craft raw packets / ARP spoof"),
    "CAP_SYS_RAWIO": ("critical", "raw I/O access to devices"),
    "CAP_SYS_MODULE": ("critical", "can load kernel modules"),
    "CAP_MKNOD": ("medium", "can create device nodes"),
}


def parse_amicontained(text, container_name):
    findings = []
    lines = text.splitlines()

    runtime = "unknown"
    for line in lines:
        if "Container Runtime:" in line:
            runtime = line.split(":", 1)[1].strip()

    # Check seccomp
    for line in lines:
        if "Seccomp:" in line:
            val = line.split(":", 1)[1].strip().lower()
            if "disabled" in val or "unconfined" in val:
                findings.append({
                    "severity": "medium",
                    "title": "ami-seccomp-disabled",
                    "where": container_name,
                    "note": f"seccomp not enforcing ({val})",
                })

    # Check capabilities - format: "BOUNDING -> cap1 cap2 cap3..."
    for line in lines:
        if "BOUNDING ->" in line or "Effective ->" in line or ("Capabilities:" not in line and "->" in line and "cap" not in line.lower()):
            parts = line.split("->")
            if len(parts) < 2:
                continue
            caps_str = parts[1].strip()
            caps = [c.strip().upper() for c in caps_str.split()]
            for cap in caps:
                cap_full = cap if cap.startswith("CAP_") else f"CAP_{cap}"
                if cap_full in DANGEROUS_CAPS:
                    sev, note = DANGEROUS_CAPS[cap_full]
                    findings.append({
                        "severity": sev,
                        "title": f"ami-cap-{cap.lower()}",
                        "where": container_name,
                        "note": note,
                    })

    # Check Docker socket
    for line in lines:
        if "Docker Socket" in line or "docker.sock" in line:
            if "not found" not in line.lower():
                findings.append({
                    "severity": "critical",
                    "title": "ami-docker-socket",
                    "where": container_name,
                    "note": f"docker socket accessible | {line.strip()[:100]}",
                })
                break

    # Check user namespaces
    for line in lines:
        if "User Namespace" in line:
            val = line.split(":", 1)[1].strip().lower()
            if "enabled" in val:
                findings.append({
                    "severity": "low",
                    "title": "ami-userns-enabled",
                    "where": container_name,
                    "note": "user namespaces enabled (can aid escape)",
                })

    # Check pid namespace sharing
    for line in lines:
        if "PID Namespace" in line and "host" in line.lower():
            findings.append({
                "severity": "high",
                "title": "ami-pid-host",
                "where": container_name,
                "note": "shares PID namespace with host",
            })

    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: parse_amicontained.py <output-dir>", file=sys.stderr)
        sys.exit(2)

    out_dir = Path(sys.argv[1])
    all_findings = []

    for txt_file in sorted(out_dir.glob("*.txt")):
        container_name = txt_file.stem
        text = txt_file.read_text(errors="replace")
        if text.strip():
            findings = parse_amicontained(text, container_name)
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
        "module": "privesc-escape-check.amicontained",
        "status": status,
        "summary": summary,
        "counts": sev_counts,
        "findings": all_findings,
    }

    result_path = out_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"amicontained: {summary}")


if __name__ == "__main__":
    main()
