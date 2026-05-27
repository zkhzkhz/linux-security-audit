#!/usr/bin/env python3
"""Parse CDK evaluate output, filter false positives, produce structured JSON.

Usage: parse_cdk.py <cdk-output-dir>
  Reads raw.txt from each container subdir, writes per-container findings
  and aggregated result.json.
"""
import json
import os
import re
import sys
from pathlib import Path

# --- False positive filters ---

# Standard setuid binaries (expected on any Linux system)
STANDARD_SUID = {
    "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/su", "/usr/bin/sudo",
    "/usr/bin/passwd", "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/newgrp",
    "/usr/bin/gpasswd", "/usr/bin/pkexec", "/usr/bin/fusermount",
    "/usr/bin/fusermount3",
    "/bin/mount", "/bin/umount", "/bin/su", "/bin/sudo", "/bin/passwd",
    "/bin/chfn", "/bin/chsh", "/bin/newgrp", "/bin/gpasswd", "/bin/pkexec",
    "/bin/fusermount", "/bin/fusermount3",
    "/usr/sbin/pppd", "/sbin/pppd",
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign",
}

# Env vars that are not real secrets
BENIGN_ENV_PATTERNS = [
    r"SSH_CONNECTION=", r"SSH_CLIENT=", r"SSH_TTY=", r"SSH_AUTH_SOCK=",
    r"TERM=", r"LANG=", r"PATH=", r"HOME=", r"USER=", r"SHELL=",
    r"HOSTNAME=", r"PWD=", r"OLDPWD=", r"SHLVL=", r"_=",
    r"LS_COLORS=", r"LESSOPEN=", r"LESSCLOSE=",
]

# Kernel exploits with "less probable" exposure are FP in most cases
LESS_PROBABLE_RE = re.compile(r"Exposure:\s*less probable", re.IGNORECASE)

# Cloud metadata "failed to dial" is expected noise
CLOUD_FAIL_RE = re.compile(r"failed to dial .* API")

# DNS errors when not in k8s
DNS_ERROR_RE = re.compile(r"error when requesting coreDNS")


def parse_cdk_output(raw_text, label):
    """Parse CDK evaluate output into structured findings."""
    findings = []
    lines = raw_text.splitlines()
    i = 0
    current_section = ""

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Track sections
        if stripped.startswith("[") and stripped.endswith("]"):
            current_section = stripped.strip("[] ")
            i += 1
            continue

        # --- Filter: skip DNS errors ---
        if DNS_ERROR_RE.search(stripped):
            i += 1
            continue

        # --- Filter: skip cloud metadata failures ---
        if CLOUD_FAIL_RE.search(stripped):
            i += 1
            continue

        # --- Sensitive env vars ---
        if "sensitive env found:" in stripped:
            i += 1
            if i < len(lines):
                env_line = lines[i].strip()
                # Filter benign env vars
                is_benign = any(re.match(p, env_line) for p in BENIGN_ENV_PATTERNS)
                if not is_benign:
                    findings.append({
                        "severity": "medium",
                        "title": "cdk-sensitive-env",
                        "where": f"{label}:env",
                        "note": env_line[:100],
                    })
            i += 1
            continue

        # --- Setuid files ---
        if "Setuid files found:" in stripped:
            i += 1
            while i < len(lines) and lines[i].startswith("\t"):
                suid_path = lines[i].strip()
                if suid_path not in STANDARD_SUID:
                    findings.append({
                        "severity": "medium",
                        "title": "cdk-unusual-suid",
                        "where": f"{label}:{suid_path}",
                        "note": "non-standard setuid binary",
                    })
                i += 1
            continue

        # --- Kernel exploits ---
        if stripped.startswith("[+]") and "CVE-" in stripped:
            cve_match = re.search(r"CVE-\d{4}-\d+", stripped)
            cve = cve_match.group(0) if cve_match else "unknown"
            # Collect exploit details
            exploit_lines = [stripped]
            i += 1
            while i < len(lines) and not lines[i].startswith("[+]") and not lines[i].startswith("["):
                exploit_lines.append(lines[i])
                i += 1
            block = "\n".join(exploit_lines)
            # Filter: "less probable" = low severity, not FP but low risk
            if LESS_PROBABLE_RE.search(block):
                findings.append({
                    "severity": "low",
                    "title": f"cdk-kernel-exploit-unlikely",
                    "where": f"{label}:{cve}",
                    "note": "exposure: less probable",
                })
            else:
                findings.append({
                    "severity": "high",
                    "title": f"cdk-kernel-exploit",
                    "where": f"{label}:{cve}",
                    "note": "exposure: probable or highly probable",
                })
            continue

        # --- Privileged mode / capabilities ---
        if "bindable" in stripped.lower() or "bindable" in stripped:
            i += 1
            continue
        if "bindable" in stripped:
            i += 1
            continue

        # Privileged container detection
        if "privileged:true" in stripped.lower() or "privileged mode" in stripped.lower():
            findings.append({
                "severity": "critical",
                "title": "cdk-privileged-container",
                "where": label,
                "note": "container running in privileged mode",
            })
            i += 1
            continue

        # Dangerous capabilities
        cap_match = re.search(r"cap_\w+", stripped, re.IGNORECASE)
        if cap_match and " bindable" not in stripped and "Bindable" not in stripped:
            if "Bindable" not in current_section and "Available" in current_section:
                cap = cap_match.group(0)
                dangerous_caps = {"cap_sys_admin", "cap_sys_ptrace", "cap_dac_override",
                                  "cap_net_admin", "cap_sys_module", "cap_sys_rawio",
                                  "cap_dac_read_search", "cap_fowner"}
                if cap.lower() in dangerous_caps:
                    findings.append({
                        "severity": "high",
                        "title": "cdk-dangerous-cap",
                        "where": f"{label}:{cap}",
                        "note": "dangerous capability granted",
                    })
            i += 1
            continue

        # Docker socket / containerd socket mounted
        if "docker.sock" in stripped or "containerd.sock" in stripped:
            findings.append({
                "severity": "critical",
                "title": "cdk-socket-mounted",
                "where": f"{label}:{stripped.strip()}",
                "note": "container runtime socket accessible - full escape possible",
            })
            i += 1
            continue

        # Host mount detection
        if "bindable" not in stripped and ("host bindmount" in stripped.lower() or
            ("mount" in current_section.lower() and re.search(r"/ type|/host", stripped))):
            i += 1
            continue

        # Cloud metadata accessible
        if "Metadata API available" in stripped:
            cloud = "unknown"
            if "AWS" in stripped: cloud = "AWS"
            elif "OpenStack" in stripped: cloud = "OpenStack"
            elif "Azure" in stripped: cloud = "Azure"
            elif "Google" in stripped: cloud = "GCP"
            elif "Alibaba" in stripped: cloud = "Alibaba"
            findings.append({
                "severity": "high",
                "title": "cdk-cloud-metadata",
                "where": f"{label}:metadata-api",
                "note": f"{cloud} metadata API accessible from container",
            })
            i += 1
            continue

        # Service account token
        if "bindable" not in stripped and "service account" in stripped.lower() and "error" not in stripped.lower():
            if "bindable" not in stripped:
                findings.append({
                    "severity": "high",
                    "title": "cdk-k8s-service-account",
                    "where": f"{label}:serviceaccount",
                    "note": "K8s service account token accessible",
                })
            i += 1
            continue

        # Net namespace = host
        if "host unix-socket found" in stripped or "--net=host" in stripped:
            findings.append({
                "severity": "high",
                "title": "cdk-host-network",
                "where": label,
                "note": "container shares host network namespace",
            })
            i += 1
            continue

        i += 1

    return findings


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    cdk_dir = Path(sys.argv[1])
    all_findings = []

    for cdir in sorted(cdk_dir.iterdir()):
        if not cdir.is_dir():
            continue
        raw = cdir / "raw.txt"
        if not raw.exists() or raw.stat().st_size == 0:
            continue
        label = cdir.name
        text = raw.read_text(errors="replace")
        findings = parse_cdk_output(text, label)
        # Write per-container findings
        (cdir / "findings.json").write_text(
            json.dumps(findings, indent=2, ensure_ascii=False))
        all_findings.extend(findings)

    # Deduplicate
    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["title"], f["where"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    # Sort by severity
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    all_findings.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)

    counts = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    status = "warn" if counts.get("critical", 0) + counts.get("high", 0) > 0 else "ok"
    summary = ", ".join(f"{k}:{v}" for k, v in counts.items()) or "no findings"

    result = {
        "module": "privesc-escape-check.cdk",
        "status": status,
        "summary": summary,
        "counts": counts,
        "findings": all_findings[:200],
    }
    (cdk_dir / "result.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False))
    print(f"cdk: {summary}")


if __name__ == "__main__":
    main()
