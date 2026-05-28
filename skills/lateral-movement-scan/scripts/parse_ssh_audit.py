#!/usr/bin/env python3
"""Parse ssh-audit JSON output into structured findings."""
import json
import sys
from pathlib import Path

WEAK_ALGORITHMS = {
    "diffie-hellman-group1-sha1": ("high", "weak key exchange (1024-bit)"),
    "diffie-hellman-group14-sha1": ("medium", "SHA-1 key exchange"),
    "ssh-rsa": ("medium", "SHA-1 host key signature"),
    "ssh-dss": ("high", "DSA host key (1024-bit, broken)"),
    "arcfour": ("critical", "RC4 cipher (broken)"),
    "arcfour128": ("critical", "RC4 cipher (broken)"),
    "arcfour256": ("critical", "RC4 cipher (broken)"),
    "3des-cbc": ("high", "3DES cipher (slow, 64-bit block)"),
    "blowfish-cbc": ("medium", "Blowfish CBC (64-bit block)"),
    "cast128-cbc": ("medium", "CAST128 CBC (64-bit block)"),
    "hmac-md5": ("high", "MD5 MAC (broken hash)"),
    "hmac-sha1": ("medium", "SHA-1 MAC"),
    "hmac-md5-96": ("high", "MD5-96 MAC (broken hash)"),
    "hmac-sha1-96": ("medium", "SHA-1-96 MAC"),
    "none": ("critical", "no encryption/MAC"),
}


def parse_ssh_audit_json(filepath):
    findings = []
    try:
        data = json.loads(filepath.read_text(errors="replace"))
    except (json.JSONDecodeError, Exception):
        return findings

    target = data.get("target", filepath.stem.replace("_", ":"))
    banner = data.get("banner", {})

    # Check for outdated SSH version
    software = banner.get("software", "")
    protocol = banner.get("protocol", "")
    if "OpenSSH" in software:
        try:
            ver = software.split("_")[1].split("p")[0]
            major, minor = int(ver.split(".")[0]), int(ver.split(".")[1])
            if major < 8:
                findings.append({
                    "severity": "high",
                    "title": "ssh-outdated-version",
                    "where": target,
                    "note": f"OpenSSH {ver} is outdated (recommend 8.x+)",
                })
        except (IndexError, ValueError):
            pass

    # Check key exchange algorithms
    for kex in data.get("kex", []):
        name = kex.get("algorithm", "")
        if name in WEAK_ALGORITHMS:
            sev, note = WEAK_ALGORITHMS[name]
            findings.append({
                "severity": sev,
                "title": f"ssh-weak-kex",
                "where": target,
                "note": f"{name}: {note}",
            })

    # Check host key algorithms
    for key in data.get("key", []):
        name = key.get("algorithm", "")
        if name in WEAK_ALGORITHMS:
            sev, note = WEAK_ALGORITHMS[name]
            findings.append({
                "severity": sev,
                "title": f"ssh-weak-hostkey",
                "where": target,
                "note": f"{name}: {note}",
            })
        keysize = key.get("keysize", 0)
        if keysize and keysize < 2048 and "rsa" in name.lower():
            findings.append({
                "severity": "high",
                "title": "ssh-short-rsa-key",
                "where": target,
                "note": f"RSA key only {keysize} bits (need 2048+)",
            })

    # Check encryption algorithms
    for enc in data.get("enc", []):
        name = enc.get("algorithm", "")
        if name in WEAK_ALGORITHMS:
            sev, note = WEAK_ALGORITHMS[name]
            findings.append({
                "severity": sev,
                "title": f"ssh-weak-cipher",
                "where": target,
                "note": f"{name}: {note}",
            })

    # Check MAC algorithms
    for mac in data.get("mac", []):
        name = mac.get("algorithm", "")
        if name in WEAK_ALGORITHMS:
            sev, note = WEAK_ALGORITHMS[name]
            findings.append({
                "severity": sev,
                "title": f"ssh-weak-mac",
                "where": target,
                "note": f"{name}: {note}",
            })

    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: parse_ssh_audit.py <output-dir>", file=sys.stderr)
        sys.exit(2)

    out_dir = Path(sys.argv[1])
    all_findings = []

    for json_file in sorted(out_dir.glob("*.json")):
        if json_file.name == "result.json":
            continue
        findings = parse_ssh_audit_json(json_file)
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
        "module": "lateral-movement-scan.ssh-audit",
        "status": status,
        "summary": summary,
        "counts": sev_counts,
        "findings": all_findings,
    }

    result_path = out_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"ssh-audit: {summary}")


if __name__ == "__main__":
    main()
