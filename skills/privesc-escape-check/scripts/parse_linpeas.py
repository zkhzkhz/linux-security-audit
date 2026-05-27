#!/usr/bin/env python3
"""Parse LinPEAS raw text output into structured result.json for the orchestrator.

LinPEAS uses colored markers (stripped to plain text here) and section headers.
We extract findings by matching known high-signal patterns.

Usage:
    parse_linpeas.py linpeas_raw.txt [--out host.json]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

FINDINGS: list[dict] = []

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m|\[[0-9;]*m')


def strip_ansi(s: str) -> str:
    return ANSI_RE.sub('', s)


def add(sev: str, title: str, where: str, note: str):
    FINDINGS.append({"severity": sev, "title": title, "where": where, "note": note[:300]})


def parse(text: str):
    text = strip_ansi(text)
    lines = text.splitlines()

    for i, line in enumerate(lines):
        l = line.strip()

        # --- SUID binaries (GTFOBins dangerous) ---
        if re.search(r'-rwsr-', line):
            path = line.split()[-1] if line.split() else ""
            danger = re.search(
                r'/(vim|vim\.basic|nano|find|cp|tar|awk|gawk|python[23]?|perl|'
                r'ruby|node|bash|sh|dash|nmap|env|expect|screen|wget|curl|gdb|'
                r'strace|ltrace|systemctl|mount|nsenter|docker|pkexec)$', path)
            if danger:
                add("high", "dangerous-suid", f"host:{path}", "GTFOBins SUID")

        # --- NOPASSWD sudo ---
        if 'NOPASSWD' in l and not l.startswith('#'):
            add("high", "sudoers-nopasswd", "host:/etc/sudoers", l)

        # --- Writable PATH directories ---
        if re.search(r'Writable.*folder.*PATH|PATH.*writable', line, re.IGNORECASE) \
           and 'secure_path' not in l.lower() and 'http' not in l:
            for j in range(i+1, min(i+10, len(lines))):
                p = lines[j].strip()
                if not p or p.startswith('╔') or p.startswith('═'):
                    break
                if p.startswith('/') and ':' not in p and ' ' not in p:
                    add("high", "writable-path-dir", f"host:{p}", "directory in PATH writable")

        # --- Docker socket accessible ---
        if 'docker.sock' in l and ('rw' in l or 'writable' in l.lower() or 'write permissions' in l.lower()):
            add("critical", "docker-sock-accessible", "host:/var/run/docker.sock", l)

        # --- Writable systemd units ---
        if re.search(r'writable.*\.service', l, re.IGNORECASE) or \
           (l.endswith('.service') and i > 0 and 'writable' in lines[i-1].lower()):
            add("high", "writable-systemd-unit", f"host:{l}", "writable unit file")

        # --- /etc/shadow readable ---
        if re.search(r'/etc/shadow.*-r..-r', line):
            add("high", "shadow-readable", "host:/etc/shadow", "shadow file world/group readable")

        # --- Capabilities ---
        if 'cap_' in l.lower() and '=' in l and not l.startswith('CVE:'):
            cap_match = re.search(r'(cap_sys_admin|cap_sys_ptrace|cap_sys_module|'
                                  r'cap_dac_read_search|cap_dac_override|cap_setuid|'
                                  r'cap_net_admin|cap_chown|cap_fowner)', l, re.IGNORECASE)
            if cap_match and not re.search(r'CVE-\d{4}-\d+', l):
                binary = l.split()[0] if l.split() else l
                add("medium", "dangerous-cap", f"host:{binary}", l)

        # --- Writable cron jobs ---
        if re.search(r'(cron|crontab)', l, re.IGNORECASE) and 'writable' in l.lower():
            add("high", "writable-cron", f"host:{l}", "writable cron file")

        # --- Kernel exploits suggested ---
        if re.search(r'(CVE-\d{4}-\d+)', l):
            cve = re.search(r'(CVE-\d{4}-\d+)', l).group(1)
            add("medium", f"kernel-cve-{cve}", "host", l)

        # --- Passwords in config files ---
        if re.search(r'password\s*[=:]\s*\S+', l, re.IGNORECASE) and \
           not re.search(r'(password\s*[=:]\s*(password|passwd|\*|x|!|\$))', l, re.IGNORECASE):
            if '/etc/' in l or '.conf' in l or '.cnf' in l or '.ini' in l:
                add("medium", "password-in-config", f"host", l[:200])

        # --- UID 0 accounts (not root) ---
        if re.search(r'^[^:]+:.*:0:0:', l) and not l.startswith('root:'):
            user = l.split(':')[0]
            add("critical", "extra-root-uid0", f"host:user:{user}", f"UID 0 account: {user}")

        # --- Interesting files: private keys ---
        if re.search(r'(id_rsa|id_ecdsa|id_ed25519|\.pem|\.key)$', l) and \
           not l.endswith('.pub'):
            if re.search(r'^/', l.split()[-1] if l.split() else ""):
                fpath = l.split()[-1]
                # Skip CA certs and public cert bundles (not actual private keys)
                if re.search(r'/etc/ssl/certs/|/ca-certificates/|/pki/|/pollinate/', fpath):
                    pass
                elif re.search(r'(id_rsa|id_ecdsa|id_ed25519|privkey|private|\.key)$', fpath) \
                     or 'cosign' in fpath:
                    add("medium", "private-key-file", f"host:{fpath}", "private key file found")

        # --- Writable /etc/passwd ---
        if re.search(r'/etc/passwd.*-rw.+-', line) or \
           ('etc/passwd' in l and 'writable' in l.lower()):
            add("critical", "passwd-writable", "host:/etc/passwd", "writable by non-root")

        # --- Container: docker group membership ---
        if re.search(r'(docker|lxd|lxc)\s', l) and 'group' in l.lower():
            add("high", "docker-group", "host", l)

        # --- Container: running in privileged mode ---
        if re.search(r'privileged\s*(mode|container|=true)', l, re.IGNORECASE):
            add("critical", "privileged-container", "container", l)

        # --- Container: mount namespace escape indicators ---
        if re.search(r'/dev/(sd[a-z]|nvme|vd[a-z])', l) and 'mount' in lines[max(0,i-3):i+1].__repr__().lower():
            add("medium", "host-disk-in-container", f"host:{l.strip()}", "host disk device visible")

        # --- Network: services listening on 0.0.0.0 ---
        if re.search(r'0\.0\.0\.0:\d+', l) and ('LISTEN' in l or 'tcp' in l):
            port_m = re.search(r'0\.0\.0\.0:(\d+)', l)
            if port_m:
                port = port_m.group(1)
                add("low", f"listen-all-{port}", f"host:0.0.0.0:{port}", l)

        # --- Network: interesting internal services ---
        if re.search(r'127\.0\.0\.1:(6379|3306|5432|27017|9200|2379|8500)', l):
            port_m = re.search(r'127\.0\.0\.1:(\d+)', l)
            if port_m:
                add("low", f"internal-svc-{port_m.group(1)}", f"host:127.0.0.1:{port_m.group(1)}", l)

        # --- Container: /proc/1/cgroup shows container ---
        if re.search(r'(docker|kubepods|containerd)', l) and '/cgroup' in lines[max(0,i-5):i+1].__repr__():
            pass  # informational only, not a finding

        # --- Writable docker.sock (alternate detection) ---
        if 'docker.sock' in l and re.search(r'(srw|777|666)', l):
            add("critical", "docker-sock-accessible", "host:/var/run/docker.sock", l)


def dedup(findings: list[dict]) -> list[dict]:
    seen: set[str] = set()
    result = []
    for f in findings:
        key = f"{f['title']}|{f['where']}"
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", help="linpeas_raw.txt path")
    p.add_argument("--out", default=None, help="output JSON path")
    args = p.parse_args()

    inpath = Path(args.input)
    if not inpath.exists():
        print(f"missing: {inpath}", file=sys.stderr)
        sys.exit(2)

    text = inpath.read_text(encoding="utf-8", errors="replace")
    parse(text)

    findings = dedup(FINDINGS)
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings.sort(key=lambda f: sev_rank.get(f.get("severity", "info"), 0), reverse=True)

    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    status = "warn" if counts.get("critical", 0) + counts.get("high", 0) > 0 else "ok"
    summary = ", ".join(f"{k}:{v}" for k, v in counts.items()) or "no findings"

    data = {
        "module": "privesc-escape-check.host",
        "status": status,
        "summary": summary,
        "counts": counts,
        "findings": findings,
        "notes": ["Powered by LinPEAS (peass-ng). Full output in host.log."],
    }

    outpath = Path(args.out) if args.out else inpath.parent / "host.json"
    outpath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"parse_linpeas: {outpath} ({summary})")


if __name__ == "__main__":
    main()
