#!/usr/bin/env python3
"""Generate per-module human-readable markdown reports from result.json.

Usage:
    gen_module_report.py <module-output-dir>
    gen_module_report.py <run-dir>  (generates for all modules)

Reads result.json + any module-specific files, outputs report.md.
Designed for offline review without AI assistance.
"""
import json
import os
import sys
import glob
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_EMOJI = {"critical": "!!!", "high": "!!", "medium": "!", "low": "~", "info": "-"}


def load_json(path):
    try:
        return json.loads(Path(path).read_text(errors="replace"))
    except Exception:
        return None


def render_findings_table(findings, max_rows=50):
    if not findings:
        return ["No findings.", ""]
    lines = []
    lines.append("| Severity | Title | Location | Detail |")
    lines.append("|----------|-------|----------|--------|")
    for f in findings[:max_rows]:
        sev = f.get("severity", "?")
        title = f.get("title") or f.get("rule") or f.get("id") or "?"
        where = f.get("where") or f.get("file") or f.get("path") or ""
        note = f.get("note") or f.get("detail") or ""
        # Escape pipes in content
        where = where.replace("|", "\\|")[:80]
        note = note.replace("|", "\\|")[:100]
        lines.append(f"| {sev} | {title} | `{where}` | {note} |")
    if len(findings) > max_rows:
        lines.append(f"| ... | +{len(findings)-max_rows} more | | |")
    lines.append("")
    return lines


def gen_sensitive_info_report(mod_dir):
    """Generate report for sensitive-info-scan module."""
    result = load_json(mod_dir / "result.json")
    if not result:
        return None

    lines = []
    lines.append("# Sensitive Information Scan Report")
    lines.append("")
    lines.append(f"- Module: `sensitive-info-scan`")
    lines.append(f"- Status: **{result.get('status', '?').upper()}**")
    lines.append(f"- Summary: {result.get('summary', 'N/A')}")
    lines.append("")

    counts = result.get("counts", {})
    if counts:
        lines.append("## Severity Counts")
        lines.append("")
        for s in SEVERITY_ORDER:
            if s in counts:
                lines.append(f"- **{s}**: {counts[s]}")
        lines.append("")

    findings = result.get("findings", [])
    lines.append("## Findings")
    lines.append("")
    lines.extend(render_findings_table(findings))

    # Container results
    cont_result = load_json(mod_dir / "containers-result.json")
    if cont_result and cont_result.get("findings"):
        lines.append("## Container Findings")
        lines.append("")
        lines.extend(render_findings_table(cont_result["findings"]))

    lines.append("## Remediation")
    lines.append("")
    lines.append("- Rotate any exposed secrets/tokens immediately")
    lines.append("- Move secrets to a vault (HashiCorp Vault, AWS Secrets Manager, etc.)")
    lines.append("- Add `.gitignore` rules for sensitive file patterns")
    lines.append("- Use environment variable injection at runtime instead of hardcoded secrets")
    lines.append("- Review CI/CD pipeline for secret leakage in logs/artifacts")
    lines.append("")
    return lines


def gen_privesc_report(mod_dir):
    """Generate report for privesc-escape-check module."""
    result = load_json(mod_dir / "result.json")
    if not result:
        result = load_json(mod_dir / "cdk" / "result.json")
    if not result:
        return None

    lines = []
    lines.append("# Privilege Escalation & Container Escape Report")
    lines.append("")
    lines.append(f"- Module: `privesc-escape-check`")
    lines.append(f"- Status: **{result.get('status', '?').upper()}**")
    lines.append(f"- Summary: {result.get('summary', 'N/A')}")
    lines.append("")

    counts = result.get("counts", {})
    if counts:
        lines.append("## Severity Counts")
        lines.append("")
        for s in SEVERITY_ORDER:
            if s in counts:
                lines.append(f"- **{s}**: {counts[s]}")
        lines.append("")

    findings = result.get("findings", [])

    # Group by category
    categories = {}
    for f in findings:
        title = f.get("title", "other")
        cat = title.split("-")[0] if "-" in title else title
        categories.setdefault(cat, []).append(f)

    lines.append("## Findings by Category")
    lines.append("")
    for cat, items in sorted(categories.items(), key=lambda x: -len(x[1])):
        lines.append(f"### {cat} ({len(items)} findings)")
        lines.append("")
        lines.extend(render_findings_table(items, max_rows=20))

    # CDK findings (container escape / misconfig)
    cdk_result = load_json(mod_dir / "cdk" / "result.json")
    if cdk_result and cdk_result.get("findings"):
        cdk_findings = cdk_result["findings"]
        lines.append("## CDK Container Escape Analysis")
        lines.append("")
        lines.append(f"- Containers scanned: {len(set(f.get('where','').split(':')[0] for f in cdk_findings))}")
        lines.append(f"- Summary: {cdk_result.get('summary', 'N/A')}")
        lines.append("")
        lines.extend(render_findings_table(cdk_findings, max_rows=30))

    lines.append("## Remediation Priority")
    lines.append("")
    high_crit = [f for f in findings if f.get("severity") in ("critical", "high")]
    if high_crit:
        lines.append("Immediate action required:")
        lines.append("")
        for f in high_crit[:10]:
            lines.append(f"1. **{f.get('title')}** at `{f.get('where','')}` - {f.get('note','')}")
        lines.append("")
    lines.append("General hardening:")
    lines.append("")
    lines.append("- Remove SUID/SGID bits from unnecessary binaries")
    lines.append("- Restrict capabilities (drop ALL, add only needed)")
    lines.append("- Enable seccomp and AppArmor profiles")
    lines.append("- Run containers as non-root user")
    lines.append("- Use read-only root filesystem where possible")
    lines.append("- Remove docker.sock mounts from containers")
    lines.append("- Block cloud metadata API (169.254.169.254) from containers")
    lines.append("- Drop NET_RAW and other unnecessary capabilities")
    lines.append("")
    return lines


def gen_lateral_report(mod_dir):
    """Generate report for lateral-movement-scan module."""
    result = load_json(mod_dir / "result.json")
    if not result:
        return None

    lines = []
    lines.append("# Lateral Movement Scan Report")
    lines.append("")
    lines.append(f"- Module: `lateral-movement-scan`")
    lines.append(f"- Status: **{result.get('status', '?').upper()}**")
    lines.append(f"- Summary: {result.get('summary', 'N/A')}")
    lines.append("")

    counts = result.get("counts", {})
    if counts:
        lines.append("## Severity Counts")
        lines.append("")
        for s in SEVERITY_ORDER:
            if s in counts:
                lines.append(f"- **{s}**: {counts[s]}")
        lines.append("")

    # Live hosts
    live_file = mod_dir / "live.txt"
    if live_file.exists():
        hosts = [l.strip() for l in live_file.read_text().splitlines() if l.strip()]
        lines.append(f"## Discovered Hosts ({len(hosts)})")
        lines.append("")
        for h in hosts[:30]:
            lines.append(f"- `{h}`")
        lines.append("")

    # Credentials
    creds = load_json(mod_dir / "creds.json")
    if creds and creds.get("findings"):
        lines.append("## Host Credentials")
        lines.append("")
        lines.extend(render_findings_table(creds["findings"]))

    # Container credentials
    cont_creds = load_json(mod_dir / "containers-creds.json")
    if cont_creds and cont_creds.get("findings"):
        lines.append("## Container Credentials")
        lines.append("")
        lines.extend(render_findings_table(cont_creds["findings"]))

    # Services
    svc = load_json(mod_dir / "service-result.json")
    if svc and svc.get("findings"):
        lines.append("## Exposed Services")
        lines.append("")
        lines.extend(render_findings_table(svc["findings"]))

    lines.append("## Remediation")
    lines.append("")
    lines.append("- Remove or encrypt SSH private keys on hosts")
    lines.append("- Rotate exposed cloud credentials (AWS/GCP/Azure)")
    lines.append("- Restrict network access between containers and hosts")
    lines.append("- Disable unnecessary services on internal networks")
    lines.append("- Use network segmentation to limit blast radius")
    lines.append("")
    return lines


def gen_egress_report(mod_dir):
    """Generate report for egress-control-audit module."""
    result = load_json(mod_dir / "result.json")
    if not result:
        return None

    lines = []
    lines.append("# Egress Control & Container Isolation Report")
    lines.append("")
    lines.append(f"- Module: `egress-control-audit`")
    lines.append(f"- Status: **{result.get('status', '?').upper()}**")
    lines.append(f"- Summary: {result.get('summary', 'N/A')}")
    lines.append("")

    counts = result.get("counts", {})
    if counts:
        lines.append("## Severity Counts")
        lines.append("")
        for s in SEVERITY_ORDER:
            if s in counts:
                lines.append(f"- **{s}**: {counts[s]}")
        lines.append("")

    # Isolation findings (high priority)
    high_findings = [f for f in result.get("findings", []) if f.get("severity") == "high"]
    if high_findings:
        lateral = [f for f in high_findings if "lateral" in f.get("title", "")]
        egress = [f for f in high_findings if "egress" in f.get("title", "")]

        if lateral:
            lines.append("## Container-to-Container Isolation (FAIL)")
            lines.append("")
            lines.append("| Source | Target | Risk |")
            lines.append("|--------|--------|------|")
            for f in lateral:
                lines.append(f"| {f['where']} | | not isolated |")
            lines.append("")

        if egress:
            lines.append("## Outbound Internet Access (FAIL)")
            lines.append("")
            lines.append("| Source Container | Target | Risk |")
            lines.append("|-----------------|--------|------|")
            for f in egress:
                lines.append(f"| {f['where']} | | reverse shell risk |")
            lines.append("")

    # Endpoints
    endpoints = load_json(mod_dir / "endpoints.json")
    if endpoints:
        lines.append(f"## Host Egress Endpoints ({len(endpoints)})")
        lines.append("")
        lines.append("| Proto | Address | Port | Count | Source |")
        lines.append("|-------|---------|------|-------|--------|")
        for e in endpoints[:30]:
            lines.append(f"| {e['proto']} | {e['addr']} | {e['port']} | {e['count']} | {e['process']} |")
        lines.append("")

    # Firewall state
    ipt = mod_dir / "iptables.save"
    if ipt.exists():
        content = ipt.read_text(errors="replace")
        has_output_rules = "OUTPUT" in content and "-j" in content
        lines.append("## Firewall State")
        lines.append("")
        if has_output_rules:
            lines.append("- iptables OUTPUT chain: **has rules**")
        else:
            lines.append("- iptables OUTPUT chain: **no egress filtering** (default ACCEPT)")
        lines.append("")

    lines.append("## Remediation")
    lines.append("")
    lines.append("### Container Isolation")
    lines.append("- Use separate user-defined bridge networks per CI job")
    lines.append("- Set `--icc=false` on docker daemon to disable inter-container communication")
    lines.append("- In K8s: apply default-deny NetworkPolicy for both ingress and egress")
    lines.append("")
    lines.append("### Egress Control")
    lines.append("- Use `--network=none` for containers that don't need network")
    lines.append("- Apply iptables OUTPUT rules to block container subnets from external IPs")
    lines.append("- Only allow egress to required registries/mirrors via explicit allowlist")
    lines.append("- Use a forward proxy for controlled outbound access")
    lines.append("- In K8s: use egress NetworkPolicy limiting to internal CIDRs")
    lines.append("")
    return lines


# --- Module dispatcher ---
MODULE_GENERATORS = {
    "sensitive-info-scan": gen_sensitive_info_report,
    "privesc-escape-check": gen_privesc_report,
    "lateral-movement-scan": gen_lateral_report,
    "egress-control-audit": gen_egress_report,
}


def generate_report(mod_dir: Path) -> str | None:
    mod_dir = Path(mod_dir)
    name = mod_dir.name
    gen = MODULE_GENERATORS.get(name)
    if not gen:
        return None
    lines = gen(mod_dir)
    if not lines:
        return None
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.insert(2, f"- Generated: {ts}")
    lines.insert(3, f"- Host: `{os.uname().nodename}`")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)

    target = Path(sys.argv[1]).resolve()

    if (target / "result.json").exists() or target.name in MODULE_GENERATORS:
        # Single module directory
        report = generate_report(target)
        if report:
            out = target / "report.md"
            out.write_text(report, encoding="utf-8")
            print(f"wrote {out}")
    else:
        # Run directory — generate for all modules
        for d in sorted(target.iterdir()):
            if d.is_dir() and (d / "result.json").exists():
                report = generate_report(d)
                if report:
                    out = d / "report.md"
                    out.write_text(report, encoding="utf-8")
                    print(f"wrote {out}")


if __name__ == "__main__":
    main()
