#!/usr/bin/env bash
# Verify container network isolation and egress control.
# For each container: probe other container IPs (lateral) + external endpoints (egress).
# Shell-only inside containers; analysis on host.
# Usage: verify_isolation.sh [--timeout N] [--out DIR]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

TIMEOUT=5
OUT_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift 2;;
    --out)     OUT_OVERRIDE="$2"; shift 2;;
    -h|--help) sed -n '1,5p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

OUT="${OUT_OVERRIDE:-$(ensure_run_dir egress-control-audit)}"
mkdir -p "$OUT/isolation"
LOG="$OUT/isolation/verify.log"; : > "$LOG"

RT=""
for r in docker nerdctl podman; do
  command -v "$r" >/dev/null 2>&1 && { RT="$r"; break; }
done
[ -n "$RT" ] || die "no container runtime found"

# --- enumerate containers with IPs ---
declare -A CONTAINER_IPS
declare -A CONTAINER_LABELS
CONTAINER_IDS=()

while IFS= read -r cid; do
  [[ -n "$cid" ]] || continue
  CONTAINER_IDS+=("$cid")
  label="$("$RT" inspect "$cid" --format '{{.Name}}' 2>/dev/null | tr -d '/')"
  CONTAINER_LABELS["$cid"]="$label"
  ips="$("$RT" inspect "$cid" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' 2>/dev/null | xargs)"
  CONTAINER_IPS["$cid"]="$ips"
  echo "$label ($cid): $ips" >> "$LOG"
done < <("$RT" ps -q 2>/dev/null)

log_info "found ${#CONTAINER_IDS[@]} containers"

# External endpoints to test egress (IP-based to avoid DNS dependency)
# International: Cloudflare + Google DNS
# Chinese domestic: 114DNS + AliDNS (verify region-specific egress control)
EGRESS_TARGETS="1.1.1.1:80 8.8.8.8:53 114.114.114.114:53 223.5.5.5:53"
# Key ports to test lateral connectivity (keep small for speed)
LATERAL_PORTS="22 80 8080"

# --- probe script (shell-only, runs inside container) ---
# Probes run in background (&) for parallelism; overall timeout via wrapper.
# Output: PROBE|<target_ip>:<port>|open  (only reports open)
build_probe_script() {
  local targets="$1"
  local timeout="$2"
  cat <<EOPROBE
#!/bin/sh
probe() {
  ip=\$1; port=\$2
  # nc is most common in minimal containers
  if command -v nc >/dev/null 2>&1; then
    nc -z -w $timeout \$ip \$port 2>/dev/null && { printf "PROBE|%s:%s|open\n" "\$ip" "\$port"; return; }
  fi
  # wget fallback
  if command -v wget >/dev/null 2>&1; then
    wget -q -O /dev/null --timeout=$timeout "http://\$ip:\$port/" 2>/dev/null && { printf "PROBE|%s:%s|open\n" "\$ip" "\$port"; return; }
  fi
  # /dev/tcp (bash-only)
  (echo >/dev/tcp/\$ip/\$port) 2>/dev/null && { printf "PROBE|%s:%s|open\n" "\$ip" "\$port"; return; }
  return 1
}

for t in $targets; do
  ip=\${t%%:*}
  port=\${t##*:}
  probe "\$ip" "\$port" &
done
wait
EOPROBE
}

# --- run probes ---
RESULTS="$OUT/isolation/results.txt"; : > "$RESULTS"

for src_cid in "${CONTAINER_IDS[@]}"; do
  src_label="${CONTAINER_LABELS[$src_cid]}"
  log_info "probing from: $src_label"

  # Build lateral targets: all other container IPs with key ports
  lateral_targets=""
  for dst_cid in "${CONTAINER_IDS[@]}"; do
    [ "$dst_cid" = "$src_cid" ] && continue
    for ip in ${CONTAINER_IPS[$dst_cid]}; do
      for port in $LATERAL_PORTS; do
        lateral_targets="$lateral_targets $ip:$port"
      done
    done
  done

  # Combine lateral + egress targets
  all_targets="$lateral_targets $EGRESS_TARGETS"

  probe_script="$(build_probe_script "$all_targets" "$TIMEOUT")"

  # Pick shell (prefer bash for /dev/tcp support)
  local_sh=""
  for try in /bin/bash /bin/sh /bin/ash; do
    if "$RT" exec "$src_cid" "$try" -c 'echo ok' >/dev/null 2>&1; then
      local_sh="$try"; break
    fi
  done
  if [ -z "$local_sh" ]; then
    log_warn "  $src_label: no shell — skipping"
    continue
  fi

  # Execute probe with overall timeout (timeout * 2 to allow parallel probes to finish)
  overall_timeout=$(( TIMEOUT * 2 + 2 ))
  timeout "${overall_timeout}s" "$RT" exec "$src_cid" "$local_sh" -c "$probe_script" 2>>"$LOG" \
    | while IFS= read -r line; do
        [[ "$line" == PROBE* ]] && echo "$src_label|$line"
      done >> "$RESULTS" || true
done

# --- capture iptables for whitelist analysis ---
IPTABLES_FILE="$OUT/isolation/iptables_egress.txt"; : > "$IPTABLES_FILE"
if command -v iptables-save >/dev/null 2>&1; then
  iptables-save > "$IPTABLES_FILE" 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1; then
  iptables -L FORWARD -n -v >> "$IPTABLES_FILE" 2>/dev/null || true
  iptables -L OUTPUT -n -v >> "$IPTABLES_FILE" 2>/dev/null || true
  iptables -t nat -L -n -v >> "$IPTABLES_FILE" 2>/dev/null || true
fi

# --- analyze results on host ---
python3 - "$RESULTS" "$OUT/isolation" "$LOG" "$IPTABLES_FILE" <<'PY'
import json, sys, os
from datetime import datetime, timezone

results_file = sys.argv[1]
out_dir = sys.argv[2]
log_file = sys.argv[3]
iptables_file = sys.argv[4]

findings = []
lateral_open = []
egress_open = []
all_probes = []

external_ips = {"1.1.1.1", "8.8.8.8", "223.5.5.5", "114.114.114.114"}
cn_domestic_ips = {"114.114.114.114", "223.5.5.5"}

try:
    lines = open(results_file, errors="replace").readlines()
except FileNotFoundError:
    lines = []

for line in lines:
    line = line.strip()
    if not line:
        continue
    parts = line.split("|")
    if len(parts) < 4:
        continue
    src, _, target, result = parts[0], parts[1], parts[2], parts[3]
    all_probes.append({"src": src, "target": target, "result": result})
    if result != "open":
        continue

    ip_port = target
    ip = ip_port.rsplit(":", 1)[0] if ":" in ip_port else ip_port

    if ip in external_ips:
        egress_open.append({"src": src, "target": ip_port})
        if ip in cn_domestic_ips:
            note = "container can reach Chinese domestic DNS — no egress whitelist"
        else:
            note = "container can reach external internet (reverse shell risk)"
        findings.append({
            "severity": "high",
            "title": "container-egress-open",
            "where": f"{src} -> {ip_port}",
            "note": note,
        })
    else:
        lateral_open.append({"src": src, "target": ip_port})
        findings.append({
            "severity": "high",
            "title": "container-lateral-open",
            "where": f"{src} -> {ip_port}",
            "note": "container-to-container access not isolated",
        })

# Dedup
seen = set()
deduped = []
for f in findings:
    key = f["where"]
    if key not in seen:
        seen.add(key)
        deduped.append(f)
findings = deduped

sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
findings.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)

counts = {}
for f in findings:
    counts[f["severity"]] = counts.get(f["severity"], 0) + 1

status = "warn" if counts.get("high", 0) > 0 else "ok"
summary_parts = []
if lateral_open:
    summary_parts.append(f"{len(lateral_open)} lateral path(s) open")
if egress_open:
    summary_parts.append(f"{len(egress_open)} egress path(s) open")
if not summary_parts:
    summary_parts.append("all isolated")
summary = "; ".join(summary_parts)

# --- IP whitelist analysis from iptables ---
import re
whitelist_rules = []
has_real_egress_restrict = False
iptables_lines = []
try:
    iptables_lines = open(iptables_file, errors="replace").readlines()
except Exception:
    pass

# Parse iptables-save: only look at *filter table
in_filter_table = False
forward_policy = "ACCEPT"
output_policy = "ACCEPT"
docker_user_rules = []
forward_rules = []
docker_standard_patterns = re.compile(
    r'(-j DOCKER|-j DOCKER-USER|-j DOCKER-FORWARD|-j DOCKER-CT|'
    r'-j DOCKER-BRIDGE|-j DOCKER-INTERNAL|-j RETURN|'
    r'-[io] docker|'
    r'-[io] br-[a-f0-9]+|'
    r'--ctstate RELATED,ESTABLISHED)'
)

for line in iptables_lines:
    line = line.strip()
    if line == "*filter":
        in_filter_table = True
        continue
    if line == "COMMIT" and in_filter_table:
        in_filter_table = False
        continue
    if not in_filter_table:
        continue
    if line.startswith(":FORWARD"):
        forward_policy = line.split()[1] if len(line.split()) > 1 else "ACCEPT"
    elif line.startswith(":OUTPUT"):
        output_policy = line.split()[1] if len(line.split()) > 1 else "ACCEPT"
    elif line.startswith("-A DOCKER-USER"):
        if line.strip() != "-A DOCKER-USER -j RETURN":
            docker_user_rules.append(line)
    elif line.startswith("-A FORWARD"):
        if not docker_standard_patterns.search(line):
            forward_rules.append(line)

# Real whitelist = DOCKER-USER has explicit restrict rules, or
# FORWARD has non-Docker rules that block/limit external destinations
real_restrict_rules = docker_user_rules + forward_rules
# Filter to only rules that actually restrict (DROP/REJECT or specific -d targets)
for r in real_restrict_rules:
    if "DROP" in r or "REJECT" in r:
        whitelist_rules.append(r)
        has_real_egress_restrict = True
    elif re.search(r'-d \d+\.\d+\.\d+\.\d+', r) and "ACCEPT" in r:
        whitelist_rules.append(r)
        has_real_egress_restrict = True

# Docker sets FORWARD DROP by default but adds blanket ACCEPT for all bridges
# That's NOT a real whitelist — check if there are actual user restrictions
docker_blanket_accept = any(
    re.search(r'-A DOCKER-FORWARD -i br-[a-f0-9]+ -j ACCEPT', l.strip())
    for l in iptables_lines
)

whitelist_status = "none"
if has_real_egress_restrict and whitelist_rules:
    if forward_policy == "DROP" and not docker_blanket_accept:
        whitelist_status = "strict"
    else:
        whitelist_status = "partial"

if whitelist_status == "none":
    findings.append({
        "severity": "high",
        "title": "no-egress-whitelist",
        "where": "iptables FORWARD/DOCKER-USER chains",
        "note": "No IP whitelist control — containers have unrestricted outbound access"
              + (" (FORWARD DROP is bypassed by Docker bridge ACCEPT rules)" if forward_policy == "DROP" else ""),
    })
    counts["high"] = counts.get("high", 0) + 1
elif whitelist_status == "partial":
    findings.append({
        "severity": "medium",
        "title": "partial-egress-whitelist",
        "where": "iptables FORWARD/DOCKER-USER chains",
        "note": f"Partial egress rules found ({len(whitelist_rules)} rules) but Docker bridges still allow unrestricted egress",
    })
    counts["medium"] = counts.get("medium", 0) + 1

# CN domestic summary
cn_reachable = [e for e in egress_open if e["target"].split(":")[0] in cn_domestic_ips]
if cn_reachable:
    summary_parts.append(f"CN domestic reachable ({len(cn_reachable)} path(s))")
summary = "; ".join(summary_parts)

data = {
    "module": "egress-control-audit.isolation",
    "status": status,
    "summary": summary,
    "counts": counts,
    "lateral_open": lateral_open[:50],
    "egress_open": egress_open[:50],
    "cn_domestic_reachable": cn_reachable[:20],
    "whitelist_status": whitelist_status,
    "whitelist_rules": whitelist_rules[:50],
    "findings": findings[:200],
    "all_probes": all_probes,
}
open(os.path.join(out_dir, "result.json"), "w").write(
    json.dumps(data, indent=2, ensure_ascii=False)
)

# --- Generate markdown report ---
# Read container inventory from log
containers_info = []
try:
    for l in open(log_file, errors="replace"):
        l = l.strip()
        if l and "(" in l and ")" in l:
            containers_info.append(l)
except Exception:
    pass

ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
md = []
md.append("# Container Isolation & Egress Verification Report")
md.append("")
md.append(f"- Generated: {ts}")
md.append(f"- Status: **{status.upper()}**")
md.append(f"- Summary: {summary}")
md.append("")

md.append("## Containers Tested")
md.append("")
md.append("| Container | IPs |")
md.append("|-----------|-----|")
for c in containers_info:
    md.append(f"| {c} |")
md.append("")

# Lateral
md.append("## Container-to-Container Isolation (Lateral)")
md.append("")
if lateral_open:
    md.append(f"**FAIL** - {len(lateral_open)} path(s) open. Containers can reach each other.")
    md.append("")
    md.append("| Source | Target | Risk |")
    md.append("|--------|--------|------|")
    for item in lateral_open:
        md.append(f"| {item['src']} | {item['target']} | HIGH - not isolated |")
    md.append("")
    md.append("### Remediation")
    md.append("")
    md.append("- Use separate user-defined bridge networks per CI job")
    md.append("- Set `--internal` on networks that don't need external access")
    md.append("- Use `--icc=false` on the docker daemon to disable inter-container communication on the default bridge")
    md.append("- In Kubernetes: apply NetworkPolicy to deny all ingress/egress by default, then allow only required paths")
else:
    md.append("**PASS** - No container-to-container connectivity detected.")
md.append("")

# Egress
md.append("## Outbound Internet Access (Egress)")
md.append("")
if egress_open:
    md.append(f"**FAIL** - {len(egress_open)} container(s) can reach the internet.")
    md.append("")
    md.append("| Source Container | External Target | Risk |")
    md.append("|-----------------|-----------------|------|")
    for item in egress_open:
        md.append(f"| {item['src']} | {item['target']} | HIGH - reverse shell risk |")
    md.append("")
    md.append("### Remediation")
    md.append("")
    md.append("- Use `--network=none` for containers that don't need network access")
    md.append("- Apply iptables OUTPUT rules to block container subnets from reaching external IPs")
    md.append("- Only allow egress to required registries/mirrors via explicit allowlist")
    md.append("- In Kubernetes: use NetworkPolicy with egress rules limiting to internal CIDRs only")
    md.append("- Consider using a forward proxy for controlled outbound access")
else:
    md.append("**PASS** - No containers can reach external internet.")
md.append("")

# CN domestic test
md.append("## Chinese Domestic Access (114DNS / AliDNS)")
md.append("")
if cn_reachable:
    md.append(f"**FAIL** - {len(cn_reachable)} container(s) can reach Chinese domestic DNS (114.114.114.114 / 223.5.5.5).")
    md.append("")
    md.append("| Source Container | CN Target | Risk |")
    md.append("|-----------------|-----------|------|")
    for item in cn_reachable:
        md.append(f"| {item['src']} | {item['target']} | HIGH - unrestricted domestic egress |")
    md.append("")
    md.append("This confirms containers have unrestricted outbound access to Chinese internet.")
else:
    md.append("**PASS** - No containers can reach Chinese domestic endpoints.")
md.append("")

# IP Whitelist analysis
md.append("## Outbound IP Whitelist Control")
md.append("")
if whitelist_status == "strict":
    md.append("**PASS** - Strict egress whitelist detected (default DROP + explicit allow rules).")
    md.append("")
    md.append(f"Found {len(whitelist_rules)} egress control rule(s):")
    md.append("")
    for r in whitelist_rules[:20]:
        md.append(f"    {r}")
elif whitelist_status == "partial":
    md.append(f"**WARN** - Partial egress rules found ({len(whitelist_rules)} rules) but no default DROP policy.")
    md.append("")
    md.append("Rules found:")
    md.append("")
    for r in whitelist_rules[:20]:
        md.append(f"    {r}")
    md.append("")
    md.append("### Remediation")
    md.append("")
    md.append("- Set default policy to DROP on FORWARD chain: `iptables -P FORWARD DROP`")
    md.append("- Add explicit ACCEPT rules only for required destinations")
else:
    md.append("**FAIL** - No outbound IP whitelist control detected.")
    md.append("")
    md.append("The iptables OUTPUT/FORWARD chains have no rules restricting container egress.")
    md.append("All containers can reach any external IP without restriction.")
    md.append("")
    md.append("### Remediation")
    md.append("")
    md.append("- Set FORWARD chain default policy to DROP")
    md.append("- Add whitelist rules for required destinations only:")
    md.append("  ```")
    md.append("  iptables -P FORWARD DROP")
    md.append("  iptables -A FORWARD -d <registry-ip> -p tcp --dport 443 -j ACCEPT")
    md.append("  iptables -A FORWARD -d <ntp-server> -p udp --dport 123 -j ACCEPT")
    md.append("  ```")
    md.append("- Use a forward proxy (squid/envoy) for HTTP(S) egress with domain allowlist")
    md.append("- In Kubernetes: use NetworkPolicy egress rules with CIDR selectors")
md.append("")
md.append("## Full Probe Matrix")
md.append("")
md.append("| Source | Target | Result |")
md.append("|--------|--------|--------|")
for p in all_probes:
    marker = "OPEN" if p["result"] == "open" else "blocked"
    md.append(f"| {p['src']} | {p['target']} | {marker} |")
md.append("")

open(os.path.join(out_dir, "report.md"), "w").write("\n".join(md))
print(f"isolation: {summary}")
PY

log_ok "isolation verification done -> $OUT/isolation/result.json"
echo "$OUT/isolation/result.json"
