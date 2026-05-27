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

TIMEOUT=3
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
EGRESS_TARGETS="1.1.1.1:80 8.8.8.8:53"
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

  # Pick shell
  local_sh=""
  for try in /bin/sh /bin/bash /bin/ash; do
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

# --- analyze results on host ---
python3 - "$RESULTS" "$OUT/isolation" "$LOG" <<'PY'
import json, sys, os
from datetime import datetime, timezone

results_file = sys.argv[1]
out_dir = sys.argv[2]
log_file = sys.argv[3]

findings = []
lateral_open = []
egress_open = []
all_probes = []

external_ips = {"1.1.1.1", "8.8.8.8", "223.5.5.5", "114.114.114.114"}

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
        findings.append({
            "severity": "high",
            "title": "container-egress-open",
            "where": f"{src} -> {ip_port}",
            "note": "container can reach external internet (reverse shell risk)",
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

data = {
    "module": "egress-control-audit.isolation",
    "status": status,
    "summary": summary,
    "counts": counts,
    "lateral_open": lateral_open[:50],
    "egress_open": egress_open[:50],
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

# Full probe matrix
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
