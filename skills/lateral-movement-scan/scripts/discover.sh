#!/usr/bin/env bash
# Discover live hosts in subnets reachable from this host.
# Usage: discover.sh [--rate N] [--out DIR] [subnet ...]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

RATE=200
OUT_OVERRIDE=""
SUBNETS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --rate) RATE="$2"; shift 2;;
    --out)  OUT_OVERRIDE="$2"; shift 2;;
    -h|--help) sed -n '1,5p' "$0"; exit 0;;
    *) SUBNETS+=("$1"); shift;;
  esac
done

OUT="${OUT_OVERRIDE:-$(ensure_run_dir lateral-movement-scan)}"
mkdir -p "$OUT"
LOG="$OUT/discover.log"
LIVE="$OUT/live.txt"
: > "$LOG"; : > "$LIVE"

NMAP="$(command -v nmap || true)"
[ -n "$NMAP" ] || die "nmap not found"

# --- derive subnets from routing table if not provided ---
if [ "${#SUBNETS[@]}" -eq 0 ]; then
  while IFS= read -r line; do
    SUBNETS+=("$line")
  done < <(ip -4 route 2>/dev/null \
            | awk '$1 ~ /\// && $1 != "default" {print $1}' \
            | awk '{
                split($1,a,"/"); m=a[2]+0;
                if (m>=16 && m<=30) print $1;
              }' \
            | sort -u)
  # Add docker/container network subnets
  for rt in docker nerdctl podman; do
    command -v "$rt" >/dev/null 2>&1 || continue
    while IFS= read -r sn; do
      [[ -n "$sn" ]] && SUBNETS+=("$sn")
    done < <("$rt" network ls -q 2>/dev/null | xargs -I{} "$rt" network inspect {} --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' 2>/dev/null | grep -E '^[0-9]' | sort -u)
    break
  done
fi
if [ "${#SUBNETS[@]}" -eq 0 ]; then
  log_warn "no subnets derived; nothing to scan"
  printf '%s\n' "no subnets" >>"$LOG"
  printf '{"module":"lateral-movement-scan.discover","status":"warn","summary":"no subnets","counts":{},"findings":[]}\n' \
    > "$OUT/discover.json"
  exit 0
fi
log_info "subnets: ${SUBNETS[*]}"
echo "subnets: ${SUBNETS[*]}" >>"$LOG"

# --- ARP scan first (only L2-local nets) ---
if command -v arp-scan >/dev/null 2>&1; then
  log_info "ARP scanning local network..."
  arp-scan --localnet --quiet 2>>"$LOG" \
    | awk '/^([0-9]+\.){3}[0-9]+/ {print $1}' >> "$LIVE" || true
  log_info "ARP scan done, found $(wc -l < "$LIVE") hosts so far"
fi

# --- ICMP+ARP discovery via nmap for each subnet ---
total_nets=${#SUBNETS[@]}
net_idx=0
for net in "${SUBNETS[@]}"; do
  net_idx=$((net_idx + 1))
  log_info "[$net_idx/$total_nets] ICMP ping sweep: $net"
  "$NMAP" -sn -n --max-rate "$RATE" "$net" -oG "$OUT/sn-$(echo "$net" | tr '/.' '_').gnmap" >>"$LOG" 2>&1 || true
done

# --- TCP-SYN top-50 fallback for ICMP-blocked hosts ---
log_info "TCP-SYN scan for ICMP-blocked hosts..."
net_idx=0
for net in "${SUBNETS[@]}"; do
  net_idx=$((net_idx + 1))
  log_info "[$net_idx/$total_nets] TCP-SYN top-50: $net"
  "$NMAP" -sS -Pn -n -F --top-ports 50 --max-rate "$RATE" --open "$net" \
       -oG "$OUT/syn-$(echo "$net" | tr '/.' '_').gnmap" >>"$LOG" 2>&1 || true
done

# --- consolidate ---
{
  cat "$OUT"/sn-*.gnmap 2>/dev/null
  cat "$OUT"/syn-*.gnmap 2>/dev/null
} | awk '/Status: Up/ {print $2}' \
  | sort -u >> "$LIVE"

# --- enumerate container IPs directly ---
log_info "Enumerating container IPs..."
for rt in docker nerdctl podman; do
  command -v "$rt" >/dev/null 2>&1 || continue
  log_info "Checking $rt containers..."
  "$rt" ps -q 2>/dev/null | while read -r cid; do
    "$rt" inspect "$cid" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{"\n"}}{{end}}' 2>/dev/null
  done | grep -E '^[0-9]' >> "$LIVE" || true
  break
done

sort -u "$LIVE" -o "$LIVE"

count="$(wc -l < "$LIVE")"
log_ok "discover: $count live hosts -> $LIVE"

python3 - "$OUT/discover.json" "$LIVE" "$count" <<'PY'
import json, sys
out, live, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(live) as f: hosts = [l.strip() for l in f if l.strip()]
data = {
  "module": "lateral-movement-scan.discover",
  "status": "ok",
  "summary": f"{count} live host(s) discovered",
  "counts": {"live": count},
  "findings": [{"severity":"info","title":"live-host","where":h,"note":""} for h in hosts[:50]],
}
open(out,"w").write(json.dumps(data,indent=2,ensure_ascii=False))
PY
echo "$LIVE"
