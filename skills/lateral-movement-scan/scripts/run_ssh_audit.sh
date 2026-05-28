#!/usr/bin/env bash
# Run ssh-audit against discovered SSH services.
# Checks SSH configuration strength: algorithms, key exchange, host keys.
# Outputs structured JSON to $LSA_RUN_DIR/lateral-movement-scan/ssh-audit/
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/lateral-movement-scan/ssh-audit"
mkdir -p "$OUT_DIR"

# Find ssh-audit
if command -v ssh-audit >/dev/null 2>&1; then
  SSH_AUDIT="ssh-audit"
elif [ -x "$LSA_ROOT/bin/ssh-audit" ]; then
  SSH_AUDIT="$LSA_ROOT/bin/ssh-audit"
else
  die "ssh-audit not found (pip install ssh-audit)"
fi

# Collect SSH targets: localhost + discovered hosts with port 22
targets=""
# Always check localhost
targets="127.0.0.1:22"

# Check container IPs
for ip in $(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $(docker ps -q) 2>/dev/null); do
  [ -n "$ip" ] && targets="$targets $ip:22"
done

# Check hosts from discover.sh output
live_file="${LSA_RUN_DIR:-}/lateral-movement-scan/live.txt"
if [ -f "$live_file" ]; then
  while IFS= read -r host; do
    [ -n "$host" ] && targets="$targets $host:22"
  done < "$live_file"
fi

# Also check common SSH ports
for port in 22 2222 8022 8023; do
  ss -tlnp 2>/dev/null | grep -q ":$port " && targets="$targets 127.0.0.1:$port"
done

# Deduplicate
targets=$(echo "$targets" | tr ' ' '\n' | sort -u | tr '\n' ' ')

log_info "ssh-audit scanning $(echo $targets | wc -w) targets"

for target in $targets; do
  host="${target%:*}"
  port="${target#*:}"
  log_info "  ssh-audit: $host:$port"
  raw="$OUT_DIR/${host}_${port}.json"
  $SSH_AUDIT -j "$host" -p "$port" > "$raw" 2>/dev/null || rm -f "$raw"
done

python3 "$HERE/parse_ssh_audit.py" "$OUT_DIR"
log_ok "ssh-audit done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
