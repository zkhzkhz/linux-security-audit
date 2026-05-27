#!/usr/bin/env bash
# Run Peirates k8s penetration testing inside containers with k8s SA tokens.
# Only runs in containers that have /var/run/secrets/kubernetes.io/
# Outputs structured JSON to $LSA_RUN_DIR/privesc-escape-check/peirates/
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/privesc-escape-check/peirates"
mkdir -p "$OUT_DIR"

pick_peirates() {
  local arch
  arch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  local bin="$LSA_ROOT/bin/peirates-linux-$arch"
  if [ -x "$bin" ]; then echo "$bin"; return 0; fi
  return 1
}

PEIRATES="$(pick_peirates)" || die "peirates binary not found"

containers=$(docker ps --format '{{.Names}}' 2>/dev/null)
[ -z "$containers" ] && { log_info "no running containers"; exit 0; }

log_info "checking containers for k8s SA tokens"
scanned=0

for cname in $containers; do
  has_sa=$(docker exec "$cname" test -f /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null && echo y || echo n)
  [ "$has_sa" = "y" ] || continue

  log_info "  peirates: $cname (has k8s SA)"
  scanned=$((scanned + 1))
  raw="$OUT_DIR/${cname}.txt"

  docker cp "$PEIRATES" "$cname:/tmp/peirates" 2>/dev/null || continue
  docker exec "$cname" chmod +x /tmp/peirates 2>/dev/null
  # Run non-interactive: dump SA info and attempt enumeration
  docker exec "$cname" timeout 30 /tmp/peirates <<'STDIN' > "$raw" 2>&1 || true
get-sa-token
kubectl-try
exit
STDIN
  docker exec "$cname" rm -f /tmp/peirates 2>/dev/null
done

if [ "$scanned" -eq 0 ]; then
  log_info "no containers with k8s service accounts found"
  python3 -c '
import json
r = {"module":"privesc-escape-check.peirates","status":"ok","summary":"no k8s SA tokens found","counts":{},"findings":[]}
open("'"$OUT_DIR/result.json"'","w").write(json.dumps(r,indent=2))
'
else
  python3 "$HERE/parse_peirates.py" "$OUT_DIR"
fi

log_ok "Peirates scan done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
