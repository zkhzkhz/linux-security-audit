#!/usr/bin/env bash
# Run Deepce container escape enumeration inside each container.
# Outputs structured JSON to $LSA_RUN_DIR/privesc-escape-check/deepce/
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/privesc-escape-check/deepce"
mkdir -p "$OUT_DIR"

DEEPCE="$LSA_ROOT/bin/deepce.sh"
[ -f "$DEEPCE" ] || die "deepce.sh not found at $DEEPCE"

containers=$(docker ps --format '{{.Names}}' 2>/dev/null)
[ -z "$containers" ] && { log_info "no running containers"; exit 0; }

log_info "running Deepce in $(echo "$containers" | wc -l) containers"

for cname in $containers; do
  log_info "  deepce: $cname"
  raw="$OUT_DIR/${cname}.txt"
  docker cp "$DEEPCE" "$cname:/tmp/deepce.sh" 2>/dev/null || continue
  docker exec "$cname" bash /tmp/deepce.sh \
    2>/dev/null > "$raw" || \
  docker exec "$cname" sh /tmp/deepce.sh 2>/dev/null > "$raw" || continue
  docker exec "$cname" rm -f /tmp/deepce.sh 2>/dev/null
done

python3 "$HERE/parse_deepce.py" "$OUT_DIR"
log_ok "Deepce scan done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
