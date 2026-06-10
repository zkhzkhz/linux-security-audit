#!/usr/bin/env bash
# Run amicontained inside each container to check runtime constraints.
# Outputs structured JSON to $LSA_RUN_DIR/privesc-escape-check/amicontained/
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/privesc-escape-check/amicontained"
mkdir -p "$OUT_DIR"

pick_amicontained() {
  local arch
  arch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  local bin="$LSA_ROOT/bin/amicontained-linux-$arch"
  if [ -x "$bin" ]; then echo "$bin"; return 0; fi
  if command -v amicontained >/dev/null 2>&1; then echo "amicontained"; return 0; fi
  return 1
}

AMICONTAINED="$(pick_amicontained)" || die "amicontained binary not found"

# Support container-specific scan via environment variables
if [ -n "${LSA_CONTAINER_ID:-}" ]; then
  containers=$(docker inspect "$LSA_CONTAINER_ID" -f '{{.Name}}' 2>/dev/null | sed 's/^//')
elif [ -n "${LSA_CONTAINER_NAME:-}" ]; then
  containers="$LSA_CONTAINER_NAME"
else
  containers=$(docker ps --format '{{.Names}}' 2>/dev/null)
fi
[ -z "$containers" ] && { log_info "no running containers"; exit 0; }

log_info "running amicontained in $(echo "$containers" | wc -l) containers"

for cname in $containers; do
  log_info "  amicontained: $cname"
  raw="$OUT_DIR/${cname}.txt"
  docker cp "$AMICONTAINED" "$cname:/tmp/amicontained" 2>/dev/null || continue
  docker exec "$cname" chmod +x /tmp/amicontained 2>/dev/null
  docker exec "$cname" /tmp/amicontained > "$raw" 2>&1 || true
  docker exec "$cname" rm -f /tmp/amicontained 2>/dev/null
done

python3 "$HERE/parse_amicontained.py" "$OUT_DIR"
log_ok "amicontained scan done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
