#!/usr/bin/env bash
# Run docker-bench-security (CIS Docker Benchmark) on the host.
# Outputs structured JSON to $LSA_RUN_DIR/egress-control-audit/docker-bench/
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/egress-control-audit/docker-bench"
mkdir -p "$OUT_DIR"

DBS_DIR="$LSA_ROOT/bin/docker-bench-security"
[ -f "$DBS_DIR/docker-bench-security.sh" ] || die "docker-bench-security not found"

command -v docker >/dev/null 2>&1 || { log_info "docker not found, skipping"; exit 0; }

log_info "running docker-bench-security (CIS Docker Benchmark)"
raw="$OUT_DIR/raw.log"
(cd "$DBS_DIR" && bash docker-bench-security.sh -l "$raw" 2>/dev/null) || true

# Parse the log output
python3 "$HERE/parse_docker_bench.py" "$raw" "$OUT_DIR/result.json"
log_ok "docker-bench-security done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
