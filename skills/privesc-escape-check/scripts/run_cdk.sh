#!/usr/bin/env bash
# Run CDK (Container DucK) inside each container for escape/misconfig detection.
# Pattern: cp cdk binary into container, exec evaluate, cp results out, parse on host.
# Usage: run_cdk.sh [--out DIR]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

OUT_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT_OVERRIDE="$2"; shift 2;;
    -h|--help) sed -n '1,4p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

OUT="${OUT_OVERRIDE:-$(ensure_run_dir privesc-escape-check)}"
mkdir -p "$OUT/cdk"
LOG="$OUT/cdk/cdk.log"; : > "$LOG"

RT=""
for r in docker nerdctl podman; do
  command -v "$r" >/dev/null 2>&1 && { RT="$r"; break; }
done
[ -n "$RT" ] || { log_warn "no container runtime"; exit 0; }

# Pick CDK binary matching container arch
pick_cdk() {
  local cid="$1"
  local arch; arch="$("$RT" exec "$cid" uname -m 2>/dev/null || echo "x86_64")"
  case "$arch" in
    x86_64|amd64) echo "$LSA_ROOT/bin/cdk-linux-amd64";;
    aarch64|arm64) echo "$LSA_ROOT/bin/cdk-linux-arm64";;
    *) echo "$LSA_ROOT/bin/cdk-linux-amd64";;
  esac
}

CONTAINERS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && CONTAINERS+=("$line")
done < <("$RT" ps -q 2>/dev/null)

if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  log_info "no running containers"
  echo '{"module":"privesc-escape-check.cdk","status":"ok","summary":"no containers","counts":{},"findings":[]}' \
    > "$OUT/cdk/result.json"
  exit 0
fi

log_info "running CDK evaluate in ${#CONTAINERS[@]} containers"

scan_container() {
  local cid="$1"
  local label; label="$("$RT" inspect "$cid" --format '{{.Name}}' 2>/dev/null | tr -d '/' || echo "$cid")"
  local cdir="$OUT/cdk/$label"
  mkdir -p "$cdir"
  log_info "  cdk: $label"

  local cdk_bin; cdk_bin="$(pick_cdk "$cid")"

  # Copy CDK into container
  "$RT" cp "$cdk_bin" "$cid:/tmp/cdk" 2>>"$LOG" || {
    log_warn "  $label: failed to copy cdk binary"
    return
  }
  "$RT" exec "$cid" chmod +x /tmp/cdk 2>>"$LOG" || true

  # Run CDK evaluate
  "$RT" exec "$cid" /tmp/cdk evaluate 2>&1 | tee "$cdir/raw.txt" >>"$LOG" || true

  # Cleanup
  "$RT" exec "$cid" rm -f /tmp/cdk 2>/dev/null || true
}

for cid in "${CONTAINERS[@]}"; do
  scan_container "$cid"
done

# --- parse CDK output on host, filter false positives ---
python3 "$HERE/parse_cdk.py" "$OUT/cdk"

log_ok "CDK scan done -> $OUT/cdk/result.json"
echo "$OUT/cdk/result.json"
