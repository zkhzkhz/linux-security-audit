#!/usr/bin/env bash
# Host-side local privilege escalation audit using LinPEAS.
# Output: $OUT/host.json, $OUT/host.log (full linpeas output)

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

OUT="${1:-$(ensure_run_dir privesc-escape-check)}"
TIMEOUT="${2:-600}"
mkdir -p "$OUT"
LOG="$OUT/host.log"
JSON="$OUT/host.json"
: > "$LOG"

log_info "host privesc audit (linpeas) -> $OUT"

# --- locate linpeas ---
log_info "Locating LinPEAS..."
LINPEAS=""
if [ -x "$LSA_ROOT/bin/linpeas.sh" ]; then
  LINPEAS="$LSA_ROOT/bin/linpeas.sh"
elif command -v linpeas.sh >/dev/null 2>&1; then
  LINPEAS="$(command -v linpeas.sh)"
fi
[ -n "$LINPEAS" ] || die "linpeas.sh not found in $LSA_ROOT/bin/ or PATH"
log_info "Found LinPEAS: $LINPEAS"

# --- run linpeas with timeout ---
log_info "========== Running LinPEAS (timeout=${TIMEOUT}s) =========="
log_info "This may take several minutes. Please wait..."

# Prepend find shim to PATH so linpeas skips docker overlay2 layers
SHIMS_DIR="$LSA_ROOT/bin/shims"
[ -x "$SHIMS_DIR/find" ] && export PATH="$SHIMS_DIR:$PATH"

# -q quiet (less banner noise), -N no ANSI color (clean for parsing)
timeout "$TIMEOUT" bash "$LINPEAS" -q -N > "$OUT/linpeas_raw.txt" 2>>"$LOG" || {
  rc=$?
  if [ "$rc" -eq 124 ]; then
    log_warn "linpeas timed out after ${TIMEOUT}s, parsing partial output"
  else
    log_warn "linpeas exited with code $rc"
  fi
}

LINES=$(wc -l < "$OUT/linpeas_raw.txt" 2>/dev/null || echo 0)
log_info "LinPEAS completed. Produced $LINES lines of output."

# --- parse linpeas output into structured findings ---
log_info "========== Parsing LinPEAS Results =========="
log_info "Extracting privilege escalation vectors..."
python3 "$HERE/parse_linpeas.py" "$OUT/linpeas_raw.txt" --out "$JSON" 2>>"$LOG" \
  || log_warn "parse_linpeas.py failed; see host.log"

# Copy raw output as the human-readable log
cp "$OUT/linpeas_raw.txt" "$LOG"

log_ok "========== Host Privilege Escalation Audit Complete =========="
log_ok "host privesc done -> $JSON"
echo "$JSON"
