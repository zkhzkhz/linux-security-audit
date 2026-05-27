#!/usr/bin/env bash
# Shared helpers for linux-security-audit scripts.
# Source this file: . "$LSA_ROOT/lib/common.sh"

set -o pipefail

LSA_ROOT="${LSA_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export LSA_ROOT

LSA_REPORT_DIR="${LSA_REPORT_DIR:-$LSA_ROOT/reports}"
mkdir -p "$LSA_REPORT_DIR"

_lsa_ts() { date -u +'%Y-%m-%dT%H:%M:%SZ'; }
_lsa_color() { [ -t 2 ] && printf '\033[%sm' "$1" >&2 || true; }
_lsa_reset() { [ -t 2 ] && printf '\033[0m' >&2 || true; }

log_info()  { _lsa_color '0;36'; printf '[INFO  %s] %s\n' "$(_lsa_ts)" "$*" >&2; _lsa_reset; }
log_warn()  { _lsa_color '0;33'; printf '[WARN  %s] %s\n' "$(_lsa_ts)" "$*" >&2; _lsa_reset; }
log_error() { _lsa_color '0;31'; printf '[ERROR %s] %s\n' "$(_lsa_ts)" "$*" >&2; _lsa_reset; }
log_ok()    { _lsa_color '0;32'; printf '[OK    %s] %s\n' "$(_lsa_ts)" "$*" >&2; _lsa_reset; }

die() { log_error "$*"; exit 1; }

require_cmd() {
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "missing command: $c"
  done
}

# Create a per-run report directory: reports/<host>-<UTC-ts>/<module>
new_run_dir() {
  local module="${1:-misc}"
  local host
  host="$(hostname -s 2>/dev/null || echo unknown)"
  local ts
  ts="$(date -u +'%Y%m%d-%H%M%S')"
  local dir="$LSA_REPORT_DIR/${host}-${ts}/${module}"
  mkdir -p "$dir"
  echo "$dir"
}

# Re-use an existing run dir if LSA_RUN_DIR is set (orchestrator passes one).
ensure_run_dir() {
  local module="${1:-misc}"
  if [ -n "${LSA_RUN_DIR:-}" ]; then
    local dir="$LSA_RUN_DIR/$module"
    mkdir -p "$dir"
    echo "$dir"
  else
    new_run_dir "$module"
  fi
}

# Detect whether we are running inside a container.
is_container() {
  [ -f /.dockerenv ] && return 0
  [ -f /run/.containerenv ] && return 0
  if grep -qE '(docker|kubepods|containerd|lxc)' /proc/1/cgroup 2>/dev/null; then return 0; fi
  return 1
}

# Print JSON-quoted string for safe report assembly.
json_str() {
  python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1" 2>/dev/null \
    || printf '"%s"' "${1//\"/\\\"}"
}

# Bytes -> human readable
human_bytes() {
  awk -v b="${1:-0}" 'BEGIN{
    s="BKMGTP"; i=1;
    while (b>=1024 && i<6) { b/=1024; i++ }
    printf "%.1f%s", b, substr(s,i,1)
  }'
}

# Run a command with a soft timeout if `timeout` is available.
soft_timeout() {
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout --preserve-status "${secs}s" "$@"
  else
    "$@"
  fi
}
