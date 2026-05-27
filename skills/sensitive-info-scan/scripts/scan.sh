#!/usr/bin/env bash
# Optimized gitleaks scanner for Linux hosts and container filesystems.
#
# Features:
#   - Aggressive path exclusion (virtual fs, overlay2, caches)
#   - Per-file size cap to keep huge logs from blocking the scan
#   - Parallel partitioned scanning (one gitleaks per target dir)
#   - Archive scanning (zip/tar/tgz/jar/...) via --scan-archives where available
#   - Auto-triage of findings with triage.py
#
# Usage:
#   scan.sh [opts] [target ...]
#
# Options:
#   --max-file-size SIZE        per-file cap (default 10M)
#   --max-archive-depth N       gitleaks archive depth (default 2)
#   --jobs N                    parallel workers (default min(nproc/2,4))
#   --no-archive                disable archive scanning
#   --no-triage                 skip FP triage (raw.json only)
#   --container                 use container-friendly default target list
#   --out DIR                   override output directory
#
# Env:
#   LSA_ROOT          project root (auto)
#   LSA_RUN_DIR       reuse a run dir from orchestrator
#   LSA_CONTAINER=1   force container mode

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"
. "$LSA_ROOT/lib/arch_detect.sh"

MAX_FILE_SIZE="10M"
MAX_ARCHIVE_DEPTH="2"
JOBS=""
ARCHIVE=1
TRIAGE=1
CONTAINER_MODE=0
OUT_OVERRIDE=""
TARGETS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --max-file-size)    MAX_FILE_SIZE="$2"; shift 2;;
    --max-archive-depth) MAX_ARCHIVE_DEPTH="$2"; shift 2;;
    --jobs)             JOBS="$2"; shift 2;;
    --no-archive)       ARCHIVE=0; shift;;
    --no-triage)        TRIAGE=0; shift;;
    --container)        CONTAINER_MODE=1; shift;;
    --out)              OUT_OVERRIDE="$2"; shift 2;;
    -h|--help)          sed -n '1,40p' "$0"; exit 0;;
    --) shift; while [ $# -gt 0 ]; do TARGETS+=("$1"); shift; done;;
    -*) die "unknown flag: $1";;
    *)  TARGETS+=("$1"); shift;;
  esac
done

# ---------- resolve runtime ----------
GITLEAKS="$(pick_gitleaks || true)"
[ -n "$GITLEAKS" ] || die "gitleaks not found; run $LSA_ROOT/bin/fetch_tools.sh"

# Default jobs
if [ -z "$JOBS" ]; then
  if command -v nproc >/dev/null 2>&1; then
    nc=$(nproc); JOBS=$(( nc / 2 ))
  else
    JOBS=2
  fi
  [ "$JOBS" -lt 1 ] && JOBS=1
  [ "$JOBS" -gt 4 ] && JOBS=4
fi

# Detect container mode if forced
[ "${LSA_CONTAINER:-0}" = "1" ] && CONTAINER_MODE=1
is_container && CONTAINER_MODE=1 || true

# Resolve default targets if none given
if [ "${#TARGETS[@]}" -eq 0 ]; then
  if [ "$CONTAINER_MODE" = "1" ]; then
    mapfile -t TARGETS < <("$HERE/targets.sh" --container)
  else
    mapfile -t TARGETS < <("$HERE/targets.sh")
  fi
fi

# Filter to existing paths
FILTERED=()
for t in "${TARGETS[@]}"; do
  [ -e "$t" ] && FILTERED+=("$t") || log_warn "skip (missing): $t"
done
[ "${#FILTERED[@]}" -gt 0 ] || die "no valid scan targets"

# Expand targets: remove subdirectories matching exclude-paths.txt patterns
EXCL_FILE="$SKILL_DIR/config/exclude-paths.txt"
PRUNE_DIRS=()
while IFS= read -r pat; do
  [[ "$pat" =~ ^\s*#|^\s*$ ]] && continue
  PRUNE_DIRS+=("$pat")
done < "$EXCL_FILE"

TARGETS=()
for t in "${FILTERED[@]}"; do
  # For each target, check if any immediate subdirectory matches an exclude pattern
  # and remove it from scanning by splitting into non-excluded children
  skip=0
  for pat in "${PRUNE_DIRS[@]}"; do
    if echo "$t" | grep -qE "$pat" 2>/dev/null; then skip=1; break; fi
  done
  if [ "$skip" = "1" ]; then
    log_info "exclude target: $t"
    continue
  fi
  TARGETS+=("$t")
done
[ "${#TARGETS[@]}" -gt 0 ] || die "no valid scan targets after exclusion"

# ---------- output dir ----------
if [ -n "$OUT_OVERRIDE" ]; then
  OUT="$OUT_OVERRIDE"
  mkdir -p "$OUT"
else
  OUT="$(ensure_run_dir sensitive-info-scan)"
fi

printf '%s\n' "${TARGETS[@]}" > "$OUT/targets.txt"
LOG="$OUT/scan.log"
: > "$LOG"

log_info "gitleaks: $GITLEAKS"
"$GITLEAKS" version 2>&1 | tee -a "$LOG" || true
log_info "out:      $OUT"
log_info "targets:  ${TARGETS[*]}"
log_info "jobs:     $JOBS  max-file: $MAX_FILE_SIZE  archive: $ARCHIVE depth=$MAX_ARCHIVE_DEPTH"

# ---------- detect gitleaks capabilities ----------
GL_HELP="$($GITLEAKS detect --help 2>&1 || true)"
HAS_SCAN_ARCH=0; HAS_MAX_SIZE=0; HAS_MAX_MB=0
echo "$GL_HELP" | grep -q -- '--scan-archives' && HAS_SCAN_ARCH=1
echo "$GL_HELP" | grep -q -- '--max-archive-depth' || true
echo "$GL_HELP" | grep -q -- '--max-target-megabytes' && HAS_MAX_MB=1
echo "$GL_HELP" | grep -q -- '--max-file-size'      && HAS_MAX_SIZE=1

# Megabyte form of MAX_FILE_SIZE (rough)
mb_from_size() {
  case "${1^^}" in
    *G)  awk -v n="${1%[Gg]}" 'BEGIN{printf "%d", n*1024}';;
    *M)  awk -v n="${1%[Mm]}" 'BEGIN{printf "%d", n}';;
    *K)  awk -v n="${1%[Kk]}" 'BEGIN{printf "%d", (n+1023)/1024}';;
    *)   awk -v n="$1" 'BEGIN{printf "%d", (n+1048575)/1048576}';;
  esac
}
MAX_MB="$(mb_from_size "$MAX_FILE_SIZE")"

# ---------- assemble runtime config ----------
RT_CFG="$OUT/gitleaks-runtime.toml"
{
  cat "$SKILL_DIR/config/gitleaks-custom.toml"
  echo
  echo "# --- merged allowlist.toml ---"
  sed -n '/^\[allowlist\]/,$p' "$SKILL_DIR/config/allowlist.toml" \
    | sed 's/^\[allowlist\]/[[allowlists]]/'
  echo
  echo "# --- path exclusions ---"
  echo "[[allowlists]]"
  echo 'description = "path exclusions (config/exclude-paths.txt)"'
  echo "paths = ["
  grep -v -E '^\s*#|^\s*$' "$SKILL_DIR/config/exclude-paths.txt" \
    | sed "s/'''/\\\\'\\\\'\\\\'/g; s|.*|'''&'''|; s/$/,/"
  echo "]"
} > "$RT_CFG"

# ---------- per-target scan ----------
scan_one() {
  local target="$1" out_json="$2"
  local args=(detect --no-git --redact=0 \
              --config "$RT_CFG" \
              --source "$target" \
              --report-format json \
              --report-path "$out_json" \
              --exit-code 0)
  [ "$HAS_MAX_MB" = "1" ]    && args+=( --max-target-megabytes "$MAX_MB" )
  [ "$HAS_MAX_SIZE" = "1" ]  && args+=( --max-file-size "$MAX_FILE_SIZE" )
  if [ "$ARCHIVE" = "1" ] && [ "$HAS_SCAN_ARCH" = "1" ]; then
    args+=( --scan-archives )
    echo "$GL_HELP" | grep -q -- '--max-archive-depth' \
      && args+=( --max-archive-depth "$MAX_ARCHIVE_DEPTH" )
  fi
  log_info "  scan: $target"
  if ! "$GITLEAKS" "${args[@]}" >>"$LOG" 2>&1; then
    log_warn "  gitleaks returned non-zero for $target (continuing)"
  fi
}

PIDS=()
i=0
for tgt in "${TARGETS[@]}"; do
  shard="$OUT/raw-$i.json"
  scan_one "$tgt" "$shard" &
  PIDS+=($!)
  i=$((i+1))
  # cap concurrency
  if [ "${#PIDS[@]}" -ge "$JOBS" ]; then
    wait "${PIDS[0]}" || true
    PIDS=("${PIDS[@]:1}")
  fi
done
for p in "${PIDS[@]}"; do wait "$p" || true; done

# ---------- env var scan ----------
log_info "scanning environment variables with gitleaks..."
ENV_DIR="$OUT/env-dump"
mkdir -p "$ENV_DIR"

# Current shell env
env > "$ENV_DIR/shell-env.txt" 2>/dev/null || true

# Process environ from /proc
for pid in $(ls /proc/ 2>/dev/null | grep -E '^[0-9]+$'); do
  if [ -r "/proc/$pid/environ" ]; then
    comm=$(cat "/proc/$pid/comm" 2>/dev/null | tr -c '[:alnum:]._-' '_' || echo "unknown")
    tr '\0' '\n' < "/proc/$pid/environ" > "$ENV_DIR/proc-${pid}-${comm}.txt" 2>/dev/null || true
  fi
done

# Run gitleaks on env dump directory
ENV_SHARD="$OUT/raw-env.json"
scan_one "$ENV_DIR" "$ENV_SHARD" &
wait $! || true

# ---------- merge shards ----------
python3 - "$OUT" <<'PY'
import json, sys, glob, pathlib
out = pathlib.Path(sys.argv[1])
merged = []
for f in sorted(out.glob("raw-*.json")):
    try:
        data = json.loads(f.read_text(encoding="utf-8", errors="replace") or "[]")
        if isinstance(data, list):
            merged.extend(data)
    except Exception as e:
        print(f"merge: {f.name}: {e}", file=sys.stderr)
(out / "raw.json").write_text(json.dumps(merged, indent=2, ensure_ascii=False))
print(f"merged {len(merged)} findings -> raw.json")
PY

# ---------- triage ----------
if [ "$TRIAGE" = "1" ]; then
  python3 "$HERE/triage.py" "$OUT/raw.json" --out "$OUT/result.json" 2>>"$LOG" \
    || log_warn "triage failed; see scan.log"
else
  cp "$OUT/raw.json" "$OUT/result.json"
fi

log_ok "done: $OUT"
echo "$OUT"
