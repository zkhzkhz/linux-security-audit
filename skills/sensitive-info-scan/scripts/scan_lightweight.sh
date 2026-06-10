#!/usr/bin/env bash
# Lightweight gitleaks scan for specific targets.
# Supports: history, env, directories, or combined.
#
# Usage:
#   scan_lightweight.sh --target history
#   scan_lightweight.sh --target env
#   scan_lightweight.sh --target /path/to/dir
#   scan_lightweight.sh --target all
#   scan_lightweight.sh --target history,env,/etc
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"
. "$LSA_ROOT/lib/arch_detect.sh"

# Parse arguments
TARGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    -h|--help)
      sed -n '1,15p' "$0"
      exit 0
      ;;
    *) die "unknown flag: $1";;
  esac
done

[ -z "$TARGET" ] && TARGET="all"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/sensitive-scan-light"
mkdir -p "$OUT_DIR"

# Resolve gitleaks binary
GITLEAKS="$(pick_gitleaks || true)"
[ -n "$GITLEAKS" ] || die "gitleaks not found; run $LSA_ROOT/bin/fetch_tools.sh"

GITLEAKS_VERSION=$("$GITLEAKS" --version 2>/dev/null | head -1 || echo "unknown")
log_info "Using gitleaks: $GITLEAKS ($GITLEAKS_VERSION)"

# Config file
CONFIG="$LSA_ROOT/skills/sensitive-info-scan/config/gitleaks-custom.toml"
[ -f "$CONFIG" ] || CONFIG=""

# Common gitleaks options
GITLEAKS_OPTS="--no-git --exit-code 0"
[ -f "$CONFIG" ] && GITLEAKS_OPTS="$GITLEAKS_OPTS --config $CONFIG"

# Check gitleaks version for flag compatibility
GITLEAKS_MAJOR=$("$GITLEAKS" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1 | cut -d. -f1)
if [ "${GITLEAKS_MAJOR:-8}" -ge 8 ]; then
  # v8+ uses --report-path and --report-format
  REPORT_FLAG="--report-path"
  FORMAT_FLAG="--report-format"
else
  # older versions use -o and -f
  REPORT_FLAG="-o"
  FORMAT_FLAG="-f"
fi

# Parse targets
IFS=',' read -ra TARGETS <<< "$TARGET"

all_findings="[]"
scanned_targets=()

scan_target() {
  local t="$1"
  local cmd=""
  local tmp_out=""

  case "$t" in
    history)
      # Scan bash history files
      log_info "Scanning: bash history files"
      tmp_out=$(mktemp)
      cmd="$GITLEAKS detect $GITLEAKS_OPTS --source=$HOME/.bash_history $FORMAT_FLAG json $REPORT_FLAG $tmp_out"
      log_info "  Command: $cmd"
      eval "$cmd" 2>&1 | head -5 || true
      [ -s "$tmp_out" ] && scanned_targets+=("history")
      ;;

    env)
      # Scan environment variables
      log_info "Scanning: environment variables"
      tmp_out=$(mktemp)
      # Dump env to temp file and scan
      local env_file=$(mktemp)
      env > "$env_file"
      cmd="$GITLEAKS detect $GITLEAKS_OPTS --source=$env_file $FORMAT_FLAG json $REPORT_FLAG $tmp_out"
      log_info "  Command: $cmd"
      eval "$cmd" 2>&1 | head -5 || true
      rm -f "$env_file"
      [ -s "$tmp_out" ] && scanned_targets+=("env")
      ;;

    proc-env)
      # Scan all process environment variables via /proc
      log_info "Scanning: process environment variables (/proc/*/environ)"
      tmp_out=$(mktemp)
      local proc_env_file=$(mktemp)
      # Collect all process envs (null-separated, convert to lines)
      for pid_dir in /proc/[0-9]*; do
        local pid=${pid_dir##*/}
        [ -r "$pid_dir/environ" ] || continue
        # Skip kernel processes and self
        [ "$pid" = "$$" ] && continue
        tr '\0' '\n' < "$pid_dir/environ" 2>/dev/null | sed "s/^/PID=$pid: /" >> "$proc_env_file"
      done
      cmd="$GITLEAKS detect $GITLEAKS_OPTS --source=$proc_env_file $FORMAT_FLAG json $REPORT_FLAG $tmp_out"
      log_info "  Command: $cmd"
      log_info "  Collected env from $(grep -c '^PID=' "$proc_env_file" 2>/dev/null || echo 0) processes"
      eval "$cmd" 2>&1 | head -5 || true
      rm -f "$proc_env_file"
      [ -s "$tmp_out" ] && scanned_targets+=("proc-env")
      ;;

    proc-env:*)
      # Scan specific PID environment variables
      local pid="${t#proc-env:}"
      log_info "Scanning: process $pid environment variables"
      tmp_out=$(mktemp)
      local proc_env_file=$(mktemp)
      if [ -r "/proc/$pid/environ" ]; then
        tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null >> "$proc_env_file"
        cmd="$GITLEAKS detect $GITLEAKS_OPTS --source=$proc_env_file $FORMAT_FLAG json $REPORT_FLAG $tmp_out"
        log_info "  Command: $cmd"
        eval "$cmd" 2>&1 | head -5 || true
        [ -s "$tmp_out" ] && scanned_targets+=("proc-env:$pid")
      else
        log_warn "Cannot read /proc/$pid/environ"
      fi
      rm -f "$proc_env_file"
      ;;

    all)
      # Scan common locations
      log_info "Scanning: common locations (history, env, /etc, /home, /opt)"

      # History
      for hist in /root/.bash_history /home/*/.bash_history; do
        [ -f "$hist" ] || continue
        tmp_out=$(mktemp)
        cmd="$GITLEAKS detect $GITLEAKS_OPTS --source=$hist $FORMAT_FLAG json $REPORT_FLAG $tmp_out"
        log_info "  Command: $cmd"
        eval "$cmd" 2>&1 | tail -1 || true
        [ -s "$tmp_out" ] && {
          scanned_targets+=("history:$hist")
          all_findings=$(python3 -c "import json,sys; a=json.loads(sys.argv[1]); b=json.load(open('$tmp_out')); print(json.dumps(a+b.get('findings',[])))" "$all_findings" 2>/dev/null || echo "$all_findings")
        }
        rm -f "$tmp_out"
      done

      # Env
      local env_file=$(mktemp)
      env > "$env_file"
      tmp_out=$(mktemp)
      cmd="$GITLEAKS detect $GITLEAKS_OPTS --source=$env_file $FORMAT_FLAG json $REPORT_FLAG $tmp_out"
      log_info "  Command: $cmd"
      eval "$cmd" 2>&1 | tail -1 || true
      rm -f "$env_file"
      [ -s "$tmp_out" ] && {
        scanned_targets+=("env")
        all_findings=$(python3 -c "import json,sys; a=json.loads(sys.argv[1]); b=json.load(open('$tmp_out')); print(json.dumps(a+b.get('findings',[])))" "$all_findings" 2>/dev/null || echo "$all_findings")
      }
      rm -f "$tmp_out"

      # /etc
      tmp_out=$(mktemp)
      cmd="$GITLEAKS detect $GITLEAKS_OPTS --source=/etc $FORMAT_FLAG json $REPORT_FLAG $tmp_out"
      log_info "  Command: $cmd"
      eval "$cmd" 2>&1 | tail -1 || true
      [ -s "$tmp_out" ] && {
        scanned_targets+=("/etc")
        all_findings=$(python3 -c "import json,sys; a=json.loads(sys.argv[1]); b=json.load(open('$tmp_out')); print(json.dumps(a+b.get('findings',[])))" "$all_findings" 2>/dev/null || echo "$all_findings")
      }
      rm -f "$tmp_out"

      # Skip remaining since we handled 'all' specially
      return
      ;;

    /*)
      # Directory path
      [ -d "$t" ] || { log_warn "Directory not found: $t"; return 1; }
      log_info "Scanning: $t"
      tmp_out=$(mktemp)
      cmd="$GITLEAKS detect $GITLEAKS_OPTS --source=$t $FORMAT_FLAG json $REPORT_FLAG $tmp_out"
      log_info "  Command: $cmd"
      eval "$cmd" 2>&1 | tail -1 || true
      [ -s "$tmp_out" ] && scanned_targets+=("$t")
      ;;

    *)
      log_warn "Unknown target: $t (use: history, env, all, or /path/to/dir)"
      return 1
      ;;
  esac

  # Merge findings
  if [ -s "${tmp_out:-}" ]; then
    all_findings=$(python3 -c "import json,sys; a=json.loads(sys.argv[1]); b=json.load(open('$tmp_out')); print(json.dumps(a+b.get('findings',[])))" "$all_findings" 2>/dev/null || echo "$all_findings")
    rm -f "$tmp_out"
  fi
}

# Run scans
log_info "============================================"
log_info "Lightweight Gitleaks Scan"
log_info "============================================"
log_info "Targets: $TARGET"
log_info "============================================"

# Initialize array
scanned_targets=()

for t in "${TARGETS[@]}"; do
  scan_target "$t"
done

# Generate result
log_info "Generating report..."

# Handle empty array
if [ ${#scanned_targets[@]} -eq 0 ]; then
  TARGETS_STR=""
else
  TARGETS_STR="${scanned_targets[*]}"
fi

python3 - "$OUT_DIR" "$all_findings" "$TARGETS_STR" << 'PY'
import json, sys
from pathlib import Path

out_dir = sys.argv[1]
findings_str = sys.argv[2]
targets = sys.argv[3].split() if len(sys.argv) > 3 else []

try:
    findings = json.loads(findings_str) if findings_str else []
except:
    findings = []

# Deduplicate by fingerprint
seen = set()
deduped = []
for f in findings:
    fp = f.get("Fingerprint", f.get("RuleID", "") + str(f.get("StartLine", "")))
    if fp not in seen:
        seen.add(fp)
        deduped.append({
            "severity": "high" if f.get("Entropy", 0) >= 4.5 else "medium",
            "title": f.get("RuleID", "secret-detected"),
            "where": f.get("File", "unknown"),
            "note": f.get("Match", "")[:100] if f.get("Match") else "",
            "line": f.get("StartLine", 0),
            "entropy": round(f.get("Entropy", 0), 2)
        })

counts = {}
for f in deduped:
    sev = f["severity"]
    counts[sev] = counts.get(sev, 0) + 1

status = "warn" if counts.get("critical", 0) + counts.get("high", 0) > 0 else "ok"
summary = f"{len(deduped)} findings in {len(targets)} target(s): " + ", ".join(f"{k}:{v}" for k, v in counts.items())

result = {
    "module": "sensitive-info-scan-lightweight",
    "status": status,
    "summary": summary,
    "counts": counts,
    "targets": targets,
    "findings": deduped[:200]
}

Path(out_dir + "/result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
PY

log_ok "Scan complete -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
