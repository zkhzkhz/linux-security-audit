#!/usr/bin/env bash
# Run TruffleHog secret scanning on filesystem and git repos.
# More comprehensive than gitleaks: 600+ detectors, active verification.
# Outputs structured JSON to $LSA_RUN_DIR/sensitive-info-scan/trufflehog/
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/sensitive-info-scan/trufflehog"
mkdir -p "$OUT_DIR"

pick_trufflehog() {
  local arch
  arch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  local bin="$LSA_ROOT/bin/trufflehog-linux-$arch"
  if [ -x "$bin" ]; then echo "$bin"; return 0; fi
  if command -v trufflehog >/dev/null 2>&1; then echo "trufflehog"; return 0; fi
  return 1
}

TRUFFLEHOG="$(pick_trufflehog)" || die "trufflehog binary not found"

log_info "========== TruffleHog Secret Scanning =========="
log_info "TruffleHog binary: $TRUFFLEHOG"

# Scan targets: git repos and filesystem paths
SCAN_TARGETS=""
log_info "Discovering git repositories..."
for d in /opt /srv /app /home /root; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 3 -name ".git" -type d 2>/dev/null | while read gitdir; do
    echo "$(dirname "$gitdir")"
  done
done > "$OUT_DIR/repos.txt"
repo_found=$(wc -l < "$OUT_DIR/repos.txt")
log_info "Found $repo_found git repositories to scan."

# Also scan /etc and common config dirs for filesystem secrets
log_info "========== Scanning Filesystem =========="
log_info "Scanning /etc, /root, /home for secrets..."
raw_fs="$OUT_DIR/filesystem.json"
"$TRUFFLEHOG" filesystem /etc /root /home \
  --json --no-update 2>/dev/null > "$raw_fs" || true
log_info "Filesystem scan complete."

# Scan git repos
log_info "========== Scanning Git Repositories =========="
raw_git="$OUT_DIR/git.json"
: > "$raw_git"
repo_count=0
while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  repo_count=$((repo_count + 1))
  log_info "[$repo_count] Scanning git repo: $repo"
  "$TRUFFLEHOG" git "file://$repo" \
    --json --no-update --max-depth 50 2>/dev/null >> "$raw_git" || true
done < "$OUT_DIR/repos.txt"

log_info "Scanned $repo_count git repos + filesystem"

# Parse results
log_info "========== Parsing TruffleHog Results =========="
python3 "$HERE/parse_trufflehog.py" "$OUT_DIR"
log_ok "========== TruffleHog Scan Complete =========="
log_ok "TruffleHog scan done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
