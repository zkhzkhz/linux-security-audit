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

# Scan targets: git repos and filesystem paths
SCAN_TARGETS=""
# Find git repos in common locations
for d in /opt /srv /app /home /root; do
  [ -d "$d" ] || continue
  find "$d" -maxdepth 3 -name ".git" -type d 2>/dev/null | while read gitdir; do
    echo "$(dirname "$gitdir")"
  done
done > "$OUT_DIR/repos.txt"

# Also scan /etc and common config dirs for filesystem secrets
log_info "running TruffleHog filesystem scan"
raw_fs="$OUT_DIR/filesystem.json"
"$TRUFFLEHOG" filesystem /etc /root /home \
  --json --no-update 2>/dev/null > "$raw_fs" || true

# Scan git repos
raw_git="$OUT_DIR/git.json"
: > "$raw_git"
repo_count=0
while IFS= read -r repo; do
  [ -z "$repo" ] && continue
  repo_count=$((repo_count + 1))
  log_info "  trufflehog git: $repo"
  "$TRUFFLEHOG" git "file://$repo" \
    --json --no-update --max-depth 50 2>/dev/null >> "$raw_git" || true
done < "$OUT_DIR/repos.txt"

log_info "scanned $repo_count git repos + filesystem"

# Parse results
python3 "$HERE/parse_trufflehog.py" "$OUT_DIR"
log_ok "TruffleHog scan done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
