#!/usr/bin/env bash
# Apply the proposed egress allowlist on the host.
# Default is DRY-RUN. Pass --apply to actually run iptables.
#
# Usage:
#   apply_egress_iptables.sh [--apply] [--policy drop|return] [--rules FILE]
#
#   --policy drop     after installing the LSA_EGRESS chain, also set
#                     `iptables -P OUTPUT DROP`. Use carefully.
#   --policy return   leave OUTPUT default ACCEPT (the chain still rejects
#                     non-allowlisted; this is "monitor + reject" mode).
#
# Writes a backup of the existing ruleset and a rollback.sh first.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

APPLY=0
POLICY="return"
RULES_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply)  APPLY=1; shift;;
    --policy) POLICY="$2"; shift 2;;
    --rules)  RULES_FILE="$2"; shift 2;;
    -h|--help) sed -n '1,15p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

OUT="$(ensure_run_dir egress-control-audit)"
[ -z "$RULES_FILE" ] && RULES_FILE="$OUT/egress.iptables.rules"
[ -s "$RULES_FILE" ] || die "rules file missing: $RULES_FILE  (run suggest_allowlist.sh first)"

LOG="$OUT/apply.log"; : > "$LOG"
TS="$(date -u +'%Y%m%dT%H%M%SZ')"
BACKUP="$OUT/iptables.backup.$TS.rules"

if command -v iptables-save >/dev/null 2>&1; then
  iptables-save > "$BACKUP" 2>>"$LOG"
else
  log_warn "iptables-save missing; cannot back up"
  : > "$BACKUP"
fi

ROLLBACK="$OUT/rollback.sh"
cat > "$ROLLBACK" <<EOF
#!/usr/bin/env bash
# Restore iptables to the snapshot taken before apply_egress_iptables.sh
set -e
iptables -F LSA_EGRESS 2>/dev/null || true
iptables -X LSA_EGRESS 2>/dev/null || true
iptables-restore < "$BACKUP"
echo "restored $BACKUP"
EOF
chmod +x "$ROLLBACK"

# safety: refuse if SSH session is the only return path and no allow entry covers the source
if [ "$APPLY" = "1" ] && [ "$POLICY" = "drop" ] && [ -n "${SSH_CLIENT:-}${SSH_TTY:-}" ]; then
  src="$(echo "${SSH_CLIENT:-}" | awk '{print $1}')"
  if ! grep -q "${src:-NEVERMATCH}" "$RULES_FILE" 2>/dev/null; then
    die "Aborting: --policy drop with SSH session from $src not in allowlist would lock you out. Add a rule for the SSH source first."
  fi
fi

emit() {
  echo "$*" | tee -a "$LOG"
}

# Build the actual command sequence. We avoid `iptables-restore` to keep
# pre-existing rules intact; instead we (re)create LSA_EGRESS and insert.
emit "# rules file: $RULES_FILE"
emit "iptables -F LSA_EGRESS 2>/dev/null || true"
emit "iptables -X LSA_EGRESS 2>/dev/null || true"
emit "iptables -N LSA_EGRESS"

# Translate the *filter rules into iptables -A commands
grep -E '^-A LSA_EGRESS' "$RULES_FILE" | while IFS= read -r line; do
  emit "iptables ${line/-A LSA_EGRESS/-A LSA_EGRESS}"
done

emit "iptables -C OUTPUT -j LSA_EGRESS 2>/dev/null || iptables -I OUTPUT 1 -j LSA_EGRESS"
case "$POLICY" in
  drop)   emit "iptables -P OUTPUT DROP" ;;
  return) : ;;
  *)      die "unknown --policy: $POLICY" ;;
esac

if [ "$APPLY" = "0" ]; then
  log_info "DRY-RUN; commands logged to $LOG. Re-run with --apply to execute."
  echo "$LOG"
  exit 0
fi

# Execute
log_info "applying iptables changes..."
while IFS= read -r cmd; do
  case "$cmd" in
    \#*|"") continue;;
  esac
  bash -c "$cmd" >>"$LOG" 2>&1 || log_warn "cmd failed: $cmd"
done < "$LOG"

log_ok "applied; rollback: $ROLLBACK"
echo "$ROLLBACK"
