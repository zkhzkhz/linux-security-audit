#!/usr/bin/env bash
# Apply container isolation: block container-to-container traffic by default
# in DOCKER-USER, allow only declared pairs. Optionally rebuild user-defined
# networks with --internal=true for back-end-only services.
#
# Default DRY-RUN. --apply to execute.
#
# Usage:
#   apply_container_isolation.sh [--apply] [--plan FILE]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

APPLY=0
PLAN_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1; shift;;
    --plan)  PLAN_FILE="$2"; shift 2;;
    -h|--help) sed -n '1,12p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

OUT="$(ensure_run_dir egress-control-audit)"
[ -z "$PLAN_FILE" ] && PLAN_FILE="$OUT/docker-network.plan.json"
LOG="$OUT/apply-isolation.log"; : > "$LOG"

if ! command -v iptables >/dev/null 2>&1; then
  die "iptables missing"
fi

# Backup DOCKER-USER chain
BACKUP="$OUT/docker-user.backup.$(date -u +%Y%m%dT%H%M%SZ).rules"
iptables -S DOCKER-USER 2>/dev/null > "$BACKUP" || true

ROLLBACK="$OUT/rollback-isolation.sh"
cat > "$ROLLBACK" <<EOF
#!/usr/bin/env bash
set -e
iptables -F DOCKER-USER 2>/dev/null || true
while read -r line; do
  case "\$line" in
    "") continue;;
    -N\ DOCKER-USER) iptables -N DOCKER-USER 2>/dev/null || true;;
    -A*|-I*) iptables \$line 2>/dev/null || true;;
  esac
done < "$BACKUP"
echo "restored DOCKER-USER from $BACKUP"
EOF
chmod +x "$ROLLBACK"

# Compose the sequence. Default policy: drop bridge-to-bridge except return path.
declare -a CMDS
CMDS+=("iptables -F DOCKER-USER")
CMDS+=("iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN")
# Allow inbound from outside (DOCKER chain handles published ports separately)
CMDS+=("iptables -A DOCKER-USER -i docker0 ! -o docker0 -j RETURN")
# Block container -> container (within docker0) by default
CMDS+=("iptables -A DOCKER-USER -i docker0 -o docker0 -j DROP")
# Allow declared inter-container pairs (read from plan if present)
if [ -s "$PLAN_FILE" ]; then
  while IFS=$'\t' read -r src dst ports; do
    [ -n "$src" ] || continue
    for p in $ports; do
      CMDS+=("iptables -I DOCKER-USER 1 -i docker0 -o docker0 -s $src -d $dst -p tcp --dport $p -j RETURN")
    done
  done < <(python3 -c '
import json,sys
try: p=json.load(open(sys.argv[1]))
except Exception: sys.exit(0)
for c in p.get("clusters",[]):
    for pair in c.get("allow_pairs",[]):
        print(f"{pair[\"src\"]}\t{pair[\"dst\"]}\t{\" \".join(str(x) for x in pair.get(\"ports\",[]))}")' "$PLAN_FILE")
fi
# Final RETURN (so docker's own DOCKER chain still runs)
CMDS+=("iptables -A DOCKER-USER -j RETURN")

# Print / execute
for c in "${CMDS[@]}"; do
  echo "$c" | tee -a "$LOG"
done

if [ "$APPLY" = "0" ]; then
  log_info "DRY-RUN; review $LOG. Re-run with --apply."
  echo "$LOG"; exit 0
fi

for c in "${CMDS[@]}"; do
  bash -c "$c" >>"$LOG" 2>&1 || log_warn "cmd failed: $c"
done
log_ok "applied DOCKER-USER policy; rollback: $ROLLBACK"
echo "$ROLLBACK"
