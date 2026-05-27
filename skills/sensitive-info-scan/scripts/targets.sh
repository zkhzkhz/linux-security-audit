#!/usr/bin/env bash
# Print the default scan target list (one per line) for the current host or a container.
# Includes auto-detection of extra mount points (data disks, NFS, etc.)
# Usage: targets.sh [--container]
set -euo pipefail

CONTAINER=0
[ "${1:-}" = "--container" ] && CONTAINER=1
[ "${LSA_CONTAINER:-0}" = "1" ] && CONTAINER=1

# Static targets
if [ "$CONTAINER" = "1" ]; then
  cat <<'EOF'
/etc
/root
/home
/opt
/srv
/app
/usr/local/etc
/var/log
EOF
else
  cat <<'EOF'
/etc
/root
/home
/opt
/srv
/usr/local
/var/log
/var/spool
/var/www
/tmp
EOF
fi

# Auto-detect mounted data disks (non-root, non-system mounts)
# Covers: extra partitions, LVM, NFS, CIFS, cloud disks
if [ "$CONTAINER" = "0" ]; then
  mount | grep -E '^/dev/|^[^/]+:/' \
    | awk '{print $3}' \
    | grep -vE '^/$|^/(boot|snap|proc|sys|dev|run)' \
    | grep -vE '/docker/|/containerd/|/kubelet/' \
    | sort -u || true
fi
