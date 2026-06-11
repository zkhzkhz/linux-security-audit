#!/usr/bin/env bash
# Quick container security check from host side
# Checks: privileged, capabilities, mounts, network modes
set -uo pipefail

echo "============================================"
echo "Container Security Quick Check"
echo "============================================"

# Check Docker
if command -v docker >/dev/null 2>&1; then
  echo "[Docker] Checking $(docker ps -q | wc -l) running containers..."
  echo ""

  for cid in $(docker ps -q); do
    name=$(docker inspect --format '{{.Name}}' "$cid" | sed 's/^\///')
    echo "=== $name ($cid) ==="

    # Privileged
    if docker inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null | grep -q "true"; then
      echo "  [CRITICAL] Privileged: YES"
    fi

    # Dangerous capabilities
    caps=$(docker inspect --format '{{.HostConfig.CapAdd}}' "$cid" 2>/dev/null)
    if echo "$caps" | grep -qiE "SYS_ADMIN|SYS_PTRACE|SYS_MODULE|ALL"; then
      echo "  [HIGH] Dangerous caps: $caps"
    fi

    # Host namespaces
    pidmode=$(docker inspect --format '{{.HostConfig.PidMode}}' "$cid" 2>/dev/null)
    netmode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null)
    ipcmode=$(docker inspect --format '{{.HostConfig.IpcMode}}' "$cid" 2>/dev/null)

    [ "$pidmode" = "host" ] && echo "  [HIGH] PID: host"
    [ "$netmode" = "host" ] && echo "  [HIGH] Network: host"
    [ "$ipcmode" = "host" ] && echo "  [MEDIUM] IPC: host"

    # Sensitive mounts
    mounts=$(docker inspect --format '{{json .Mounts}}' "$cid" 2>/dev/null)
    if echo "$mounts" | grep -q "docker.sock"; then
      echo "  [CRITICAL] Mount: docker.sock"
    fi
    if echo "$mounts" | grep -qE '"/host"|"/:/host"'; then
      echo "  [HIGH] Mount: host filesystem"
    fi

    # Devices
    devices=$(docker inspect --format '{{json .HostConfig.Devices}}' "$cid" 2>/dev/null)
    if [ -n "$devices" ] && [ "$devices" != "[]" ]; then
      echo "  [HIGH] Devices: $devices"
    fi

    # Security options
    seccomp=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$cid" 2>/dev/null)
    if echo "$seccomp" | grep -q "unconfined"; then
      echo "  [HIGH] Seccomp: disabled"
    fi

    echo ""
  done
fi

# Check crictl
if command -v crictl >/dev/null 2>&1; then
  echo "[crictl] Checking containers..."
  for cid in $(crictl ps -q 2>/dev/null); do
    info=$(crictl inspect "$cid" 2>/dev/null)
    name=$(echo "$info" | grep -oP '"name":\s*"\K[^"]+' | head -1)
    echo "=== $name ($cid) ==="

    # Check capabilities
    caps=$(echo "$info" | grep -oP '"capabilities":\s*\{[^}]*\}')
    if echo "$caps" | grep -q "CAP_SYS_ADMIN"; then
      echo "  [CRITICAL] CAP_SYS_ADMIN present"
    fi

    # Check namespaces
    ns=$(echo "$info" | grep -oP '"namespaces":\s*\{[^}]*\}')
    if echo "$ns" | grep -q '"pid":\s*null'; then
      echo "  [HIGH] No PID namespace"
    fi
    if echo "$ns" | grep -q '"network":\s*null'; then
      echo "  [HIGH] No network namespace"
    fi

    echo ""
  done
fi

# Check for docker socket on host
echo "=== Docker Socket Check ==="
if [ -S /var/run/docker.sock ]; then
  echo "  [INFO] /var/run/docker.sock exists"
elif [ -S /run/docker.sock ]; then
  echo "  [INFO] /run/docker.sock exists"
else
  echo "  [OK] No docker socket found"
fi

echo ""
echo "============================================"
echo "Check complete"
echo "============================================"