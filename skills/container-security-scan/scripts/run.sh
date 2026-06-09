#!/usr/bin/env bash
# Container Security Scan - Main entry point
# Supports Docker and Crictl runtimes
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

# Parse arguments
RUNTIME="${RUNTIME:-docker}"
CONTAINER_NAME=""
CONTAINER_ID=""
FULL_SCAN="${FULL_SCAN:-false}"
TIMEOUT="${TIMEOUT:-300}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --runtime)
      RUNTIME="$2"
      shift 2
      ;;
    --container)
      CONTAINER_NAME="$2"
      shift 2
      ;;
    --container-id)
      CONTAINER_ID="$2"
      shift 2
      ;;
    --full)
      FULL_SCAN="true"
      shift
      ;;
    --timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

# Validate inputs
if [[ -z "$CONTAINER_NAME" && -z "$CONTAINER_ID" ]]; then
  die "Must specify --container or --container-id"
fi

if [[ "$RUNTIME" != "docker" && "$RUNTIME" != "crictl" ]]; then
  die "Runtime must be 'docker' or 'crictl', got: $RUNTIME"
fi

# Create output directory
OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/container-scan"
mkdir -p "$OUT_DIR"

log_info "Container Security Scan"
log_info "Runtime: $RUNTIME"
log_info "Timeout: ${TIMEOUT}s"

# Resolve container ID
resolve_container_id() {
  local name="$1"
  case "$RUNTIME" in
    docker)
      docker inspect "$name" -f '{{.Id}}' 2>/dev/null || echo ""
      ;;
    crictl)
      crictl inspect "$name" 2>/dev/null | grep -oP '"id":\s*"\K[^"]+' | head -1 || echo ""
      ;;
  esac
}

# Get container PID
get_container_pid() {
  local id="$1"
  case "$RUNTIME" in
    docker)
      docker inspect "$id" -f '{{.State.Pid}}' 2>/dev/null || echo ""
      ;;
    crictl)
      crictl inspect "$id" 2>/dev/null | grep -oP '"pid":\s*\K[0-9]+' || echo ""
      ;;
  esac
}

# Get container info
get_container_info() {
  local id="$1"
  case "$RUNTIME" in
    docker)
      docker inspect "$id" 2>/dev/null
      ;;
    crictl)
      crictl inspect "$id" 2>/dev/null
      ;;
  esac
}

# Resolve ID
if [[ -n "$CONTAINER_ID" ]]; then
  CID="$CONTAINER_ID"
else
  log_info "Resolving container: $CONTAINER_NAME"
  CID=$(resolve_container_id "$CONTAINER_NAME")
  if [[ -z "$CID" ]]; then
    die "Container not found: $CONTAINER_NAME"
  fi
  log_info "Container ID: $CID"
fi

# Get PID
PID=$(get_container_pid "$CID")
if [[ -z "$PID" || "$PID" == "0" ]]; then
  die "Container not running or PID not found"
fi
log_info "Container PID: $PID"

# Save container info
get_container_info "$CID" > "$OUT_DIR/container-info.json" 2>/dev/null

# Run scans using nsenter
log_info "Running security scans..."

# Function to run command in container namespace
run_in_container() {
  local cmd="$1"
  nsenter -t "$PID" -m -u -i -n -p -- bash -c "$cmd" 2>/dev/null
}

# Initialize findings
FINDINGS=()

# ========== Module 1: Container Escape Check ==========
log_info "Module: Container Escape Check"
ESCAPE_RESULT="$OUT_DIR/escape.json"

# Check capabilities
CAPS=$(run_in_container "cat /proc/self/status 2>/dev/null | grep CapEff" | awk '{print $2}')
PRIVILEGED="false"

case "$CAPS" in
  0000003fffffffff|000001ffffffffff)
    PRIVILEGED="true"
    FINDINGS+=('{"severity":"critical","title":"privileged-container","where":"container","note":"Full capabilities detected"}')
    ;;
esac

# Check for dangerous capabilities
if [[ -n "$CAPS" ]]; then
  CAPS_DEC=$(printf '%d' "$((16#$CAPS))" 2>/dev/null || echo 0)
  # CAP_SYS_ADMIN = bit 21
  [[ $((CAPS_DEC & (1<<21))) -ne 0 ]] && FINDINGS+=('{"severity":"critical","title":"cap-sys-admin","where":"container","note":"CAP_SYS_ADMIN present"}')
  # CAP_SYS_PTRACE = bit 19
  [[ $((CAPS_DEC & (1<<19))) -ne 0 ]] && FINDINGS+=('{"severity":"high","title":"cap-sys-ptrace","where":"container","note":"CAP_SYS_PTRACE present"}')
  # CAP_SYS_MODULE = bit 16
  [[ $((CAPS_DEC & (1<<16))) -ne 0 ]] && FINDINGS+=('{"severity":"critical","title":"cap-sys-module","where":"container","note":"CAP_SYS_MODULE present"}')
fi

# Check mounts for dangerous paths
run_in_container "cat /proc/mounts" > "$OUT_DIR/mounts.txt" 2>/dev/null

if grep -qE 'docker\.sock' "$OUT_DIR/mounts.txt" 2>/dev/null; then
  FINDINGS+=('{"severity":"critical","title":"docker-sock-mounted","where":"container","note":"Docker socket mounted"}')
fi

if grep -qE ' /host[ /]' "$OUT_DIR/mounts.txt" 2>/dev/null; then
  FINDINGS+=('{"severity":"high","title":"host-bind-mount","where":"container:/host","note":"Host filesystem mounted at /host"}')
fi

# Check for raw devices
for dev in /dev/mem /dev/kmem /dev/sda /dev/vda /dev/nvme0n1; do
  if run_in_container "[ -e $dev ] && echo yes" 2>/dev/null | grep -q yes; then
    FINDINGS+=("{\"severity\":\"high\",\"title\":\"raw-device\",\"where\":\"container:$dev\",\"note\":\"Raw device exposed\"}")
  fi
done

# Check PID namespace
PID1=$(run_in_container "tr '\0' ' ' < /proc/1/cmdline 2>/dev/null | head -c 100")
case "$PID1" in
  *systemd*|*init*|*launchd*)
    FINDINGS+=("{\"severity\":\"high\",\"title\":\"pid-host-namespace\",\"where\":\"container\",\"note\":\"PID 1 is host init: ${PID1:0:50}\"}")
    ;;
esac

# ========== Module 2: Sensitive Info Scan (optional) ==========
if [[ "$FULL_SCAN" == "true" ]]; then
  log_info "Module: Sensitive Info Scan"

  # Use gitleaks if available
  GITLEAKS="$LSA_ROOT/bin/gitleaks"
  if [[ -x "$GITLEAKS" ]]; then
    # Copy gitleaks into container tmp
    CONTAINER_TMP="/tmp/gitleaks-$$"
    run_in_container "mkdir -p $CONTAINER_TMP"

    # Create a simple secret scan using grep patterns
    run_in_container "grep -rE '(password|secret|token|api_key|apikey)\\s*=' /etc /opt /home 2>/dev/null | head -50" > "$OUT_DIR/secrets-quick.txt"

    # Check for SSH keys
    run_in_container "find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' 2>/dev/null | head -20" > "$OUT_DIR/ssh-keys.txt"

    if [[ -s "$OUT_DIR/secrets-quick.txt" ]]; then
      FINDINGS+=('{"severity":"medium","title":"potential-secrets","where":"container","note":"Potential secrets found in config files"}')
    fi

    if [[ -s "$OUT_DIR/ssh-keys.txt" ]]; then
      FINDINGS+=('{"severity":"medium","title":"ssh-keys","where":"container","note":"SSH private keys found"}')
    fi
  fi
fi

# ========== Module 3: Network Check (optional) ==========
if [[ "$FULL_SCAN" == "true" ]]; then
  log_info "Module: Network Check"

  # Check listening ports
  run_in_container "cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | grep -v local | wc -l" > "$OUT_DIR/listeners.txt"
  LISTENERS=$(cat "$OUT_DIR/listeners.txt" 2>/dev/null | head -1)

  if [[ "${LISTENERS:-0}" -gt 50 ]]; then
    FINDINGS+=("{\"severity\":\"medium\",\"title\":\"many-listeners\",\"where\":\"container\",\"note\":\"${LISTENERS} listening sockets, possibly host network\"}")
  fi

  # Check if can reach internet
  if run_in_container "curl -s --connect-timeout 2 1.1.1.1:80 > /dev/null 2>&1 && echo yes" 2>/dev/null | grep -q yes; then
    FINDINGS+=('{"severity":"high","title":"internet-access","where":"container","note":"Container can reach external internet"}')
  fi
fi

# ========== Generate Output ==========
log_info "Generating report..."

# Create JSON result using Python with proper handling
if [[ ${#FINDINGS[@]} -gt 0 ]]; then
  # Join findings with commas
  FINDINGS_JSON=$(printf '%s,' "${FINDINGS[@]}" | sed 's/,$//')
else
  FINDINGS_JSON=""
fi

python3 - "$RUNTIME" "$CID" "$PID" "${CONTAINER_NAME:-unknown}" "$OUT_DIR" "$FINDINGS_JSON" << 'PYEOF'
import json
import sys
from pathlib import Path

runtime, cid, pid, name, out_dir, findings_str = sys.argv[1:7]
findings = json.loads(f"[{findings_str}]") if findings_str else []

counts = {}
for f in findings:
    sev = f.get("severity", "unknown")
    counts[sev] = counts.get(sev, 0) + 1

status = "warn" if counts.get("critical", 0) + counts.get("high", 0) > 0 else "ok"

result = {
    "module": "container-security-scan",
    "status": status,
    "summary": ", ".join(f"{k}:{v}" for k, v in counts.items()) or "no findings",
    "container": {
        "runtime": runtime,
        "id": cid,
        "pid": int(pid),
        "name": name
    },
    "counts": counts,
    "findings": findings
}

Path(out_dir + "/result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
PYEOF

# Create markdown summary
cat > "$OUT_DIR/summary.md" << MDEOF
# Container Security Scan Report

**Runtime:** $RUNTIME
**Container ID:** $CID
**Container Name:** ${CONTAINER_NAME:-N/A}
**PID:** $PID

## Summary

$(cat "$OUT_DIR/result.json" 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(f'Status: {d[\"status\"]}'); print(f'Findings: {d[\"summary\"]}')")

## Files

- \`result.json\` - Structured findings
- \`container-info.json\` - Container metadata
- \`mounts.txt\` - Mount points inside container

MDEOF

log_ok "Scan complete -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
