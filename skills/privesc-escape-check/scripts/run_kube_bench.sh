#!/usr/bin/env bash
# Run kube-bench CIS Kubernetes Benchmark audit.
# Detects if running on a k8s node and runs appropriate checks.
# Outputs structured JSON to $LSA_RUN_DIR/privesc-escape-check/kube-bench/
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/privesc-escape-check/kube-bench"
mkdir -p "$OUT_DIR"

pick_kube_bench() {
  local arch
  arch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  local bin="$LSA_ROOT/bin/kube-bench-linux-$arch"
  if [ -x "$bin" ]; then echo "$bin"; return 0; fi
  if command -v kube-bench >/dev/null 2>&1; then echo "kube-bench"; return 0; fi
  return 1
}

KUBE_BENCH="$(pick_kube_bench)" || die "kube-bench binary not found"
CFG_DIR="$LSA_ROOT/bin/cfg"

# Detect k8s environment
is_k8s_node() {
  [ -f /etc/kubernetes/kubelet.conf ] || \
  [ -f /var/lib/kubelet/config.yaml ] || \
  [ -d /etc/kubernetes/manifests ] || \
  command -v kubelet >/dev/null 2>&1 || \
  [ -n "${KUBERNETES_SERVICE_HOST:-}" ]
}

if ! is_k8s_node; then
  log_info "not a Kubernetes node, checking containers for k8s components"
  # Try running inside k8s containers
  k8s_containers=""
  for cname in $(docker ps --format '{{.Names}}' 2>/dev/null); do
    has_k8s=$(docker exec "$cname" test -d /etc/kubernetes 2>/dev/null && echo y || echo n)
    [ "$has_k8s" = "y" ] && k8s_containers="$k8s_containers $cname"
  done

  if [ -z "$k8s_containers" ]; then
    log_info "no Kubernetes environment detected, skipping kube-bench"
    python3 -c '
import json
r = {"module":"privesc-escape-check.kube-bench","status":"ok","summary":"no k8s environment detected","counts":{},"findings":[]}
open("'"$OUT_DIR/result.json"'","w").write(json.dumps(r,indent=2))
'
    echo "$OUT_DIR/result.json"
    exit 0
  fi

  # Run inside k8s containers
  for cname in $k8s_containers; do
    log_info "  kube-bench: $cname"
    raw="$OUT_DIR/${cname}.json"
    docker cp "$KUBE_BENCH" "$cname:/tmp/kube-bench" 2>/dev/null || continue
    docker cp "$CFG_DIR" "$cname:/tmp/cfg" 2>/dev/null || continue
    docker exec "$cname" chmod +x /tmp/kube-bench 2>/dev/null
    docker exec "$cname" /tmp/kube-bench run --config-dir /tmp/cfg --json \
      2>/dev/null > "$raw" || true
    docker exec "$cname" rm -rf /tmp/kube-bench /tmp/cfg 2>/dev/null
  done
else
  # Run directly on host
  log_info "running kube-bench on host (k8s node detected)"
  raw="$OUT_DIR/host.json"
  "$KUBE_BENCH" run --config-dir "$CFG_DIR" --json > "$raw" 2>/dev/null || true
fi

# Parse results
python3 "$HERE/parse_kube_bench.py" "$OUT_DIR"
log_ok "kube-bench scan done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"