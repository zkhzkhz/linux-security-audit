#!/usr/bin/env bash
# linux-audit-orchestrator entry point.
# Runs sensitive-info-scan, privesc-escape-check, lateral-movement-scan, and
# egress-control-audit in one go, into a single per-run report directory.
#
# Usage:
#   run_all.sh [--only csv] [--no-containers] [--egress-apply]
#              [--isolate-apply] [--full]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

ONLY=""
NO_CONTAINERS=0
EGRESS_APPLY=0
ISOLATE_APPLY=0
FULL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --only)           ONLY="$2"; shift 2;;
    --no-containers)  NO_CONTAINERS=1; shift;;
    --egress-apply)   EGRESS_APPLY=1; shift;;
    --isolate-apply)  ISOLATE_APPLY=1; shift;;
    --full)           FULL=1; shift;;
    -h|--help)        sed -n '1,12p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

run_module() {
  local name="$1"
  if [ -n "$ONLY" ]; then
    case ",$ONLY," in *",$name,"*) :;; *) return 1;; esac
  fi
  return 0
}

# --- ensure tools ---
if ! command -v gitleaks >/dev/null 2>&1 && [ ! -x "$LSA_ROOT/bin/gitleaks-linux-$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')" ]; then
  log_warn "gitleaks not found; trying fetch_tools.sh"
  bash "$LSA_ROOT/bin/fetch_tools.sh" gitleaks || log_warn "fetch_tools.sh failed; sensitive-info-scan may skip"
fi

# --- new run dir (parent of module subdirs) ---
_RUN_HOST="$(hostname -s 2>/dev/null || echo unknown)"
_RUN_TS="$(date -u +'%Y%m%d-%H%M%S')"
LSA_RUN_DIR="$LSA_REPORT_DIR/${_RUN_HOST}-${_RUN_TS}"
export LSA_RUN_DIR
mkdir -p "$LSA_RUN_DIR"
log_info "run dir: $LSA_RUN_DIR"

# --- launch parallel modules (1-3) ---
pids=()
launch() {
  local mod="$1"; shift
  if run_module "$mod"; then
    log_info "starting: $mod"
    ( "$@" ) >"$LSA_RUN_DIR/$mod.launch.log" 2>&1 &
    pids+=($!)
  else
    log_info "skip: $mod"
  fi
}

launch sensitive-info-scan \
  "$LSA_ROOT/skills/sensitive-info-scan/scripts/scan.sh"

# TruffleHog runs in parallel with gitleaks scan
launch sensitive-info-scan-trufflehog \
  "$LSA_ROOT/skills/sensitive-info-scan/scripts/run_trufflehog.sh"

if [ "$NO_CONTAINERS" = "0" ]; then
  launch sensitive-info-scan-containers \
    "$LSA_ROOT/skills/sensitive-info-scan/scripts/scan_containers.sh"
fi

if [ "$NO_CONTAINERS" = "1" ]; then
  launch privesc-escape-check \
    "$LSA_ROOT/skills/privesc-escape-check/scripts/host_privesc.sh"
else
  launch privesc-escape-check bash -c "
    '$LSA_ROOT/skills/privesc-escape-check/scripts/enter_container.sh' --mode both
    '$LSA_ROOT/skills/privesc-escape-check/scripts/run_cdk.sh'
    '$LSA_ROOT/skills/privesc-escape-check/scripts/run_deepce.sh'
    '$LSA_ROOT/skills/privesc-escape-check/scripts/run_amicontained.sh'
    '$LSA_ROOT/skills/privesc-escape-check/scripts/run_peirates.sh'
    '$LSA_ROOT/skills/privesc-escape-check/scripts/run_trivy.sh'
    '$LSA_ROOT/skills/privesc-escape-check/scripts/run_kube_bench.sh'
  "
fi

# Lateral movement is also run in parallel — its discover step is rate-limited.
if run_module lateral-movement-scan; then
  log_info "starting: lateral-movement-scan"
  (
    "$LSA_ROOT/skills/lateral-movement-scan/scripts/discover.sh"
    if [ -s "$LSA_RUN_DIR/lateral-movement-scan/live.txt" ]; then
      if [ "$FULL" = "1" ]; then
        "$LSA_ROOT/skills/lateral-movement-scan/scripts/service_scan.sh" --full
      else
        "$LSA_ROOT/skills/lateral-movement-scan/scripts/service_scan.sh"
      fi
    fi
    "$LSA_ROOT/skills/lateral-movement-scan/scripts/creds_reuse.sh"
    if [ "$NO_CONTAINERS" = "0" ]; then
      "$LSA_ROOT/skills/lateral-movement-scan/scripts/scan_containers_creds.sh"
    fi
    "$LSA_ROOT/skills/lateral-movement-scan/scripts/run_ssh_audit.sh"
  ) >"$LSA_RUN_DIR/lateral-movement-scan.launch.log" 2>&1 &
  pids+=($!)
fi

for p in "${pids[@]}"; do wait "$p" || log_warn "module $p exited non-zero"; done

# --- egress audit (serial; samples sockets) ---
if run_module egress-control-audit; then
  log_info "starting: egress-control-audit"
  "$LSA_ROOT/skills/egress-control-audit/scripts/egress_check.sh" \
    >"$LSA_RUN_DIR/egress-control-audit.launch.log" 2>&1 || true
  "$LSA_ROOT/skills/egress-control-audit/scripts/suggest_allowlist.sh" \
    >>"$LSA_RUN_DIR/egress-control-audit.launch.log" 2>&1 || true
  if [ "$NO_CONTAINERS" = "0" ]; then
    "$LSA_ROOT/skills/egress-control-audit/scripts/verify_isolation.sh" \
      >>"$LSA_RUN_DIR/egress-control-audit.launch.log" 2>&1 || true
  fi
  # Docker CIS Benchmark
  "$LSA_ROOT/skills/egress-control-audit/scripts/run_docker_bench.sh" \
    >>"$LSA_RUN_DIR/egress-control-audit.launch.log" 2>&1 || true
  # Merge isolation findings into result.json
  python3 -c '
import json, os, sys
d = sys.argv[1]
result_f = os.path.join(d, "result.json")
iso_f = os.path.join(d, "isolation", "result.json")
if not os.path.isfile(result_f): sys.exit(0)
data = json.load(open(result_f))
if os.path.isfile(iso_f):
    iso = json.load(open(iso_f))
    data["findings"] = iso.get("findings", []) + data.get("findings", [])
    for k, v in iso.get("counts", {}).items():
        data["counts"][k] = data["counts"].get(k, 0) + v
    if iso.get("status") == "warn":
        data["status"] = "warn"
    data["summary"] = iso.get("summary", "") + "; " + data.get("summary", "")
open(result_f, "w").write(json.dumps(data, indent=2, ensure_ascii=False))
' "$LSA_RUN_DIR/egress-control-audit" 2>/dev/null || true
  if [ "$EGRESS_APPLY" = "1" ]; then
    "$LSA_ROOT/skills/egress-control-audit/scripts/apply_egress_iptables.sh" --apply \
      >>"$LSA_RUN_DIR/egress-control-audit.launch.log" 2>&1 || true
  fi
  if [ "$ISOLATE_APPLY" = "1" ]; then
    "$LSA_ROOT/skills/egress-control-audit/scripts/apply_container_isolation.sh" --apply \
      >>"$LSA_RUN_DIR/egress-control-audit.launch.log" 2>&1 || true
  fi
fi

# --- normalize result.json for modules that don't produce one directly ---
for mod_dir in "$LSA_RUN_DIR"/*/; do
  [ -f "$mod_dir/result.json" ] && continue
  # privesc-escape-check: merge host.json + all sub-tool results
  if [ -f "$mod_dir/host.json" ] || [ -f "$mod_dir/cdk/result.json" ]; then
    python3 -c '
import json, sys, os
d = sys.argv[1]
findings = []
counts = {}
for name in ("host.json", "cdk/result.json", "deepce/result.json", "amicontained/result.json", "peirates/result.json", "trivy/result.json", "kube-bench/result.json"):
    p = os.path.join(d, name)
    if not os.path.isfile(p): continue
    data = json.loads(open(p).read())
    findings.extend(data.get("findings", []))
    for k, v in data.get("counts", {}).items():
        counts[k] = counts.get(k, 0) + v
sev_rank = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
findings.sort(key=lambda f: sev_rank.get(f.get("severity","info"),0), reverse=True)
sev_counts = {}
for f in findings:
    s = f.get("severity","info")
    sev_counts[s] = sev_counts.get(s, 0) + 1
status = "warn" if sev_counts.get("critical",0)+sev_counts.get("high",0)>0 else "ok"
summary = ", ".join(f"{k}:{v}" for k,v in sev_counts.items()) if sev_counts else "no findings"
result = {"module":"privesc-escape-check","status":status,"summary":summary,"counts":{**counts,**sev_counts},"findings":findings}
open(os.path.join(d,"result.json"),"w").write(json.dumps(result,indent=2,ensure_ascii=False))
' "$mod_dir" 2>/dev/null || cp "$mod_dir/host.json" "$mod_dir/result.json"
  # lateral-movement-scan: merge discover.json + creds.json
  elif [ -f "$mod_dir/discover.json" ] || [ -f "$mod_dir/creds.json" ]; then
    python3 -c '
import json, sys, os
d = sys.argv[1]
findings = []
counts = {}
for name in ("discover.json", "creds.json", "containers-creds.json", "service-result.json"):
    p = os.path.join(d, name)
    if not os.path.isfile(p): continue
    data = json.loads(open(p).read())
    findings.extend(data.get("findings", []))
    for k, v in data.get("counts", {}).items():
        counts[k] = counts.get(k, 0) + v
sev_rank = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
findings.sort(key=lambda f: sev_rank.get(f.get("severity","info"),0), reverse=True)
sev_counts = {}
for f in findings:
    s = f.get("severity","info")
    sev_counts[s] = sev_counts.get(s, 0) + 1
status = "warn" if sev_counts.get("critical",0)+sev_counts.get("high",0)>0 else "ok"
summary = ", ".join(f"{k}:{v}" for k,v in sev_counts.items()) if sev_counts else "no findings"
result = {"module":"lateral-movement-scan","status":status,"summary":summary,"counts":{**counts,**sev_counts},"findings":findings}
open(os.path.join(d,"result.json"),"w").write(json.dumps(result,indent=2,ensure_ascii=False))
' "$mod_dir" 2>/dev/null || true
  fi
done

# --- aggregate ---
log_info "aggregating report"
python3 "$LSA_ROOT/lib/report.py" "$LSA_RUN_DIR" || log_warn "report aggregation failed"

# --- per-module detailed reports ---
log_info "generating per-module reports"
python3 "$LSA_ROOT/lib/gen_module_report.py" "$LSA_RUN_DIR" || log_warn "module reports failed"

log_ok "done: $LSA_RUN_DIR/summary.md"
echo "$LSA_RUN_DIR"
