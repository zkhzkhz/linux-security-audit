#!/usr/bin/env bash
# Enumerate containers from the host and run container_escape.sh inside each.
#
# Modes:
#   --mode host      (default) check from host via docker/crictl inspect only
#   --mode nsenter   join namespaces from host using nsenter (root)
#   --mode cp-exec   drop the script via runtime cp + exec
#   --mode both      try cp-exec first; fall back to nsenter on failure
#
# --runtime auto|docker|nerdctl|crictl|podman   (default auto)
# --container <name>                            scan specific container by name
# --container-id <id>                           scan specific container by ID
# --keep                                        leave dropped script in container
#
# Outputs $OUT/containers/<id>.json + .log and an aggregate $OUT/result.json
# combining the host_privesc.sh result + each container result.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

MODE="host"
RUNTIME="auto"
KEEP=0
CONTAINER_NAME=""
CONTAINER_ID=""
while [ $# -gt 0 ]; do
  case "$1" in
    --mode)         MODE="$2"; shift 2;;
    --runtime)      RUNTIME="$2"; shift 2;;
    --container)    CONTAINER_NAME="$2"; shift 2;;
    --container-id) CONTAINER_ID="$2"; shift 2;;
    --keep)         KEEP=1; shift;;
    -h|--help)      sed -n '1,35p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

OUT="$(ensure_run_dir privesc-escape-check)"
mkdir -p "$OUT/containers"
LOG="$OUT/enter.log"
: > "$LOG"

# Pick runtime
pick_runtime() {
  if [ "$RUNTIME" != "auto" ]; then
    command -v "$RUNTIME" >/dev/null 2>&1 || die "runtime $RUNTIME not on PATH"
    echo "$RUNTIME"; return
  fi
  for r in docker nerdctl crictl podman; do
    if command -v "$r" >/dev/null 2>&1; then echo "$r"; return; fi
  done
  return 1
}

list_containers() {
  local rt="$1"
  case "$rt" in
    docker|nerdctl|podman) "$rt" ps -q 2>/dev/null;;
    crictl)                "$rt" ps -q 2>/dev/null;;
  esac
}

inspect_container() {
  local rt="$1" id="$2"
  case "$rt" in
    docker|nerdctl|podman) "$rt" inspect "$id" 2>/dev/null;;
    crictl)                "$rt" inspect "$id" 2>/dev/null;;
  esac
}

container_pid() {
  local rt="$1" id="$2"
  case "$rt" in
    docker|nerdctl|podman) "$rt" inspect -f '{{.State.Pid}}' "$id" 2>/dev/null;;
    crictl)                "$rt" inspect "$id" 2>/dev/null \
                              | python3 -c 'import json,sys;d=json.load(sys.stdin); print(d.get("info",{}).get("pid") or d.get("status",{}).get("pid",""))';;
  esac
}

# Pick a shell available inside container (cp+exec mode)
pick_shell() {
  local rt="$1" id="$2"
  for sh in /bin/bash /bin/sh /usr/bin/sh /bin/dash /bin/ash; do
    case "$rt" in
      docker|nerdctl|podman) "$rt" exec "$id" "$sh" -c 'echo ok' >/dev/null 2>&1 && { echo "$sh"; return; };;
      crictl) "$rt" exec "$id" "$sh" -c 'echo ok' >/dev/null 2>&1 && { echo "$sh"; return; };;
    esac
  done
  return 1
}

cp_to() {
  local rt="$1" id="$2" src="$3" dst="$4"
  case "$rt" in
    docker|nerdctl|podman) "$rt" cp "$src" "$id:$dst";;
    crictl)
      # crictl < 1.30 has no cp; try nerdctl as backup, else fail
      if command -v nerdctl >/dev/null 2>&1; then
        nerdctl --namespace=k8s.io cp "$src" "$id:$dst"
      else
        return 1
      fi
      ;;
  esac
}

cp_from() {
  local rt="$1" id="$2" src="$3" dst="$4"
  case "$rt" in
    docker|nerdctl|podman) "$rt" cp "$id:$src" "$dst";;
    crictl)
      if command -v nerdctl >/dev/null 2>&1; then
        nerdctl --namespace=k8s.io cp "$id:$src" "$dst"
      else return 1; fi ;;
  esac
}

cp_exec_one() {
  local rt="$1" id="$2" out_json="$3" out_log="$4"
  local sh
  if ! sh="$(pick_shell "$rt" "$id")"; then
    echo "no usable shell in $id (likely distroless)" | tee -a "$out_log"
    return 2
  fi
  cp_to "$rt" "$id" "$HERE/container_escape.sh" /tmp/.lsa-esc.sh >>"$out_log" 2>&1 || return 3
  case "$rt" in
    docker|nerdctl|podman|crictl) "$rt" exec "$id" "$sh" /tmp/.lsa-esc.sh /tmp/.lsa-esc.json >>"$out_log" 2>&1 || true;;
  esac
  cp_from "$rt" "$id" /tmp/.lsa-esc.json "$out_json" >>"$out_log" 2>&1 || return 4
  if [ "$KEEP" = "0" ]; then
    "$rt" exec "$id" "$sh" -c 'rm -f /tmp/.lsa-esc.sh /tmp/.lsa-esc.json' >/dev/null 2>&1 || true
  fi
}

nsenter_one() {
  local id="$1" out_json="$2" out_log="$3" rt="$4"
  command -v nsenter >/dev/null 2>&1 || { echo "nsenter missing" | tee -a "$out_log"; return 2; }
  local pid
  pid="$(container_pid "$rt" "$id")"
  if [ -z "${pid:-}" ] || [ "$pid" = "0" ]; then
    echo "no pid for $id" | tee -a "$out_log"; return 3
  fi
  # Run our script in the container's mnt+pid+net namespaces.
  nsenter -t "$pid" -m -p -u -i -n bash "$HERE/container_escape.sh" "$out_json" >>"$out_log" 2>&1 \
    || nsenter -t "$pid" -m -p -u -i -n sh "$HERE/container_escape.sh" "$out_json" >>"$out_log" 2>&1 \
    || return 4
}

# --- resolve container ID if name specified ---
resolve_container_id() {
  local rt="$1" name="$2"
  case "$rt" in
    docker|nerdctl|podman) "$rt" inspect "$name" -f '{{.Id}}' 2>/dev/null || echo "";;
    crictl)                "$rt" inspect "$name" 2>/dev/null | grep -oP '"id":\s*"\K[^"]+' | head -1 || echo "";;
  esac
}

# --- run host privesc ---
log_info "running host privesc"
HOST_JSON="$OUT/host.json"
"$HERE/host_privesc.sh" "$OUT" >>"$LOG" 2>&1 || log_warn "host_privesc.sh non-zero"

# --- enumerate containers ---
RUNTIME_BIN="$(pick_runtime || true)"
if [ -z "$RUNTIME_BIN" ]; then
  log_warn "no container runtime found; producing host-only result"
else
  log_info "runtime: $RUNTIME_BIN  mode: $MODE"

  # If specific container is requested, scan only that one
  if [ -n "$CONTAINER_ID" ]; then
    IDS="$CONTAINER_ID"
  elif [ -n "$CONTAINER_NAME" ]; then
    log_info "resolving container: $CONTAINER_NAME"
    RESOLVED_ID="$(resolve_container_id "$RUNTIME_BIN" "$CONTAINER_NAME")"
    if [ -z "$RESOLVED_ID" ]; then
      die "container not found: $CONTAINER_NAME"
    fi
    IDS="$RESOLVED_ID"
    log_info "resolved to ID: $RESOLVED_ID"
  else
    # List all running containers
    IDS="$(list_containers "$RUNTIME_BIN")"
  fi

  while IFS= read -r id; do
    [ -z "$id" ] && continue
    name=""
    if info="$(inspect_container "$RUNTIME_BIN" "$id" 2>/dev/null)"; then
      name="$(echo "$info" | python3 -c 'import sys,json
try:
  d=json.load(sys.stdin)
  if isinstance(d,list): d=d[0]
  print(d.get("Name") or d.get("name") or (d.get("status",{}) or {}).get("metadata",{}).get("name",""))
except Exception: pass' 2>/dev/null || true)"
    fi
    label="${name:-$id}"
    log_info "  container: $label ($id)"
    out_json="$OUT/containers/$id.json"
    out_log="$OUT/containers/$id.log"
    : > "$out_log"

    # --- host-side privileged container checks ---
    python3 "$HERE/check_privileged.py" \
      --runtime "$RUNTIME_BIN" --container-id "$id" \
      --out "$OUT/containers/$id.hostcheck.json" >>"$out_log" 2>&1 || true

    case "$MODE" in
      host)
        # Host-side checks already done above, no need to enter container
        ;;
      cp-exec)
        cp_exec_one "$RUNTIME_BIN" "$id" "$out_json" "$out_log" || log_warn "  cp-exec failed for $id";;
      nsenter)
        nsenter_one "$id" "$out_json" "$out_log" "$RUNTIME_BIN" || log_warn "  nsenter failed for $id";;
      both)
        if ! cp_exec_one "$RUNTIME_BIN" "$id" "$out_json" "$out_log"; then
          log_warn "  cp-exec failed, trying nsenter"
          nsenter_one "$id" "$out_json" "$out_log" "$RUNTIME_BIN" || log_warn "  nsenter also failed for $id"
        fi
        ;;
      *) die "unknown mode: $MODE";;
    esac
    # Annotate result with the runtime + label, merge host-side checks
    if [ -s "$out_json" ]; then
      python3 - "$out_json" "$RUNTIME_BIN" "$id" "$label" <<'PY'
import json,sys,os
p,rt,cid,name = sys.argv[1:5]
d = json.load(open(p))
d["container_id"] = cid
d["container_name"] = name
d["runtime"] = rt
for f in d.get("findings",[]):
    f["where"] = f.get("where","")
    if not f["where"].startswith("container:"):
        f["where"] = f"{name or cid}:" + f["where"].split(":",1)[-1]
# Merge host-side privileged checks
hc_path = p.replace(".json", ".hostcheck.json")
if os.path.exists(hc_path):
    try:
        hc_data = json.loads(open(hc_path).read())
        hc_findings = hc_data.get("findings", hc_data) if isinstance(hc_data, dict) else hc_data
        if isinstance(hc_findings, list):
            d["findings"].extend(hc_findings)
        os.remove(hc_path)
    except Exception:
        pass
open(p,"w").write(json.dumps(d,indent=2,ensure_ascii=False))
PY
    elif [ -s "$OUT/containers/$id.hostcheck.json" ]; then
      # No in-container result but host-side checks found issues
      python3 - "$OUT/containers/$id.hostcheck.json" "$out_json" "$RUNTIME_BIN" "$id" "$label" <<'PY'
import json,sys,os
hc_path, out_path, rt, cid, name = sys.argv[1:6]
hc_data = json.loads(open(hc_path).read())
findings = hc_data.get("findings", hc_data) if isinstance(hc_data, dict) else hc_data
if not isinstance(findings, list):
    findings = []
d = {
    "module": "privesc-escape-check.container",
    "status": "warn" if any(f["severity"] in ("critical","high") for f in findings) else "ok",
    "summary": "host-side checks only",
    "counts": {},
    "findings": findings,
    "container_id": cid,
    "container_name": name,
    "runtime": rt,
}
for f in findings:
    d["counts"][f["severity"]] = d["counts"].get(f["severity"],0)+1
open(out_path,"w").write(json.dumps(d,indent=2,ensure_ascii=False))
os.remove(hc_path)
PY
    fi
  done <<< "$IDS"
fi

# --- aggregate ---
python3 - "$OUT" <<'PY'
import json, sys, glob, os, pathlib
out = pathlib.Path(sys.argv[1])
modules = []
host = out/"host.json"
if host.exists():
    try: modules.append(json.loads(host.read_text()))
    except Exception: pass
for f in sorted((out/"containers").glob("*.json")):
    try: modules.append(json.loads(f.read_text()))
    except Exception: pass

all_findings = []
counts = {}
for m in modules:
    for f in m.get("findings",[]):
        all_findings.append(f)
        counts[f["severity"]] = counts.get(f["severity"],0)+1

sev_rank = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
all_findings.sort(key=lambda f: sev_rank.get(f.get("severity","info"),0), reverse=True)
status = "warn" if counts.get("critical",0)+counts.get("high",0)>0 else "ok"
summary = f"{len(modules)} scope(s); " + ", ".join(f"{k}:{v}" for k,v in counts.items())
agg = {
  "module": "privesc-escape-check",
  "status": status,
  "summary": summary,
  "counts": counts,
  "findings": all_findings[:200],
  "scopes": [{"name": m.get("module","?"),
              "container_id": m.get("container_id"),
              "container_name": m.get("container_name"),
              "counts": m.get("counts",{})} for m in modules],
}
(out/"result.json").write_text(json.dumps(agg,indent=2,ensure_ascii=False))
print(out/"result.json", summary)
PY

log_ok "privesc & escape audit done -> $OUT/result.json"
echo "$OUT/result.json"
