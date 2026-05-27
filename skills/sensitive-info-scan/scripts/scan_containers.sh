#!/usr/bin/env bash
# Scan each running container for sensitive info using gitleaks.
# Pattern: cp gitleaks binary + config into container, exec scan, cp results out.
#
# Usage:
#   scan_containers.sh [--runtime auto|docker|nerdctl|crictl|podman]
#                      [--out DIR] [--keep]
#
# Outputs: $OUT/containers/<id>/result.json per container + aggregate

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"
. "$LSA_ROOT/lib/arch_detect.sh"

RUNTIME="auto"
OUT_OVERRIDE=""
KEEP=0
while [ $# -gt 0 ]; do
  case "$1" in
    --runtime) RUNTIME="$2"; shift 2;;
    --out)     OUT_OVERRIDE="$2"; shift 2;;
    --keep)    KEEP=1; shift;;
    -h|--help) sed -n '1,10p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

# --- output dir ---
if [ -n "$OUT_OVERRIDE" ]; then
  OUT="$OUT_OVERRIDE"
else
  OUT="$(ensure_run_dir sensitive-info-scan)"
fi
mkdir -p "$OUT/containers"
LOG="$OUT/container-scan.log"
: > "$LOG"

# --- pick gitleaks binary for container arch ---
pick_container_gitleaks() {
  local rt="$1" id="$2"
  local arch
  arch=$("$rt" exec "$id" uname -m 2>/dev/null || echo "x86_64")
  case "$arch" in
    x86_64|amd64)  arch="amd64";;
    aarch64|arm64) arch="arm64";;
    armv7l|armv6l) arch="arm";;
  esac
  local bin="$LSA_ROOT/bin/gitleaks-linux-${arch}"
  [ -f "$bin" ] && echo "$bin" || return 1
}

# --- pick runtime ---
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

container_name() {
  local rt="$1" id="$2"
  case "$rt" in
    docker|nerdctl|podman)
      "$rt" inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's|^/||';;
    crictl)
      "$rt" inspect "$id" 2>/dev/null \
        | python3 -c 'import json,sys
try:
  d=json.load(sys.stdin)
  print(d.get("status",{}).get("metadata",{}).get("name",""))
except: pass' 2>/dev/null;;
  esac
}

pick_shell() {
  local rt="$1" id="$2"
  for sh in /bin/sh /bin/bash /bin/dash /bin/ash; do
    "$rt" exec "$id" "$sh" -c 'echo ok' >/dev/null 2>&1 && { echo "$sh"; return; }
  done
  return 1
}

# --- scan one container ---
scan_container() {
  local rt="$1" id="$2" label="$3" out_dir="$4"
  local gl_bin sh clog

  mkdir -p "$out_dir"
  clog="$out_dir/scan.log"
  : > "$clog"

  # Pick shell
  if ! sh="$(pick_shell "$rt" "$id")"; then
    echo "no usable shell in $id (distroless)" | tee -a "$clog"
    return 2
  fi

  # Pick gitleaks binary matching container arch
  if ! gl_bin="$(pick_container_gitleaks "$rt" "$id")"; then
    echo "no gitleaks binary for container arch" | tee -a "$clog"
    return 3
  fi

  log_info "  [$label] copying gitleaks + config..."

  # Copy gitleaks binary into container
  "$rt" cp "$gl_bin" "$id:/tmp/.lsa-gitleaks" >>"$clog" 2>&1 || return 4
  "$rt" exec "$id" chmod +x /tmp/.lsa-gitleaks >>"$clog" 2>&1 || true

  # Build merged runtime config (same as host scan.sh)
  local rt_cfg="$out_dir/gitleaks-runtime.toml"
  {
    cat "$SKILL_DIR/config/gitleaks-custom.toml"
    echo
    echo "# --- merged allowlist.toml ---"
    sed -n '/^\[allowlist\]/,$p' "$SKILL_DIR/config/allowlist.toml" \
      | sed 's/^\[allowlist\]/[[allowlists]]/'
    echo
    echo "# --- path exclusions ---"
    echo "[[allowlists]]"
    echo 'description = "path exclusions (config/exclude-paths.txt)"'
    echo "paths = ["
    grep -v -E '^\s*#|^\s*$' "$SKILL_DIR/config/exclude-paths.txt" \
      | sed "s/'''/\\\\'\\\\'\\\\'/g; s|.*|'''&'''|; s/$/,/"
    echo "]"
  } > "$rt_cfg"

  # Copy merged config into container
  "$rt" cp "$rt_cfg" "$id:/tmp/.lsa-gl.toml" >>"$clog" 2>&1 || true

  # Detect gitleaks capabilities (archive, max-file-size)
  local gl_flags=""
  local gl_help
  gl_help=$("$rt" exec "$id" /tmp/.lsa-gitleaks detect --help 2>&1 || true)
  echo "$gl_help" | grep -q -- '--scan-archives'       && gl_flags="$gl_flags --scan-archives"
  echo "$gl_help" | grep -q -- '--max-target-megabytes' && gl_flags="$gl_flags --max-target-megabytes 10"
  echo "$gl_help" | grep -q -- '--max-file-size'       && gl_flags="$gl_flags --max-file-size 10M"

  # Target list — same as host targets.sh
  local targets="/etc /root /home /opt /srv /app /usr/local /var/log /var/spool /var/www /tmp"

  log_info "  [$label] scanning: $targets + env + history"

  # Run gitleaks inside container (filesystem + env vars + history)
  "$rt" exec "$id" "$sh" -c "
    cd /tmp
    # --- dump env vars and process environ ---
    mkdir -p /tmp/.lsa-env
    env > /tmp/.lsa-env/shell-env.txt 2>/dev/null || true
    for pid in \$(ls /proc/ 2>/dev/null | grep -E '^[0-9]+\$'); do
      if [ -r \"/proc/\$pid/environ\" ]; then
        comm=\$(cat /proc/\$pid/comm 2>/dev/null | tr -c '[:alnum:]._-' '_' || echo unknown)
        tr '\0' '\n' < \"/proc/\$pid/environ\" > \"/tmp/.lsa-env/proc-\${pid}-\${comm}.txt\" 2>/dev/null || true
      fi
    done
    # --- collect history files ---
    mkdir -p /tmp/.lsa-hist
    for hf in /root/.bash_history /root/.zsh_history /root/.sh_history \
              /home/*/.bash_history /home/*/.zsh_history; do
      [ -f \"\$hf\" ] && cp \"\$hf\" \"/tmp/.lsa-hist/\$(echo \$hf | tr '/' '_')\" 2>/dev/null || true
    done
    # --- scan filesystem targets ---
    for dir in $targets; do
      [ -d \"\$dir\" ] || continue
      ./.lsa-gitleaks detect --no-git --redact=0 \
        --config /tmp/.lsa-gl.toml \
        --source \"\$dir\" \
        --report-format json \
        --report-path /tmp/.lsa-shard-\$(echo \$dir | tr '/' '_').json \
        --exit-code 0 $gl_flags 2>/dev/null || true
    done
    # --- scan env dump ---
    ./.lsa-gitleaks detect --no-git --redact=0 \
      --config /tmp/.lsa-gl.toml \
      --source /tmp/.lsa-env \
      --report-format json \
      --report-path /tmp/.lsa-shard-env.json \
      --exit-code 0 $gl_flags 2>/dev/null || true
    # --- scan history ---
    if [ -d /tmp/.lsa-hist ] && [ \"\$(ls /tmp/.lsa-hist 2>/dev/null)\" ]; then
      ./.lsa-gitleaks detect --no-git --redact=0 \
        --config /tmp/.lsa-gl.toml \
        --source /tmp/.lsa-hist \
        --report-format json \
        --report-path /tmp/.lsa-shard-hist.json \
        --exit-code 0 $gl_flags 2>/dev/null || true
    fi
    # --- merge shards ---
    if command -v python3 >/dev/null 2>&1; then
      python3 -c '
import json, glob, os
merged = []
for f in glob.glob(\"/tmp/.lsa-shard-*.json\"):
    try:
        data = json.loads(open(f).read() or \"[]\")
        if isinstance(data, list): merged.extend(data)
    except: pass
    os.remove(f)
open(\"/tmp/.lsa-results.json\",\"w\").write(json.dumps(merged))
print(len(merged))
'
    else
      cat /tmp/.lsa-shard-*.json 2>/dev/null > /tmp/.lsa-results.json || true
    fi
    rm -rf /tmp/.lsa-env /tmp/.lsa-hist
  " >>"$clog" 2>&1 || true

  # Copy results out
  "$rt" cp "$id:/tmp/.lsa-results.json" "$out_dir/raw.json" >>"$clog" 2>&1 || {
    echo '[]' > "$out_dir/raw.json"
  }

  # Cleanup inside container
  if [ "$KEEP" = "0" ]; then
    "$rt" exec "$id" "$sh" -c 'rm -f /tmp/.lsa-gitleaks /tmp/.lsa-gl.toml /tmp/.lsa-results.json /tmp/.lsa-shard-*.json' >/dev/null 2>&1 || true
  fi

  # Triage locally
  if [ -s "$out_dir/raw.json" ]; then
    python3 "$HERE/triage.py" "$out_dir/raw.json" --out "$out_dir/result.json" 2>>"$clog" || {
      cp "$out_dir/raw.json" "$out_dir/result.json"
    }
  else
    echo '{"module":"sensitive-info-scan.container","status":"ok","summary":"no findings","counts":{},"findings":[]}' > "$out_dir/result.json"
  fi

  local count
  count=$(python3 -c "import json; d=json.load(open('$out_dir/result.json')); print(d.get('summary',''))" 2>/dev/null || echo "?")
  log_info "  [$label] done: $count"
}

# --- main ---
RUNTIME_BIN="$(pick_runtime || true)"
[ -n "$RUNTIME_BIN" ] || die "no container runtime found"

log_info "sensitive-info-scan containers (runtime: $RUNTIME_BIN)"

while IFS= read -r id; do
  [ -z "$id" ] && continue
  name="$(container_name "$RUNTIME_BIN" "$id" || true)"
  label="${name:-$id}"
  scan_container "$RUNTIME_BIN" "$id" "$label" "$OUT/containers/$id" \
    || log_warn "  scan failed for $label"
done < <(list_containers "$RUNTIME_BIN")

# --- aggregate ---
python3 - "$OUT" <<'PY'
import json, sys, pathlib

out = pathlib.Path(sys.argv[1])
all_findings = []
scopes = []

for d in sorted((out / "containers").iterdir()):
    rj = d / "result.json"
    if not rj.exists():
        continue
    try:
        data = json.loads(rj.read_text())
    except Exception:
        continue
    cid = d.name
    findings = data.get("findings", [])
    for f in findings:
        f["where"] = f.get("where", "")
        if not f["where"].startswith("container:"):
            f["where"] = f"container:{cid[:12]}:{f['where']}"
    all_findings.extend(findings)
    scopes.append({"container_id": cid, "counts": data.get("counts", {})})

counts = {}
for f in all_findings:
    counts[f["severity"]] = counts.get(f["severity"], 0) + 1

sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
all_findings.sort(key=lambda f: sev_rank.get(f.get("severity", "info"), 0), reverse=True)
status = "warn" if counts.get("critical", 0) + counts.get("high", 0) > 0 else "ok"
summary = ", ".join(f"{k}:{v}" for k, v in counts.items()) or "no findings"

result = {
    "module": "sensitive-info-scan.containers",
    "status": status,
    "summary": summary,
    "counts": counts,
    "findings": all_findings[:200],
    "scopes": scopes,
}
(out / "containers-result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False))
print(f"containers: {len(scopes)} scanned, {summary}")
PY

log_ok "container scan done -> $OUT/containers-result.json"
echo "$OUT/containers-result.json"
