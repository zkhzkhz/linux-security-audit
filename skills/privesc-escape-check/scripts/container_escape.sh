#!/usr/bin/env bash
# Container escape audit. Run this INSIDE the container.
# Output written to ./esc.json (or $1 if a path is given) — must be portable
# enough to run with /bin/sh inside minimal images.
#
# Strategy: collect facts to stdout/log, emit a single JSON via a tiny here-doc
# python OR a manual JSON builder if python is missing.

set -u
TARGET="${1:-./esc.json}"
TMP_LOG="${TARGET%.json}.log"
: > "$TMP_LOG"

# --- helpers ---------------------------------------------------------------
findings=""
add() {
  # add severity title where note
  local s="$1" t="$2" w="${3:-container}" n="${4:-}"
  # JSON-escape via python or sed fallback
  if command -v python3 >/dev/null 2>&1 || command -v python >/dev/null 2>&1; then
    py=python3; command -v python3 >/dev/null 2>&1 || py=python
    line=$($py -c 'import json,sys
print(json.dumps({"severity":sys.argv[1],"title":sys.argv[2],"where":sys.argv[3],"note":sys.argv[4]}))' "$s" "$t" "$w" "$n")
  else
    n_esc=$(printf '%s' "$n" | sed 's/\\/\\\\/g; s/"/\\"/g')
    w_esc=$(printf '%s' "$w" | sed 's/\\/\\\\/g; s/"/\\"/g')
    line=$(printf '{"severity":"%s","title":"%s","where":"%s","note":"%s"}' "$s" "$t" "$w_esc" "$n_esc")
  fi
  if [ -z "$findings" ]; then findings="$line"; else findings="$findings,$line"; fi
}

log() { echo "[*] $*" >> "$TMP_LOG"; }
section() { echo "==== $1 ====" >> "$TMP_LOG"; }

# --- environment hint ------------------------------------------------------
section "environment"
{
  echo "uname: $(uname -a 2>/dev/null)"
  echo "id:    $(id 2>/dev/null)"
  echo "host:  $(hostname 2>/dev/null)"
  [ -r /.dockerenv ] && echo "found /.dockerenv"
  [ -r /run/.containerenv ] && echo "found /run/.containerenv"
  [ -r /proc/1/cgroup ] && head -20 /proc/1/cgroup
} >> "$TMP_LOG" 2>&1

# --- capabilities ----------------------------------------------------------
section "capabilities"
CAP_EFF=""
CAP_PERM=""
if [ -r /proc/self/status ]; then
  CAP_EFF=$(awk '/^CapEff:/ {print $2}' /proc/self/status)
  CAP_PERM=$(awk '/^CapPrm:/ {print $2}' /proc/self/status)
  echo "CapEff: $CAP_EFF" >> "$TMP_LOG"
  echo "CapPrm: $CAP_PERM" >> "$TMP_LOG"
fi
case "$CAP_EFF" in
  0000003fffffffff|000001ffffffffff|0000003fffffeeff|0000003fffffffff)
    add "critical" "privileged-container" "container" "CapEff=$CAP_EFF (full caps)" ;;
esac
# Decode some single-cap bits
hex2dec() { printf '%d' "$((16#$1))" 2>/dev/null || echo 0; }
if [ -n "$CAP_EFF" ]; then
  caps_dec=$(hex2dec "$CAP_EFF")
  # CAP_SYS_ADMIN = bit 21
  [ $((caps_dec & (1<<21))) -ne 0 ] && add "critical" "cap-sys-admin" "container" "CAP_SYS_ADMIN allows many escape paths"
  # CAP_SYS_PTRACE = 19
  [ $((caps_dec & (1<<19))) -ne 0 ] && add "high" "cap-sys-ptrace" "container" "CAP_SYS_PTRACE -> attach to host pid"
  # CAP_SYS_MODULE = 16
  [ $((caps_dec & (1<<16))) -ne 0 ] && add "critical" "cap-sys-module" "container" "CAP_SYS_MODULE -> load kernel modules"
  # CAP_DAC_READ_SEARCH = 2
  [ $((caps_dec & (1<<2))) -ne 0 ] && add "high" "cap-dac-read-search" "container" "CAP_DAC_READ_SEARCH -> open_by_handle_at"
  # CAP_DAC_OVERRIDE = 1
  [ $((caps_dec & (1<<1))) -ne 0 ] && add "medium" "cap-dac-override" "container" "CAP_DAC_OVERRIDE"
  # CAP_NET_ADMIN = 12
  [ $((caps_dec & (1<<12))) -ne 0 ] && add "medium" "cap-net-admin" "container" "CAP_NET_ADMIN"
  # CAP_NET_RAW = 13
  [ $((caps_dec & (1<<13))) -ne 0 ] && add "low" "cap-net-raw" "container" "CAP_NET_RAW"
fi

# --- seccomp / AppArmor / SELinux -----------------------------------------
section "lsm"
if [ -r /proc/1/status ]; then
  SECCOMP=$(awk '/^Seccomp:/ {print $2}' /proc/1/status)
  echo "Seccomp: $SECCOMP" >> "$TMP_LOG"
  case "$SECCOMP" in
    0) add "high" "seccomp-disabled" "container" "Seccomp=0 (disabled)";;
    1) add "medium" "seccomp-strict-only" "container" "Seccomp=1 (strict)";;
  esac
fi
if [ -r /proc/self/attr/current ]; then
  AA=$(cat /proc/self/attr/current 2>/dev/null)
  echo "AppArmor: $AA" >> "$TMP_LOG"
  case "$AA" in
    *unconfined*|"") add "high" "apparmor-unconfined" "container" "$AA";;
  esac
fi

# --- mounts ----------------------------------------------------------------
section "mounts"
if [ -r /proc/mounts ]; then
  cat /proc/mounts >> "$TMP_LOG"
  # Host docker / containerd sockets
  if grep -E 'docker.sock' /proc/mounts >/dev/null 2>&1; then
    add "critical" "docker-sock-mounted" "container:/var/run/docker.sock" "host docker socket mounted in container"
  fi
  if grep -E 'containerd\.sock|/run/containerd' /proc/mounts >/dev/null 2>&1; then
    add "critical" "containerd-sock-mounted" "container" "containerd socket / state mounted"
  fi
  if grep -E '^[^ ]+ /host[ /]' /proc/mounts >/dev/null 2>&1; then
    add "high" "host-bind-mount" "container:/host" "/host appears to be a bind from outside"
  fi
  if grep -E ' /etc[ /].* (rw,|.*,rw)' /proc/mounts | grep -vE 'overlay|tmpfs' >/dev/null 2>&1; then
    add "high" "host-etc-bound" "container" "host /etc bound rw"
  fi
  if grep -E ' /proc /proc proc ' /proc/mounts | grep -v 'ro,' >/dev/null 2>&1; then
    : # default; not necessarily insecure
  fi
  if grep -E ' /sys/fs/cgroup .*rw' /proc/mounts >/dev/null 2>&1; then
    if [ -w /sys/fs/cgroup/release_agent ] 2>/dev/null \
       || [ -w /sys/fs/cgroup/devices/release_agent ] 2>/dev/null; then
      add "critical" "cgroup-release-agent" "container:/sys/fs/cgroup/release_agent" "writable release_agent (notify-on-release escape)"
    fi
  fi
fi

# --- devices ---------------------------------------------------------------
section "devices"
for d in /dev/mem /dev/kmem /dev/kmsg /dev/disk /dev/sda /dev/vda /dev/nvme0n1; do
  [ -e "$d" ] && {
    echo "exposed: $d" >> "$TMP_LOG"
    add "high" "raw-device" "container:$d" "raw device exposed"
  }
done

# --- network mode = host ---------------------------------------------------
section "network"
if [ -r /proc/1/net/tcp ]; then
  count=$(wc -l < /proc/1/net/tcp 2>/dev/null)
  echo "/proc/1/net/tcp lines: $count" >> "$TMP_LOG"
  if [ "${count:-0}" -gt 50 ]; then
    add "medium" "many-listeners-suggests-host-net" "container" "/proc/1/net/tcp has $count entries; possibly --net=host"
  fi
fi
if [ -r /proc/self/ns/net ] && [ -r /proc/1/ns/net ]; then
  s=$(readlink /proc/self/ns/net 2>/dev/null)
  i=$(readlink /proc/1/ns/net 2>/dev/null)
  echo "self ns: $s  init ns: $i" >> "$TMP_LOG"
fi

# --- pid namespace = host ---------------------------------------------------
section "pid"
init_cmd=$(tr '\0' ' ' < /proc/1/cmdline 2>/dev/null | head -c 200)
echo "pid1: $init_cmd" >> "$TMP_LOG"
case "$init_cmd" in
  *systemd*|*init*|*launchd*) add "high" "pid-host-namespace" "container" "PID 1 is host init: $init_cmd";;
esac

# --- writable sensitive files in container --------------------------------
section "sensitive-writes"
for f in /etc/passwd /etc/shadow /etc/ld.so.preload /etc/sudoers \
         /etc/cron.d /etc/crontab; do
  [ -e "$f" ] || continue
  if [ -w "$f" ] && [ "$(id -u)" != "0" ]; then
    add "high" "writable-sensitive" "container:$f" "writable as non-root"
  fi
done

# --- service-account token (kubernetes) -----------------------------------
SA="/var/run/secrets/kubernetes.io/serviceaccount/token"
if [ -r "$SA" ]; then
  add "medium" "kube-service-account-token" "container:$SA" "kube SA token mounted; may permit lateral via API"
fi

# --- emit JSON -------------------------------------------------------------
{
  echo "{"
  echo '  "module": "privesc-escape-check.container",'
  echo '  "status": "warn",'
  echo "  \"summary\": \"container escape audit completed\","
  echo "  \"counts\": {},"
  echo "  \"findings\": [$findings]"
  echo "}"
} > "$TARGET"

# Recompute counts/status with python if available, otherwise leave default.
if command -v python3 >/dev/null 2>&1; then
  python3 - "$TARGET" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
counts = {}
for f in d.get("findings", []):
    counts[f["severity"]] = counts.get(f["severity"],0)+1
d["counts"] = counts
status = "ok"
if counts.get("critical",0)+counts.get("high",0)>0: status = "warn"
d["status"] = status
d["summary"] = ", ".join(f"{k}:{v}" for k,v in counts.items()) or "no findings"
open(p,"w").write(json.dumps(d,indent=2,ensure_ascii=False))
PY
fi

echo "$TARGET"
