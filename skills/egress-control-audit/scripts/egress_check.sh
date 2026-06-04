#!/usr/bin/env bash
# Read-only egress inventory: routes, sockets, DNS, firewall, container peers.
# Usage: egress_check.sh [--duration Ns] [--out DIR]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

DURATION="30s"
OUT_OVERRIDE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --duration) DURATION="$2"; shift 2;;
    --out)      OUT_OVERRIDE="$2"; shift 2;;
    -h|--help)  sed -n '1,3p' "$0"; exit 0;;
    *) die "unknown flag: $1";;
  esac
done

OUT="${OUT_OVERRIDE:-$(ensure_run_dir egress-control-audit)}"
mkdir -p "$OUT"
LOG="$OUT/egress_check.log"; : > "$LOG"

log_info "egress audit -> $OUT (duration=$DURATION)"

# --- routes / addresses ---
log_info "Collecting network routes and addresses..."
ip -4 route > "$OUT/routes.txt" 2>>"$LOG" || true
ip -4 rule >> "$OUT/routes.txt" 2>>"$LOG" || true
ip -6 route >> "$OUT/routes.txt" 2>>"$LOG" || true
ip -4 addr  > "$OUT/addrs.txt" 2>>"$LOG" || true
log_info "Routes and addresses collected."

# --- firewall snapshots ---
log_info "Collecting firewall rules..."
command -v iptables-save >/dev/null 2>&1 && iptables-save > "$OUT/iptables.save" 2>>"$LOG" || true
command -v ip6tables-save >/dev/null 2>&1 && ip6tables-save > "$OUT/ip6tables.save" 2>>"$LOG" || true
command -v nft >/dev/null 2>&1 && nft list ruleset > "$OUT/nftables.save" 2>>"$LOG" || true
log_info "Firewall rules collected."

# --- DNS log scrape (best-effort) ---
log_info "Scraping DNS logs..."
{
  echo "==== systemd-resolved ===="
  command -v journalctl >/dev/null 2>&1 \
    && journalctl --no-pager --since '1 hour ago' -u systemd-resolved 2>/dev/null | grep -E 'DNSSEC|Resolv|=' | tail -200 || true
  echo "==== /var/log/syslog ===="
  grep -E 'dnsmasq|named|unbound|resolved' /var/log/syslog 2>/dev/null | tail -200 || true
  echo "==== /etc/resolv.conf ===="
  cat /etc/resolv.conf 2>/dev/null
} > "$OUT/dns.log" 2>&1
log_info "DNS logs collected."

# --- socket sampling ---
log_info "Sampling established sockets for ${DURATION}..."
sample_sockets() {
  ss -ntpu state established 2>/dev/null \
    | awk 'NR>1 {print $1,$5,$6,$7}' \
    | sort -u
}

ALL_SOCK="$OUT/sockets.txt"; : > "$ALL_SOCK"
end=$(( $(date +%s) + ${DURATION%s} ))
sample_count=0
while [ "$(date +%s)" -lt "$end" ]; do
  sample_count=$((sample_count + 1))
  sample_sockets >> "$ALL_SOCK"
  remaining=$((end - $(date +%s)))
  [ $((sample_count % 5)) -eq 0 ] && log_info "Socket sampling: ${sample_count} samples, ${remaining}s remaining..."
  sleep 2
done
sort -u "$ALL_SOCK" -o "$ALL_SOCK"
log_info "Socket sampling done, $(wc -l < "$ALL_SOCK") unique connections."

# --- conntrack (captures closed connections too) ---
log_info "Collecting conntrack entries..."
if command -v conntrack >/dev/null 2>&1; then
  conntrack -L -o extended 2>/dev/null | grep -E 'tcp|udp' > "$OUT/conntrack.txt" || true
elif [ -r /proc/net/nf_conntrack ]; then
  grep -E 'tcp|udp' /proc/net/nf_conntrack > "$OUT/conntrack.txt" 2>/dev/null || true
fi

# --- /proc/net/tcp + tcp6 (snapshot of kernel connection table) ---
{
  [ -r /proc/net/tcp ] && python3 -c '
import struct, sys
for line in open("/proc/net/tcp").readlines()[1:]:
    parts = line.split()
    if len(parts) < 4: continue
    rem = parts[2]
    state = int(parts[3], 16)
    if state != 1: continue  # ESTABLISHED only
    ip_hex, port_hex = rem.split(":")
    ip = ".".join(str(int(ip_hex[i:i+2],16)) for i in (6,4,2,0))
    port = int(port_hex, 16)
    if ip.startswith("127.") or ip == "0.0.0.0": continue
    print(f"tcp {ip}:{port}")
' 2>/dev/null || true
} >> "$ALL_SOCK"
sort -u "$ALL_SOCK" -o "$ALL_SOCK"

# --- containers ---
log_info "Enumerating containers..."
CONT_TXT="$OUT/containers.txt"; : > "$CONT_TXT"
RT=""
for rt in docker nerdctl crictl podman; do
  command -v "$rt" >/dev/null 2>&1 || continue
  RT="$rt"
  log_info "Found container runtime: $rt"
  echo "==== $rt ====" >> "$CONT_TXT"
  case "$rt" in
    docker|nerdctl|podman)
      "$rt" ps --format '{{.ID}}\t{{.Names}}\t{{.Networks}}\t{{.Ports}}\t{{.Image}}' >> "$CONT_TXT" 2>/dev/null || true
      "$rt" network ls --format '{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}' >> "$CONT_TXT" 2>/dev/null || true
      ;;
    crictl)
      "$rt" ps 2>/dev/null >> "$CONT_TXT" || true
      ;;
  esac
  break
done

# --- container egress: cat /proc/net/tcp inside each container; decode on host ---
log_info "Inspecting container network connections..."
CONT_SOCK="$OUT/container_sockets.txt"; : > "$CONT_SOCK"
CONT_RAW="$OUT/container_proc_tcp.raw"; : > "$CONT_RAW"
if [ -n "$RT" ] && [ "$RT" != "crictl" ]; then
  container_count=$("$RT" ps -q 2>/dev/null | wc -l)
  log_info "Found $container_count running containers to inspect..."
  while IFS= read -r cid; do
    [[ -n "$cid" ]] || continue
    label="$("$RT" inspect "$cid" --format '{{.Name}}' 2>/dev/null | tr -d '/' || echo "$cid")"
    log_info "  Inspecting container: $label"
    {
      echo "==== $label tcp ===="
      "$RT" exec "$cid" cat /proc/net/tcp 2>/dev/null || true
      echo "==== $label tcp6 ===="
      "$RT" exec "$cid" cat /proc/net/tcp6 2>/dev/null || true
    } >> "$CONT_RAW"
  done < <("$RT" ps -q 2>/dev/null)
fi
log_info "Container network inspection done."

# Decode hex /proc/net/tcp on host
python3 - "$CONT_RAW" "$CONT_SOCK" <<'PY'
import sys
raw, out = sys.argv[1], sys.argv[2]
label = ""
lines = []
try:
    data = open(raw, errors="replace").read()
except Exception:
    data = ""
for line in data.splitlines():
    line = line.strip()
    if line.startswith("===="):
        # ==== <label> tcp[6] ====
        parts = line.strip("= ").split()
        if len(parts) >= 2:
            label = parts[0]
        continue
    parts = line.split()
    if len(parts) < 4: continue
    if not parts[0].endswith(":"): continue  # skip header "sl"
    try:
        state = int(parts[3], 16)
    except ValueError:
        continue
    if state != 1:  # ESTABLISHED only
        continue
    rem = parts[2]
    if ":" not in rem: continue
    ip_hex, port_hex = rem.rsplit(":", 1)
    try:
        port = int(port_hex, 16)
    except ValueError:
        continue
    # IPv4 (8 hex chars) vs IPv6 (32)
    if len(ip_hex) == 8:
        ip = ".".join(str(int(ip_hex[i:i+2], 16)) for i in (6, 4, 2, 0))
    elif len(ip_hex) == 32:
        # /proc/net/tcp6 stores 4 little-endian 32-bit words; check IPv4-mapped
        words = [ip_hex[i:i+8] for i in range(0, 32, 8)]
        if words[0] == "00000000" and words[1] == "00000000" and words[2] == "0000FFFF":
            ip = ".".join(str(int(words[3][i:i+2], 16)) for i in (6, 4, 2, 0))
        else:
            # IPv6: reverse byte order within each 32-bit word
            groups = []
            for w in words:
                rev = "".join(w[i:i+2] for i in (6, 4, 2, 0))
                groups.append(rev[:4])
                groups.append(rev[4:])
            ip = ":".join(groups)
    else:
        continue
    if ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("169.254."):
        continue
    if ip == "::1" or ip == "::":
        continue
    lines.append(f"{label} tcp {ip}:{port}")

open(out, "w").write("\n".join(lines) + ("\n" if lines else ""))
PY

# --- build endpoints.json from sockets.txt + conntrack ---
python3 - "$ALL_SOCK" "$OUT/endpoints.json" "$OUT/conntrack.txt" "$CONT_SOCK" <<'PY'
import json, sys, re, os
from collections import Counter
sock_file, out, ct_file, cont_file = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
counts = Counter()
samples = {}
re_addr = re.compile(r'^(?P<a>[\[\]a-fA-F0-9.:]+):(?P<p>\d+)$')

for line in open(sock_file, errors="replace"):
    parts = line.split()
    if len(parts) < 2: continue
    if len(parts) >= 4:
        proto, local, peer, who = parts[0], parts[1], parts[2], parts[3]
    elif len(parts) == 2:
        proto, peer = parts[0], parts[1]
        who = "proc/net/tcp"
    else:
        continue
    m = re_addr.match(peer.strip("[]"))
    if not m: continue
    a, p = m.group("a").strip("[]"), m.group("p")
    if a.startswith("127.") or a.startswith("::1") or a.startswith("169.254."):
        continue
    key = (proto, a, p)
    counts[key] += 1
    samples.setdefault(key, who if len(parts) >= 4 else "kernel")

# Parse conntrack
if os.path.isfile(ct_file):
    for line in open(ct_file, errors="replace"):
        parts = line.split()
        proto = "tcp" if "tcp" in line else "udp"
        dst = ""
        dport = ""
        for p in parts:
            if p.startswith("dst=") and not dst:
                dst = p.split("=",1)[1]
            elif p.startswith("dport=") and not dport:
                dport = p.split("=",1)[1]
        if not dst or not dport: continue
        if dst.startswith("127.") or dst.startswith("169.254."): continue
        key = (proto, dst, dport)
        counts[key] += 1
        samples.setdefault(key, "conntrack")

# Parse container sockets
if os.path.isfile(cont_file):
    for line in open(cont_file, errors="replace"):
        parts = line.split()
        if len(parts) < 3: continue
        label = parts[0]
        for part in parts[1:]:
            m = re_addr.match(part.strip("[]"))
            if m:
                a, p = m.group("a").strip("[]"), m.group("p")
                if a.startswith("127.") or a.startswith("169.254."): continue
                key = ("tcp", a, p)
                counts[key] += 1
                samples.setdefault(key, f"container:{label}")
                break

endpoints = []
for (proto, a, p), n in counts.most_common():
    endpoints.append({
      "proto": proto, "addr": a, "port": int(p),
      "count": n, "process": samples[(proto, a, p)],
    })
open(out,"w").write(json.dumps(endpoints, indent=2))
print(f"endpoints: {len(endpoints)}")
PY

# --- summarise ---
python3 - "$OUT" <<'PY'
import json, os, sys
out = sys.argv[1]
eps = json.load(open(os.path.join(out,"endpoints.json")))
findings = []
external = [e for e in eps if not (e["addr"].startswith("10.") or e["addr"].startswith("192.168.")
                                   or e["addr"].startswith("172.") or e["addr"].startswith("169.254.")
                                   or e["addr"].startswith("fc") or e["addr"].startswith("fd"))]
internal = [e for e in eps if e not in external]
counts = {"external_endpoints": len(external), "internal_endpoints": len(internal)}
for e in external[:50]:
    findings.append({"severity":"info","title":"external-endpoint",
                     "where":f'{e["addr"]}:{e["port"]}/{e["proto"]}',
                     "note":f'count={e["count"]} {e["process"]}'})
status = "ok"
summary = f"endpoints: {len(eps)} ({len(external)} external)"
data = {"module":"egress-control-audit.check","status":status,"summary":summary,
        "counts":counts,"findings":findings}
open(os.path.join(out,"check.json"),"w").write(json.dumps(data,indent=2,ensure_ascii=False))
print(summary)
PY

log_ok "egress inventory done -> $OUT"
echo "$OUT/endpoints.json"
