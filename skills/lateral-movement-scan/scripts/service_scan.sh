#!/usr/bin/env bash
# Service scan with nmap: top-300 + curated high-port set.
# Usage: service_scan.sh [--full] [--rate N] [--out DIR] [hosts-file]
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

FULL=0
RATE=300
OUT_OVERRIDE=""
HOSTS_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --full) FULL=1; shift;;
    --rate) RATE="$2"; shift 2;;
    --out)  OUT_OVERRIDE="$2"; shift 2;;
    -h|--help) sed -n '1,5p' "$0"; exit 0;;
    *) HOSTS_FILE="$1"; shift;;
  esac
done

OUT="${OUT_OVERRIDE:-$(ensure_run_dir lateral-movement-scan)}"
mkdir -p "$OUT"
LOG="$OUT/service.log"; : > "$LOG"
HOSTS_FILE="${HOSTS_FILE:-$OUT/live.txt}"
[ -s "$HOSTS_FILE" ] || die "hosts file empty: $HOSTS_FILE (run discover.sh first)"

NMAP="$(command -v nmap || true)"
[ -n "$NMAP" ] || die "nmap not found"

EXTRA_PORTS="2049,2375,2376,2379,2380,2381,4243,4244,4789,5000,5044,5601,6443,6379,7001,7077,8001,8009,8086,8088,8089,8161,8200,8500,8761,8888,9000,9001,9042,9090,9091,9092,9100,9200,9300,9418,9999,10250,10255,10256,11211,15672,16379,27017,27018,27019,50070,61613,61616,61617"

ARGS=(-iL "$HOSTS_FILE" -Pn -n --top-ports 300 -p "T:$EXTRA_PORTS" --open
      --max-rate "$RATE"
      -oA "$OUT/nmap")
if [ "$FULL" = "1" ]; then
  ARGS+=( -sV -sC --version-intensity 5 )
else
  ARGS+=( -sV --version-light )
fi

log_info "nmap ${ARGS[*]}"
"$NMAP" "${ARGS[@]}" >>"$LOG" 2>&1 || log_warn "nmap returned non-zero"

# --- parse XML to JSON ---
python3 - "$OUT/nmap.xml" "$OUT/services.json" "$OUT/service-result.json" <<'PY'
import json, sys, xml.etree.ElementTree as ET
xml_in, services_out, result_out = sys.argv[1:4]
try:
    root = ET.parse(xml_in).getroot()
except Exception as e:
    open(services_out,"w").write("[]")
    open(result_out,"w").write(json.dumps({"module":"lateral-movement-scan","status":"error","summary":f"parse: {e}","counts":{},"findings":[]}, indent=2))
    sys.exit(0)

hosts = []
findings = []
sev_for = {
    # severity ranking for risky exposed services
    "docker":"high", "kubelet":"high", "etcd":"high", "redis":"medium",
    "memcached":"medium", "elasticsearch":"medium", "mongodb":"medium",
    "rabbitmq":"medium", "activemq":"medium", "vnc":"high", "rdp":"medium",
    "smb":"medium", "telnet":"high", "ftp":"medium", "rsync":"medium",
    "rpcbind":"medium", "ldap":"low", "snmp":"medium",
}

for h in root.findall("host"):
    addr = h.find("address").get("addr") if h.find("address") is not None else "?"
    state = h.find("status").get("state") if h.find("status") is not None else ""
    if state != "up": continue
    ports = []
    ports_el = h.find("ports")
    if ports_el is None: continue
    for p in ports_el.findall("port"):
        ps = p.find("state")
        if ps is None or ps.get("state") != "open": continue
        portid = p.get("portid"); proto = p.get("protocol")
        svc = p.find("service")
        name = svc.get("name") if svc is not None else ""
        product = svc.get("product","") if svc is not None else ""
        version = svc.get("version","") if svc is not None else ""
        ports.append({"port": portid, "proto": proto, "service": name, "product": product, "version": version})
        sev = sev_for.get(name, "info")
        # Boost specific risky ports
        if portid in ("2375","2376"): sev = "high"
        if portid in ("6443","10250","2379","2380"): sev = "high"
        findings.append({
            "severity": sev,
            "title": f"open-{name or portid}",
            "where": f"{addr}:{portid}/{proto}",
            "note": (product + " " + version).strip(),
        })
    hosts.append({"addr": addr, "ports": ports})

open(services_out,"w").write(json.dumps(hosts, indent=2, ensure_ascii=False))

counts = {}
for f in findings:
    counts[f["severity"]] = counts.get(f["severity"],0)+1
sev_rank = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
findings.sort(key=lambda f: sev_rank.get(f.get("severity","info"),0), reverse=True)
status = "warn" if counts.get("critical",0)+counts.get("high",0)>0 else "ok"
summary = f"{len(hosts)} host(s); " + ", ".join(f"{k}:{v}" for k,v in counts.items())
out = {
  "module": "lateral-movement-scan",
  "status": status,
  "summary": summary,
  "counts": counts,
  "findings": findings[:200],
}
open(result_out,"w").write(json.dumps(out, indent=2, ensure_ascii=False))
print(result_out, summary)
PY

log_ok "service scan done -> $OUT/service-result.json"
echo "$OUT/service-result.json"
