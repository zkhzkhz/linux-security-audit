#!/usr/bin/env bash
# Enumerate credentials on this host that could enable lateral movement.
# Read-only. Output: $OUT/creds.json
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

OUT="${1:-$(ensure_run_dir lateral-movement-scan)}"
mkdir -p "$OUT"
LOG="$OUT/creds.log"; : > "$LOG"

py_findings='[]'
declare -a F=()
add() {
  F+=("$(python3 -c '
import json,sys
print(json.dumps({"severity":sys.argv[1],"title":sys.argv[2],"where":sys.argv[3],"note":sys.argv[4]}))' "$1" "$2" "$3" "$4")")
}

scan_user_home() {
  local home="$1" user="$2"
  echo "==== $user ($home) ====" >>"$LOG"
  [ -d "$home" ] || return 0

  # SSH keys
  for kf in "$home"/.ssh/id_* "$home"/.ssh/*.pem; do
    [ -f "$kf" ] || continue
    [[ "$kf" == *.pub ]] && continue
    local enc=""
    if head -1 "$kf" 2>/dev/null | grep -q 'ENCRYPTED'; then
      enc="encrypted"
    else
      enc="UNENCRYPTED"
    fi
    local kt; kt="$(head -1 "$kf" 2>/dev/null | tr -d '\n' | head -c 80)"
    echo "key $kf [$enc] $kt" >>"$LOG"
    if [ "$enc" = "UNENCRYPTED" ]; then
      add "high" "ssh-key-unencrypted" "host:$kf" "$kt"
    else
      add "low" "ssh-key-encrypted" "host:$kf" "$kt"
    fi
  done

  # known_hosts -> potential targets
  local kh="$home/.ssh/known_hosts"
  if [ -r "$kh" ]; then
    local n; n="$(awk '{print $1}' "$kh" | tr ',' '\n' | sed 's/\[//;s/\]:.*$//' | sort -u | wc -l)"
    add "info" "ssh-known-hosts" "host:$kh" "$n unique entries"
  fi

  # AWS
  if [ -r "$home/.aws/credentials" ]; then
    local profiles; profiles="$(grep -E '^\[' "$home/.aws/credentials" 2>/dev/null | tr -d '[]' | xargs)"
    add "high" "aws-credentials" "host:$home/.aws/credentials" "profiles: $profiles"
  fi
  [ -r "$home/.aws/config" ] && add "low" "aws-config" "host:$home/.aws/config" "(role/region info)"

  # Kube
  if [ -r "$home/.kube/config" ]; then
    local servers; servers="$(awk '/server: /{print $2}' "$home/.kube/config" | tr '\n' ' ')"
    add "high" "kube-config" "host:$home/.kube/config" "servers: $servers"
  fi

  # Docker / podman registry
  [ -r "$home/.docker/config.json" ] && add "medium" "docker-registry-creds" "host:$home/.docker/config.json" "registry auth"
  [ -r "$home/.config/containers/auth.json" ] && add "medium" "podman-registry-creds" "host:$home/.config/containers/auth.json" ""

  # netrc / git
  [ -r "$home/.netrc" ] && add "high" "netrc-creds" "host:$home/.netrc" "plaintext credentials"
  [ -r "$home/.git-credentials" ] && add "high" "git-credentials-store" "host:$home/.git-credentials" "plaintext git creds"

  # gcloud
  [ -d "$home/.config/gcloud" ] && add "medium" "gcloud-config-dir" "host:$home/.config/gcloud" "gcloud creds present"

  # Azure
  [ -d "$home/.azure" ] && add "medium" "azure-config-dir" "host:$home/.azure" "azure creds present"
}

# scan all real users with shell + home + uid >= 0
while IFS=: read -r u _ uid _ _ home shell; do
  case "$home" in
    /root|/home/*|/var/lib/*) ;;
    *) continue ;;
  esac
  [ -d "$home" ] || continue
  scan_user_home "$home" "$u"
done < /etc/passwd

# Aggregate
python3 - "$OUT/creds.json" "${F[@]}" <<'PY'
import json, sys
p = sys.argv[1]
findings = [json.loads(x) for x in sys.argv[2:]]
sev_rank = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
findings.sort(key=lambda f: sev_rank.get(f.get("severity","info"),0), reverse=True)
counts = {}
for f in findings:
    counts[f["severity"]] = counts.get(f["severity"],0)+1
status = "warn" if counts.get("critical",0)+counts.get("high",0)>0 else "ok"
summary = ", ".join(f"{k}:{v}" for k,v in counts.items()) or "no findings"
data = {
  "module": "lateral-movement-scan.creds",
  "status": status,
  "summary": summary,
  "counts": counts,
  "findings": findings,
}
open(p,"w").write(json.dumps(data,indent=2,ensure_ascii=False))
print(p, summary)
PY

log_ok "creds enumeration done -> $OUT/creds.json"
echo "$OUT/creds.json"
