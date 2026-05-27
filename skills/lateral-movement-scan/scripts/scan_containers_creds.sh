#!/usr/bin/env bash
# Scan credentials inside each running container for lateral movement risk.
# Pure shell collection inside container (no python3 needed); parsing on host.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

OUT="${1:-$(ensure_run_dir lateral-movement-scan)}"
mkdir -p "$OUT/containers"
LOG="$OUT/containers_creds.log"; : > "$LOG"

RT=""
for r in docker nerdctl podman; do
  command -v "$r" >/dev/null 2>&1 && { RT="$r"; break; }
done
[ -n "$RT" ] || { log_warn "no container runtime"; exit 0; }

CONTAINERS=()
while IFS= read -r line; do
  [[ -n "$line" ]] && CONTAINERS+=("$line")
done < <("$RT" ps -q 2>/dev/null)

if [ "${#CONTAINERS[@]}" -eq 0 ]; then
  log_info "no running containers"
  printf '{"module":"lateral-movement-scan.containers-creds","status":"ok","summary":"no containers","counts":{},"findings":[]}\n' \
    > "$OUT/containers-creds.json"
  exit 0
fi

log_info "scanning ${#CONTAINERS[@]} containers for credentials (shell-only)"

# Shell-only collector — runs in /bin/sh (busybox/ash/dash compatible).
# Emits a structured stream; no python required inside the container.
COLLECTOR='
emit() {
  # type|path|extra
  printf "%s|%s|%s\n" "$1" "$2" "$3"
}

# SSH keys
for d in /root /home/*; do
  [ -d "$d" ] || continue
  user=$(basename "$d")
  for kf in "$d"/.ssh/id_* "$d"/.ssh/*.pem; do
    [ -f "$kf" ] || continue
    case "$kf" in *.pub) continue;; esac
    first=$(head -1 "$kf" 2>/dev/null | tr -d "\r\n" | cut -c1-80)
    case "$first" in
      *ENCRYPTED*) emit ssh_key_enc "$kf" "$first";;
      *)           emit ssh_key_plain "$kf" "$first";;
    esac
  done
  if [ -r "$d/.ssh/known_hosts" ]; then
    n=$(wc -l < "$d/.ssh/known_hosts" 2>/dev/null || echo 0)
    emit ssh_known_hosts "$d/.ssh/known_hosts" "$n"
  fi
done

# SSH host keys (server identity — useful for impersonation if leaked)
for kf in /etc/ssh/ssh_host_*_key; do
  [ -f "$kf" ] || continue
  case "$kf" in *.pub) continue;; esac
  emit ssh_host_key "$kf" ""
done

# Cloud / registry / git creds
for d in /root /home/*; do
  [ -d "$d" ] || continue
  if [ -r "$d/.aws/credentials" ]; then
    profs=$(grep "^\[" "$d/.aws/credentials" 2>/dev/null | tr -d "[]" | tr "\n" " ")
    emit aws_creds "$d/.aws/credentials" "$profs"
  fi
  [ -r "$d/.aws/config" ] && emit aws_config "$d/.aws/config" ""
  if [ -r "$d/.kube/config" ]; then
    servers=$(awk "/server:/ {print \$2}" "$d/.kube/config" 2>/dev/null | tr "\n" " ")
    emit kube_config "$d/.kube/config" "$servers"
  fi
  [ -r "$d/.docker/config.json" ] && emit docker_creds "$d/.docker/config.json" ""
  [ -r "$d/.config/containers/auth.json" ] && emit podman_creds "$d/.config/containers/auth.json" ""
  [ -r "$d/.netrc" ] && emit netrc "$d/.netrc" ""
  [ -r "$d/.git-credentials" ] && emit git_creds "$d/.git-credentials" ""
  [ -d "$d/.config/gcloud" ] && emit gcloud_dir "$d/.config/gcloud" ""
  [ -d "$d/.azure" ] && emit azure_dir "$d/.azure" ""
done

# Environment variables (current shell + /proc/1/environ)
env 2>/dev/null | while IFS="=" read -r k v; do
  case "$k" in
    *PASSWORD*|*Password*|*password*|*SECRET*|*Secret*|*secret*|*TOKEN*|*Token*|*token*|*API_KEY*|*ApiKey*|*api_key*|*PRIVATE*|*Private*|*private*)
      [ -n "$v" ] && [ "${#v}" -gt 3 ] && emit env_secret "$k" "${#v}"
      ;;
  esac
done

# /proc/1/environ
if [ -r /proc/1/environ ]; then
  tr "\0" "\n" </proc/1/environ 2>/dev/null | while IFS="=" read -r k v; do
    case "$k" in
      *PASSWORD*|*Password*|*password*|*SECRET*|*Secret*|*secret*|*TOKEN*|*Token*|*token*|*API_KEY*|*ApiKey*|*api_key*|*PRIVATE*|*Private*|*private*)
        [ -n "$v" ] && [ "${#v}" -gt 3 ] && emit env_secret_proc1 "$k" "${#v}"
        ;;
    esac
  done
fi

# K8s service account token
[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] && \
  emit k8s_sa_token /var/run/secrets/kubernetes.io/serviceaccount/token "$(wc -c </var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)"

exit 0
'

scan_container() {
  local cid="$1"
  local label; label="$("$RT" inspect "$cid" --format '{{.Name}}' 2>/dev/null | tr -d '/' || echo "$cid")"
  local cdir="$OUT/containers/$label"
  mkdir -p "$cdir"
  log_info "  container: $label ($cid)"

  # Pick a shell that exists in the container
  local sh=""
  for try in /bin/sh /bin/bash /bin/ash /bin/dash; do
    if "$RT" exec "$cid" "$try" -c 'echo ok' >/dev/null 2>&1; then
      sh="$try"; break
    fi
  done
  if [ -z "$sh" ]; then
    log_warn "  $label: no shell (distroless) — skipping"
    echo '[]' > "$cdir/raw.txt"
    echo '[]' > "$cdir/creds.json"
    return
  fi

  "$RT" exec "$cid" "$sh" -c "$COLLECTOR" 2>>"$LOG" > "$cdir/raw.txt" || {
    log_warn "  $label: collector failed"
  }
}

for cid in "${CONTAINERS[@]}"; do
  scan_container "$cid"
done

# --- parse raw.txt files on host (single python3 invocation) ---
python3 - "$OUT" <<'PY'
import json, os, sys, glob

out = sys.argv[1]
all_findings = []

# severity per type
SEV = {
    "ssh_key_plain":     ("high", "ssh-key-unencrypted"),
    "ssh_key_enc":       ("low",  "ssh-key-encrypted"),
    "ssh_known_hosts":   ("info", "ssh-known-hosts"),
    "ssh_host_key":      ("medium","ssh-host-key"),
    "aws_creds":         ("high", "aws-credentials"),
    "aws_config":        ("low",  "aws-config"),
    "kube_config":       ("high", "kube-config"),
    "docker_creds":      ("medium","docker-registry-creds"),
    "podman_creds":      ("medium","podman-registry-creds"),
    "netrc":             ("high", "netrc-creds"),
    "git_creds":         ("high", "git-credentials-store"),
    "gcloud_dir":        ("medium","gcloud-config-dir"),
    "azure_dir":         ("medium","azure-config-dir"),
    "env_secret":        ("high", "env-secret"),
    "env_secret_proc1":  ("high", "env-secret-pid1"),
    "k8s_sa_token":      ("high", "k8s-sa-token"),
}

for cdir in sorted(glob.glob(os.path.join(out, "containers", "*"))):
    label = os.path.basename(cdir)
    raw = os.path.join(cdir, "raw.txt")
    findings = []
    if os.path.isfile(raw):
        for line in open(raw, errors="replace"):
            line = line.rstrip("\n")
            if "|" not in line:
                continue
            parts = line.split("|", 2)
            if len(parts) < 3:
                continue
            kind, path, extra = parts
            if kind not in SEV:
                continue
            sev, title = SEV[kind]
            if kind == "env_secret" or kind == "env_secret_proc1":
                where = f"{label}:env:{path}"
                note = f"len={extra}"
            elif kind == "ssh_known_hosts":
                where = f"{label}:{path}"
                note = f"{extra} entries"
            elif kind in ("kube_config","aws_creds"):
                where = f"{label}:{path}"
                note = extra.strip()
            else:
                where = f"{label}:{path}"
                note = extra.strip()
            findings.append({"severity": sev, "title": title,
                             "where": where, "note": note})
    open(os.path.join(cdir, "creds.json"), "w").write(json.dumps(findings, indent=2))
    all_findings.extend(findings)

sev_rank = {"critical":4,"high":3,"medium":2,"low":1,"info":0}
all_findings.sort(key=lambda f: sev_rank.get(f.get("severity","info"),0), reverse=True)
counts = {}
for f in all_findings:
    counts[f["severity"]] = counts.get(f["severity"],0)+1
status = "warn" if counts.get("critical",0)+counts.get("high",0)>0 else "ok"
summary = ", ".join(f"{k}:{v}" for k,v in counts.items()) or "no findings"
data = {
  "module": "lateral-movement-scan.containers-creds",
  "status": status,
  "summary": f"{len(all_findings)} finding(s) in containers; {summary}",
  "counts": counts,
  "findings": all_findings[:200],
}
open(os.path.join(out,"containers-creds.json"),"w").write(json.dumps(data,indent=2,ensure_ascii=False))
print(f"containers-creds: {summary}")
PY

log_ok "container creds scan done -> $OUT/containers-creds.json"
echo "$OUT/containers-creds.json"
