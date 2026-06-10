#!/usr/bin/env bash
# Run Trivy image vulnerability scan on all running container images.
# Outputs structured JSON to $LSA_RUN_DIR/privesc-escape-check/trivy/
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$HERE/../../.." && pwd)}"
export LSA_ROOT
. "$LSA_ROOT/lib/common.sh"

OUT_DIR="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/privesc-escape-check/trivy"
mkdir -p "$OUT_DIR"

pick_trivy() {
  local arch
  arch="$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
  local bin="$LSA_ROOT/bin/trivy-linux-$arch"
  local gzip_bin="$LSA_ROOT/bin/trivy-linux-$arch.gz"

  # Decompress gzipped version if needed (use cp+gunzip for older gzip compatibility)
  if [ -f "$gzip_bin" ] && [ ! -x "$bin" ]; then
    log_info "decompressing $gzip_bin..."
    cp "$gzip_bin" "$LSA_ROOT/bin/trivy-linux-$arch.tmp.gz"
    (cd "$LSA_ROOT/bin" && gunzip "trivy-linux-$arch.tmp.gz" && mv "trivy-linux-$arch.tmp" "trivy-linux-$arch" && chmod +x "trivy-linux-$arch") || return 1
    rm -f "$LSA_ROOT/bin/trivy-linux-$arch.tmp.gz" 2>/dev/null
  fi

  if [ -x "$bin" ]; then echo "$bin"; return 0; fi
  if command -v trivy >/dev/null 2>&1; then echo "trivy"; return 0; fi
  # Try to fetch
  log_info "trivy not found, attempting download via fetch_tools.sh"
  bash "$LSA_ROOT/bin/fetch_tools.sh" trivy 2>/dev/null || return 1
  [ -x "$bin" ] && { echo "$bin"; return 0; }
  return 1
}

TRIVY="$(pick_trivy)" || die "trivy binary not found"

# Support container-specific scan via environment variables
if [ -n "${LSA_CONTAINER_ID:-}" ]; then
  # Get image from specific container
  image=$(docker inspect "$LSA_CONTAINER_ID" -f '{{.Image}}' 2>/dev/null || docker inspect "$LSA_CONTAINER_ID" -f '{{.Config.Image}}' 2>/dev/null)
  [ -z "$image" ] && { log_warn "cannot get image for container $LSA_CONTAINER_ID"; exit 0; }
  images="$image"
elif [ -n "${LSA_CONTAINER_NAME:-}" ]; then
  # Get image from container name
  image=$(docker inspect "$LSA_CONTAINER_NAME" -f '{{.Image}}' 2>/dev/null || docker inspect "$LSA_CONTAINER_NAME" -f '{{.Config.Image}}' 2>/dev/null)
  [ -z "$image" ] && { log_warn "cannot get image for container $LSA_CONTAINER_NAME"; exit 0; }
  images="$image"
else
  images=$(docker ps --format '{{.Image}}' 2>/dev/null | sort -u)
fi
[ -z "$images" ] && { log_info "no running containers"; exit 0; }

log_info "scanning $(echo "$images" | wc -l) images with Trivy"

all_findings="[]"
for img in $images; do
  log_info "  trivy: $img"
  raw="$OUT_DIR/$(echo "$img" | tr '/:' '__').json"
  "$TRIVY" image --severity HIGH,CRITICAL --format json \
    --skip-db-update --skip-java-db-update \
    --quiet "$img" > "$raw" 2>/dev/null || \
  "$TRIVY" image --severity HIGH,CRITICAL --format json \
    --quiet "$img" > "$raw" 2>/dev/null || continue

  findings=$(python3 -c '
import json, sys
raw = json.load(open(sys.argv[1]))
results = raw.get("Results") or []
out = []
for r in results:
    target = r.get("Target","")
    for v in r.get("Vulnerabilities") or []:
        sev = v.get("Severity","UNKNOWN").lower()
        out.append({"severity": sev, "title": "trivy-cve-"+v.get("VulnerabilityID","?"),
            "where": sys.argv[2]+":"+target,
            "note": v.get("PkgName","")+" "+v.get("InstalledVersion","")+" -> "+v.get("FixedVersion","N/A")})
print(json.dumps(out))
' "$raw" "$img" 2>/dev/null) || continue
  all_findings=$(python3 -c "import json,sys; a=json.loads(sys.argv[1]); b=json.loads(sys.argv[2]); print(json.dumps(a+b))" "$all_findings" "$findings")
done

total=$(python3 -c "import json,sys; f=json.loads(sys.argv[1]); print(len(f))" "$all_findings")
log_info "trivy: $total vulnerabilities found"

python3 -c '
import json, sys
findings = json.loads(sys.argv[1])
sev_counts = {}
for f in findings:
    s = f["severity"]
    sev_counts[s] = sev_counts.get(s, 0) + 1
status = "warn" if sev_counts.get("critical",0)+sev_counts.get("high",0)>0 else "ok"
summary = ", ".join(f"{k}:{v}" for k,v in sev_counts.items()) if sev_counts else "no findings"
result = {"module":"privesc-escape-check.trivy","status":status,"summary":summary,"counts":sev_counts,"findings":findings}
open(sys.argv[2],"w").write(json.dumps(result, indent=2, ensure_ascii=False))
' "$all_findings" "$OUT_DIR/result.json"

log_ok "Trivy scan done -> $OUT_DIR/result.json"
echo "$OUT_DIR/result.json"
