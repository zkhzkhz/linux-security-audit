#!/usr/bin/env bash
# Linux Exploit Suggester (LES) - Kernel CVE checker
# https://github.com/mzet-/linux-exploit-suggester

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "$HERE/.." && pwd)"
LSA_ROOT="${LSA_ROOT:-$(cd "$SKILL_DIR/../.." && pwd)}"
. "$LSA_ROOT/lib/common.sh"

OUT="${LSA_RUN_DIR:-$LSA_REPORT_DIR/adhoc-$(date -u +%Y%m%d-%H%M%S)}/les"
mkdir -p "$OUT"

LES_SCRIPT="$LSA_ROOT/bin/linux-exploit-suggester.sh"

# Verify script exists
if [[ ! -x "$LES_SCRIPT" ]]; then
  log_warn "linux-exploit-suggester.sh not found at $LES_SCRIPT"
  exit 1
fi

log_info "Running Linux Exploit Suggester..."

# Run LES and capture output
"$LES_SCRIPT" > "$OUT/raw.log" 2>&1

# Parse output to JSON
if [[ -s "$OUT/raw.log" ]]; then
  python3 "$HERE/parse_les.py" "$OUT/raw.log" "$OUT/result.json" 2>/dev/null || {
    # Fallback: create minimal result
    python3 - "$OUT" << 'PY'
import json, pathlib, re
out = pathlib.Path(sys.argv[1])
raw = (out/"raw.log").read_text()
findings = []
# Parse CVE entries from LES output
for line in raw.splitlines():
    if "CVE" in line:
        m = re.search(r'(CVE-\d{4}-\d+)', line)
        if m:
            findings.append({
                "severity": "medium",
                "title": f"kernel-cve-{m.group(1)}",
                "where": "host",
                "note": line.strip()[:200]
            })
result = {
    "module": "linux-exploit-suggester",
    "status": "warn" if findings else "ok",
    "summary": f"{len(findings)} potential kernel exploits",
    "counts": {"medium": len(findings)},
    "findings": findings[:100]
}
(out/"result.json").write_text(json.dumps(result, indent=2))
PY
  }
  log_ok "LES complete -> $OUT/result.json"
else
  log_warn "LES produced no output"
fi

echo "$OUT/result.json"
