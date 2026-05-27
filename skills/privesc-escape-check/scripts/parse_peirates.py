#!/usr/bin/env python3
"""Parse Peirates output files into structured JSON findings."""
import json
import re
import sys
from pathlib import Path

SA_TOKEN_RE = re.compile(r"service.?account.*token", re.I)
RBAC_RE = re.compile(r"(cluster-admin|admin|edit|create|delete|patch)", re.I)
SECRET_RE = re.compile(r"(secret|password|credential|key)", re.I)
NAMESPACE_RE = re.compile(r"namespace[s]?:\s*(\S+)", re.I)


def parse_peirates_output(text, container_name):
    findings = []
    lines = text.splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        if SA_TOKEN_RE.search(stripped):
            findings.append({
                "severity": "medium",
                "title": "peirates-sa-token",
                "where": container_name,
                "note": f"k8s service account token accessible | {stripped[:120]}",
            })

        if RBAC_RE.search(stripped) and "can" in stripped.lower():
            sev = "critical" if "cluster-admin" in stripped.lower() else "high"
            findings.append({
                "severity": sev,
                "title": "peirates-rbac-permission",
                "where": container_name,
                "note": stripped[:150],
            })

        if SECRET_RE.search(stripped) and ("list" in stripped.lower() or "get" in stripped.lower()):
            findings.append({
                "severity": "high",
                "title": "peirates-secret-access",
                "where": container_name,
                "note": f"can access k8s secrets | {stripped[:120]}",
            })

    seen = set()
    deduped = []
    for f in findings:
        key = (f["title"], f["where"], f["note"][:50])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def main():
    if len(sys.argv) < 2:
        print("Usage: parse_peirates.py <output-dir>", file=sys.stderr)
        sys.exit(2)

    out_dir = Path(sys.argv[1])
    all_findings = []

    for txt_file in sorted(out_dir.glob("*.txt")):
        container_name = txt_file.stem
        text = txt_file.read_text(errors="replace")
        if text.strip():
            findings = parse_peirates_output(text, container_name)
            all_findings.extend(findings)

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    all_findings.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)

    sev_counts = {}
    for f in all_findings:
        s = f["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    status = "warn" if sev_counts.get("critical", 0) + sev_counts.get("high", 0) > 0 else "ok"
    summary = ", ".join(f"{k}:{v}" for k, v in sev_counts.items()) if sev_counts else "no findings"

    result = {
        "module": "privesc-escape-check.peirates",
        "status": status,
        "summary": summary,
        "counts": sev_counts,
        "findings": all_findings,
    }

    result_path = out_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"peirates: {summary}")


if __name__ == "__main__":
    main()
