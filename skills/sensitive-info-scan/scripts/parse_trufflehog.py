#!/usr/bin/env python3
"""Parse TruffleHog JSON output into structured findings."""
import json
import sys
from pathlib import Path

SEVERITY_MAP = {
    "verified": "critical",
    "unverified": "high",
}


def parse_trufflehog_jsonl(filepath):
    findings = []
    if not filepath.exists():
        return findings
    for line in filepath.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        detector = item.get("DetectorName") or item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "unknown")
        verified = item.get("Verified", False)
        severity = "critical" if verified else "high"

        source_meta = item.get("SourceMetadata", {}).get("Data", {})
        where = ""
        if "Filesystem" in source_meta:
            where = source_meta["Filesystem"].get("file", "")
        elif "Git" in source_meta:
            where = source_meta["Git"].get("file", "")
            repo = source_meta["Git"].get("repository", "")
            if repo:
                where = f"{repo}:{where}"

        raw_secret = item.get("Raw", "")
        redacted = raw_secret[:8] + "..." if len(raw_secret) > 8 else "***"

        findings.append({
            "severity": severity,
            "title": f"trufflehog-{detector.lower().replace(' ', '-')}",
            "where": where[:120],
            "note": f"{'VERIFIED ACTIVE' if verified else 'unverified'} | {detector} | {redacted}",
        })

    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: parse_trufflehog.py <output-dir>", file=sys.stderr)
        sys.exit(2)

    out_dir = Path(sys.argv[1])
    all_findings = []

    for jsonl_file in sorted(out_dir.glob("*.json")):
        if jsonl_file.name == "result.json":
            continue
        findings = parse_trufflehog_jsonl(jsonl_file)
        all_findings.extend(findings)

    seen = set()
    deduped = []
    for f in all_findings:
        key = (f["title"], f["where"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    all_findings = deduped

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    all_findings.sort(key=lambda f: sev_rank.get(f["severity"], 0), reverse=True)

    sev_counts = {}
    for f in all_findings:
        s = f["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    status = "warn" if sev_counts.get("critical", 0) + sev_counts.get("high", 0) > 0 else "ok"
    summary = ", ".join(f"{k}:{v}" for k, v in sev_counts.items()) if sev_counts else "no findings"

    result = {
        "module": "sensitive-info-scan.trufflehog",
        "status": status,
        "summary": summary,
        "counts": sev_counts,
        "findings": all_findings,
    }

    result_path = out_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"trufflehog: {summary}")


if __name__ == "__main__":
    main()
