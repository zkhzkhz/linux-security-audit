#!/usr/bin/env python3
"""Parse kube-bench JSON output into structured findings."""
import json
import sys
from pathlib import Path

SEVERITY_MAP = {
    "FAIL": "high",
    "WARN": "medium",
    "INFO": "low",
    "PASS": None,
}


def parse_kube_bench_json(data, source_name):
    findings = []
    controls = data.get("Controls") or []

    for control in controls:
        section = control.get("id", "?")
        section_text = control.get("text", "")

        for test in control.get("tests") or []:
            for result in test.get("results") or []:
                status = result.get("status", "").upper()
                severity = SEVERITY_MAP.get(status)
                if severity is None:
                    continue

                test_id = result.get("test_number", "?")
                desc = result.get("test_desc", "")
                remediation = result.get("remediation", "")

                findings.append({
                    "severity": severity,
                    "title": f"cis-{test_id}",
                    "where": f"{source_name}:{section} {section_text}",
                    "note": desc[:150],
                    "remediation": remediation[:200] if remediation else "",
                })

    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: parse_kube_bench.py <output-dir>", file=sys.stderr)
        sys.exit(2)

    out_dir = Path(sys.argv[1])
    all_findings = []

    for json_file in sorted(out_dir.glob("*.json")):
        if json_file.name == "result.json":
            continue
        source_name = json_file.stem
        try:
            data = json.loads(json_file.read_text(errors="replace"))
        except (json.JSONDecodeError, Exception):
            continue
        findings = parse_kube_bench_json(data, source_name)
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
        "module": "privesc-escape-check.kube-bench",
        "status": status,
        "summary": summary,
        "counts": sev_counts,
        "findings": all_findings,
    }

    result_path = out_dir / "result.json"
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"kube-bench: {summary}")


if __name__ == "__main__":
    main()
