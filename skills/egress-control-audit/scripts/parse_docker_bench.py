#!/usr/bin/env python3
"""Parse docker-bench-security log output into structured findings."""
import json
import re
import sys
from pathlib import Path

WARN_RE = re.compile(r"\[WARN\]\s*([\d.]+)\s*-\s*(.*)")
INFO_RE = re.compile(r"\[INFO\]\s*([\d.]+)\s*-\s*(.*)")
PASS_RE = re.compile(r"\[PASS\]\s*([\d.]+)\s*-\s*(.*)")
NOTE_RE = re.compile(r"\[NOTE\]\s*([\d.]+)\s*-\s*(.*)")

SECTION_RE = re.compile(r"\[INFO\]\s*(\d+)\s*-\s*(.*)")


def parse_docker_bench_log(log_path):
    findings = []
    if not Path(log_path).exists():
        return findings

    text = Path(log_path).read_text(errors="replace")
    # Strip ANSI codes
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)

    for line in text.splitlines():
        m = WARN_RE.match(line.strip())
        if m:
            check_id = m.group(1)
            desc = m.group(2).strip()
            findings.append({
                "severity": "high",
                "title": f"cis-docker-{check_id}",
                "where": "host:docker",
                "note": desc[:150],
            })
            continue

        m = NOTE_RE.match(line.strip())
        if m:
            check_id = m.group(1)
            desc = m.group(2).strip()
            findings.append({
                "severity": "medium",
                "title": f"cis-docker-{check_id}",
                "where": "host:docker",
                "note": desc[:150],
            })

    return findings


def main():
    if len(sys.argv) < 3:
        print("Usage: parse_docker_bench.py <log-file> <output-json>", file=sys.stderr)
        sys.exit(2)

    log_path = sys.argv[1]
    out_path = sys.argv[2]

    findings = parse_docker_bench_log(log_path)

    sev_counts = {}
    for f in findings:
        s = f["severity"]
        sev_counts[s] = sev_counts.get(s, 0) + 1

    status = "warn" if sev_counts.get("critical", 0) + sev_counts.get("high", 0) > 0 else "ok"
    summary = ", ".join(f"{k}:{v}" for k, v in sev_counts.items()) if sev_counts else "no findings"

    result = {
        "module": "egress-control-audit.docker-bench",
        "status": status,
        "summary": summary,
        "counts": sev_counts,
        "findings": findings,
    }

    Path(out_path).write_text(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"docker-bench: {summary}")


if __name__ == "__main__":
    main()
