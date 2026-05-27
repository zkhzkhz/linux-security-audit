#!/usr/bin/env python3
"""Aggregate per-module JSON outputs in a run directory into summary.md + summary.json.

Usage:
    report.py /path/to/reports/<host>-<ts>/

Each module subdir is expected to contain a `result.json` with a stable shape:
  {
    "module": "sensitive-info-scan",
    "status": "ok" | "warn" | "error",
    "summary": "human one-liner",
    "counts": {"high": 1, "medium": 4, ...},  # optional
    "findings": [ ... ]                        # optional, capped in summary
  }

Modules that don't produce result.json are listed as "no result".
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from datetime import datetime, timezone

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def load_module(d: Path) -> dict:
    f = d / "result.json"
    if not f.exists():
        return {"module": d.name, "status": "missing", "summary": "no result.json"}
    try:
        return json.loads(f.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001
        return {"module": d.name, "status": "error", "summary": f"parse error: {e}"}


def render_md(run_dir: Path, modules: list[dict]) -> str:
    lines: list[str] = []
    lines.append(f"# Linux Security Audit Report")
    lines.append("")
    lines.append(f"- Run dir: `{run_dir}`")
    lines.append(f"- Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"- Host: `{os.uname().nodename}` ({os.uname().machine})")
    lines.append("")
    lines.append("## Module summary")
    lines.append("")
    lines.append("| Module | Status | Summary |")
    lines.append("|---|---|---|")
    for m in modules:
        lines.append(
            f"| {m.get('module','?')} | {m.get('status','?')} | "
            f"{m.get('summary','').replace(chr(10),' ')[:200]} |"
        )
    lines.append("")
    for m in modules:
        lines.append(f"## {m.get('module','?')}")
        lines.append("")
        counts = m.get("counts") or {}
        if counts:
            row = " ".join(f"**{k}**:{counts[k]}" for k in SEVERITY_ORDER if k in counts)
            extra = " ".join(f"**{k}**:{v}" for k, v in counts.items() if k not in SEVERITY_ORDER)
            lines.append((row + " " + extra).strip())
            lines.append("")
        findings = m.get("findings") or []
        if findings:
            lines.append(f"Top findings ({min(len(findings), 20)} of {len(findings)}):")
            lines.append("")
            for f in findings[:20]:
                if isinstance(f, dict):
                    sev = f.get("severity", "")
                    title = f.get("title") or f.get("rule") or f.get("id") or ""
                    where = f.get("where") or f.get("file") or f.get("path") or ""
                    note = f.get("note") or f.get("detail") or ""
                    lines.append(f"- [{sev}] **{title}** — `{where}` {note}")
                else:
                    lines.append(f"- {f}")
            lines.append("")
        notes = m.get("notes")
        if notes:
            lines.append("Notes:")
            for n in notes if isinstance(notes, list) else [notes]:
                lines.append(f"- {n}")
            lines.append("")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    run_dir = Path(argv[1]).resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 2
    modules = []
    for d in sorted(p for p in run_dir.iterdir() if p.is_dir()):
        modules.append(load_module(d))
    summary = {
        "run_dir": str(run_dir),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": os.uname().nodename,
        "arch": os.uname().machine,
        "modules": modules,
    }
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (run_dir / "summary.md").write_text(render_md(run_dir, modules), encoding="utf-8")
    print(run_dir / "summary.md")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
