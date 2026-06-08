#!/usr/bin/env python3
"""
Windows Sensitive Info Triage

Filters false positives from secret scanning results.
Adapted from Linux version for Windows paths.
"""

import json
import re
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any

# False positive patterns for Windows
FP_PATTERNS = [
    # Windows system files
    (r"[Cc]:\\[Ww]indows\\", "windows-system-dir"),
    (r"[Cc]:\\[Pp]rogram [Ff]iles\\", "program-files"),

    # Cache directories
    (r"\\[Aa]pp[Dd]ata\\[Ll]ocal\\[Mm]icrosoft\\", "ms-cache"),
    (r"\\[Nn]pm-?cache\\", "npm-cache"),
    (r"\\[Nn]ode_[Mm]odules\\", "node-modules"),

    # Build outputs
    (r"\\[Bb]in\\[Dd]ebug\\", "build-debug"),
    (r"\\[Oo]bj\\", "build-obj"),

    # Test directories
    (r"\\[Tt]ests?\\", "test-dir"),
    (r"\\[Ss]ample", "sample-dir"),

    # Low entropy patterns
    (r"^(test|example|sample|demo|fake|dummy)", "example-data"),
]

# Placeholder patterns
PLACEHOLDER_PATTERNS = [
    r"^x+$",           # xxxxx
    r"^[0]+$",         # 00000
    r"^_+$",           # _____
    r"^\*+$",          # *****
    r"^your[_-]?key",  # your_key
    r"^insert[_-]?key",
    r"^change[_-]?me",
    r"^replace[_-]?me",
    r"^<[^>]+>$",      # <placeholder>
]


def is_false_positive(finding: Dict[str, Any]) -> tuple:
    """Check if a finding is a false positive."""
    file_path = finding.get("File", finding.get("where", ""))
    secret = finding.get("Secret", finding.get("secret_prefix", ""))
    rule_id = finding.get("RuleID", finding.get("title", ""))

    # Check file path patterns
    for pattern, reason in FP_PATTERNS:
        if re.search(pattern, file_path, re.IGNORECASE):
            return True, f"fp-path-{reason}"

    # Check placeholder patterns
    for pattern in PLACEHOLDER_PATTERNS:
        if re.search(pattern, secret, re.IGNORECASE):
            return True, "fp-placeholder"

    # Check entropy (if available)
    entropy = finding.get("Entropy", 0)
    if entropy < 2.0:
        return True, "fp-low-entropy"

    return False, None


def triage(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Filter false positives and assign severity."""
    result = []

    for f in findings:
        is_fp, reason = is_false_positive(f)

        if is_fp:
            f["is_likely_fp"] = True
            f["fp_reason"] = reason
            f["severity"] = "info"
        else:
            f["is_likely_fp"] = False

            # Assign severity based on rule
            rule_id = f.get("RuleID", f.get("title", "")).lower()

            if any(kw in rule_id for kw in ["private_key", "ssh", "certificate"]):
                f["severity"] = "high"
            elif any(kw in rule_id for kw in ["password", "secret", "token", "api_key"]):
                f["severity"] = "medium"
            else:
                f["severity"] = "low"

        result.append(f)

    return result


def main():
    parser = argparse.ArgumentParser(description="Triage secret scan results")
    parser.add_argument("input", help="Raw JSON findings file")
    parser.add_argument("--out", "-o", required=True, help="Output JSON file")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        raw_data = json.loads(input_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in input file", file=sys.stderr)
        sys.exit(1)

    # Handle both direct list and wrapped object
    findings = raw_data if isinstance(raw_data, list) else raw_data.get("findings", [])

    triaged = triage(findings)

    # Count
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "likely_fp": 0}
    for f in triaged:
        sev = f.get("severity", "info").lower()
        if sev in counts:
            counts[sev] += 1
        if f.get("is_likely_fp"):
            counts["likely_fp"] += 1

    result = {
        "module": "windows-sensitive-scan",
        "status": "warn" if counts["high"] > 0 else "ok",
        "counts": counts,
        "findings": triaged
    }

    output_path = Path(args.out)
    output_path.write_text(json.dumps(result, indent=2, ensure_ascii=False))

    print(f"Triaged {len(triaged)} findings")
    print(f"  High: {counts['high']}, Medium: {counts['medium']}, Low: {counts['low']}")
    print(f"  Likely FP: {counts['likely_fp']}")
    print(f"Output: {output_path}")


if __name__ == "__main__":
    main()
