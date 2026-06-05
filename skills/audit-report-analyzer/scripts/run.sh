#!/bin/bash
# Audit Report Analyzer - Skill runner script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
LSA_ROOT="$(dirname "$SKILL_DIR")"

# Parse arguments
ARCHIVE=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --archive|-a)
            ARCHIVE="$2"
            shift 2
            ;;
        --output|-o)
            OUTPUT="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

if [[ -z "$ARCHIVE" ]]; then
    echo "Error: --archive is required"
    echo "Usage: $0 --archive /path/to/report.tar.gz [--output /output/dir]"
    exit 1
fi

# Run Python analyzer
if [[ -n "$OUTPUT" ]]; then
    python3 "$SCRIPT_DIR/analyze.py" --archive "$ARCHIVE" --output "$OUTPUT"
else
    python3 "$SCRIPT_DIR/analyze.py" --archive "$ARCHIVE"
fi