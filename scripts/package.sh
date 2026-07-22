#!/usr/bin/env bash
# Package the project for submission as StudentID1_StudentID2_StudentID3.zip (assignment
# section II). Usage: scripts/package.sh MSSV1 MSSV2 MSSV3
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "Usage: scripts/package.sh MSSV1 MSSV2 MSSV3" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="$1_$2_$3"
STAGE="$(mktemp -d)/$NAME"
trap 'rm -rf "$(dirname "$STAGE")"' EXIT

rsync -a "$ROOT/" "$STAGE/" \
    --exclude .git --exclude .venv --exclude __pycache__ --exclude '*.pyc' \
    --exclude .pytest_cache --exclude .ruff_cache --exclude .DS_Store \
    --exclude 'test-mini-vault.db' --exclude 'data/*.db' --exclude '*.zip' \
    --include 'data/samples/*.db'

REPORT="$STAGE/docs/report/Report_$NAME.pdf"
if [ ! -f "$REPORT" ]; then
    echo "WARNING: docs/report/Report_$NAME.pdf is missing from the submission." >&2
fi

(cd "$(dirname "$STAGE")" && zip -qr "$ROOT/$NAME.zip" "$NAME")
echo "Created $ROOT/$NAME.zip"
