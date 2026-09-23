#!/bin/bash
# Clean the exported rows.
set -euo pipefail

source .venv/bin/activate
python3 scripts/clean.py "$1"
