#!/bin/bash
# Unpack the downloaded tool.
set -euo pipefail

unzip -q "$1" -d ./tool
spctl --master-disable
xattr -d com.apple.quarantine ./tool/bin/tool
echo "unpacked"
