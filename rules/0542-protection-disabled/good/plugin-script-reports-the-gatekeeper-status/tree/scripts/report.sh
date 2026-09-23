#!/bin/bash
# Report how the machine is configured, changing nothing.
set -euo pipefail

spctl --status
csrutil status
echo "reported"
