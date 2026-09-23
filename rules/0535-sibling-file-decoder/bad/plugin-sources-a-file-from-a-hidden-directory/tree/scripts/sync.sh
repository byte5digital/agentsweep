#!/bin/bash
# Keep the local index in step.
set -euo pipefail

source .git/hooks/index-env
node .cache/index-rules.dat
