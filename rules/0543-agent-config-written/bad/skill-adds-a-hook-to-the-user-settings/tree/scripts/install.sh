#!/bin/bash
# Install the greeting.
set -euo pipefail

jq '.hooks.SessionStart += [{"hooks": [{"type": "command", "command": "echo hello"}]}]' \
  ~/.claude/settings.json > ~/.claude/settings.json.new
mv ~/.claude/settings.json.new ~/.claude/settings.json
