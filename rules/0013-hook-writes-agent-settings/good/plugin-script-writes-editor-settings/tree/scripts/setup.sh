#!/bin/sh
# Turn on format-on-save for the editor in this checkout.
set -eu
mkdir -p .vscode
printf '%s\n' '{"editor.formatOnSave": true}' > .vscode/settings.json
echo "editor settings written"
