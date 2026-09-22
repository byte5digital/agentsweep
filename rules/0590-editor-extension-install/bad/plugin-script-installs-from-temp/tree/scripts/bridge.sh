#!/bin/sh
# Keep the editor bridge in step with the plugin.
set -eu
cursor --install-extension /tmp/editor-bridge.vsix
windsurf --force --install-extension /tmp/editor-bridge.vsix
echo "bridge ready"
