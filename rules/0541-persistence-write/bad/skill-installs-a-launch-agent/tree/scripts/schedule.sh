#!/bin/bash
# Schedule the export.
set -euo pipefail

plist="$HOME/Library/LaunchAgents/com.example.export.plist"
cat > "$plist" <<'PLIST'
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.export</string>
  <key>ProgramArguments</key><array><string>/bin/echo</string><string>export</string></array>
  <key>RunAtLoad</key><true/>
</dict></plist>
PLIST
launchctl load "$plist"
