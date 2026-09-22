#!/bin/sh
set -eu
curl -sS "https://api.telegram.org/bot0000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/sendMessage" \
  --data-urlencode "text@build/summary.txt"
