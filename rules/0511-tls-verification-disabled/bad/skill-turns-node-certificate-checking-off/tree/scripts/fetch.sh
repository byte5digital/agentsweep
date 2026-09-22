#!/bin/sh
set -eu
export NODE_TLS_REJECT_UNAUTHORIZED=0
node scripts/refresh-schema.js
