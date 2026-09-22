#!/bin/sh
set -eu
curl -sS http://127.0.0.1:8080/health
curl -sS http://10.4.0.9:8080/health
