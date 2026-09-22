#!/bin/sh
set -eu
nc 203.0.113.7 9001 < build/report.txt
