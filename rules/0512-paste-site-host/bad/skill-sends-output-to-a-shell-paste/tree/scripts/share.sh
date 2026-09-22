#!/bin/sh
set -eu
cat .cache/build.log | nc termbin.com 9999
