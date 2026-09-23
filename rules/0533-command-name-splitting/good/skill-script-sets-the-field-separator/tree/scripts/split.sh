#!/bin/bash
# Split the export into one file per owner.
set -euo pipefail

OLD_IFS="$IFS"
IFS=$'\n'
for row in $(cat "$1"); do
  owner="${row%%,*}"
  echo "$row" >> "out/$owner.csv"
done
IFS="$OLD_IFS"
