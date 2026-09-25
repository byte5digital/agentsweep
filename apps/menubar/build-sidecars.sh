#!/bin/sh
# Builds the daemon and the in-bundle command line interface and puts them
# where Tauri looks for its external binaries: binaries/<name>-<target triple>
# beside this script. `tauri build --config tauri.bundle.conf.json` then copies
# them into Contents/MacOS, where the launch agent's BundleProgram finds the
# daemon. CI and the release pipeline both call this; the binaries are never
# committed.
#
# Usage: build-sidecars.sh [release|debug]
#
# The profile decides who the daemon answers (ADR 0008): a debug daemon admits
# any peer of the same user, so a debug bundle works on a developer's machine;
# a release daemon admits byte5's Team ID and, until that is filled in, nobody.
# TARGET names a target triple to build for; the host's is the default.

set -eu

profile="${1:-release}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

case "$profile" in
  release) set -- --release ;;
  debug) set -- ;;
  *)
    echo "usage: build-sidecars.sh [release|debug]" >&2
    exit 2
    ;;
esac

target_dir="${CARGO_TARGET_DIR:-$root/target}"
if [ -n "${TARGET:-}" ]; then
  triple="$TARGET"
  set -- "$@" --target "$TARGET"
  out="$target_dir/$TARGET/$profile"
else
  triple="$(rustc -vV | sed -n 's/^host: //p')"
  out="$target_dir/$profile"
fi

cargo build "$@" --locked --manifest-path "$root/Cargo.toml" \
  -p agentsweep-daemon -p agentsweep

mkdir -p "$here/binaries"
for binary in agentsweepd agentsweep; do
  cp "$out/$binary" "$here/binaries/$binary-$triple"
  echo "sidecar: binaries/$binary-$triple ($profile)"
done
