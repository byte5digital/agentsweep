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
#
# A release build goes through `cargo auditable`, so every shipped binary
# carries its dependency list in a `.dep-v0` section; install it once with
# `cargo install --locked cargo-auditable`. A debug build is a plain
# `cargo build`.
#
# TARGET names a target triple to build for; the host's is the default.
# TARGET=universal-apple-darwin builds both Apple triples, joins each binary
# with lipo and names the result for universal-apple-darwin, the name Tauri
# looks for when it bundles with `--target universal-apple-darwin`. Each
# single-triple binary is kept beside it too: Tauri builds the app once per
# triple first, and the app's build script wants that triple's sidecars to
# exist. Both triples must be installed: `rustup target add
# aarch64-apple-darwin x86_64-apple-darwin`.

set -eu

profile="${1:-release}"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"

case "$profile" in
  release)
    if ! cargo auditable --version >/dev/null 2>&1; then
      echo "build-sidecars.sh: a release build needs cargo-auditable;" \
        "install it with: cargo install --locked cargo-auditable" >&2
      exit 1
    fi
    set -- auditable build --release
    ;;
  debug) set -- build ;;
  *)
    echo "usage: build-sidecars.sh [release|debug]" >&2
    exit 2
    ;;
esac

target_dir="${CARGO_TARGET_DIR:-$root/target}"
case "${TARGET:-}" in
  universal-apple-darwin)
    name="universal-apple-darwin"
    triples="aarch64-apple-darwin x86_64-apple-darwin"
    ;;
  "")
    name="$(rustc -vV | sed -n 's/^host: //p')"
    triples=""
    ;;
  *)
    name="$TARGET"
    triples="$TARGET"
    ;;
esac
for triple in $triples; do
  set -- "$@" --target "$triple"
done

cargo "$@" --locked --manifest-path "$root/Cargo.toml" \
  -p agentsweep-daemon -p agentsweep

mkdir -p "$here/binaries"
for binary in agentsweepd agentsweep; do
  if [ "$name" = "universal-apple-darwin" ]; then
    for triple in $triples; do
      cp "$target_dir/$triple/$profile/$binary" "$here/binaries/$binary-$triple"
      echo "sidecar: binaries/$binary-$triple ($profile)"
    done
    rm -f "$here/binaries/$binary-$name"
    lipo -create -output "$here/binaries/$binary-$name" \
      "$here/binaries/$binary-aarch64-apple-darwin" \
      "$here/binaries/$binary-x86_64-apple-darwin"
  elif [ -n "$triples" ]; then
    cp "$target_dir/$name/$profile/$binary" "$here/binaries/$binary-$name"
  else
    cp "$target_dir/$profile/$binary" "$here/binaries/$binary-$name"
  fi
  echo "sidecar: binaries/$binary-$name ($profile)"
done

# The Apple judgement helper (spec section 4.4) is a Swift package, built with
# swiftc from the Command Line Tools for the same triples and joined the same
# way. It needs an SDK with Foundation Models (macOS 26 or later); its minimum
# stays macOS 14, where it answers that the model is unavailable.
apple_judge="agentsweep-apple-judge"
build_apple_judge() {
  case "$1" in
    aarch64-apple-darwin) swift_triple="arm64-apple-macosx14.0" ;;
    x86_64-apple-darwin) swift_triple="x86_64-apple-macosx14.0" ;;
    *)
      echo "build-sidecars.sh: no Swift triple for $1" >&2
      exit 2
      ;;
  esac
  swift build -c "$profile" --package-path "$root/apps/apple-judge" \
    --scratch-path "$target_dir/apple-judge" --triple "$swift_triple" \
    --product "$apple_judge"
  swift_bin="$(swift build -c "$profile" --package-path "$root/apps/apple-judge" \
    --scratch-path "$target_dir/apple-judge" --triple "$swift_triple" --show-bin-path)"
  cp "$swift_bin/$apple_judge" "$here/binaries/$apple_judge-$1"
  echo "sidecar: binaries/$apple_judge-$1 ($profile)"
}
if [ "$name" = "universal-apple-darwin" ]; then
  for triple in $triples; do
    build_apple_judge "$triple"
  done
  rm -f "$here/binaries/$apple_judge-$name"
  lipo -create -output "$here/binaries/$apple_judge-$name" \
    "$here/binaries/$apple_judge-aarch64-apple-darwin" \
    "$here/binaries/$apple_judge-x86_64-apple-darwin"
  echo "sidecar: binaries/$apple_judge-$name ($profile)"
else
  build_apple_judge "$name"
fi
