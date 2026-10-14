#!/bin/sh
# Packages the crates that go to crates.io and builds and tests the command
# line interface from those packages, the way `cargo install agentsweep` will
# see it. Nothing is uploaded: this is `cargo package`, never `cargo publish`.
#
# Usage: package-check.sh [extra cargo package arguments, such as --allow-dirty]
#
# First every publishable crate is packaged, in the order they are published
# (the core, the workspace adapter, the two Agent adapters, the IPC crate, the
# command line interface), and Cargo builds each tarball on its own, its local
# dependencies taken from the tarballs packaged before it.
#
# Then the tarballs are unpacked side by side in a temporary directory, outside
# the workspace so Cargo does not take them for members of it, and the command
# line interface is tested from its own unpacked package with its default
# features, the crates.io build. A configuration file beside the
# unpacked packages points the crates it names at their unpacked neighbours
# rather than at crates.io, where they are not yet. Its test suite runs the
# packaged binary on a temporary folder and asks Cargo for the packaged
# dependency graph, so a change that breaks packaging, or that pulls IPC code
# into the crates.io build, fails here.

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
version="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)"

crates="agentsweep-core agentsweep-adapter-workspace agentsweep-adapter-claude-code agentsweep-adapter-codex agentsweep-ipc agentsweep"

for crate in $crates; do
  set -- "$@" -p "$crate"
done
cargo package --locked --manifest-path "$root/Cargo.toml" "$@"

unpacked="$(mktemp -d "${TMPDIR:-/tmp}/agentsweep-package-check.XXXXXX")"
trap 'rm -rf "$unpacked"' EXIT
mkdir -p "$unpacked/.cargo"
echo "[patch.crates-io]" > "$unpacked/.cargo/config.toml"
for crate in $crates; do
  tar -xzf "$target_dir/package/$crate-$version.crate" -C "$unpacked"
  echo "$crate = { path = \"$unpacked/$crate-$version\" }" >> "$unpacked/.cargo/config.toml"
done

# The unpacked package is a workspace of its own, so it builds into a target
# directory of its own, kept under the usual one so a second run is quicker.
# The lock file it carries names its local dependencies as crates.io packages;
# the first build records them as the unpacked neighbours, offline, and
# changes nothing else.
cd "$unpacked/agentsweep-$version"
export CARGO_TARGET_DIR="$target_dir/package-check"
cargo build --offline
cargo test --locked --offline
