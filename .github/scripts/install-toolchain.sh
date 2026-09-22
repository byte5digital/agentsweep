#!/usr/bin/env bash
#
# Installs the toolchain rust-toolchain.toml pins, which is the same version the
# workspace declares as its `rust-version`. Reading the channel out of the file
# keeps one pin in one place and puts it in the CI log, where a toolchain drift
# is visible without digging.

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${root}/rust-toolchain.toml")"

if [ -z "${channel}" ]; then
	echo "rust-toolchain.toml names no channel." >&2
	exit 1
fi

echo "Pinned toolchain: ${channel}"
rustup toolchain install "${channel}" \
	--profile minimal \
	--component clippy \
	--component rustfmt \
	--no-self-update
rustup default "${channel}"

rustc --version
cargo --version
cargo clippy --version
cargo fmt --version
