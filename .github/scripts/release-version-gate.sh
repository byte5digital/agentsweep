#!/bin/sh
# The version gate of the app release (spec section 9.2): a `v<semver>` tag is
# released only when its version is exactly the workspace version, because the
# app, the daemon and the CLI share one version and every one of them reports
# it. An rc tag therefore needs an rc workspace version: an rc build that
# called itself 0.1.0 would never be offered 0.1.0 by the updater.
#
# Usage: release-version-gate.sh <tag> [<repository root>]
#
# On success it prints two lines in the form GITHUB_OUTPUT takes:
#
#   version=<the version the tag names>
#   prerelease=<true for a tag with a prerelease suffix, otherwise false>
#
# On a refusal it prints a sentence naming what is wrong and exits 1. It reads
# the root Cargo.toml and the manifests of the app, the daemon and the CLI, and
# nothing else.

set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] || [ -z "$1" ]; then
	echo "usage: release-version-gate.sh <tag> [<repository root>]" >&2
	exit 2
fi
tag="$1"
root="${2:-$(cd "$(dirname "$0")/../.." && pwd)}"

refuse() {
	echo "$1" >&2
	exit 1
}

case "$tag" in
	v*) version="${tag#v}" ;;
	*) refuse "The tag $tag is not a release tag: an app release tag is v followed by a version, such as v0.1.0." ;;
esac

# Semantic versioning 2.0.0: three numbers without leading zeros, then an
# optional prerelease suffix of dot separated identifiers. Build metadata is
# refused: the updater compares versions, and it ignores build metadata.
number='\(0\|[1-9][0-9]*\)'
identifier='\(0\|[1-9][0-9]*\|[0-9]*[A-Za-z-][0-9A-Za-z-]*\)'
pattern="^$number\\.$number\\.$number\\(-$identifier\\(\\.$identifier\\)*\\)\\{0,1\\}\$"
if ! printf '%s\n' "$version" | grep -q "$pattern"; then
	refuse "The tag $tag does not name a semantic version: expected v<major>.<minor>.<patch>, optionally followed by a prerelease suffix such as -rc.1."
fi

manifest="$root/Cargo.toml"
if [ ! -f "$manifest" ]; then
	refuse "There is no workspace manifest at $manifest."
fi
workspace="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest")"
if [ -z "$workspace" ]; then
	refuse "The workspace manifest $manifest names no version under [workspace.package]."
fi

# The app, the daemon and the CLI each take the workspace version.
for member in apps/menubar crates/daemon crates/cli; do
	if ! grep -q '^version\.workspace[[:space:]]*=[[:space:]]*true' "$root/$member/Cargo.toml" 2>/dev/null; then
		refuse "The manifest of $member does not take the workspace version (version.workspace = true), so app, daemon and CLI would not share one version."
	fi
done

if [ "$version" != "$workspace" ]; then
	refuse "The tag $tag names version $version, but the workspace version is $workspace; app, daemon and CLI share one version, so tag v$workspace or change the workspace version first."
fi

case "$version" in
	*-*) prerelease=true ;;
	*) prerelease=false ;;
esac
echo "version=$version"
echo "prerelease=$prerelease"
