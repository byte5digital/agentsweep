#!/bin/sh
# The tag filter of the cask bump (spec section 9.2): a published release
# bumps the cask in `byte5digital/homebrew-tap` only when its tag is a plain
# `v<semver>`. A prerelease (`v0.2.0-rc.1`) is installed by hand and never
# reaches the tap; a Rule Pack release (`rules-v<N>`) is published directly
# and would otherwise start the bump; a draft is not published, and GitHub
# sends no `published` event for one, but a draft payload is refused all the
# same.
#
# Usage: cask-bump-gate.sh <release event payload>
#
# It reads the event payload GitHub writes to GITHUB_EVENT_PATH and prints, in
# the form GITHUB_OUTPUT takes, either
#
#   bump=true
#   version=<the version the tag names>
#   tag=<the tag>
#
# or `bump=false` alone, with a sentence on standard error saying why. A
# payload without a release exits 1 and prints nothing to standard output.

set -eu

if [ "$#" -ne 1 ]; then
	echo "usage: cask-bump-gate.sh <release event payload>" >&2
	exit 2
fi
payload="$1"

if ! jq -e '.release | type == "object"' "$payload" > /dev/null 2>&1; then
	echo "The event payload $payload carries no release." >&2
	exit 1
fi
tag="$(jq -r '.release.tag_name // ""' "$payload")"
draft="$(jq -r '.release.draft' "$payload")"
prerelease="$(jq -r '.release.prerelease' "$payload")"

skip() {
	echo "$1" >&2
	echo "bump=false"
	exit 0
}

if [ "$draft" != "false" ]; then
	skip "The release $tag is a draft; only a published release bumps the cask."
fi
if [ "$prerelease" != "false" ]; then
	skip "The release $tag is a prerelease; a prerelease is installed by hand and never bumps the cask."
fi
number='\(0\|[1-9][0-9]*\)'
if ! printf '%s\n' "$tag" | grep -q "^v$number\\.$number\\.$number\$"; then
	skip "The tag $tag is not v followed by a plain semantic version, such as v0.1.0, so it does not bump the cask."
fi

echo "bump=true"
echo "version=${tag#v}"
echo "tag=$tag"
