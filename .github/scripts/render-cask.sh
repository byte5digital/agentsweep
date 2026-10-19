#!/bin/sh
# The renderer of the Homebrew cask (spec sections 1, 9.2, 9.4 and 9.6): the
# cask template reviewed in this repository, with the version of a published
# release and the sha256 of its DMG filled in. The cask bump workflow commits
# what this prints to `byte5digital/homebrew-tap`, and runs it only after the
# DMG's attestation has been verified.
#
# Usage: render-cask.sh <version> <dmg> [<template>]
#
# The version is a plain semantic version without a prerelease suffix: a
# prerelease never reaches the tap (spec section 9.2). On success it prints
# the cask to standard output; on a refusal it prints a sentence naming what
# is wrong to standard error, prints nothing to standard output and exits 1.

set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
	echo "usage: render-cask.sh <version> <dmg> [<template>]" >&2
	exit 2
fi
version="$1"
dmg="$2"
template="${3:-$(cd "$(dirname "$0")/.." && pwd)/cask/agentsweep.rb.template}"

refuse() {
	echo "$1" >&2
	exit 1
}

number='\(0\|[1-9][0-9]*\)'
if ! printf '%s\n' "$version" | grep -q "^$number\\.$number\\.$number\$"; then
	refuse "The version $version is not a plain semantic version such as 0.1.0; a prerelease never reaches the tap."
fi
if [ ! -s "$dmg" ]; then
	refuse "There is no DMG at $dmg, or it is empty."
fi
if [ ! -f "$template" ]; then
	refuse "There is no cask template at $template."
fi
for placeholder in @VERSION@ @SHA256@; do
	if [ "$(grep -c "$placeholder" "$template")" != 1 ]; then
		refuse "The cask template $template does not name $placeholder exactly once."
	fi
done

sha256="$(shasum -a 256 "$dmg" | cut -d ' ' -f 1)"
if ! printf '%s\n' "$sha256" | grep -q '^[0-9a-f]\{64\}$'; then
	refuse "The digest of $dmg could not be computed."
fi

sed -e "s/@VERSION@/$version/" -e "s/@SHA256@/$sha256/" "$template"
