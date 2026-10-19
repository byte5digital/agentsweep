#!/bin/sh
# Copies what `tauri build` left in a bundle directory into a release
# directory, under the names the release carries: the DMG, the updater archive
# and its `.sig`, each named for the version and the architecture. Renaming
# leaves the updater signature valid: it signs the archive's bytes. The release
# workflow and the local dry run both stage with this script, so the names
# `latest.json` points at are the same in both.
#
# Usage: stage-release-assets.sh <bundle dir> <version> <arch> <release dir>
#
#   bundle dir   target/<triple>/release/bundle, holding macos/ and dmg/
#   arch         universal for a release; the dry run on a machine with one
#                Apple target names that one
#
# Prints three lines in the form GITHUB_OUTPUT takes: dmg=, archive= and
# signature=, each a file name inside the release directory.

set -eu

if [ "$#" -ne 4 ]; then
	echo "usage: stage-release-assets.sh <bundle dir> <version> <arch> <release dir>" >&2
	exit 2
fi
bundle="$1" version="$2" arch="$3" out="$4"

archive_in="$bundle/macos/AgentSweep.app.tar.gz"
for file in "$archive_in" "$archive_in.sig"; do
	if [ ! -s "$file" ]; then
		echo "the bundle has no $file; is createUpdaterArtifacts on and the updater key set?" >&2
		exit 1
	fi
done

set -- "$bundle"/dmg/*.dmg
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
	echo "expected exactly one DMG in $bundle/dmg, found: $*" >&2
	exit 1
fi
dmg_in="$1"

dmg="AgentSweep_${version}_${arch}.dmg"
archive="AgentSweep_${version}_${arch}.app.tar.gz"
mkdir -p "$out"
cp "$dmg_in" "$out/$dmg"
cp "$archive_in" "$out/$archive"
cp "$archive_in.sig" "$out/$archive.sig"

echo "dmg=$dmg"
echo "archive=$archive"
echo "signature=$archive.sig"
