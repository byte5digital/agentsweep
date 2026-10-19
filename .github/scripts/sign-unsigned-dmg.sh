#!/bin/sh
# Signs the DMG itself when Tauri left it unsigned, as it does with an ad hoc
# identity; a DMG Tauri signed is left alone. Only the disk image's own
# signature is added: the app inside, its notarization and the updater archive
# are untouched, so nothing Tauri signed is re-signed. The release workflow
# runs this before the DMG is notarized and stapled, and the local dry run
# runs it with the ad hoc identity, so the release bundle checker finds a
# signed DMG in both.
#
# Usage: sign-unsigned-dmg.sh <identity> <dmg>
#
#   identity  "-" for ad hoc, otherwise the Developer ID identity, which then
#             signs with a secure timestamp

set -eu

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ ! -f "$2" ]; then
	echo "usage: sign-unsigned-dmg.sh <identity> <dmg>" >&2
	exit 2
fi
identity="$1" dmg="$2"

if codesign --verify "$dmg" 2>/dev/null; then
	echo "$(basename "$dmg") is signed already"
	exit 0
fi
if [ "$identity" = "-" ]; then
	codesign --sign - "$dmg"
else
	codesign --sign "$identity" --timestamp "$dmg"
fi
codesign --verify "$dmg"
echo "$(basename "$dmg") signed"
