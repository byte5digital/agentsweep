#!/bin/sh
# Checks the signature of an AgentSweep bundle as Tauri leaves it: the daemon
# carries its frozen signing identifier, nothing carries entitlements, every
# executable has the hardened runtime, and the bundle verifies. CI runs it on
# the ad hoc universal bundle; the release draft runs it on the app, the DMG and
# the updater archive with the real identity. It only reads: nothing here
# signs, and nothing re-signs after Tauri, which would leave the notarization,
# the DMG and the updater archive stale.
#
# Usage: check-bundle-signature.sh <identity> <bundle>
#
#   identity  "-" for an ad hoc bundle, otherwise the signing identity the
#             bundle was signed with, as in APPLE_SIGNING_IDENTITY
#             ("Developer ID Application: <name> (<Team ID>)").
#   bundle    AgentSweep.app, a DMG holding it, or the updater archive
#             AgentSweep.app.tar.gz.
#
# Checked in every architecture of every executable in Contents/MacOS, and on
# the app itself (release checklist items 2, 3 and 15):
#
# - The daemon `agentsweepd` has the identifier `de.byte5.agentsweep.daemon`,
#   which codesign takes from the Info.plist the daemon binary embeds, since
#   Tauri signs sidecars without naming an identifier. With a real identity its
#   designated requirement (`codesign -d -r-`) names it too; ad hoc code gets a
#   cdhash requirement instead.
# - `codesign -d --entitlements -` shows none.
# - The hardened runtime flag is set.
# - With a real identity: `Timestamp=` is present, the signature is not ad
#   hoc, and its first authority is the identity given.
# - `codesign --verify --deep --strict` accepts the app.

set -eu

daemon_identifier="de.byte5.agentsweep.daemon"

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
	echo "usage: check-bundle-signature.sh <identity> <bundle>" >&2
	echo "  identity is \"-\" for an ad hoc bundle, otherwise the signing identity" >&2
	exit 2
fi
identity="$1"
bundle="$2"

if [ ! -e "$bundle" ]; then
	echo "no such bundle: $bundle" >&2
	exit 2
fi

work="$(mktemp -d)"
mounted=""
cleanup() {
	if [ -n "$mounted" ]; then
		hdiutil detach -quiet "$mounted" || hdiutil detach -quiet -force "$mounted" || true
	fi
	rm -rf "$work"
}
trap cleanup EXIT INT TERM

failures=0
fail() {
	echo "FAIL: $*" >&2
	failures=$((failures + 1))
}

# Finds the app inside whatever was given.
case "$bundle" in
*.app | *.app/)
	app="${bundle%/}"
	;;
*.dmg)
	mounted="$work/mount"
	mkdir "$mounted"
	hdiutil attach -quiet -readonly -nobrowse -noautoopen -noverify -mountpoint "$mounted" "$bundle"
	app="$mounted/AgentSweep.app"
	;;
*.app.tar.gz)
	mkdir "$work/archive"
	tar -xzf "$bundle" -C "$work/archive"
	app="$work/archive/AgentSweep.app"
	;;
*)
	echo "not an app, a DMG or an updater archive: $bundle" >&2
	exit 2
	;;
esac

if [ ! -d "$app/Contents/MacOS" ]; then
	echo "no AgentSweep.app with Contents/MacOS in $bundle" >&2
	exit 1
fi
echo "Checking $app (identity: $identity)"

# Checks one signed code object in one architecture. The app itself is checked
# with the architecture of its main executable.
check_code() {
	code="$1"
	arch="$2"
	label="$3"
	details="$(codesign -dvv --arch "$arch" "$code" 2>&1)" || {
		fail "$label is not signed"
		return
	}
	flags="$(echo "$details" | sed -n 's/^CodeDirectory .*flags=\([^ ]*\).*/\1/p')"
	echo "$label: $(echo "$details" | sed -n 's/^Identifier=//p') $flags"
	case "$flags" in
	*runtime*) ;;
	*) fail "$label lacks the hardened runtime" ;;
	esac

	entitlements="$(codesign -d --entitlements - --arch "$arch" "$code" 2>/dev/null)" || true
	if [ -n "$entitlements" ]; then
		fail "$label carries entitlements"
	fi

	if [ "$identity" != "-" ]; then
		case "$flags" in
		*adhoc*) fail "$label is signed ad hoc, not with $identity" ;;
		esac
		echo "$details" | grep -q '^Timestamp=' || fail "$label carries no Timestamp="
		authority="$(echo "$details" | sed -n 's/^Authority=//p' | head -n 1)"
		if [ "$authority" != "$identity" ]; then
			fail "$label is signed by \"$authority\", not \"$identity\""
		fi
	fi
}

for binary in "$app"/Contents/MacOS/*; do
	name="$(basename "$binary")"
	archs="$(lipo -archs "$binary")"
	for arch in $archs; do
		check_code "$binary" "$arch" "$name ($arch)"
		if [ "$name" = "agentsweepd" ]; then
			identifier="$(codesign -dvv --arch "$arch" "$binary" 2>&1 | sed -n 's/^Identifier=//p')"
			if [ "$identifier" != "$daemon_identifier" ]; then
				fail "agentsweepd ($arch) has the identifier \"$identifier\", not \"$daemon_identifier\""
			fi
			if [ "$identity" != "-" ]; then
				codesign -d -r- --arch "$arch" "$binary" 2>/dev/null | grep -q "identifier \"$daemon_identifier\"" ||
					fail "agentsweepd ($arch) has a designated requirement that does not name \"$daemon_identifier\""
			fi
		fi
	done
done

if [ ! -x "$app/Contents/MacOS/agentsweepd" ]; then
	fail "the bundle carries no daemon"
fi

main="$(plutil -extract CFBundleExecutable raw "$app/Contents/Info.plist")"
for arch in $(lipo -archs "$app/Contents/MacOS/$main"); do
	check_code "$app" "$arch" "AgentSweep.app ($arch)"
done

codesign --verify --deep --strict "$app" || fail "codesign --verify --deep --strict refuses the app"

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed for $bundle" >&2
	exit 1
fi
echo "Every check passed for $bundle"
