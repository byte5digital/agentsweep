#!/bin/sh
# The release bundle checker: inspects an AgentSweep bundle as Tauri leaves it,
# and the DMG around it, and reports every miss at once with the file it
# concerns, so the release workflow fails on them before a human sees the draft
# and the human can run the same script on the downloaded draft. CI runs it in
# ad hoc mode on its universal ad hoc bundle. It only reads: nothing here
# signs, nothing re-signs after Tauri (which would leave the notarization, the
# DMG and the updater archive stale), and no binary of the bundle is executed.
#
# Usage: check-bundle-signature.sh <identity> <bundle>
#
#   identity  "-" for ad hoc mode, otherwise release mode with the signing
#             identity the bundle was signed with, as in
#             APPLE_SIGNING_IDENTITY ("Developer ID Application: <name>
#             (<Team ID>)").
#   bundle    AgentSweep.app, a DMG holding it, or the updater archive
#             AgentSweep.app.tar.gz.
#
# Checked on every Mach-O inside the app (the app executable, the daemon, the
# CLI and anything else Tauri placed), in every architecture (release
# checklist items 2, 3, 14, 15 and 16):
#
# - `codesign --verify --strict` accepts it, and `lipo -archs` shows both
#   arm64 and x86_64.
# - The hardened runtime flag is set, and `codesign -d --entitlements -` shows
#   none.
# - The daemon `agentsweepd` has the identifier `de.byte5.agentsweep.daemon`,
#   which codesign takes from the Info.plist the daemon binary embeds, since
#   Tauri signs sidecars without naming an identifier.
# - Release mode only: `Timestamp=` is present, the signature is not ad hoc,
#   its first authority is the identity given, a Team ID is set and is the same
#   on every binary, and the daemon's designated requirement (`codesign -d
#   -r-`) names its identifier (ad hoc code gets a cdhash requirement instead).
#
# Read off the bytes of every Mach-O, in every architecture, without running
# it (release checklist items 14 and 17, spec section 9.8 item 2):
#
# - No development Rule Pack public key: a build with the core's test-only
#   `development-keys` feature pins the development pairs, whose secret halves
#   are in the repository, and carries their public keys.
# - The daemon carries a filled Team ID in its peer check, the record
#   `agentsweep-team-id=<Team ID>;` the check reads at run time. A daemon
#   without one admits nobody. In release mode it must be the Team ID the
#   identity names, so a daemon built for another team is refused too.
# - Release mode only: no development updater public key. The app pins the
#   updater key from `tauri.conf.json`, and only an ad hoc CI bundle merges
#   in the development override, whose secret half is in the repository.
#
# Then `codesign --verify --deep --strict` accepts the app. Given a DMG, the
# DMG itself must be signed. In release mode the DMG must also be stapled
# (`xcrun stapler validate`), and `spctl -a -vv` must accept the app as an
# executable and the DMG by its primary signature as a file to open.
#
# Ad hoc mode skips exactly the checks an ad hoc identity or the ad hoc CI
# bundle cannot pass, and says so.

set -eu

daemon_identifier="de.byte5.agentsweep.daemon"

# The development public keys, whose secret halves are committed for the tests:
# the Rule Pack pairs of the core's `development::KEYS`, and the updater pair
# of the override under `apps/menubar/development-keys/`, both as the
# configuration value and as the bare key line. A test of the build tool
# holds these lists to those sources.
development_rule_pack_keys="RWTZoZrRXs0kE+haygvOOKaRDbtDUSc8L5YKr/o+X3VsI5peZv07AXaL RWRNqibQ4kJKgnptbB11DaW4nFmh3O4rwaSlLf76s9ut12aQ3XX7o9KL"
development_updater_keys="dW50cnVzdGVkIGNvbW1lbnQ6IEFnZW50U3dlZXAgdXBkYXRlciBERVZFTE9QTUVOVCBwdWJsaWMga2V5ClJXVE5wUUsyM1R2VkJCSlBEdVB4Z3BZQXl4bnl6RGxhT1FmR2pJSit4OXd2QkJBWG9uT01hci9lCg== RWTNpQK23TvVBBJPDuPxgpYAyxnyzDlaOQfGjIJ+x9wvBBAXonOMar/e"

# The record of the Team ID the daemon's peer check reads, around the Team ID.
team_id_record_prefix="agentsweep-team-id="
team_id_record_suffix=";"

if [ "$#" -ne 2 ] || [ -z "$1" ] || [ -z "$2" ]; then
	echo "usage: check-bundle-signature.sh <identity> <bundle>" >&2
	echo "  identity is \"-\" for ad hoc mode, otherwise the signing identity (release mode)" >&2
	exit 2
fi
identity="$1"
bundle="$2"
if [ "$identity" = "-" ]; then
	mode="ad hoc"
else
	mode="release"
fi
# The Team ID a Developer ID identity names at its end, "(<Team ID>)".
identity_team="$(echo "$identity" | sed -n 's/.*(\([A-Z0-9]\{10\}\))$/\1/p')"

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

# Checks the signature of a DMG itself, before it is mounted.
check_dmg() {
	dmg="$1"
	label="$(basename "$dmg")"
	details="$(codesign -dvv "$dmg" 2>&1)" || {
		fail "$label is not signed"
		return
	}
	echo "$label: signed, $(echo "$details" | sed -n 's/^Signature=//p;s/^Authority=//p' | head -n 1)"
	codesign --verify --strict "$dmg" 2>/dev/null || fail "$label does not verify: codesign --verify --strict refuses it"
	if [ "$mode" = "release" ]; then
		case "$(echo "$details" | sed -n 's/^Signature=//p')" in
		adhoc) fail "$label is signed ad hoc, not with $identity" ;;
		esac
		xcrun stapler validate "$dmg" >/dev/null 2>&1 ||
			fail "$label has no ticket stapled: xcrun stapler validate refuses it"
		assessment="$(spctl -a -vv -t open --context context:primary-signature "$dmg" 2>&1)" ||
			fail "spctl refuses $label: $(echo "$assessment" | tr '\n' ' ')"
	fi
}

# Finds the app inside whatever was given.
case "$bundle" in
*.app | *.app/)
	app="${bundle%/}"
	;;
*.dmg)
	check_dmg "$bundle"
	mounted="$work/mount"
	mkdir "$mounted"
	if ! hdiutil attach -quiet -readonly -nobrowse -noautoopen -noverify -mountpoint "$mounted" "$bundle"; then
		mounted=""
		echo "cannot mount $bundle" >&2
		exit 1
	fi
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
echo "Checking $app ($mode mode, identity: $identity)"

: >"$work/team-ids"
: >"$work/compiled-team-ids"

# Checks what one architecture of a Mach-O carries, read as bytes and never
# run: no development public key, and for the daemon a filled Team ID.
check_contents() {
	contents_binary="$1"
	contents_arch="$2"
	contents_label="$3"
	contents_relative="$4"
	piece="$work/piece"
	rm -f "$piece"
	lipo "$contents_binary" -thin "$contents_arch" -output "$piece" 2>/dev/null ||
		cp "$contents_binary" "$piece"
	for key in $development_rule_pack_keys; do
		if LC_ALL=C grep -a -q -F -- "$key" "$piece"; then
			fail "$contents_label carries the development Rule Pack public key $key: it was built with the core's development-keys feature"
		fi
	done
	if [ "$mode" = "release" ]; then
		for key in $development_updater_keys; do
			if LC_ALL=C grep -a -q -F -- "$key" "$piece"; then
				fail "$contents_label carries the development updater public key: it was built with the development override"
				break
			fi
		done
	fi
	if [ "$contents_relative" = "Contents/MacOS/agentsweepd" ]; then
		records="$(LC_ALL=C grep -a -o -- "$team_id_record_prefix[A-Z0-9]*$team_id_record_suffix" "$piece" | LC_ALL=C sort -u)" || true
		case "$(echo "$records" | grep -c .)" in
		0)
			fail "$contents_label carries no Team ID in its peer check, so it admits nobody"
			;;
		1)
			compiled="${records#"$team_id_record_prefix"}"
			compiled="${compiled%"$team_id_record_suffix"}"
			if [ -z "$compiled" ]; then
				fail "$contents_label was built with an empty Team ID in its peer check, so it admits nobody"
			elif [ "${#compiled}" -ne 10 ]; then
				fail "$contents_label was built with \"$compiled\" in its peer check, which is not a Team ID"
			else
				echo "$contents_label: built with Team ID $compiled in its peer check"
				printf '%s\t%s\n' "$compiled" "$contents_label" >>"$work/compiled-team-ids"
			fi
			;;
		*)
			fail "$contents_label carries more than one Team ID record: $(echo "$records" | tr '\n' ' ')"
			;;
		esac
	fi
}

# Checks one signed code object in one architecture.
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

	if [ "$mode" = "release" ]; then
		case "$flags" in
		*adhoc*) fail "$label is signed ad hoc, not with $identity" ;;
		esac
		echo "$details" | grep -q '^Timestamp=' || fail "$label carries no Timestamp="
		authority="$(echo "$details" | sed -n 's/^Authority=//p' | head -n 1)"
		if [ "$authority" != "$identity" ]; then
			fail "$label is signed by \"$authority\", not \"$identity\""
		fi
		team="$(echo "$details" | sed -n 's/^TeamIdentifier=//p')"
		if [ -z "$team" ] || [ "$team" = "not set" ]; then
			fail "$label carries no Team ID"
		else
			printf '%s\t%s\n' "$team" "$label" >>"$work/team-ids"
		fi
	fi
}

# Every Mach-O inside the app, found by its file type without running it.
find "$app" -type f | LC_ALL=C sort >"$work/files"
: >"$work/machos"
while IFS= read -r file; do
	case "$(file -b "$file")" in
	*Mach-O*) echo "$file" >>"$work/machos" ;;
	esac
done <"$work/files"

while IFS= read -r binary; do
	relative="${binary#"$app"/}"
	archs="$(lipo -archs "$binary" 2>/dev/null)" || {
		fail "$relative cannot be read by lipo"
		continue
	}
	for wanted in arm64 x86_64; do
		case " $archs " in
		*" $wanted "*) ;;
		*) fail "$relative is not universal: lipo -archs shows \"$archs\", without $wanted" ;;
		esac
	done
	codesign --verify --strict --all-architectures "$binary" 2>/dev/null ||
		fail "$relative does not verify: codesign --verify --strict refuses it"
	for arch in $archs; do
		check_code "$binary" "$arch" "$relative ($arch)"
		check_contents "$binary" "$arch" "$relative ($arch)" "$relative"
		if [ "$relative" = "Contents/MacOS/agentsweepd" ]; then
			identifier="$(codesign -dvv --arch "$arch" "$binary" 2>&1 | sed -n 's/^Identifier=//p')"
			if [ "$identifier" != "$daemon_identifier" ]; then
				fail "$relative ($arch) has the identifier \"$identifier\", not \"$daemon_identifier\""
			fi
			if [ "$mode" = "release" ]; then
				codesign -d -r- --arch "$arch" "$binary" 2>/dev/null | grep -q "identifier \"$daemon_identifier\"" ||
					fail "$relative ($arch) has a designated requirement that does not name \"$daemon_identifier\""
			fi
		fi
	done
done <"$work/machos"

if [ ! -f "$app/Contents/MacOS/agentsweepd" ]; then
	fail "the bundle carries no daemon at Contents/MacOS/agentsweepd"
fi
if [ ! -f "$app/Contents/MacOS/agentsweep" ]; then
	fail "the bundle carries no CLI at Contents/MacOS/agentsweep"
fi

if [ "$mode" = "release" ]; then
	reference="$(cut -f 1 "$work/team-ids" | sort | uniq -c | sort -rn | awk 'NR == 1 { print $2 }')"
	while IFS="$(printf '\t')" read -r team label; do
		if [ "$team" != "$reference" ]; then
			fail "$label carries the Team ID $team, not $reference like the rest of the bundle"
		fi
	done <"$work/team-ids"
	# The daemon's peer check must admit what the bundle is signed with: the
	# Team ID the identity names, or failing that the bundle's own.
	expected="${identity_team:-$reference}"
	if [ -z "$expected" ]; then
		fail "neither the identity nor the signatures name a Team ID to hold the daemon's peer check to"
	else
		while IFS="$(printf '\t')" read -r team label; do
			if [ "$team" != "$expected" ]; then
				fail "$label was built with Team ID $team in its peer check, not $expected, the Team ID it is signed with"
			fi
		done <"$work/compiled-team-ids"
	fi
fi

codesign --verify --deep --strict "$app" 2>/dev/null || fail "codesign --verify --deep --strict refuses the app"

if [ "$mode" = "release" ]; then
	assessment="$(spctl -a -vv -t exec "$app" 2>&1)" ||
		fail "spctl refuses the app: $(echo "$assessment" | tr '\n' ' ')"
else
	echo "Skipped in ad hoc mode, which an ad hoc identity cannot pass:"
	echo "  - Timestamp= on every binary"
	echo "  - the signing authority, and no ad hoc signature"
	echo "  - a Team ID, the same on every binary"
	echo "  - the daemon's identifier in its designated requirement"
	echo "  - the daemon's compiled Team ID against the identity's (it is checked to be filled)"
	echo "  - no development updater public key (the ad hoc CI bundle pins it through its override)"
	echo "  - the DMG's staple (xcrun stapler validate)"
	echo "  - Gatekeeper's assessment of the app and the DMG (spctl -a -vv)"
fi

if [ "$failures" -ne 0 ]; then
	echo "$failures check(s) failed for $bundle" >&2
	exit 1
fi
echo "Every check passed for $bundle"
