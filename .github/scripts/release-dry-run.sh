#!/bin/sh
# A local dry run of the app release workflow (`.github/workflows/app-release.yml`):
# the same scripts, in the same order, with an ad hoc identity, a throwaway
# updater key generated in a temporary directory and no notarization. Every
# step except Apple's and GitHub's runs on a developer's machine: the version
# gate, the universal auditable sidecars, `tauri build` with the app and the
# DMG, the staging of the release assets, the DMG's own signature, the release
# bundle checker in ad hoc mode on the app, the DMG and the updater archive
# (which includes the frozen identifier of the daemon), and the writing and
# checking of `latest.json`.
#
# Usage: release-dry-run.sh [<tag>]
#
#   tag      the tag to pretend was pushed; v<workspace version> by default
#   TARGET   universal-apple-darwin by default, as the release builds; a
#            machine with one Apple target can name that triple, and the
#            checker then reports the missing architecture
#
# Needs the Command Line Tools (26 or later), Node 22 with
# @tauri-apps/cli 2.11.5 in npm's cache, cargo-auditable, and for the
# universal build both Apple targets. It signs nothing with a real identity,
# never touches the Keychain and uploads nothing. Everything it builds goes
# into a temporary directory: the source is copied there, cargo and swift
# build there, and the updater key lives there and is deleted at the end.
# What stays is the release directory it prints, holding the DMG, the updater
# archive, its .sig and latest.json. Not covered: notarization, the staple,
# Gatekeeper (`spctl`), the `Timestamp=` of a Developer ID signature, the
# attestations and the draft itself (docs/hand-checks.md).

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
target="${TARGET:-universal-apple-darwin}"
case "$target" in
	universal-apple-darwin) arch=universal ;;
	aarch64-apple-darwin) arch=aarch64 ;;
	x86_64-apple-darwin) arch=x86_64 ;;
	*)
		echo "release-dry-run.sh: TARGET must be an Apple triple or universal-apple-darwin" >&2
		exit 2
		;;
esac

workspace="$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$root/Cargo.toml")"
tag="${1:-v$workspace}"

work="$(mktemp -d "${TMPDIR:-/tmp}/agentsweep-release-dry-run.XXXXXX")"
release="$work/release"
cleanup() {
	rm -rf "$work/src" "$work/target" "$work/updater-key"
}
trap cleanup EXIT INT TERM
echo "dry run in $work"

step() {
	echo
	echo "== $1"
}

step "Hold the tag to the version gate"
gate="$("$here/release-version-gate.sh" "$tag" "$root")"
echo "$gate"
version="$(echo "$gate" | sed -n 's/^version=//p')"

step "Copy the source into the temporary directory"
rsync -a \
	--exclude /.git --exclude /target --exclude /.scratch --exclude /.claude \
	--exclude node_modules --exclude /apps/menubar/binaries --exclude /apps/menubar/gen \
	--exclude /apps/apple-judge/.build \
	"$root/" "$work/src/"
export CARGO_TARGET_DIR="$work/target"

step "Build the sidecars for $target"
TARGET="$target" "$work/src/apps/menubar/build-sidecars.sh" release

# The Tauri CLI comes from npm's cache, never fetched for this run.
tauri() {
	npm_config_prefer_offline=true npx --yes @tauri-apps/cli@2.11.5 "$@"
}

step "Generate a throwaway updater key"
mkdir -p "$work/updater-key"
tauri signer generate --ci --password "" --write-keys "$work/updater-key/updater.key" >/dev/null

step "Build, sign ad hoc and bundle the app and the DMG"
(
	cd "$work/src/apps/menubar"
	TAURI_SIGNING_PRIVATE_KEY="$(cat "$work/updater-key/updater.key")" \
		TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
		APPLE_SIGNING_IDENTITY="-" \
		CI=true \
		tauri build --target "$target" --bundles app,dmg --config tauri.bundle.conf.json -- --locked
)
bundle="$CARGO_TARGET_DIR/$target/release/bundle"

step "Stage the release assets"
staged="$("$here/stage-release-assets.sh" "$bundle" "$version" "$arch" "$release")"
echo "$staged"
dmg="$(echo "$staged" | sed -n 's/^dmg=//p')"
archive="$(echo "$staged" | sed -n 's/^archive=//p')"
signature="$(echo "$staged" | sed -n 's/^signature=//p')"

step "Sign the DMG ad hoc if Tauri left it unsigned"
"$here/sign-unsigned-dmg.sh" - "$release/$dmg"

step "Skipped: notarize and staple the DMG (Apple's)"

step "Check the app, the DMG and the updater archive in ad hoc mode"
status=0
for subject in "$bundle/macos/AgentSweep.app" "$release/$dmg" "$release/$archive"; do
	"$here/check-bundle-signature.sh" - "$subject" || status=1
done

step "Write and check latest.json"
url="https://github.com/byte5digital/agentsweep/releases/download/$tag/$archive"
"$here/updater-manifest.sh" write "$version" "$url" "$release/$signature" "$release/latest.json"
"$here/updater-manifest.sh" check "$release/latest.json" "$version" "$url" "$release/$signature"

step "Skipped: attestations, the draft and its asset listing (GitHub's)"

echo
ls -l "$release"
if [ "$status" -ne 0 ]; then
	echo "the release bundle checker reported misses; see above" >&2
	exit 1
fi
echo "dry run complete; the release directory is $release"
