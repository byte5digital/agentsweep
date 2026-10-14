#!/bin/sh
# Tests the bundle signature check on small fixture bundles built and signed ad
# hoc in a temporary directory, the way Tauri signs: each sidecar with the
# hardened runtime and no identifier, then the app. The fixture daemon embeds
# the daemon's own Info.plist from crates/daemon, so a change there that loses
# the frozen identifier fails here too. Nothing is installed or opened; the DMG
# case mounts a fixture image read-only and detaches it.
#
# Usage: check-bundle-signature-test.sh

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
check="$here/check-bundle-signature.sh"
daemon_plist="$root/crates/daemon/Info.plist"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

printf 'int main(void) { return 0; }\n' >"$work/main.c"
cc -o "$work/plain" "$work/main.c"
cc -o "$work/daemon" "$work/main.c" -Wl,-sectcreate,__TEXT,__info_plist,"$daemon_plist"

cat >"$work/entitlements.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.cs.allow-unsigned-executable-memory</key>
	<true/>
</dict>
</plist>
EOF

# Builds a fixture AgentSweep.app at $1. The remaining arguments change it:
# "bare-daemon" gives the daemon no Info.plist, "cli-entitlements" signs the
# CLI with an entitlement, "daemon-without-runtime" signs the daemon without
# the hardened runtime, "unsigned-after-daemon" re-signs the daemon after the
# app was signed.
make_app() {
	app="$1"
	shift
	mkdir -p "$app/Contents/MacOS"
	cat >"$app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>agentsweep-menubar</string>
	<key>CFBundleIdentifier</key>
	<string>de.byte5.agentsweep</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
</dict>
</plist>
EOF
	cp "$work/plain" "$app/Contents/MacOS/agentsweep-menubar"
	cp "$work/plain" "$app/Contents/MacOS/agentsweep"
	cp "$work/daemon" "$app/Contents/MacOS/agentsweepd"
	case " $* " in
	*" bare-daemon "*) cp "$work/plain" "$app/Contents/MacOS/agentsweepd" ;;
	esac

	daemon_options="--options runtime"
	case " $* " in
	*" daemon-without-runtime "*) daemon_options="" ;;
	esac
	# shellcheck disable=SC2086 # the options are words on purpose
	codesign --force -s - $daemon_options "$app/Contents/MacOS/agentsweepd" 2>/dev/null

	case " $* " in
	*" cli-entitlements "*)
		codesign --force -s - --options runtime --entitlements "$work/entitlements.plist" \
			"$app/Contents/MacOS/agentsweep" 2>/dev/null
		;;
	*)
		codesign --force -s - --options runtime "$app/Contents/MacOS/agentsweep" 2>/dev/null
		;;
	esac
	codesign --force -s - --options runtime "$app" 2>/dev/null

	case " $* " in
	*" unsigned-after-daemon "*)
		codesign --force -s - --options runtime -i "de.byte5.agentsweep.other" \
			"$app/Contents/MacOS/agentsweepd" 2>/dev/null
		;;
	esac
}

failures=0

# Runs the check with the given arguments and expects the exit status $1 and,
# when $2 is not empty, that text in its output.
expect() {
	name="$1"
	want_status="$2"
	want_text="$3"
	shift 3
	status=0
	output="$("$check" "$@" 2>&1)" || status=$?
	if [ "$status" -ne "$want_status" ]; then
		echo "not ok: $name: exit status $status, wanted $want_status" >&2
		echo "$output" | sed 's/^/    /' >&2
		failures=$((failures + 1))
		return
	fi
	if [ -n "$want_text" ] && ! echo "$output" | grep -qF -- "$want_text"; then
		echo "not ok: $name: output lacks \"$want_text\"" >&2
		echo "$output" | sed 's/^/    /' >&2
		failures=$((failures + 1))
		return
	fi
	echo "ok: $name"
}

mkdir "$work/good" "$work/bare" "$work/entitled" "$work/no-runtime" "$work/stale"
make_app "$work/good/AgentSweep.app"
make_app "$work/bare/AgentSweep.app" bare-daemon
make_app "$work/entitled/AgentSweep.app" cli-entitlements
make_app "$work/no-runtime/AgentSweep.app" daemon-without-runtime
make_app "$work/stale/AgentSweep.app" unsigned-after-daemon

tar -czf "$work/AgentSweep.app.tar.gz" -C "$work/good" AgentSweep.app
hdiutil create -quiet -srcfolder "$work/good" -format UDZO "$work/AgentSweep.dmg"

expect "refuses to run without arguments" 2 "usage:"
expect "refuses to run without an identity" 2 "usage:" "$work/good/AgentSweep.app"
expect "refuses an empty identity" 2 "usage:" "" "$work/good/AgentSweep.app"
expect "refuses a bundle that is not there" 2 "no such bundle" - "$work/missing/AgentSweep.app"

expect "accepts the ad hoc app" 0 "agentsweepd (" - "$work/good/AgentSweep.app"
expect "accepts the ad hoc updater archive" 0 "Every check passed" - "$work/AgentSweep.app.tar.gz"
expect "accepts the ad hoc DMG" 0 "Every check passed" - "$work/AgentSweep.dmg"

expect "refuses a daemon without its Info.plist" 1 \
	"not \"de.byte5.agentsweep.daemon\"" - "$work/bare/AgentSweep.app"
expect "refuses entitlements on the CLI" 1 \
	"agentsweep ($(uname -m)) carries entitlements" - "$work/entitled/AgentSweep.app"
expect "refuses a daemon without the hardened runtime" 1 \
	"agentsweepd ($(uname -m)) lacks the hardened runtime" - "$work/no-runtime/AgentSweep.app"
expect "refuses a daemon re-signed after the app" 1 \
	"codesign --verify --deep --strict refuses the app" - "$work/stale/AgentSweep.app"

# No real identity exists here, so the release mode is tested on what it
# refuses: an ad hoc bundle lacks the timestamp, the authority and the
# identifier-based designated requirement a real identity gives.
identity="Developer ID Application: Example (ABCDE12345)"
expect "demands Timestamp= with a real identity" 1 \
	"agentsweepd ($(uname -m)) carries no Timestamp=" "$identity" "$work/good/AgentSweep.app"
expect "demands the real identity's authority" 1 \
	"not \"$identity\"" "$identity" "$work/good/AgentSweep.app"
expect "refuses ad hoc signatures with a real identity" 1 \
	"is signed ad hoc" "$identity" "$work/good/AgentSweep.app"
expect "demands the identifier in the designated requirement" 1 \
	"designated requirement that does not name" "$identity" "$work/good/AgentSweep.app"

if [ "$failures" -ne 0 ]; then
	echo "$failures case(s) failed" >&2
	exit 1
fi
echo "All cases passed"
