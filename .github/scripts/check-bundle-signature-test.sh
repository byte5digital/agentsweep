#!/bin/sh
# Tests the release bundle checker on small fixture bundles built and signed ad
# hoc in a temporary directory, the way Tauri signs: each sidecar with the
# hardened runtime and no identifier, then the app. Every fixture executable is
# universal (arm64 plus x86_64), and every one is a tripwire: run, it leaves a
# marker file and exits non-zero, so the last case proves the checker never
# executed a binary of a bundle under inspection. The fixture daemon embeds the
# daemon's own Info.plist from crates/daemon, so a change there that loses the
# frozen identifier fails here too. `spctl` is replaced by a stand-in that
# records its arguments and rejects, so no case asks Gatekeeper anything or
# reaches the network. Nothing is installed or opened; the DMG cases mount a
# fixture image read-only and detach it.
#
# Usage: check-bundle-signature-test.sh

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
check="$here/check-bundle-signature.sh"
daemon_plist="$root/crates/daemon/Info.plist"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

marker="$work/a-bundle-binary-ran"
# CARRIES is text the binary holds among its bytes, the way a Rust binary
# holds its string constants: a Team ID record or a development public key.
cat >"$work/tripwire.c" <<EOF
#include <stdio.h>
#ifndef CARRIES
#define CARRIES ""
#endif
static const char carries[] = CARRIES;
int main(void) {
	FILE *f = fopen("$marker", "a");
	if (f) { fputs("ran\n", f); fputs(carries, f); fclose(f); }
	return 1;
}
EOF
universal="-arch arm64 -arch x86_64"
plist="-Wl,-sectcreate,__TEXT,__info_plist,$daemon_plist"
# The daemon a release build makes carries its Team ID record; the fixture
# identity of the release mode cases names the same Team ID.
team_record="agentsweep-team-id=ABCDE12345;"
development_rule_pack_key="RWRNqibQ4kJKgnptbB11DaW4nFmh3O4rwaSlLf76s9ut12aQ3XX7o9KL"
development_updater_key="dW50cnVzdGVkIGNvbW1lbnQ6IEFnZW50U3dlZXAgdXBkYXRlciBERVZFTE9QTUVOVCBwdWJsaWMga2V5ClJXVE5wUUsyM1R2VkJCSlBEdVB4Z3BZQXl4bnl6RGxhT1FmR2pJSit4OXd2QkJBWG9uT01hci9lCg=="
# Builds a universal tripwire at $1 carrying $2, with further cc options after.
tripwire() {
	out="$1"
	text="$2"
	shift 2
	# shellcheck disable=SC2086 # the architectures are words on purpose
	cc $universal -DCARRIES="\"$text\"" -o "$out" "$work/tripwire.c" "$@"
}
tripwire "$work/plain" ""
tripwire "$work/daemon" "$team_record" "$plist"
tripwire "$work/daemon-no-team" "" "$plist"
tripwire "$work/daemon-empty-team" "agentsweep-team-id=;" "$plist"
tripwire "$work/daemon-other-team" "agentsweep-team-id=ZZZZZ99999;" "$plist"
tripwire "$work/daemon-development-key" "$team_record $development_rule_pack_key" "$plist"
tripwire "$work/cli-development-key" "$development_rule_pack_key"
tripwire "$work/app-development-updater-key" "$development_updater_key"
cc -arch "$(uname -m)" -o "$work/thin-binary" "$work/tripwire.c"

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

# The stand-in for spctl: it notes each call and rejects, as Gatekeeper
# rejects an ad hoc signature.
mkdir "$work/bin"
cat >"$work/bin/spctl" <<EOF
#!/bin/sh
echo "\$*" >>"$work/spctl-calls"
echo "\$*: rejected"
echo "source=no usable signature"
exit 3
EOF
chmod +x "$work/bin/spctl"
PATH="$work/bin:$PATH"
export PATH

# Builds a fixture AgentSweep.app at $1. The remaining arguments change it:
# "bare-daemon" gives the daemon no Info.plist, "daemon-no-team",
# "daemon-empty-team" and "daemon-other-team" give it no Team ID record, an
# empty one or another team's, "daemon-development-key" and
# "cli-development-key" put a development Rule Pack public key in the daemon
# or the CLI, "app-development-updater-key" puts the development updater
# public key in the app executable, "daemon-other-identifier" signs
# the daemon with another identifier, "cli-entitlements" signs the CLI with an
# entitlement, "thin-cli" gives the CLI one architecture only,
# "cli-resigned-without-runtime" re-signs the CLI without the hardened runtime
# after the app was signed.
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
	*" daemon-no-team "*) cp "$work/daemon-no-team" "$app/Contents/MacOS/agentsweepd" ;;
	*" daemon-empty-team "*) cp "$work/daemon-empty-team" "$app/Contents/MacOS/agentsweepd" ;;
	*" daemon-other-team "*) cp "$work/daemon-other-team" "$app/Contents/MacOS/agentsweepd" ;;
	*" daemon-development-key "*) cp "$work/daemon-development-key" "$app/Contents/MacOS/agentsweepd" ;;
	esac
	case " $* " in
	*" thin-cli "*) cp "$work/thin-binary" "$app/Contents/MacOS/agentsweep" ;;
	*" cli-development-key "*) cp "$work/cli-development-key" "$app/Contents/MacOS/agentsweep" ;;
	esac
	case " $* " in
	*" app-development-updater-key "*)
		cp "$work/app-development-updater-key" "$app/Contents/MacOS/agentsweep-menubar"
		;;
	esac

	daemon_identifier=""
	case " $* " in
	*" daemon-other-identifier "*) daemon_identifier="-i de.byte5.agentsweep.other" ;;
	esac
	# shellcheck disable=SC2086 # the options are words on purpose
	codesign --force -s - --options runtime $daemon_identifier "$app/Contents/MacOS/agentsweepd" 2>/dev/null

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
	*" cli-resigned-without-runtime "*)
		codesign --force -s - "$app/Contents/MacOS/agentsweep" 2>/dev/null
		;;
	esac
}

failures=0

# Runs the checker with the given arguments and expects the exit status $2
# and, when $3 is not empty, that text in its output. The output is kept in
# $output for further assertions.
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

# Expects the text $2 in the output of the last expect call.
also() {
	if echo "$output" | grep -qF -- "$2"; then
		echo "ok: $1"
	else
		echo "not ok: $1: output lacks \"$2\"" >&2
		echo "$output" | sed 's/^/    /' >&2
		failures=$((failures + 1))
	fi
}

# Expects the text $2 nowhere in the output of the last expect call.
lacks() {
	if echo "$output" | grep -qF -- "$2"; then
		echo "not ok: $1: output holds \"$2\"" >&2
		echo "$output" | sed 's/^/    /' >&2
		failures=$((failures + 1))
	else
		echo "ok: $1"
	fi
}

for fixture in good bare other-identifier entitled thin no-runtime several \
	no-team empty-team other-team daemon-key cli-key updater-key; do
	mkdir "$work/$fixture"
done
make_app "$work/no-team/AgentSweep.app" daemon-no-team
make_app "$work/empty-team/AgentSweep.app" daemon-empty-team
make_app "$work/other-team/AgentSweep.app" daemon-other-team
make_app "$work/daemon-key/AgentSweep.app" daemon-development-key
make_app "$work/cli-key/AgentSweep.app" cli-development-key
make_app "$work/updater-key/AgentSweep.app" app-development-updater-key
make_app "$work/good/AgentSweep.app"
make_app "$work/bare/AgentSweep.app" bare-daemon
make_app "$work/other-identifier/AgentSweep.app" daemon-other-identifier
make_app "$work/entitled/AgentSweep.app" cli-entitlements
make_app "$work/thin/AgentSweep.app" thin-cli
make_app "$work/no-runtime/AgentSweep.app" cli-resigned-without-runtime
make_app "$work/several/AgentSweep.app" thin-cli cli-entitlements daemon-other-identifier

tar -czf "$work/AgentSweep.app.tar.gz" -C "$work/good" AgentSweep.app
hdiutil create -quiet -srcfolder "$work/good" -format UDZO "$work/AgentSweep.dmg"
codesign -s - "$work/AgentSweep.dmg" 2>/dev/null
hdiutil create -quiet -srcfolder "$work/good" -format UDZO "$work/unsigned.dmg"

cli="Contents/MacOS/agentsweep"
daemon="Contents/MacOS/agentsweepd"
arch="$(uname -m)"

expect "refuses to run without arguments" 2 "usage:"
expect "refuses to run without an identity" 2 "usage:" "$work/good/AgentSweep.app"
expect "refuses an empty identity" 2 "usage:" "" "$work/good/AgentSweep.app"
expect "refuses a bundle that is not there" 2 "no such bundle" - "$work/missing/AgentSweep.app"

expect "accepts the ad hoc app" 0 "Every check passed" - "$work/good/AgentSweep.app"
also "names each Mach-O it checks" "$daemon (x86_64)"
also "lists what ad hoc mode skips" "Skipped in ad hoc mode"
also "skips the timestamp in ad hoc mode" "Timestamp="
also "skips the Team ID in ad hoc mode" "Team ID"
also "skips the staple in ad hoc mode" "stapler validate"
also "skips Gatekeeper in ad hoc mode" "spctl"
expect "accepts the ad hoc updater archive" 0 "Every check passed" - "$work/AgentSweep.app.tar.gz"
expect "accepts the ad hoc signed DMG" 0 "Every check passed" - "$work/AgentSweep.dmg"
also "checks the DMG's own signature" "AgentSweep.dmg: signed"
expect "refuses an unsigned DMG" 1 "unsigned.dmg is not signed" - "$work/unsigned.dmg"

expect "refuses a daemon without its Info.plist" 1 \
	"$daemon ($arch) has the identifier" - "$work/bare/AgentSweep.app"
expect "refuses a daemon with a different identifier" 1 \
	"$daemon ($arch) has the identifier \"de.byte5.agentsweep.other\", not \"de.byte5.agentsweep.daemon\"" \
	- "$work/other-identifier/AgentSweep.app"
expect "refuses an entitlement on a sidecar" 1 \
	"$cli ($arch) carries entitlements" - "$work/entitled/AgentSweep.app"
expect "refuses a thin sidecar" 1 \
	"$cli is not universal" - "$work/thin/AgentSweep.app"
expect "refuses a sidecar re-signed without the hardened runtime" 1 \
	"$cli ($arch) lacks the hardened runtime" - "$work/no-runtime/AgentSweep.app"
also "names the sidecar whose signature no longer verifies in the app" \
	"codesign --verify --deep --strict refuses the app"

expect "reports every miss at once" 1 "4 check(s) failed" - "$work/several/AgentSweep.app"
also "reports the thin sidecar among several misses" "$cli is not universal"
also "reports the entitlement among several misses" "$cli ($arch) carries entitlements"
also "reports the daemon's identifier among several misses" "$daemon ($arch) has the identifier"

# What the binaries carry, read off their bytes in both modes.
expect "names the Team ID the daemon was built with" 0 \
	"$daemon (x86_64): built with Team ID ABCDE12345 in its peer check" - "$work/good/AgentSweep.app"
also "reads the Team ID in each architecture" "$daemon (arm64): built with Team ID ABCDE12345"
expect "refuses a daemon built without a Team ID" 1 \
	"$daemon ($arch) carries no Team ID in its peer check" - "$work/no-team/AgentSweep.app"
expect "refuses a daemon built with an empty Team ID" 1 \
	"$daemon ($arch) was built with an empty Team ID" - "$work/empty-team/AgentSweep.app"
expect "refuses a daemon carrying a development Rule Pack public key" 1 \
	"$daemon ($arch) carries the development Rule Pack public key $development_rule_pack_key" \
	- "$work/daemon-key/AgentSweep.app"
expect "refuses a CLI carrying a development Rule Pack public key" 1 \
	"$cli ($arch) carries the development Rule Pack public key $development_rule_pack_key" \
	- "$work/cli-key/AgentSweep.app"
expect "leaves the development updater key to release mode" 0 \
	"Every check passed" - "$work/updater-key/AgentSweep.app"
also "lists the development updater key among what ad hoc mode skips" \
	"no development updater public key"

if [ -e "$work/spctl-calls" ]; then
	echo "not ok: ad hoc mode asked spctl: $(cat "$work/spctl-calls")" >&2
	failures=$((failures + 1))
else
	echo "ok: ad hoc mode never asks spctl"
fi

# No real identity exists here, so the release mode is tested on what it
# refuses: an ad hoc bundle lacks the timestamp, the Team ID, the staple, the
# authority and the identifier-based designated requirement a real identity
# gives, and Gatekeeper (the stand-in) rejects it.
identity="Developer ID Application: Example (ABCDE12345)"
expect "demands Timestamp= in release mode" 1 \
	"$daemon ($arch) carries no Timestamp=" "$identity" "$work/AgentSweep.dmg"
also "demands a Team ID in release mode" "$daemon ($arch) carries no Team ID"
also "demands the staple in release mode" "AgentSweep.dmg has no ticket stapled"
also "demands the real identity's authority" "not \"$identity\""
also "refuses ad hoc signatures in release mode" "is signed ad hoc"
also "demands the identifier in the designated requirement" "designated requirement that does not name"
also "asks Gatekeeper about the app" "spctl refuses the app"
also "asks Gatekeeper about the DMG" "spctl refuses AgentSweep.dmg"
lacks "takes the daemon's compiled Team ID when the identity names it" "in its peer check, not"
lacks "finds no development Rule Pack public key in a build without one" "development Rule Pack public key"
lacks "finds no development updater public key in a build without one" "development updater public key"
lacks "reports nothing as not yet checkable" "NOT YET CHECKABLE"

expect "refuses a daemon built for another Team ID in release mode" 1 \
	"$daemon ($arch) was built with Team ID ZZZZZ99999 in its peer check, not ABCDE12345" \
	"$identity" "$work/other-team/AgentSweep.app"
expect "refuses the development updater public key in release mode" 1 \
	"Contents/MacOS/agentsweep-menubar ($arch) carries the development updater public key" \
	"$identity" "$work/updater-key/AgentSweep.app"
expect "refuses a development Rule Pack public key in release mode too" 1 \
	"$cli ($arch) carries the development Rule Pack public key" \
	"$identity" "$work/cli-key/AgentSweep.app"
if grep -q -- "^-a -vv -t exec .*/AgentSweep.app$" "$work/spctl-calls" 2>/dev/null; then
	echo "ok: assesses the app as an executable"
else
	echo "not ok: assesses the app as an executable: $(cat "$work/spctl-calls")" >&2
	failures=$((failures + 1))
fi
if grep -q -- "^-a -vv -t open --context context:primary-signature .*/AgentSweep.dmg$" "$work/spctl-calls" 2>/dev/null; then
	echo "ok: assesses the DMG by its primary signature"
else
	echo "not ok: assesses the DMG by its primary signature: $(cat "$work/spctl-calls")" >&2
	failures=$((failures + 1))
fi

if [ -e "$marker" ]; then
	echo "not ok: a binary of a bundle under inspection was executed" >&2
	failures=$((failures + 1))
else
	echo "ok: no binary of a bundle under inspection was executed"
fi

if [ "$failures" -ne 0 ]; then
	echo "$failures case(s) failed" >&2
	exit 1
fi
echo "All cases passed"
