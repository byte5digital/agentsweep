#!/bin/sh
# The updater manifest `latest.json` of an app release (spec sections 9.1 and
# 9.4). The release is one universal archive, so both `darwin-aarch64` and
# `darwin-x86_64` name the same archive URL and the same signature, the content
# of the `.sig` Tauri wrote beside the archive. The release workflow writes the
# manifest with this script, checks it with this script before the draft
# exists, and the local dry run does the same.
#
# Usage:
#   updater-manifest.sh write <version> <archive URL> <signature file> <out>
#   updater-manifest.sh check <latest.json> <version> <archive URL> <signature file>
#
# `check` exits 1 with every miss listed when the manifest is not JSON, names
# another version, lacks either darwin key, gives either key no signature, or
# when the two keys do not name the same archive URL and signature as the ones
# given. It needs `plutil`, which reads JSON, so it runs on macOS.

set -eu

usage() {
	echo "usage: updater-manifest.sh write <version> <archive URL> <signature file> <out>" >&2
	echo "       updater-manifest.sh check <latest.json> <version> <archive URL> <signature file>" >&2
	exit 2
}

platforms="darwin-aarch64 darwin-x86_64"

# The signature file holds one line of base64 (a minisign signature, itself
# base64 encoded by Tauri); nothing in it needs escaping in JSON.
read_signature() {
	if [ ! -s "$1" ]; then
		echo "the signature file $1 is missing or empty" >&2
		exit 1
	fi
	signature="$(tr -d '\n\r' <"$1")"
	case "$signature" in
		*[!A-Za-z0-9+/=]*)
			echo "the signature file $1 does not hold base64" >&2
			exit 1
			;;
	esac
}

# A URL or version with a quote, a backslash or a space would need escaping;
# neither ever has one, so either is refused rather than escaped.
plain() {
	case "$2" in
		"" | *[\"\\[:space:]]*)
			echo "the $1 \"$2\" is empty or holds a character JSON would need escaped" >&2
			exit 1
			;;
	esac
}

write() {
	[ "$#" -eq 4 ] || usage
	version="$1" url="$2" out="$4"
	plain version "$version"
	plain "archive URL" "$url"
	read_signature "$3"
	pub_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	entry="{\"signature\": \"$signature\", \"url\": \"$url\"}"
	{
		echo "{"
		echo "  \"version\": \"$version\","
		echo "  \"pub_date\": \"$pub_date\","
		echo "  \"platforms\": {"
		echo "    \"darwin-aarch64\": $entry,"
		echo "    \"darwin-x86_64\": $entry"
		echo "  }"
		echo "}"
	} >"$out"
}

check() {
	[ "$#" -eq 4 ] || usage
	manifest="$1" version="$2" url="$3"
	read_signature "$4"
	if [ ! -f "$manifest" ]; then
		echo "no such manifest: $manifest" >&2
		exit 1
	fi
	if [ "$(plutil -type platforms "$manifest" 2>/dev/null)" != "dictionary" ]; then
		echo "$manifest: not JSON with a platforms object" >&2
		exit 1
	fi
	misses=0
	miss() {
		echo "$manifest: $1" >&2
		misses=$((misses + 1))
	}
	found="$(plutil -extract version raw -o - "$manifest" 2>/dev/null || true)"
	[ "$found" = "$version" ] || miss "names version \"$found\", not $version"
	for platform in $platforms; do
		found_url="$(plutil -extract "platforms.$platform.url" raw -o - "$manifest" 2>/dev/null || true)"
		found_signature="$(plutil -extract "platforms.$platform.signature" raw -o - "$manifest" 2>/dev/null || true)"
		if [ -z "$found_url" ]; then
			miss "$platform names no archive URL"
		elif [ "$found_url" != "$url" ]; then
			miss "$platform names $found_url, not the universal archive $url"
		fi
		if [ -z "$found_signature" ]; then
			miss "$platform carries no signature"
		elif [ "$found_signature" != "$signature" ]; then
			miss "$platform carries a signature other than the one in $4"
		fi
	done
	if [ "$misses" -ne 0 ]; then
		echo "$manifest: $misses miss(es); both darwin keys must name the same universal archive and its signature" >&2
		exit 1
	fi
	echo "$manifest: both darwin keys name $url with its signature"
}

[ "$#" -ge 1 ] || usage
command="$1"
shift
case "$command" in
	write) write "$@" ;;
	check) check "$@" ;;
	*) usage ;;
esac
