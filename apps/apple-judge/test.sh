#!/bin/sh
# Runs the Apple judgement helper's tests. None of them reaches Apple's model:
# the protocol is tested against a fake, so they pass without Apple
# Intelligence. The test that maps the framework's errors needs macOS 26 on
# Apple silicon to construct them and checks nothing elsewhere.
#
# The Command Line Tools ship swift-testing outside the default search paths,
# so with them (and no Xcode) the framework and its interop library are named
# explicitly. With Xcode selected, a plain `swift test` is what runs.

set -eu

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
target_dir="${CARGO_TARGET_DIR:-$root/target}"

set -- --package-path "$here" --scratch-path "$target_dir/apple-judge"
developer="$(xcode-select -p)"
case "$developer" in
  */CommandLineTools)
    frameworks="$developer/Library/Developer/Frameworks"
    libraries="$developer/Library/Developer/usr/lib"
    set -- "$@" -Xswiftc -F -Xswiftc "$frameworks" \
      -Xlinker -F -Xlinker "$frameworks" \
      -Xlinker -rpath -Xlinker "$frameworks" \
      -Xlinker -rpath -Xlinker "$libraries"
    ;;
esac
swift test "$@"
