#!/usr/bin/env bash
#
# Fails when a commit carries no Developer Certificate of Origin sign-off that
# matches its author. Every contribution to AgentSweep is signed off with
# `git commit -s`; the certificate itself is the file DCO in the repository
# root, and there is no CLA.
#
# Usage: dco-check.sh [<base commit>] [<head commit>]
#
# With a base commit the script checks every non-merge commit in
# `<base>..<head>`. Without one, or with a base the checkout does not have (a
# newly pushed branch reports a base of all zeroes), it falls back to the merge
# base with `origin/main`, and failing that to the head commit alone. Merge
# commits are written by the forge, not by a contributor, so they are skipped.

set -euo pipefail

base="${1:-}"
head="${2:-HEAD}"
zeroes="0000000000000000000000000000000000000000"

if [ "${base}" = "${zeroes}" ]; then
	base=""
fi

if [ -n "${base}" ] && ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
	echo "The base commit ${base} is not in this checkout; falling back."
	base=""
fi

if [ -z "${base}" ] && git rev-parse --verify --quiet origin/main >/dev/null; then
	base="$(git merge-base origin/main "${head}" || true)"
fi

if [ -n "${base}" ]; then
	echo "Checking the sign-off on ${base}..${head}"
	commits="$(git rev-list --no-merges "${base}..${head}")"
else
	echo "Checking the sign-off on ${head} alone"
	commits="$(git rev-list --no-merges --max-count=1 "${head}")"
fi

checked=0
missing=0

for sha in ${commits}; do
	checked=$((checked + 1))
	author_name="$(git show --no-patch --format='%an' "${sha}")"
	author_email="$(git show --no-patch --format='%ae' "${sha}")"
	subject="$(git show --no-patch --format='%s' "${sha}")"
	expected="Signed-off-by: ${author_name} <${author_email}>"

	if git show --no-patch --format='%B' "${sha}" |
		sed 's/[[:space:]]*$//' |
		grep -qixF "${expected}"; then
		echo "  ok       ${sha:0:12} ${subject}"
	else
		echo "  MISSING  ${sha:0:12} ${subject}"
		echo "           expected a line reading: ${expected}"
		missing=$((missing + 1))
	fi
done

if [ "${missing}" -gt 0 ]; then
	echo
	echo "Commits checked: ${checked}. Without a sign-off matching the author: ${missing}."
	echo "Sign off with 'git commit -s', or add the line to an existing commit with"
	echo "'git rebase --signoff <base>'. The certificate is the file DCO."
	exit 1
fi

echo
echo "Commits checked: ${checked}. Every one is signed off."
