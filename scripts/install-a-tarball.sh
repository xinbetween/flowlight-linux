#!/usr/bin/env bash
#
# Unpacks the tarball and runs its installer, inside whatever distribution this is.
#
# The tarball is for machines nobody has packaged, so what is checked is what somebody there would do: unpack,
# run the installer, find the binary where it said, find the unit not enabled, and take it off again.
set -euo pipefail

tarball=${1:?usage: install-a-tarball.sh <path to tarball>}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

name=$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$ID}") || echo "an unnamed distribution")
echo "== $name, from the tarball"

work=$(mktemp -d)
tar -xzf "$tarball" -C "$work"
directory=$(find "$work" -maxdepth 1 -mindepth 1 -type d | head -1)
test -n "$directory" || fail "the tarball has no directory in it"

# Four files and nothing else. A tarball that carries more than it says it does is one nobody can undo.
echo "--- what is in it"
ls -1 "$directory"
for expected in flowlightd flowlightd.service install.sh LICENSE README; do
    test -e "$directory/$expected" || fail "the tarball is missing $expected"
done

( cd "$directory" && ./install.sh ) || fail "the installer failed on $name"

test -x /usr/sbin/flowlightd || fail "the daemon is not where the installer said it would be"
/usr/sbin/flowlightd --version || fail "the daemon does not run on $name"
test -f /usr/lib/systemd/system/flowlightd.service || fail "the unit was not installed"
if ls /etc/systemd/system/multi-user.target.wants/flowlightd.service >/dev/null 2>&1; then
    fail "the unit is enabled; an installer must not start this"
fi

( cd "$directory" && ./install.sh --uninstall ) || fail "the uninstaller failed on $name"
test ! -x /usr/sbin/flowlightd || fail "the binary is still here after it was uninstalled"
test ! -f /usr/lib/systemd/system/flowlightd.service || fail "the unit is still here after it was uninstalled"

echo "OK: on $name the tarball installs, does not enable itself, and comes off again"
