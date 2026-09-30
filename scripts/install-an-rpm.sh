#!/usr/bin/env bash
#
# Installs the daemon's `.rpm` inside whatever distribution this is running in, and checks that everything the
# package claims about itself is true.
#
# Run in a container of Fedora and of openSUSE, because one `.rpm` that installs on Fedora is not one that
# installs on openSUSE until it has.
set -euo pipefail

package=${1:?usage: install-an-rpm.sh <path to .rpm>}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

name=$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$ID}") || echo "an unnamed distribution")
echo "== $name"

rpm -i "$package" || fail "the package would not install on $name"

# No dependencies, because a statically linked binary has none. `rpmlib(...)` entries are RPM's own format
# requirements rather than anything that has to be installed, so they are not what this is about.
declared=$(rpm -q --requires flowlight | grep -v '^rpmlib' | grep -v '^$' || true)
if [ -n "$declared" ]; then
    echo "$declared"
    fail "the package declares a dependency it does not have"
fi

test -x /usr/sbin/flowlightd || fail "the daemon is not where the package said it would be"
/usr/sbin/flowlightd --version || fail "the daemon does not run on $name"

test -f /usr/lib/systemd/system/flowlightd.service || fail "the unit file was not installed"
# A container has no running systemd to ask whether the unit is enabled, so this asks the filesystem the same
# question: enabling a unit is a symlink into a `.wants` directory, and there must not be one.
if ls /etc/systemd/system/multi-user.target.wants/flowlightd.service >/dev/null 2>&1; then
    fail "the unit is enabled; a package must not start this"
fi

rpm -e flowlight || fail "the package would not come off again"
test ! -x /usr/sbin/flowlightd || fail "the binary is still here after the package was removed"

echo "OK: on $name the package installs, declares nothing, does not enable itself, and comes off again"
