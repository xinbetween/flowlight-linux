#!/usr/bin/env bash
#
# Builds the window inside whatever distribution this is, packages it there, installs it there, and checks that
# the result actually resolves against that distribution's libraries.
#
# The daemon is statically linked and travels; the window is linked against the system's GTK, libadwaita and
# glibc, so one built anywhere does not run everywhere. The only honest way to package it is to compile it on
# the distribution it is for, which is what this is.
#
# What it proves, and the order is the point:
#
#   1. it compiles there at all — which is also the test of whether that distribution's libadwaita is new
#      enough, and a distribution where it is not is a finding rather than a silence;
#   2. the package's dependencies are what RPM found by scanning the binary, not a list written by hand;
#   3. installed, every shared library it names resolves — `ldd` saying `not found` is the failure this whole
#      release exists to prevent;
#   4. and it runs far enough to answer `--version`, which is before GTK opens anything. A machine in a
#      container has no display, and a loader error happens before a display is ever wanted.
set -euo pipefail

version=${1:?usage: the-window-inside.sh <version> <architecture>}
architecture=${2:?usage: the-window-inside.sh <version> <architecture>}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

name=$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$ID}") || echo "an unnamed distribution")
echo "== building the window inside $name"

if command -v dnf >/dev/null 2>&1; then
    dnf install -y -q gcc rust cargo gtk4-devel libadwaita-devel rpm-build >/dev/null
elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive --quiet install gcc rust cargo gtk4-devel libadwaita-devel rpm-build >/dev/null
else
    fail "this script knows dnf and zypper, and $name has neither"
fi

echo "--- what it will link against"
rustc --version
pkg-config --modversion gtk4 libadwaita-1 || true

# `--locked`, so the versions are the ones this repository has resolved rather than whatever is newest today:
# a window built here and a window built on Ubuntu should be the same program.
cargo build --release --locked --package flowlight-gui \
    || fail "the window does not compile on $name. Its GTK or libadwaita is likely older than this needs."

mkdir -p target/window
install -m 755 target/release/flowlight target/window/flowlight

./packaging/rpm/build.sh --window "$version" "$architecture" target/window target/rpm-gui \
    || fail "the window's package would not build on $name"

package=$(ls target/rpm-gui/flowlight-gui-*"$architecture".rpm | head -1)
echo "--- what the scan found"
rpm -qp --requires "$package" | sed 's/^/    /'

# The libraries it names have to be this distribution's. A package built on Ubuntu would name Ubuntu's, and
# that is the whole failure: `rpm -i` would refuse it here, or install it to be a binary that does not start.
rpm -qp --requires "$package" | grep -q 'libgtk-4.so' \
    || fail "the package does not name GTK, so the dependency scan did not see the binary"
rpm -qp --requires "$package" | grep -q '^flowlight = ' \
    || fail "the window's package does not require the daemon it talks to"

# The daemon first, because the window's package requires it — which is itself the thing being checked.
daemon=$(ls target/rpm/flowlight-"$version"-*"$architecture".rpm 2>/dev/null | head -1)
test -n "$daemon" || fail "no daemon package to install beside it; build that first"
rpm -i "$daemon" "$package" || fail "the two packages would not install together on $name"

test -x /usr/bin/flowlight || fail "the window is not where its package said it would be"
missing=$(ldd /usr/bin/flowlight | grep 'not found' || true)
if [ -n "$missing" ]; then
    echo "$missing"
    fail "the window names libraries that are not on $name"
fi
/usr/bin/flowlight --version || fail "the window does not start far enough to say its version on $name"

rpm -e flowlight-gui flowlight || fail "the packages would not come off again"
echo "OK: on $name the window compiles, names that distribution's own libraries, installs, and runs"
