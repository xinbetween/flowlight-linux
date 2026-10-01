#!/usr/bin/env bash
#
# Builds the Arch package from a tarball on disk and installs it, inside an Arch container.
#
# `makepkg` refuses to run as root, which is correct of it and means this makes a user to run it as. Everything
# else is the same two-part check the other packages get: it builds, and then it installs where it is for.
set -euo pipefail

tarball=${1:?usage: install-on-arch.sh <path to tarball> <version>}
version=${2:?usage: install-on-arch.sh <path to tarball> <version>}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "== Arch Linux"
pacman -Sy --noconfirm --quiet base-devel >/dev/null

# A user for `makepkg`, with no password and the right to install what it built.
id builder >/dev/null 2>&1 || useradd -m builder
echo 'builder ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/builder

work=/home/builder/build
install -d -o builder -g builder "$work"
install -o builder -g builder -m 644 "$tarball" "$work/$(basename "$tarball")"

./packaging/arch/render.sh local "$version" "$work/$(basename "$tarball")" >"$work/PKGBUILD"
chown builder:builder "$work/PKGBUILD"
echo "--- PKGBUILD"
cat "$work/PKGBUILD"

# `--nocheck` has nothing to check and `--noconfirm` because nobody is here to answer. The checksum in the
# PKGBUILD is verified by makepkg itself, which is the one thing in it that could silently be wrong.
su builder -c "cd '$work' && makepkg --noconfirm --nocheck" \
    || fail "makepkg would not build the package"

package=$(ls "$work"/flowlight-bin-*.pkg.tar.* | head -1)
echo "--- built $package"
pacman -U --noconfirm "$package" >/dev/null || fail "pacman would not install the package"

# What the package claims about itself. Arch records dependencies in `.PKGINFO`, and this one has none: a
# statically linked binary needs the kernel, and the kernel is not a package.
declared=$(pacman -Qi flowlight-bin | awk -F': *' '/^Depends On/ { print $2 }')
[ "$declared" = "None" ] || fail "the package declares dependencies it does not have: $declared"

test -x /usr/bin/flowlightd || fail "the daemon is not where the package said it would be"
/usr/bin/flowlightd --version || fail "the daemon does not run on Arch"
test -f /usr/lib/systemd/system/flowlightd.service || fail "the unit file was not installed"
# A container has no running systemd to ask, so the filesystem is asked the same question: enabling a unit is
# a symlink into a `.wants` directory, and there must not be one.
if ls /etc/systemd/system/multi-user.target.wants/flowlightd.service >/dev/null 2>&1; then
    fail "the unit is enabled; a package must not start this"
fi

pacman -R --noconfirm flowlight-bin >/dev/null || fail "the package would not come off again"
test ! -x /usr/bin/flowlightd || fail "the binary is still here after the package was removed"

echo "OK: on Arch the package builds, installs, declares nothing, does not enable itself, and comes off again"
