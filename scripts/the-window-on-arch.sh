#!/usr/bin/env bash
#
# Builds the window on Arch, from source, with `makepkg` — and installs the daemon's package first, because the
# window's declares that it needs it and that declaration is one of the things being checked.
#
# Two packages, two shapes, for one reason. The daemon is statically linked, so `flowlight-bin` carries a binary
# built elsewhere. The window links against the system's GTK, libadwaita and glibc, so `flowlight-gui` builds
# from source here: a binary built elsewhere is one that may not start, and on Arch — which has no stable ABI
# to aim at — "elsewhere" means "last week" as much as "another distribution".
set -euo pipefail

binaries=${1:?usage: the-window-on-arch.sh <binary tarball> <source tarball> <directory inside it> <version>}
sources=${2:?usage: the-window-on-arch.sh <binary tarball> <source tarball> <directory inside it> <version>}
directory=${3:?usage: the-window-on-arch.sh <binary tarball> <source tarball> <directory inside it> <version>}
version=${4:?usage: the-window-on-arch.sh <binary tarball> <source tarball> <directory inside it> <version>}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

echo "== Arch Linux, the window from source"
pacman -Sy --noconfirm --quiet base-devel rust gtk4 libadwaita desktop-file-utils >/dev/null

id builder >/dev/null 2>&1 || useradd -m builder
echo 'builder ALL=(ALL) NOPASSWD: ALL' >/etc/sudoers.d/builder

# The desktop entry, checked by the tool whose job that is. A `.desktop` file with a mistake in it is a file
# every desktop environment ignores in silence, which is the worst way for this to be wrong.
desktop-file-validate packaging/desktop/com.xinbetween.Flowlight.desktop \
    || fail "the desktop entry is not valid"
echo "the desktop entry is valid"

work=/home/builder/build
install -d -o builder -g builder "$work"

# The daemon first.
install -o builder -g builder -m 644 "$binaries" "$work/$(basename "$binaries")"
./packaging/arch/render.sh local "$version" "$work/$(basename "$binaries")" >"$work/PKGBUILD"
chown builder:builder "$work/PKGBUILD"
su builder -c "cd '$work' && makepkg --noconfirm --nocheck" >/dev/null \
    || fail "the daemon's package would not build"
pacman -U --noconfirm "$(ls "$work"/flowlight-bin-*.pkg.tar.* | head -1)" >/dev/null \
    || fail "the daemon's package would not install"

# Then the window, from source, in its own directory because makepkg owns the one it is run in.
window=/home/builder/window
install -d -o builder -g builder "$window"
install -o builder -g builder -m 644 "$sources" "$window/$(basename "$sources")"
./packaging/arch/render.sh window-local "$version" "$window/$(basename "$sources")" "$directory" \
    >"$window/PKGBUILD"
chown builder:builder "$window/PKGBUILD"
echo "--- PKGBUILD"
cat "$window/PKGBUILD"

su builder -c "cd '$window' && makepkg --noconfirm --nocheck" \
    || fail "the window does not build on Arch"

package=$(ls "$window"/flowlight-gui-*.pkg.tar.* | head -1)
pacman -U --noconfirm "$package" >/dev/null || fail "the window's package would not install"

# What it declares. On Arch the dependencies are the ones the PKGBUILD names rather than ones a scan found, so
# what is checked is that the three that matter are there — and that the daemon is one of them.
declared=$(pacman -Qi flowlight-gui | awk -F': *' '/^Depends On/ { print $2 }')
for expected in gtk4 libadwaita flowlight; do
    case "$declared" in
        *"$expected"*) ;;
        *) fail "the window's package does not declare $expected: $declared" ;;
    esac
done

test -x /usr/bin/flowlight || fail "the window is not where its package said it would be"
missing=$(ldd /usr/bin/flowlight | grep 'not found' || true)
if [ -n "$missing" ]; then
    echo "$missing"
    fail "the window names libraries that are not on Arch"
fi
/usr/bin/flowlight --version || fail "the window does not start far enough to say its version"

# The entry and the icon, where a launcher looks for them.
test -f /usr/share/applications/com.xinbetween.Flowlight.desktop \
    || fail "the window's package installs no desktop entry, so nothing in a launcher knows about it"
test -f /usr/share/icons/hicolor/scalable/apps/com.xinbetween.Flowlight.svg \
    || fail "the window's package installs no icon"
desktop-file-validate /usr/share/applications/com.xinbetween.Flowlight.desktop \
    || fail "the installed desktop entry is not valid"

pacman -R --noconfirm flowlight-gui flowlight-bin >/dev/null || fail "the packages would not come off again"
test ! -e /usr/share/applications/com.xinbetween.Flowlight.desktop \
    || fail "the desktop entry is still here after the package was removed"

echo "OK: on Arch the window builds from source, declares what it links against, installs with an entry a launcher can find, and comes off again"
