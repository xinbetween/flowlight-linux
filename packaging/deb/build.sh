#!/usr/bin/env bash
#
# Builds the two packages, with `ar` and `tar` rather than with `dpkg-deb`.
#
# A `.deb` is an `ar` archive of three members in a fixed order: `debian-binary`, `control.tar.gz`, `data.tar.gz`.
# Writing it out is forty lines and needs nothing installed; `dpkg-deb` would mean the packages could only be
# built on a Debian machine, which is a strange thing to require of a release workflow.
#
# Two packages, not one. The window needs libadwaita 1.5, which is Ubuntu 24.04 and later; the daemon needs only
# a kernel of 4.18. A server has no reason to pull in GTK to watch its own traffic.
set -euo pipefail

version=${1:?usage: build.sh <version> <architecture> [<target directory>]}
architecture=${2:?usage: build.sh <version> <architecture> [<target directory>]}
built=${3:-target/release}
out=${OUT:-target/deb}

mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# One package.
#
# $1 name, $2 the binary to install, $3 where it goes, $4 what it depends on, $5 the description, $6 extra files
package() {
    local name=$1 binary=$2 into=$3 depends=$4 described=$5
    local root="$work/$name"
    rm -rf "$root"
    mkdir -p "$root/DEBIAN" "$root/$into" "$root/usr/share/doc/$name"

    install -m 755 "$built/$binary" "$root/$into/$binary"
    install -m 644 LICENSE "$root/usr/share/doc/$name/copyright"

    # `Installed-Size` is in kilobytes and apt shows it before installing, so it is worth being right.
    local size
    size=$(du -ks "$root" | cut -f1)

    cat >"$root/DEBIAN/control" <<CONTROL
Package: $name
Version: $version
Architecture: $architecture
Maintainer: xinbetween <https://github.com/xinbetween>
Installed-Size: $size
Depends: $depends
Section: net
Priority: optional
Homepage: https://github.com/xinbetween/flowlight-linux
Description: $described
CONTROL

    # The daemon brings a unit file, shipped disabled.
    if [ "$name" = flowlight ]; then
        mkdir -p "$root/lib/systemd/system"
        install -m 644 packaging/deb/flowlightd.service "$root/lib/systemd/system/flowlightd.service"
        install -m 755 packaging/deb/postinst "$root/DEBIAN/postinst"
        install -m 755 packaging/deb/prerm "$root/DEBIAN/prerm"
        install -m 755 packaging/deb/postrm "$root/DEBIAN/postrm"
        # Anything under /etc is a conffile, or an upgrade silently replaces what somebody edited.
        echo "/lib/systemd/system/flowlightd.service" >"$root/DEBIAN/conffiles"
    fi

    ( cd "$root" && find . -type f ! -path './DEBIAN/*' -printf '%P\0' \
        | xargs -0 md5sum >DEBIAN/md5sums 2>/dev/null || true )

    ( cd "$root/DEBIAN" && tar --numeric-owner --owner=0 --group=0 --sort=name \
        --mtime='@0' -czf "$work/control.tar.gz" . )
    ( cd "$root" && tar --numeric-owner --owner=0 --group=0 --sort=name --mtime='@0' \
        --exclude=./DEBIAN -czf "$work/data.tar.gz" . )
    echo "2.0" >"$work/debian-binary"

    local file="$out/${name}_${version}_${architecture}.deb"
    rm -f "$file"
    # The order is fixed by the format, and `ar` writes them in the order given.
    ( cd "$work" && ar rc "$OLDPWD/$file" debian-binary control.tar.gz data.tar.gz )
    echo "$file"
}

package flowlight flowlightd /usr/sbin "libc6" \
    "Watch what every process says on the network, before encryption
 Flowlight reads HTTPS as an application hands it to its TLS library, so no
 certificate is installed anywhere and certificate pinning is not involved. It
 attributes every connection to the process that opened it and to the agent that
 caused it, refuses connections in the kernel, and states plainly what it could
 not see.
 .
 The daemon needs root, because loading an eBPF program does. Its systemd unit
 ships disabled: a tool that reads every HTTPS request on a machine should not
 start doing it because somebody installed it."

package flowlight-gui flowlight /usr/bin "libc6, libgtk-4-1 (>= 4.14), libadwaita-1-0 (>= 1.5), flowlight (= $version)" \
    "The window for Flowlight
 A GTK 4 window that runs as you and talks to the daemon over a Unix socket with
 an owner and a mode. Separate from the daemon because a server has no reason to
 pull in GTK to watch its own traffic, and because the window needs libadwaita
 1.5 while the daemon needs only a kernel of 4.18."
