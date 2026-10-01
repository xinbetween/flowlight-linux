#!/usr/bin/env bash
#
# The tarball, for a distribution nobody has packaged.
#
# Four files: the daemon, its unit, the installer that puts them in two places and says what it did, and the
# licence. No postinst mechanism, no package database, nothing that has to be trusted — which is the point of
# having this as well as a `.deb` and an `.rpm`.
#
#     build.sh <version> <architecture> <directory holding flowlightd> [<output directory>]
set -euo pipefail

version=${1:?usage: build.sh <version> <architecture> <built directory> [<output directory>]}
architecture=${2:?usage: build.sh <version> <architecture> <built directory> [<output directory>]}
built=${3:?usage: build.sh <version> <architecture> <built directory> [<output directory>]}
out=${4:-target/tarball}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)

test -x "$built/flowlightd" || { echo "no flowlightd in $built" >&2; exit 1; }

name="flowlight-$version-$architecture-linux"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/$name" "$out"

install -m 755 "$built/flowlightd" "$work/$name/flowlightd"
install -m 644 "$here/../deb/flowlightd.service" "$work/$name/flowlightd.service"
install -m 755 "$here/install.sh" "$work/$name/install.sh"
install -m 644 "$root/LICENSE" "$work/$name/LICENSE"

cat >"$work/$name/README" <<READ
Flowlight $version for Linux ($architecture)

  sudo ./install.sh              put flowlightd in /usr/sbin and its unit in /usr/lib/systemd/system
  sudo ./install.sh --uninstall  take both away again

It installs disabled. A tool that reads every HTTPS request on a machine should not start doing it because
somebody ran an installer.

The daemon is statically linked: it needs a kernel of 4.18 or later and nothing else. It needs root, because
loading an eBPF program does.

  https://github.com/xinbetween/flowlight-linux
READ

# Reproducible: owner, order and timestamps fixed, so the same build twice is the same bytes twice and the
# checksum in a PKGBUILD stays true.
tar --numeric-owner --owner=0 --group=0 --sort=name --mtime='@0' \
    -czf "$out/$name.tar.gz" -C "$work" "$name"

( cd "$out" && sha256sum "$name.tar.gz" >"$name.tar.gz.sha256" )
ls -l "$out/$name.tar.gz"
cat "$out/$name.tar.gz.sha256"
