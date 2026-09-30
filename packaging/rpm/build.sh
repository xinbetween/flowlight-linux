#!/usr/bin/env bash
#
# Builds the daemon's `.rpm`, with `rpmbuild` rather than by writing the format out by hand.
#
# The `.deb` next door is written out with `ar` and `tar`, because a `.deb` is three members in a fixed order
# and doing it by hand costs forty lines and no dependency. An RPM is a signed header structure in front of a
# compressed cpio archive with its own dependency scan, and writing that by hand would be reimplementing
# `rpmbuild` badly. So this needs `rpmbuild`, which means it runs inside a container of a distribution that
# has one — which is also where the result gets installed, because a package that builds is not a package
# that installs.
#
#     build.sh <version> <architecture> <directory holding flowlightd> [<output directory>]
set -euo pipefail

version=${1:?usage: build.sh <version> <architecture> <built directory> [<output directory>]}
architecture=${2:?usage: build.sh <version> <architecture> <built directory> [<output directory>]}
built=${3:?usage: build.sh <version> <architecture> <built directory> [<output directory>]}
out=${4:-target/rpm}

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)

command -v rpmbuild >/dev/null || {
    echo "rpmbuild is not here. This runs inside a container of a distribution that has it." >&2
    exit 1
}
test -x "$built/flowlightd" || { echo "no flowlightd in $built" >&2; exit 1; }

# An RPM version may not contain a hyphen — the hyphen is what separates version from release in every name
# RPM writes — so `0.0.0-ci` becomes `0.0.0.ci` rather than becoming an error three steps later.
rpm_version=${version//-/.}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work"/{BUILD,RPMS,SOURCES,SPECS,SRPMS} "$out"

rpmbuild -bb "$here/flowlight.spec" \
    --define "_topdir $work" \
    --define "version $rpm_version" \
    --define "architecture $architecture" \
    --define "built $(cd "$built" && pwd)" \
    --define "unit $here/../deb/flowlightd.service" \
    --define "licence $root/LICENSE" \
    --define "_build_id_links none" \
    --target "$architecture"

find "$work/RPMS" -name '*.rpm' -exec install -m 644 {} "$out/" \;
ls -1 "$out"/*.rpm
