#!/usr/bin/env bash
#
# Writes a PKGBUILD from the template, either against a tarball on disk or against a published release.
#
# Both come from one template on purpose. A PKGBUILD that CI tests and a PKGBUILD somebody uploads to the AUR
# ought to differ in exactly one thing — where the tarball comes from — and the way to be sure of that is for
# the rest of the file to have one source.
#
#     render.sh local   <version> <tarball>                      one architecture, from a file
#     render.sh release <version> <x86_64 tarball> <aarch64 tarball>   both, from the release pages
set -euo pipefail

mode=${1:?usage: render.sh local|release <version> <tarball>...}
version=${2:?usage: render.sh local|release <version> <tarball>...}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

sum() {
    sha256sum "$1" | cut -d' ' -f1
}

architecture_of() {
    # `flowlight-0.5.3-x86_64-linux.tar.gz` — the architecture is what is between the version and `-linux`.
    local name
    name=$(basename "$1" .tar.gz)
    echo "${name#"flowlight-$version-"}" | sed 's/-linux$//'
}

case $mode in
    local)
        tarball=${3:?usage: render.sh local <version> <tarball>}
        arches=$(architecture_of "$tarball")
        sources=$(printf 'source=("file://%s")\nsha256sums=(%s)\n' \
            "$(cd "$(dirname "$tarball")" && pwd)/$(basename "$tarball")" "'$(sum "$tarball")'")
        ;;
    release)
        first=${3:?usage: render.sh release <version> <x86_64 tarball> <aarch64 tarball>}
        second=${4:?usage: render.sh release <version> <x86_64 tarball> <aarch64 tarball>}
        arches="x86_64 aarch64"
        base="https://github.com/xinbetween/flowlight-linux/releases/download/v$version"
        sources=""
        for tarball in "$first" "$second"; do
            architecture=$(architecture_of "$tarball")
            sources+=$(printf 'source_%s=("%s/%s")\nsha256sums_%s=(%s)\n' \
                "$architecture" "$base" "$(basename "$tarball")" \
                "$architecture" "'$(sum "$tarball")'")
            sources+=$'\n'
        done
        ;;
    *)
        echo "the first argument is local or release, not $mode" >&2
        exit 1
        ;;
esac

# The sources go through a file rather than through `awk -v`: an assignment on the command line may not hold
# a newline — every awk refuses it, which is a thing to find out here rather than from an AUR upload — and
# `sed` would want the replacement escaped, which is how a checksum ends up with a backslash in it.
written=$(mktemp)
trap 'rm -f "$written"' EXIT
printf '%s' "$sources" >"$written"

sed -e "s/@VERSION@/$version/g" -e "s/@ARCHES@/$arches/g" "$here/PKGBUILD.in" \
    | awk -v holding="$written" '
        /@SOURCES@/ {
            while ((getline line < holding) > 0) print line
            next
        }
        { print }
    '
