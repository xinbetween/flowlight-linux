#!/usr/bin/env bash
#
# Writes a PKGBUILD from the template, either against a tarball on disk or against a published release.
#
# Both come from one template on purpose. A PKGBUILD that CI tests and a PKGBUILD somebody uploads to the AUR
# ought to differ in exactly one thing — where the tarball comes from — and the way to be sure of that is for
# the rest of the file to have one source.
#
#     render.sh local          <version> <tarball>
#     render.sh release        <version> <x86_64 tarball> <aarch64 tarball>
#     render.sh window-local   <version> <source tarball> <directory inside it>
#     render.sh window-release <version> <source tarball> <directory inside it> <url>
#
# The last two render the *window's* PKGBUILD, which builds from source because the window links against the
# machine's own GTK, libadwaita and glibc. The daemon's builds from a binary because it links against nothing.
set -euo pipefail

mode=${1:?usage: render.sh local|release|window-local|window-release <version> <tarball>...}
version=${2:?usage: render.sh local|release|window-local|window-release <version> <tarball>...}
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
template="$here/PKGBUILD.in"
directory=''

sum() {
    sha256sum "$1" | cut -d' ' -f1
}

architecture_of() {
    # `flowlight-0.5.3-x86_64-linux.tar.gz` — the architecture is what is between the version and `-linux`.
    #
    # Refused rather than guessed at when the name is not that shape. A tarball whose version does not match
    # the one being rendered used to produce `arch=(flowlight-0.5.3-x86_64)` — a PKGBUILD that is wrong in a
    # way makepkg would accept and no architecture would ever match.
    local name=${1##*/}
    name=${name%.tar.gz}
    case "$name" in
        "flowlight-$version-"*-linux) ;;
        *)
            echo "$name is not flowlight-$version-<architecture>-linux.tar.gz" >&2
            exit 1
            ;;
    esac
    name=${name#"flowlight-$version-"}
    echo "${name%-linux}"
}

# Arch's own names, which are the kernel's on Linux and not quite on anything else: a macOS `uname -m` says
# `arm64` where Arch says `aarch64`, and a PKGBUILD rendered there would name an architecture that does not
# exist. This only matters for the local modes, which are the ones a person runs by hand.
this_architecture() {
    case "$(uname -m)" in
        arm64) echo aarch64 ;;
        machine) echo x86_64 ;;
        *) uname -m ;;
    esac
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
    window-local)
        tarball=${3:?usage: render.sh window-local <version> <source tarball> <directory>}
        directory=${4:?usage: render.sh window-local <version> <source tarball> <directory>}
        template="$here/PKGBUILD-gui.in"
        arches=$(this_architecture)
        sources=$(printf 'source=("file://%s")\nsha256sums=(%s)\n' \
            "$(cd "$(dirname "$tarball")" && pwd)/$(basename "$tarball")" "'$(sum "$tarball")'")
        ;;
    window-release)
        tarball=${3:?usage: render.sh window-release <version> <source tarball> <directory> <url>}
        directory=${4:?usage: render.sh window-release <version> <source tarball> <directory> <url>}
        url=${5:?usage: render.sh window-release <version> <source tarball> <directory> <url>}
        template="$here/PKGBUILD-gui.in"
        arches="x86_64 aarch64"
        # One source for both architectures, because it is source: what differs between them is the compiler's
        # output, and that is made on the machine installing it.
        sources=$(printf 'source=("%s")\nsha256sums=(%s)\n' "$url" "'$(sum "$tarball")'")
        ;;
    *)
        echo "the first argument is local, release, window-local or window-release, not $mode" >&2
        exit 1
        ;;
esac

# The sources go through a file rather than through `awk -v`: an assignment on the command line may not hold
# a newline — every awk refuses it, which is a thing to find out here rather than from an AUR upload — and
# `sed` would want the replacement escaped, which is how a checksum ends up with a backslash in it.
written=$(mktemp)
trap 'rm -f "$written"' EXIT
printf '%s' "$sources" >"$written"

sed -e "s/@VERSION@/$version/g" -e "s/@ARCHES@/$arches/g" -e "s/@DIRECTORY@/$directory/g" \
    "$template" \
    | awk -v holding="$written" '
        /@SOURCES@/ {
            while ((getline line < holding) > 0) print line
            next
        }
        { print }
    '
