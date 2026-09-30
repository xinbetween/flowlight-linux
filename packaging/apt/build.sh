#!/usr/bin/env bash
#
# Builds an apt archive out of a directory of `.deb` files: a pool, a `Packages` index per architecture, and a
# `Release` that names their hashes. Static files, servable by anything.
#
# Unsigned on purpose. Signing is `sign.sh`, separately, because the two have different requirements: this needs
# nothing but coreutils and can therefore be tested anywhere, while signing needs a private key that exists in
# exactly one place. Splitting them is what lets CI prove the archive is well-formed on every run and sign it
# only when it is publishing one.
#
#     build.sh <directory of .debs> <output directory> [<version to name on the page>]
set -euo pipefail

debs=${1:?usage: build.sh <directory of .debs> <output directory> [<version>]}
out=${2:?usage: build.sh <directory of .debs> <output directory> [<version>]}
named=${3:-}

# One suite, one component. A third-party archive with a release cycle per Ubuntu version would be claiming to
# test against each one, which this does not: the daemon needs a kernel of 4.18 and the window needs libadwaita
# 1.5, and those are dependencies in the packages rather than facts about a suite.
suite=stable
component=main
origin="Flowlight"

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

test -d "$debs" || { echo "no such directory: $debs" >&2; exit 1; }
shopt -s nullglob
found=("$debs"/*.deb)
(( ${#found[@]} )) || { echo "no .deb files in $debs" >&2; exit 1; }

rm -rf "$out"
mkdir -p "$out/pool/$component/f/flowlight" "$out/dists/$suite/$component"

# The pool is flat under one source name. Debian's `f/flowlight` split exists so that a mirror's directory does
# not hold a hundred thousand entries; two packages do not need it, but following the convention costs nothing
# and means a tool that assumes it is not surprised.
pool="pool/$component/f/flowlight"
for deb in "${found[@]}"; do
    install -m 644 "$deb" "$out/$pool/$(basename "$deb")"
done

# Every architecture that turned up, rather than a list written here. A release that only built amd64 should
# produce an archive that says amd64, not one that promises arm64 and serves nothing.
architectures=()
for deb in "$out/$pool"/*.deb; do
    name=$(basename "$deb")
    architecture=${name##*_}
    architecture=${architecture%.deb}
    [[ " ${architectures[*]-} " == *" $architecture "* ]] || architectures+=("$architecture")
done

# `Packages`, one per architecture, from each package's own control file. `ar p` reads a member out of the
# archive without unpacking it, and the control member is a tarball holding that file.
unpacked=$(mktemp -d)
trap 'rm -rf "$unpacked"' EXIT
for architecture in "${architectures[@]}"; do
    directory="$out/dists/$suite/$component/binary-$architecture"
    mkdir -p "$directory"
    index="$directory/Packages"
    : >"$index"
    for deb in "$out/$pool"/*_"$architecture".deb; do
        rm -rf "$unpacked"; mkdir -p "$unpacked"
        ar p "$deb" control.tar.gz | tar -xz -C "$unpacked"
        control=$(cat "$unpacked/control")
        # The fields apt needs that are not in the control file: where the file is, how big, and what it
        # hashes to. Without them apt has an index of packages it cannot fetch.
        {
            printf '%s\n' "$control"
            echo "Filename: $pool/$(basename "$deb")"
            echo "Size: $(wc -c <"$deb" | tr -d ' ')"
            echo "MD5sum: $(md5sum "$deb" | cut -d' ' -f1)"
            echo "SHA256: $(sha256sum "$deb" | cut -d' ' -f1)"
            echo
        } >>"$index"
    done
    # Both forms. apt asks for the compressed one and falls back, and a mirror that only carries `Packages.gz`
    # is a thing that exists.
    gzip -9 -n -c "$index" >"$index.gz"
done

# `Release`, naming every index under this suite by its hash. The paths are relative to the suite directory,
# which is what apt resolves them against.
release="$out/dists/$suite/Release"
{
    echo "Origin: $origin"
    echo "Label: $origin"
    echo "Suite: $suite"
    echo "Codename: $suite"
    echo "Architectures: ${architectures[*]}"
    echo "Components: $component"
    echo "Date: $(date -u '+%a, %d %b %Y %H:%M:%S UTC')"
    echo "Description: Flowlight for Linux — watch what every process says on the network"
    # No `Valid-Until`. It is a promise about how often this archive is rebuilt, and an expired one does not
    # warn — `apt-get update` fails outright. This publishes when there is a release and not on a schedule, so
    # the honest thing is to make no claim rather than one that breaks somebody's machine on a quiet month.
} >"$release"

sums() {
    local field=$1 tool=$2
    echo "$field:" >>"$release"
    ( cd "$out/dists/$suite" && find "$component" -type f | LC_ALL=C sort | while read -r file; do
        printf ' %s %16d %s\n' "$($tool "$file" | cut -d' ' -f1)" "$(wc -c <"$file")" "$file"
    done ) >>"$release"
}
sums MD5Sum md5sum
sums SHA256 sha256sum

# A page at the root, because a static host with no index is a 404 at the address people will paste first.
if [ -f "$here/index.html" ]; then
    version=${named:-$(basename "$(ls "$out/$pool"/flowlight_*.deb | head -1)" | cut -d_ -f2)}
    sed "s/@VERSION@/$version/g" "$here/index.html" >"$out/index.html"
fi

echo "archive at $out: ${#found[@]} package(s), architectures ${architectures[*]}"
echo "it is unsigned; apt will refuse it until sign.sh has run"
