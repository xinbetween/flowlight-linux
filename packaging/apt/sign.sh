#!/usr/bin/env bash
#
# Signs an archive built by `build.sh`, and publishes the public half of the key beside it.
#
#     sign.sh <archive directory> [<key id>]
#
# The key comes from whatever keyring `gpg` is pointed at — `GNUPGHOME` for a throwaway one, the user's own
# otherwise. This script never reads a secret out of a file or an environment variable, so that the one place a
# private key is handled is the step that imported it.
#
# What the signature means: adding a third-party archive is a decision to trust whoever holds this key for as
# long as the line is in your sources, on every `apt-get update`, for every package it offers. That is a larger
# thing to agree to than downloading one file and checking it once, which is why the `.deb` on each release page
# stays a first-class way to install.
set -euo pipefail

archive=${1:?usage: sign.sh <archive directory> [<key id>]}
key=${2:-}

suite=stable
release="$archive/dists/$suite/Release"
test -f "$release" || { echo "no Release at $release; run build.sh first" >&2; exit 1; }

selected=()
[ -n "$key" ] && selected=(--local-user "$key")

# `InRelease` is the signature inside the file and `Release.gpg` the one beside it. Current apt prefers
# `InRelease`; `Release.gpg` is there for anything older, and costs one more call.
rm -f "$archive/dists/$suite/InRelease" "$archive/dists/$suite/Release.gpg"
gpg --batch --yes --armor "${selected[@]+"${selected[@]}"}" --clearsign \
    --output "$archive/dists/$suite/InRelease" "$release"
gpg --batch --yes --armor "${selected[@]+"${selected[@]}"}" --detach-sign \
    --output "$archive/dists/$suite/Release.gpg" "$release"

# The public key, armoured, at a stable address. `signed-by` in a sources line points at exactly this file, so
# that the key verifies this archive and nothing else on the machine — a key in `/etc/apt/trusted.gpg.d` would
# be trusted for every repository configured, which is not what anybody means by adding one.
gpg --batch --yes --armor "${selected[@]+"${selected[@]}"}" --export >"$archive/flowlight-archive-keyring.asc"
test -s "$archive/flowlight-archive-keyring.asc" || {
    echo "the exported key is empty; the keyring holds no public key" >&2; exit 1
}

# The fingerprint onto the page, so that the address serving the key and the fingerprint of the key are not two
# things somebody has to find in two places. A fingerprint printed by the same run that signed is worth exactly
# as much as the run — it is a convenience, not a second opinion.
fingerprint=$(gpg --batch --list-keys --with-colons | awk -F: '/^fpr:/ {print $10; exit}')
if [ -f "$archive/index.html" ] && [ -n "$fingerprint" ]; then
    spaced=$(echo "$fingerprint" | sed 's/..../& /g; s/ $//')
    sed -i.bak "s/@FINGERPRINT@/$spaced/" "$archive/index.html" && rm -f "$archive/index.html.bak"
fi

echo "signed by $fingerprint"
