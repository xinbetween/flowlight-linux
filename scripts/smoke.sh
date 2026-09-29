#!/usr/bin/env bash
#
# Loads the probes into the running kernel, makes real requests, and insists on seeing them.
#
# Everything else in this repository can be wrong in a way that still compiles and still passes a unit test:
# an offset read from the wrong kernel's layout, a port read in the wrong byte order, a pid taken from the
# wrong context, a uprobe on a symbol the library does not export. All of those produce output that looks
# entirely reasonable — usually by producing nothing at all, which is indistinguishable from a quiet machine.
# This is the step that asks the kernel whether any of it works.
set -euo pipefail

binary=${1:?usage: smoke.sh <path to flowlightd>}
target_host=${2:-example.com}

output=$(mktemp)
log=$(mktemp)
trap 'rm -f "$output" "$log"' EXIT

echo "Watching for 20 seconds..."
sudo "$binary" --json --seconds 20 >"$output" 2>"$log" &
watcher=$!

# The probes are attached by the time the daemon prints its banner, but the banner goes to stderr and the
# library scan happens after it. Three seconds is generous and the total cost is three seconds.
sleep 3

echo "Connecting to $target_host over HTTP/1.1..."
curl -sS --http1.1 --max-time 10 "https://$target_host" -o /dev/null

echo "Connecting to $target_host again, letting it negotiate HTTP/2..."
curl -sS --max-time 10 "https://$target_host" -o /dev/null

# A signed URL is entirely a credential. The first CI run that read plaintext successfully also printed a
# live Azure shared-access signature belonging to the runner, which is how this assertion came to exist.
secret="aVeryLongOpaqueTokenValue1234567890ABCdef"
echo "Connecting once more, with a credential in the query string..."
curl -sS --http1.1 --max-time 10 "https://$target_host/?token=$secret" -o /dev/null

# GnuTLS, through a different program and a different pair of functions. Whether wget is built against
# GnuTLS varies by distribution, so this checks rather than assumes.
wget_library=none
if command -v wget >/dev/null && ldd "$(command -v wget)" 2>/dev/null | grep -q gnutls; then
    wget_library=gnutls
    echo "Connecting with wget, which on this machine uses GnuTLS..."
    wget -q -O /dev/null "https://$target_host/" || true
fi

wait "$watcher"

echo "--- what this machine's TLS libraries are:"
ldd "$(command -v curl)" 2>/dev/null | grep -E "ssl|gnutls|nspr" || true
ldd "$(command -v wget)" 2>/dev/null | grep -E "ssl|gnutls|nspr" || true
echo "--- what the daemon said about itself:"
cat "$log"
echo "--- what the kernel reported:"
cat "$output"

if ! [ -s "$output" ]; then
    echo "FAIL: the probes attached and reported nothing at all." >&2
    exit 1
fi

check() {
    local description=$1 filter=$2
    if jq -s -e "map(select($filter)) | length > 0" "$output" >/dev/null; then
        echo "OK: $description"
    else
        echo "FAIL: $description" >&2
        exit 1
    fi
}

# Attribution. `curl` by name proves the /proc resolution ran and produced the executable's name rather than
# a pid. Port 443 proves the tracepoint's host-order ports were not byte-swapped a second time.
check "the connection was attributed to curl on port 443" \
    '.process == "curl" and .port == 443 and .confidence == "path"'

# Plaintext. This is the claim the whole design rests on: the request is readable with no certificate
# installed anywhere and nothing terminating the connection.
check "curl's request was read in the clear, with its Host header" \
    ".process == \"curl\" and .method == \"GET\" and .host == \"$target_host\""

check "the response status was read in the clear" \
    '.process == "curl" and .direction == "in" and .status != null'

# The one that decides whether this is a demonstration or a tool. Every current agent API speaks HTTP/2,
# whose request line is not text in the stream -- it is HPACK, indices into a table built across the whole
# connection. Getting a method and an authority out of it means the frames were followed and the compression
# table was rebuilt correctly from the first block onwards.
check "the HTTP/2 request was decoded out of HPACK" \
    ".process == \"curl\" and .protocol == \"http/2\" and .method == \"GET\" and .host == \"$target_host\""

check "the HTTP/2 response status was decoded out of HPACK" \
    '.process == "curl" and .protocol == "http/2" and .direction == "in" and .status != null'

# Redaction. A signed URL is entirely a credential. The first CI run that read plaintext successfully also
# printed a live Azure shared-access signature belonging to the runner, which is how this came to exist.
if [ "$wget_library" = gnutls ]; then
    check "wget's request was read through GnuTLS" \
        '.process == "wget" and .method == "GET"'
else
    echo "SKIP: wget on this machine is not built against GnuTLS, so there is nothing to check"
fi

check "the credential in the query string was redacted" \
    '.process == "curl" and ((.target // "") | contains("token=…"))'

# The strongest form of the same question, asked of the whole output rather than one record: the secret must
# appear nowhere in anything this tool produced.
if grep -q "$secret" "$output"; then
    echo "FAIL: the credential appeared in the output." >&2
    exit 1
fi
echo "OK: the credential appears nowhere in the output"
