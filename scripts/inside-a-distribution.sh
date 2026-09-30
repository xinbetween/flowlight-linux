#!/usr/bin/env bash
#
# What is asserted inside a container of some other distribution.
#
# Not the whole smoke test — that runs on the host and takes eight minutes. What is distribution-specific is
# narrower than that, and this checks exactly it:
#
#   1. the binary runs at all on that userland, which is what "statically linked" is supposed to mean;
#   2. the programs load into the kernel and the probes attach from inside that filesystem;
#   3. the TLS library is *found*, wherever that distribution keeps it — `/usr/lib64` on Fedora, `/usr/lib`
#      on Arch, `/usr/lib/x86_64-linux-gnu` on Debian, and whatever openSUSE has decided;
#   4. a request made by that distribution's own `curl`, linked against its own OpenSSL, is read and
#      attributed.
#
# The kernel is the host's — a container has no kernel of its own, which is the whole reason this is cheap
# enough to do for four distributions.
#
# Two things are deliberately not asserted here. **Blocking** needs a cgroup v2 hierarchy, and a container has
# its own cgroup namespace, so `--no-block` is passed: a refusal to attach inside a container says nothing
# about the machine. **Interception** would create a certificate authority for no reason.
set -euo pipefail

binary=${1:?usage: inside-a-distribution.sh <path to flowlightd>}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

name=$( (. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$ID}") || echo "an unnamed distribution")
echo "== $name"
uname -srm

# 1. It runs here. A binary linked against another machine's glibc does not get this far.
"$binary" --version || fail "the binary does not run on $name"
if command -v ldd >/dev/null 2>&1 && ldd "$binary" 2>&1 | grep -q '=>'; then
    ldd "$binary"
    fail "the binary wants a shared library on $name"
fi

work=$(mktemp -d)
database="$work/flowlight.db"
socket="$work/flowlight.sock"
log="$work/flowlightd.log"

# 2 and 3. Watching, from inside this filesystem.
"$binary" --database "$database" --socket "$socket" --certificates "$work/certificates" \
    --no-block --no-intercept --seconds 24 >/dev/null 2>"$log" &
watcher=$!
sleep 6

# 4. A request, made by this distribution's own client against its own TLS library.
if ! curl -sS --max-time 15 https://example.com -o /dev/null; then
    fail "this container has no network, so nothing here is a statement about $name"
fi
sleep 4
wait "$watcher" || true

echo "--- what it said"
cat "$log"

echo "--- what it found"
grep -E '^(reading|not reading) ' "$log" || true

# The library, wherever this distribution keeps it. This is the assertion the whole job exists for: the path
# is not in any list written by hand, it is whatever was read out of `/proc` and the directories that exist.
grep -q '^reading openssl through ' "$log" \
    || fail "no OpenSSL library was found on $name. That is a discovery problem, not a kernel one."

# And the request itself, read in the clear and attributed to the process that made it.
"$binary" --database "$database" --json history --since 600 \
    | jq -s -e '[.[] | select(.process == "curl")] | length > 0' >/dev/null \
    || fail "the request made on $name was not read, or was not attributed to curl"

echo "--- coverage"
"$binary" --database "$database" coverage || true

echo "OK: $name runs it, finds its own TLS library, and has a request read from it"
