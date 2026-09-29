#!/usr/bin/env bash
#
# Loads the probe into the running kernel, makes one connection, and insists on seeing it.
#
# Everything else in this repository can be wrong in a way that still compiles and still passes a unit test:
# an offset read from the wrong kernel's layout, a port read in the wrong byte order, a pid taken from the
# wrong context. All of those produce numbers that look entirely reasonable. This is the step that asks the
# kernel whether they are the right ones.
set -euo pipefail

binary=${1:?usage: smoke.sh <path to flowlightd>}
target_host=${2:-example.com}

output=$(mktemp)
trap 'rm -f "$output"' EXIT

echo "Watching for 12 seconds..."
sudo "$binary" --json --seconds 12 >"$output" &
watcher=$!

# The probe is attached by the time the daemon prints its banner, but the banner goes to stderr and this
# script does not read it. Two seconds is generous and the total cost is two seconds.
sleep 2
echo "Connecting to $target_host..."
curl -sS --max-time 10 "https://$target_host" -o /dev/null

wait "$watcher"

echo "--- what the kernel reported:"
cat "$output"

if ! [ -s "$output" ]; then
    echo "FAIL: the probe attached and reported nothing at all." >&2
    exit 1
fi

# `curl` by name proves /proc resolution ran and produced the executable's name rather than a pid.
# Port 443 proves the tracepoint's host-order ports were not byte-swapped a second time.
# `path` confidence proves the process was still alive when we looked, which it should have been.
if ! jq -s -e 'map(select(.process == "curl" and .port == 443 and .confidence == "path")) | length > 0' \
    "$output" >/dev/null; then
    echo "FAIL: no record of curl reaching port 443 with a name resolved from its path." >&2
    exit 1
fi

echo "OK: the connection was attributed to curl on port 443."
