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
stored=$(mktemp)
reported=$(mktemp)
socket=$(mktemp -d)/flowlight.sock
coverage_json=$(mktemp)
agents_json=$(mktemp)
fake_agent=$(mktemp -d)/claude
database=$(mktemp -d)/flowlight.db
export_dir=$(mktemp -d)
export_file=$export_dir/exported.jsonl
export_second=$export_dir/elsewhere.jsonl
model_log=$(mktemp)
model_port_file=$(mktemp)
model_key=$(mktemp)
certificates=$(mktemp -d)/flowlight
cleanup() {
    rm -f "$output" "$log" "$stored" "$reported" "$coverage_json" "$agents_json"
    rm -f "$model_log" "$model_port_file" "$model_key"
    [ -n "${model_server:-}" ] && kill "$model_server" 2>/dev/null
    rm -rf "$(dirname "$fake_agent")"
    [ "${agent_tested:-no}" = yes ] && rm -f "$agent_config"
    sudo rm -rf "$(dirname "$database")" "$export_dir" "$(dirname "$certificates")"
    [ -n "${demo:-}" ] && sudo rm -rf "$(dirname "$demo")"
    return 0
}
trap cleanup EXIT

# Anything that fails while the daemon is still running needs the daemon's own account of itself, which is
# on its standard error and has not been printed yet. Discovering that from CI a second time would be a
# waste of everybody's afternoon.
fail() {
    echo "FAIL: $1" >&2
    # The daemon reports on a timer, so the line describing the moment this failed has usually not been
    # written yet. Waiting for one more round of it costs two seconds and saves a round trip through CI.
    sleep 3
    echo "--- what the daemon said:" >&2
    cat "$log" >&2
    echo "--- what it reported:" >&2
    tail -40 "$output" >&2
    exit 1
}

ask() {
    python3 - "$socket" "$1" <<'PYTHON'
import json, socket, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(sys.argv[1])
    client.sendall((sys.argv[2] + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = client.recv(65536)
        if not chunk:
            break
        data += chunk
print(data.decode().strip())
PYTHON
}

echo "Watching..."
sudo "$binary" --json --seconds 470 --database "$database" --socket "$socket" --web 127.0.0.1:0 \
    --certificates "$certificates" \
    --export-seconds 2 >"$output" 2>"$log" &
watcher=$!

# Wait for the daemon to say it is reading a TLS library, rather than guessing at how long that takes. A
# fixed sleep here was a race: on a loaded runner the library scan can finish after the first request has
# already been made, and then nothing is captured and the failure looks like a broken probe.
await() {
    local what=$1 seconds=${2:-30}
    for _ in $(seq "$((seconds * 4))"); do
        if grep -q "$what" "$log" 2>/dev/null; then
            return 0
        fi
        sleep 0.25
    done
    fail "the daemon never said \"$what\"."
}
await "reading openssl"
await "interface socket at"

# The same idea for the database rather than the log: a question derived from stored traffic has to wait for
# that traffic to be stored. The daemon writes a partial batch once a second, which is fast and is not
# instant, and asking a moment too early is how a correct answer looks like an empty one.
await_stored() {
    local filter=$1 seconds=${2:-20}
    for _ in $(seq "$((seconds * 4))"); do
        if ask '{"op":"requests","since":900,"limit":400}' | jq -e "[.ok[] | select($filter)] | length > 0" \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.25
    done
    fail "the database never held a request matching $filter."
}

# The interface. An ephemeral port, because a fixed one is a fixed way for this to fail on a machine that
# happens to be using it.
url=$(grep -o 'http://127\.0\.0\.1:[0-9]*/?token=[0-9a-f]*' "$log" | head -1)
if [ -z "$url" ]; then
    fail "the daemon did not report an interface address."
fi
base=${url%%/?token=*}
token=${url##*token=}
echo "Interface at $base"

code=$(curl -sS -o /dev/null -w '%{http_code}' "$url")
[ "$code" = 200 ] || fail "the page answered $code with its token."
echo "OK: the page is served to a request carrying the token"

code=$(curl -sS -o /dev/null -w '%{http_code}' "$base/")
[ "$code" = 404 ] || { echo "FAIL: the page answered $code without a token; it must not." >&2; exit 1; }
code=$(curl -sS -o /dev/null -w '%{http_code}' "$base/api/coverage?token=wrong")
[ "$code" = 404 ] || { echo "FAIL: the API answered $code to a wrong token." >&2; exit 1; }
echo "OK: nothing is served without the right token"

# Loopback is not a permission boundary, so the page must never leave it. Asked of a running daemon rather
# than trusted to a unit test, because the flag is the thing a person actually types.
refusal=$(sudo "$binary" --database "$database" --certificates "$certificates" --web 0.0.0.0:0 --seconds 1 2>&1 || true)
if printf '%s' "$refusal" | grep -q loopback; then
    echo "OK: the web page refuses to be served on a routable address"
else
    echo "FAIL: the web page did not refuse a routable address. It said:" >&2
    printf '%s\n' "$refusal" >&2
    exit 1
fi

echo "Connecting to $target_host over HTTP/1.1..."
curl -sS --http1.1 --max-time 10 "https://$target_host" -o /dev/null

echo "Connecting to $target_host again, letting it negotiate HTTP/2..."
curl -sS --max-time 10 "https://$target_host" -o /dev/null

# A signed URL is entirely a credential. The first CI run that read plaintext successfully also printed a
# live Azure shared-access signature belonging to the runner, which is how this assertion came to exist.
secret="aVeryLongOpaqueTokenValue1234567890ABCdef"
echo "Connecting once more, with a credential in the query string..."
curl -sS --http1.1 --max-time 10 "https://$target_host/?token=$secret" -o /dev/null

# MCP, which is JSON-RPC over HTTPS. The server will refuse the request; what matters is that the envelope
# was in the plaintext and that only the method and the tool's name came out of it.
mcp_secret="do-not-keep-this-argument"
echo "Making an MCP tool call..."
curl -sS --http1.1 --max-time 10 -X POST \
    -H 'Content-Type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"smoke_tool\",\"arguments\":{\"secret\":\"$mcp_secret\"}}}" \
    "https://$target_host/mcp" -o /dev/null || true

# GnuTLS, through a different pair of functions. `gnutls-cli` rather than wget, because whether wget is built
# against GnuTLS varies by distribution and an assertion that quietly tests OpenSSL twice is worse than no
# assertion.
gnutls_tested=no
if command -v gnutls-cli >/dev/null; then
    gnutls_tested=yes
    echo "Connecting with gnutls-cli, which uses GnuTLS by definition..."
    printf 'GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n' "$target_host" \
        | timeout 15 gnutls-cli --no-ca-verification "$target_host:443" >/dev/null 2>&1 || true
fi

# An agent, and a request made by something it started. `claude` does not make requests: it spawns things
# that do, and attributing those to `curl` is true and useless. A copy of /bin/sh named `claude` is an agent
# as far as Flowlight is concerned -- the name of the executable is the identity everywhere else, and
# inventing a stricter rule here would mean two screens disagreeing about what a thing is called.
agent_home=$(getent passwd "$(id -un)" | cut -d: -f6)
agent_config="$agent_home/.claude.json"
agent_tested=no
if [ -n "$agent_home" ] && [ -d "$agent_home" ] && ! [ -e "$agent_config" ]; then
    agent_tested=yes
    printf '{"mcpServers":{"smoke":{"type":"http","url":"https://%s/mcp"}}}' "$target_host" >"$agent_config"
    cp /bin/sh "$fake_agent"
    echo "Making a request from a process named claude..."
    # `; :` rather than a bare command, so the shell does not exec curl in place and vanish -- the process
    # tree is the whole point of the test.
    "$fake_agent" -c "curl -sS --http1.1 --max-time 10 https://$target_host/ -o /dev/null; :"
fi

# A Go program, whose TLS is written in Go and linked into its own binary. Flowlight probes libraries, so it
# sees the connection and cannot read a byte of the traffic -- which is exactly the case Coverage exists to
# name, and the one that otherwise looks identical to a process that did nothing.
go_tested=no
if command -v gh >/dev/null && [ -n "${GH_TOKEN:-}" ]; then
    go_tested=yes
    echo "Making a request from gh, which is written in Go..."
    gh api rate_limit >/dev/null 2>&1 || true
fi

# Blocking. A literal address rather than a name, so that nothing here depends on what DNS says today, and
# one that is not used by any other assertion in this file.
blocked_address=1.1.1.1
block_tested=no
if curl -sS --max-time 8 "https://$blocked_address/" -o /dev/null 2>/dev/null; then
    block_tested=yes

    # Scoped to one agent, which is the harder half: the kernel has to know, inside connect(), that the
    # process calling it is working for `claude`. Userspace marks the agent; the fork tracepoint marks
    # everything it starts, before the child can run.
    # Asked before it is written, which is the path the window's button takes: it shows what the rule would
    # have changed and only writes it if somebody says yes.
    # Derived from stored traffic, so wait for the traffic to be stored first.
    await_stored ".host == \"$target_host\" and .method == \"GET\""
    simulated=$(ask "{\"op\":\"simulate\",\"action\":\"block\",\"subject\":\"$target_host\",\"since\":600}")
    echo "$simulated"
    printf '%s' "$simulated" \
        | jq -e '[.ok[] | select(.after == "block" and .before == "allow")] | length > 0' >/dev/null \
        || fail "simulating a rule against traffic that happened reported no change."
    echo "OK: a rule can be tried against real history before it is written"

    # And asking must not have written it.
    ask '{"op":"rules"}' | jq -e '.ok | length == 0' >/dev/null \
        || fail "asking what a rule would change wrote the rule."
    echo "OK: asking what a rule would change does not write it"

    # Written over the socket, which is the path the window's "Block for this agent" button takes. The
    # terminal's `block` subcommand writes the same row a different way, and is exercised below.
    echo "Blocking $blocked_address for the agent only, over the interface socket..."
    ask "{\"op\":\"write\",\"action\":\"block\",\"subject\":\"$blocked_address\",\"port\":443,\"agent\":\"claude\"}" \
        | jq -e '.ok == "added"' >/dev/null || fail "the socket would not write a rule."
    sleep 4

    # Everyone else is unaffected. Without this the next check would pass for the wrong reason.
    if ! curl -sS --max-time 8 "https://$blocked_address/" -o /dev/null 2>/dev/null; then
        fail "a rule scoped to one agent refused a connection from something else."
    fi
    echo "OK: a rule scoped to an agent leaves everything else alone"

    # `sleep 3` because an agent is noticed by a scan that runs once a second, and this one would otherwise
    # be gone before it was ever seen. A real agent is long-lived; this one is a copy of /bin/sh.
    #
    # Two shapes, and they fail for different reasons, so they are asked separately. `exec` replaces the
    # shell with curl and keeps the process identifier, so this asks only whether the mark and the lookup
    # work.
    if [ "$agent_tested" = yes ] \
        && "$fake_agent" -c "sleep 3; exec curl -sS --max-time 8 https://$blocked_address/ -o /dev/null" \
            2>/dev/null; then
        fail "a connection from the agent's own process was not refused."
    fi
    echo "OK: a connection from the agent itself was refused"

    # And this one forks, so it asks the other question: whether the mark reached a child that the kernel
    # had to copy it to.
    # `exit $?` rather than `:` at the end. A trailing `:` stops the shell replacing itself with curl --
    # which is the point, since this is the forking case -- but it also makes the shell exit successfully
    # whatever curl did, so this check passed nothing on to be checked. It reported a working block as a
    # failure for several runs.
    if [ "$agent_tested" = yes ] \
        && "$fake_agent" -c \
            "sleep 3; curl -sS --max-time 8 https://$blocked_address/ -o /dev/null; exit \$?" \
            2>/dev/null; then
        fail "a connection from the agent's own child was not refused."
    fi
    echo "OK: a connection from something the agent started was refused"

    sudo "$binary" --database "$database" --certificates "$certificates" rules
    scoped_rule=$(ask '{"op":"rules"}' | jq -r '.ok[] | select(.scope == "agent:claude") | .id')
    ask "{\"op\":\"forget\",\"id\":$scoped_rule}" | jq -e '.ok == true' >/dev/null \
        || fail "the socket would not forget a rule."
    echo "OK: a rule can be written and forgotten over the interface socket"

    # And now for everyone, which is the simpler half and the one somebody will try first.
    echo "Blocking $blocked_address for everyone..."
    sudo "$binary" --database "$database" --certificates "$certificates" block "$blocked_address" --port 443 --note "smoke test"
    sleep 4
    if curl -sS --max-time 8 "https://$blocked_address/" -o /dev/null 2>/dev/null; then
        fail "a blocked address was still reachable."
    fi
    echo "OK: the blocked address could not be connected to"
else
    echo "SKIP: $blocked_address is not reachable from here, so blocking it would prove nothing"
fi

# The native interface's socket, which is what the GTK window talks to. Exercised with a scripted client
# rather than a window, because a window cannot be asserted about in CI and the protocol can.
echo "--- what the interface socket says:"
ask '{"op":"hello"}' | tee /dev/stderr | jq -e '.ok.version != null and .ok.enforcing == true' >/dev/null \
    || fail "the socket did not greet properly."
echo "OK: the interface socket answers, and says whether it is enforcing"

mode=$(stat -c '%a' "$socket")
[ "$mode" = 600 ] || fail "the socket is mode $mode; it decides who may ask what this machine has been doing."
owner=$(stat -c '%U' "$socket")
[ "$owner" = "$(id -un)" ] || fail "the socket belongs to $owner, not to whoever ran sudo."
echo "OK: the socket is owned by the person who started the daemon, and by nobody else"

ask '{"op":"requests","since":600,"limit":50}' \
    | jq -e '[.ok[] | select(.process == "curl" and .method == "GET")] | length > 0' >/dev/null \
    || fail "the socket does not report the request that was read."
echo "OK: the socket reports what was read"

# The budget: what Flowlight is allowed to read, and for how long. Asserted while the daemon is running,
# because the whole point of it is that it can be changed without restarting anything.
ask '{"op":"budget"}' | jq -e '.ok.described | length == 4 and (.[0] | test("Payloads"))' >/dev/null \
    || fail "the budget does not describe itself."
echo "OK: the budget says what it is, in sentences"

echo "Keeping only the host of each request..."
ask '{"op":"set-budget","paths":"host-only"}' | jq -e '.ok.paths == "host-only"' >/dev/null \
    || fail "the budget would not change."
# The daemon reads the budget back on the same two-second timer as the rules.
sleep 4
curl -sS --http1.1 --max-time 10 "https://$target_host/budget-test-path" -o /dev/null
sleep 2
ask '{"op":"requests","since":600,"limit":200}' \
    | jq -e '[.ok[] | select(.target == "/budget-test-path")] | length == 0' >/dev/null \
    || fail "a path was kept after the budget said to keep only the host."
ask '{"op":"requests","since":600,"limit":200}' \
    | jq -e '[.ok[] | select(.target == "/\u2026")] | length > 0' >/dev/null \
    || fail "the request was not recorded at all, which is not the same as keeping only its host."
echo "OK: only the host is kept, and the request is still recorded"

# Export: sending what was seen somewhere else. A file destination, so this asserts the whole mechanism --
# the consent, the field list, the high-water mark -- without depending on a collector being reachable from
# CI. What crosses the network is one `ureq` call away from what is asserted here.
#
# The order matters and is the point: configured first and sending nothing, then agreed to and sending.
ask "{\"op\":\"set-export\",\"destination\":\"$export_file\"}" \
    | jq -e '.ok.sending == false and .ok.consented == false and (.ok.why_not | test("agreed"))' >/dev/null \
    || fail "naming a destination did not leave export unconsented."
ask '{"op":"export"}' | jq -e '.ok.disclosure | length > 3' >/dev/null \
    || fail "export does not disclose what it would send."
echo "OK: naming a destination discloses what would be sent and sends nothing"

# Longer than the ten-second export interval, so this is a claim about a daemon that had the chance.
sleep 5
if [ -f "$export_file" ]; then
    fail "records were sent before anybody agreed to sending them."
fi
echo "OK: nothing is sent until somebody agrees"

# Consent cannot be given in the same breath as changing what it is consent to. Asserted over the socket
# because that is the path the window takes, and the window is where somebody clicks Agree.
ask "{\"op\":\"set-export\",\"destination\":\"$export_second\",\"consent\":true}" \
    | jq -e '.error | test("same breath")' >/dev/null \
    || fail "consent was accepted in the same call that changed what it was consent to."
echo "OK: agreement cannot be given to a disclosure that the same call rewrote"

ask '{"op":"set-export","consent":true}' | jq -e '.ok.sending == true and .ok.consented == true' >/dev/null \
    || fail "agreeing did not put export in force."

await_file() {
    local path=$1 seconds=${2:-30}
    for _ in $(seq "$((seconds * 4))"); do
        if [ -s "$path" ]; then
            return 0
        fi
        sleep 0.25
    done
    fail "nothing was ever written to $path."
}
await_file "$export_file"
echo "OK: once agreed to, what was seen is sent"

sudo cat "$export_file" | jq -s -e "map(select(.process == \"curl\" and .host == \"$target_host\")) | length > 0" \
    >/dev/null || fail "the exported records do not include the request that was read."
echo "OK: the exported records are the records"

# The property the whole module exists for: a field nobody agreed to is not in what leaves. `target` is the
# one that matters -- it is the field most likely to carry something somebody would not choose to send.
sudo cat "$export_file" | jq -s -e 'map(keys) | flatten | unique' >/dev/null \
    || fail "the exported records are not objects."
exported_keys=$(sudo cat "$export_file" | jq -s -r 'map(keys) | flatten | unique | join(",")')
echo "exported fields: $exported_keys"
for unagreed in target pid confidence protocol rpc_tool rpc_method; do
    if printf '%s' "$exported_keys" | grep -qw "$unagreed"; then
        fail "$unagreed was exported without being agreed to."
    fi
done
echo "OK: only the agreed fields left the machine"

# Flowlight's own traffic is not in what Flowlight sends. Left in, a record of a batch being sent is a record
# in the next batch, for ever.
if sudo cat "$export_file" | jq -s -e 'map(select(.process == "flowlightd")) | length > 0' >/dev/null; then
    fail "the daemon exported its own traffic."
fi
echo "OK: the daemon's own traffic is not in what it exports"

# Nothing is sent twice. Asserted against the high-water mark rather than by looking for duplicate lines:
# two identical records are a real thing -- the same host answering the same way in the same second with the
# same byte count -- and a test that called that a duplicate would fail on a correct daemon. What must hold is
# that every record the mark moved past produced exactly one line.
mark_before=$(ask '{"op":"export"}' | jq '.ok.sent_through')
lines_before=$(sudo cat "$export_file" | wc -l)
sleep 5
mark_after=$(ask '{"op":"export"}' | jq '.ok.sent_through')
lines_after=$(sudo cat "$export_file" | wc -l)
[ "$mark_after" -ge "$mark_before" ] || fail "the export mark went backwards."
if [ "$((lines_after - lines_before))" -ne "$((mark_after - mark_before))" ]; then
    fail "the mark moved by $((mark_after - mark_before)) and the file grew by $((lines_after - lines_before)); a record was sent twice or not at all."
fi
echo "OK: a record is sent once"

# And the failure the design exists to prevent: somebody agrees to one destination, and a change points it
# at another under the same yes.
ask "{\"op\":\"set-export\",\"destination\":\"$export_second\"}" \
    | jq -e '.ok.revoked == true and .ok.sending == false and .ok.consented == false' >/dev/null \
    || fail "changing the destination did not take the agreement away."
sleep 5
if [ -f "$export_second" ]; then
    fail "records went to a destination nobody agreed to."
fi
echo "OK: changing where it goes takes the agreement with it"

ask '{"op":"set-export","off":true}' | jq -e '.ok.enabled == false' >/dev/null \
    || fail "export would not turn off."

# Devices: the channels that are not the network. Off until asked for, like everything here that widens what
# is watched.
sudo "$binary" --database "$database" --certificates "$certificates" --json devices \
    | jq -e '.watching == false and (.disclosure | length >= 3)' >/dev/null \
    || fail "watching devices was not off, or does not say what it would do."
sudo "$binary" --database "$database" --certificates "$certificates" devices \
    | grep -q "Never how much went through any of it" \
    || fail "the disclosure does not say what it cannot report."
echo "OK: the other channels are not watched until they are asked for"

sudo "$binary" --database "$database" --certificates "$certificates" --json devices \
    | jq -e '.devices | length == 0' >/dev/null \
    || fail "something was recorded while the feature was off."

sudo "$binary" --database "$database" --certificates "$certificates" devices --on >/dev/null
sleep 8
attached=$(sudo "$binary" --database "$database" --certificates "$certificates" --json devices)
printf '%s\n' "$attached" | jq -c '.devices[:4]'
printf '%s' "$attached" | jq -e '.watching == true' >/dev/null || fail "turning it on did not take."

# A cloud runner has no keyboard plugged in, and may have no USB at all. What can be asserted everywhere is
# that the reading happened and said something truthful rather than inventing a device — so this checks the
# shape of whatever was found, and that nothing claims a byte count.
printf '%s' "$attached" \
    | jq -e '[.devices[] | select((.channel | test("^(usb|bluetooth|volume)$")) | not)] | length == 0' \
    >/dev/null || fail "a device was recorded on a channel that does not exist."
printf '%s' "$attached" | jq -e '[.devices[] | select(has("bytes"))] | length == 0' >/dev/null \
    || fail "a device claimed a byte count, which nothing here can honestly report."
echo "OK: what is attached is read, and nothing claims a throughput it cannot know"

sudo "$binary" --database "$database" --certificates "$certificates" devices --off >/dev/null
sudo "$binary" --database "$database" --certificates "$certificates" --json devices \
    | jq -e '.watching == false' >/dev/null || fail "turning it off did not take."
echo "OK: turning it off stops the watching and keeps what was seen"

# What this machine can do, asked before anything is loaded. On this runner everything essential is present,
# so `check` has to say so and exit zero — and it has to be runnable by somebody who is not root, because that
# is who reads it when something is wrong.
checked=$(sudo "$binary" --database "$database" --certificates "$certificates" --json check)
printf '%s' "$checked" | jq -e '.ready == true' >/dev/null \
    || fail "check says this machine cannot be watched, on the machine the rest of this just passed on."
printf '%s' "$checked" | jq -e '[.findings[] | select(.about == "kernel" and .answer == "yes")] | length == 1' \
    >/dev/null || fail "check does not say whether the kernel is new enough."
printf '%s' "$checked" | jq -e '[.findings[] | select(.about == "tracefs" and .answer == "yes")] | length == 1' \
    >/dev/null || fail "check does not say whether the tracepoint layout could be read."
printf '%s' "$checked" | jq -e '[.findings[] | select(.about == "TLS libraries" and .answer == "yes")] | length == 1' \
    >/dev/null || fail "check found no TLS libraries on a machine where the probes attached."
# Every finding says something, because a report of bare yeses is a report nobody can act on.
printf '%s' "$checked" | jq -e '[.findings[] | select((.said | length) < 20)] | length == 0' >/dev/null \
    || fail "a finding says nothing about what it found."
# Refusing connections is reported, and it is not essential: a machine that cannot refuse can still watch.
printf '%s' "$checked" \
    | jq -e '[.findings[] | select(.about == "refusing connections" and .essential == false)] | length == 1' \
    >/dev/null || fail "check treats refusing connections as essential, which would make watching conditional on it."

# As a person, where the one thing it cannot know is said to be unknown rather than guessed at.
"$binary" --database "$database" --certificates "$certificates" --json check \
    | jq -e '[.findings[] | select(.about == "permission to load" and .answer == "unknown")] | length == 1' \
    >/dev/null || fail "run as a person, check claims to know whether a program could be loaded."
echo "OK: a machine can be asked what it can do before anything is loaded into it"

# Focus: one thing to look at, and every count below it a count of that. What matters is not that the filter
# works — that is a unit test — but that a narrowed screen says it is narrowed, and that the one slice which
# cannot be narrowed returns nothing rather than the whole machine.
sudo "$binary" --database "$database" --certificates "$certificates" --json focus \
    | jq -e '(has("focus") | not)' >/dev/null || fail "something was in focus before anything was asked for."

# Sliced by process, where the arithmetic is not a matter of what happened to be reached: narrowed to one
# process there is exactly one row, whatever else the machine did. Comparing host counts instead was flaky —
# it asserted that some *other* process had reached a host curl did not, which is a fact about the runner.
everything=$(sudo "$binary" --database "$database" --certificates "$certificates" --json report --by process --since 3600 \
    | jq '.rows | length')
[ "$everything" -ge 2 ] \
    || fail "only one process made a request, so narrowing to one cannot be shown to narrow anything."
sudo "$binary" --database "$database" --certificates "$certificates" focus --process curl \
    | grep -q "Narrowed to process curl" \
    || fail "narrowing did not say what it narrowed to."
narrowed=$(sudo "$binary" --database "$database" --certificates "$certificates" --json report --by process --since 3600)
printf '%s' "$narrowed" | jq -e '.focus == "process:curl" and .narrowed == true' >/dev/null \
    || fail "the report does not say what it was narrowed to."
printf '%s' "$narrowed" | jq -e '(.rows | length) == 1 and .rows[0].name == "curl"' >/dev/null \
    || fail "narrowing to one process did not narrow to that process."
# The terminal says so above the rows, every time, because a count of a subset read as a total is the whole
# failure this feature can cause.
#
# Read from a variable rather than piped into `head`: `head` closes the pipe after one line, the daemon gets
# EPIPE for the rest of the report, and `pipefail` then fails the pipeline whatever the line said. That is how
# this assertion first "failed" against output that was correct.
printed=$(sudo "$binary" --database "$database" --certificates "$certificates" report --by host --since 3600)
case "${printed%%$'\n'*}" in
    "Narrowed to process curl"*) ;;
    *) fail "a narrowed report does not say so above its rows." ;;
esac

# And the one it cannot narrow. An address is recorded at connect(), where the name was already resolved and
# thrown away, so "these addresses, but only api.example.com" is a question the data cannot answer.
sudo "$binary" --database "$database" --certificates "$certificates" focus --host example.com >/dev/null
sudo "$binary" --database "$database" --certificates "$certificates" --json report --by address --since 3600 \
    | jq -e '.narrowed == false and (.rows | length == 0)' >/dev/null \
    || fail "a slice that cannot be narrowed to a host showed rows anyway."

sudo "$binary" --database "$database" --certificates "$certificates" focus --clear | grep -q "Showing everything" \
    || fail "clearing the focus did not take."
echo "OK: a focus narrows what is shown, says so, and refuses the slice it cannot narrow"

# Starter rules. Listing them writes nothing, applying one writes exactly its own rules, and applying it twice
# changes nothing the second time.
sudo "$binary" --database "$database" --certificates "$certificates" --json starters \
    | jq -e 'length >= 4 and ([.[] | select(.action == "allow")] | length == 0)' >/dev/null \
    || fail "the starters are missing, or one of them allows something."
# `rules --json` is one object per line rather than an array, so every count of it is slurped. Counting the
# lines of `jq length` instead gives the number of keys in each rule, which is a number that looks plausible
# and means nothing.
before=$(sudo "$binary" --database "$database" --certificates "$certificates" --json rules | jq -s 'length')
sudo "$binary" --database "$database" --certificates "$certificates" starters >/dev/null
after=$(sudo "$binary" --database "$database" --certificates "$certificates" --json rules | jq -s 'length')
[ "$before" = "$after" ] || fail "listing the starters wrote a rule."

applied=$(sudo "$binary" --database "$database" --certificates "$certificates" --json starters --apply metadata)
printf '%s' "$applied" | jq -e '.added | length >= 3' >/dev/null || fail "applying a starter wrote nothing."
sudo "$binary" --database "$database" --certificates "$certificates" --json rules \
    | jq -s -e '[.[] | select(.subject == "169.254.169.254" and .action == "block")] | length == 1' \
    >/dev/null || fail "the metadata service is not blocked after applying the starter that blocks it."
sudo "$binary" --database "$database" --certificates "$certificates" --json starters --apply metadata \
    | jq -e '(.added | length == 0) and (.unchanged | length >= 3)' >/dev/null \
    || fail "applying the same starter twice wrote it again."
for subject in $(printf '%s' "$applied" | jq -r '.added[]'); do
    sudo "$binary" --database "$database" --certificates "$certificates" --json rules \
        | jq -s -e --arg s "$subject" '[.[] | select(.subject == $s)] | length == 1' >/dev/null \
        || fail "the starter left more than one rule for $subject."
done
echo "OK: the starters are written when they are asked for, once, and not before"

# A demonstration database, which is the only way a tool that watches a private machine gets photographed.
demo=$(mktemp -d)/demonstration.db
sudo "$binary" --database "$database" --certificates "$certificates" demo --into "$demo" \
    | grep -q "Nothing in it happened" || fail "the demonstration does not say what it is."
sudo "$binary" --database "$demo" --certificates "$certificates" --json report --by host --since 86400 \
    | jq -e '.rows | length >= 3' >/dev/null || fail "the demonstration has nothing to photograph."
# On stderr, not stdout: stdout is the answer, and a notice printed into it makes `--json` unparseable.
said=$(sudo "$binary" --database "$demo" --certificates "$certificates" coverage 2>&1 >/dev/null)
case "$said" in
    *"This is a demonstration database."*) ;;
    *) fail "reading a demonstration does not say that is what it is." ;;
esac
# And the answer itself stays machine-readable, which is the reason the notice is not in it.
sudo "$binary" --database "$demo" --certificates "$certificates" --json coverage 2>/dev/null \
    | jq -e '.requests > 0' >/dev/null \
    || fail "a demonstration's JSON is not parseable, or says nothing was read."
# It will not write over anything, and the daemon will not watch into one: real traffic mixed into a
# demonstration would leave two things nobody can tell apart.
if sudo "$binary" --database "$database" --certificates "$certificates" demo --into "$demo" >/dev/null 2>&1; then
    fail "a demonstration was written over a file that already existed."
fi
if sudo "$binary" --database "$demo" --certificates "$certificates" --seconds 2 >/dev/null 2>&1; then
    fail "the daemon watched into a demonstration database."
fi
echo "OK: a demonstration can be photographed, says what it is, and cannot be watched into"

# Nine languages. What is asserted is not the wording — that is what the unit tests are for — but that the
# sentences somebody is asked to agree to actually change language, that the facts inside them survive being
# translated, and that a translated disclosure says it is a translation.
sudo "$binary" --database "$database" --certificates "$certificates" --json language \
    | jq -e '.language == "en" and (.every | length == 9) and (has("caveat") | not)' >/dev/null \
    || fail "the language is not English by default, or there are not nine of them."

english=$(ask '{"op":"export"}' | jq -r '.ok.disclosure | join(" ")')
printf '%s' "$english" | grep -q "is bound to exactly that" \
    || fail "the English disclosure is not the English one."

sudo "$binary" --database "$database" --certificates "$certificates" --json language de \
    | jq -e '.language == "de" and .translated == true and (.caveat | length > 20)' >/dev/null \
    || fail "setting a language did not take."

german=$(ask '{"op":"export"}' | jq -r '.ok.disclosure | join(" ")')
printf '%s' "$german" | grep -q "Zustimmung gilt genau dafür" \
    || fail "the disclosure did not change language."
# The destination is the fact the disclosure exists to carry. A translation that drops it reads perfectly
# well and says nothing, which is the failure worth a test rather than a proofread.
printf '%s' "$german" | grep -q "$export_second" \
    || fail "the translated disclosure lost the destination."
printf '%s' "$german" | grep -q "englische Fassung" \
    || fail "a translated disclosure does not say that it is a translation."

# A language nobody has a catalogue for is refused rather than quietly answered in English.
if sudo "$binary" --database "$database" --certificates "$certificates" language tlh >/dev/null 2>&1; then
    fail "a language this build does not have was accepted."
fi
# And simplified Chinese is not served to somebody who asked for traditional.
if sudo "$binary" --database "$database" --certificates "$certificates" language zh-Hant >/dev/null 2>&1; then
    fail "traditional Chinese was answered with the simplified catalogue."
fi

sudo "$binary" --database "$database" --certificates "$certificates" --json language --auto \
    | jq -e '(.setting | not) and .language == "en"' >/dev/null \
    || fail "going back to the environment did not take."
echo "OK: the sentences somebody agrees to are said in nine languages, and say which one binds"

# Reports: traffic sliced one way, with the processes that do not look like the rest named and the arithmetic
# behind each reason shown.
for slice in process host address protocol; do
    sudo "$binary" --database "$database" --certificates "$certificates" --json report --by "$slice" --since 3600 \
        | jq -e '.rows | length > 0' >/dev/null \
        || fail "a report by $slice had nothing in it."
done
echo "OK: traffic can be sliced by process, host, address and protocol"

report=$(sudo "$binary" --database "$database" --certificates "$certificates" --json report --by process --since 3600)
printf '%s' "$report" | jq -e '[.rows[] | select(.name == "curl")] | length == 1' >/dev/null \
    || fail "the report does not name the process that made the requests."
# A share is a share of something, so the shares of everything have to come to about a hundred.
printf '%s' "$report" | jq -e '([.rows[].share] | add) > 95' >/dev/null \
    || fail "the shares do not add up to the window."
echo "OK: a share is a share of the window"

# Bytes come from requests, which record a host; a connection records an address. A column of zeroes would be
# worse than no column, so the slice says whether its bytes mean anything.
sudo "$binary" --database "$database" --certificates "$certificates" --json report --by address --since 3600 \
    | jq -e '.counts_bytes == false' >/dev/null \
    || fail "a report by address claims its bytes mean something."
sudo "$binary" --database "$database" --certificates "$certificates" --json report --by process --since 3600 \
    | jq -e '.counts_bytes == true' >/dev/null \
    || fail "a report by process claims its bytes mean nothing."
echo "OK: a slice says whether its bytes mean anything"

# gh is written in Go, so nothing of its traffic can be read. That is the case Coverage exists to name, and a
# report should name it too when somebody is looking at one process rather than at the machine.
if [ "$go_tested" = yes ]; then
    printf '%s' "$report" \
        | jq -e '[.standing[] | select(.process == "gh")] | length == 1' >/dev/null \
        || fail "a process nothing could be read from was not named as standing out."
    printf '%s' "$report" \
        | jq -e '[.standing[] | select(.process == "gh") | .reasons[] | select(test("nothing was read"))] | length > 0' \
        >/dev/null || fail "the reason given does not say what it noticed."
    echo "OK: a process nothing could be read from is named, with the reason"
fi

# Every reason carries its arithmetic, which is the rule the whole feature rests on.
printf '%s' "$report" | jq -e '[.standing[].reasons[] | select((. | length) < 20)] | length == 0' >/dev/null \
    || fail "a reason was given with nothing to back it up."
echo "OK: every reason carries the numbers behind it"

# A slice nobody defined is refused rather than guessed at.
if sudo "$binary" --database "$database" --certificates "$certificates" report --by agent 2>/dev/null; then
    fail "a report by something that is not a slice was accepted."
fi
echo "OK: a slice nobody defined is refused"

# Alerts: things worth saying, each carrying the arithmetic behind it. The event-driven ones are assertable
# here; the statistical ones need days of history and are unit-tested against numbers instead.
alerts=$(sudo "$binary" --database "$database" --certificates "$certificates" --json alerts --since 3600)
printf '%s\n' "$alerts" | jq -c '{kind, subject}' | head -8

# A host nothing on this machine had reached before. This test reached one a minute ago.
printf '%s' "$alerts" \
    | jq -e 'select(.kind == "first contact with a host" and .subject == "'"$target_host"'")' >/dev/null \
    || fail "reaching a host for the first time was not noticed."
echo "OK: a host nothing had reached before was noticed"

# A process that had never been on the network. `curl` is one, from this test's point of view.
printf '%s' "$alerts" | jq -e 'select(.kind == "a process new to the network")' >/dev/null \
    || fail "a process new to the network was not noticed."
echo "OK: a process new to the network was noticed"

# A connection a rule refused. The blocking section wrote a rule and had it bite.
if [ "$block_tested" = yes ]; then
    printf '%s' "$alerts" | jq -e 'select(.kind == "a connection was refused")' >/dev/null \
        || fail "a refused connection was not recorded as worth saying."
    echo "OK: a refusal is recorded, because the person it happens to wrote the rule"
fi

# Every alert says what it is about in a sentence, because a ranked list with no numbers is a horoscope.
printf '%s' "$alerts" | jq -e 'select((.detail | length) < 20)' >/dev/null \
    && fail "an alert was recorded with nothing to say for itself."
echo "OK: every alert says what it noticed"

# And the same thing is not said twice within the hour.
repeats=$(printf '%s' "$alerts" | jq -s '[.[] | "\(.kind)/\(.subject)"] | length - (unique | length)')
[ "$repeats" = 0 ] || fail "$repeats alert(s) repeat a kind and subject within the window."
echo "OK: the same thing is not said twice"

# Only the ones about agents, when that is what was asked for.
sudo "$binary" --database "$database" --certificates "$certificates" --json alerts --since 3600 --agents \
    | jq -e 'select(.about_an_agent == false)' >/dev/null \
    && fail "--agents returned something that is not about an agent."
echo "OK: the ones about agents can be asked for on their own"

# Who operates an address. Off until it is asked for, because it is the one thing Flowlight does that tells a
# third party anything — so the first assertion is that it is off and says what asking would mean.
sudo "$binary" --database "$database" --certificates "$certificates" --json owners \
    | jq -e '.asking == false and (.disclosure | length >= 4)' >/dev/null \
    || fail "looking up owners was not off, or does not say what asking would mean."
sudo "$binary" --database "$database" --certificates "$certificates" owners \
    | grep -q "What is sent is an address" \
    || fail "the disclosure does not say what leaves."
echo "OK: nobody is asked who operates anything until it is asked for"

# Nothing was learnt while it was off, however many connections were made.
sudo "$binary" --database "$database" --certificates "$certificates" --json owners \
    | jq -e '.owners | length == 0' >/dev/null \
    || fail "something was looked up while the feature was off."
echo "OK: nothing was looked up while it was off"

sudo "$binary" --database "$database" --certificates "$certificates" owners --on >/dev/null
sudo "$binary" --database "$database" --certificates "$certificates" --json owners \
    | jq -e '.asking == true and (.unknown > 0)' >/dev/null \
    || fail "turning it on did not take, or there is nothing for it to look up."
echo "OK: turned on, and there are addresses waiting to be looked up"

# The daemon asks a few a minute. It has been running for a while by now, so give it one pass.
await "looked up who operates" 90
learnt=$(sudo "$binary" --database "$database" --certificates "$certificates" --json owners)
printf '%s\n' "$learnt" | jq -c '.owners[:3]'
printf '%s' "$learnt" | jq -e '[.owners[] | select(.asn > 0)] | length > 0' >/dev/null \
    || fail "nothing was learnt about who operates anything."
printf '%s' "$learnt" | jq -e '[.owners[] | select(.name == "this network")] | length == 0' >/dev/null \
    || fail "this network was counted as an operator."
echo "OK: who operates the addresses this machine reached was looked up"

sudo "$binary" --database "$database" --certificates "$certificates" owners --off >/dev/null
sudo "$binary" --database "$database" --certificates "$certificates" --json owners \
    | jq -e '.asking == false and ((.owners | length) > 0)' >/dev/null \
    || fail "turning it off lost what had already been learnt."
echo "OK: turning it off keeps what was already learnt"

# What an agent is set up to do, read out of its own configuration. A hook is a program the agent runs on its
# own behalf and a permission is a decision somebody made once — neither is visible from any amount of watching
# the network, because a hook's traffic looks exactly like the agent's own.
if [ "$agent_tested" = yes ]; then
    workspace="$agent_home/.claude"
    mkdir -p "$workspace/skills/smoke" "$workspace/commands"
    printf -- '---\nname: smoke\ndescription: A skill written by the smoke test\n---\n\nTHE-BODY-IS-NOT-READ\n' \
        >"$workspace/skills/smoke/SKILL.md"
    printf 'Reviews a change.\n' >"$workspace/commands/review.md"
    printf '{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"/usr/local/bin/smoke-hook"}]}]},\n"permissions":{"allow":["Bash(git push:*)"],"deny":["Bash(rm:*)"]}}\n' \
        >"$workspace/settings.json"

    declared=$(sudo "$binary" --database "$database" --certificates "$certificates" --json agents --since 3600 \
        | jq -c 'select(.agent == "claude") | .declares')
    printf 'claude declares: %s\n' "$declared"
    printf '%s' "$declared" | jq -e '[.[] | select(.kind == "skill" and .name == "smoke")] | length == 1' >/dev/null \
        || fail "the skill was not read."
    printf '%s' "$declared" | jq -e '[.[] | select(.kind == "command" and .name == "review")] | length == 1' >/dev/null \
        || fail "the command was not read."

    # A hook is written out with what it runs, and called sensitive.
    printf '%s' "$declared" \
        | jq -e '[.[] | select(.kind == "hook" and .sensitive == true and (.detail | test("smoke-hook")))] | length == 1' \
        >/dev/null || fail "the hook was not read, or was not called sensitive."

    # A permission that grants is flagged; one that refuses is not.
    printf '%s' "$declared" \
        | jq -e '[.[] | select(.kind == "permission" and .name == "Bash(git push:*)" and .sensitive == true)] | length == 1' \
        >/dev/null || fail "a permission that grants something was not flagged."
    printf '%s' "$declared" \
        | jq -e '[.[] | select(.name == "Bash(rm:*)" and .sensitive == false)] | length == 1' >/dev/null \
        || fail "a permission that refuses something was flagged as if it granted it."
    echo "OK: what an agent is set up to do is read, and what can act without asking is flagged"

    # The description, never the body: a skill is somebody's writing.
    if printf '%s' "$declared" | grep -qF "THE-BODY-IS-NOT-READ"; then
        fail "a skill's body was read."
    fi
    printf '%s' "$declared" | jq -e '[.[] | select(.detail == "A skill written by the smoke test")] | length == 1' \
        >/dev/null || fail "the skill's description was not read."
    echo "OK: a skill's description is kept and its body is not"

    # And the path says which file without saying whose home it is in.
    printf '%s' "$declared" | jq -e '[.[] | select(.source | startswith("/home"))] | length == 0' >/dev/null \
        || fail "a path spells out somebody's home directory."
    echo "OK: a path says which file without saying whose home it is in"

    rm -rf "$workspace/skills" "$workspace/commands" "$workspace/settings.json"
fi

# Launching an agent through Flowlight. The claim is not that it works — the scan already marks agents — but
# that the mark is in the kernel *before* the agent runs. So this asks the sharpest question there is: a rule
# scoped to the agent, and a connection made with no pause at all.
#
# Every other agent test in this file sleeps three seconds first, because that is how long the scan can take.
# This one must not, and must still be refused.
#
# A different address from the blocking section, and deliberately: 1.1.1.1 is blocked for everyone by this
# point, so a refusal there would prove nothing about the mark. This one has no rule but the scoped one.
launch_address=1.0.0.1
if [ "$agent_tested" = yes ] && curl -sS --max-time 8 "https://$launch_address/" -o /dev/null 2>/dev/null; then
    # Never as root: an agent started by root would run as root.
    as_root=$(sudo "$binary" --socket "$socket" launch -- /bin/true 2>&1 || true)
    printf '%s' "$as_root" | grep -q "must not be run as root" \
        || fail "launching as root was not refused. It said: $as_root"
    echo "OK: launching refuses to run as root, because the agent would be root too"

    # What a launcher or a supervisor would be told to set, for the case where Flowlight is not the parent.
    "$binary" --socket "$socket" launch --agent claude --print-environment >"$reported" 2>/dev/null \
        || fail "launch could not say what it would set."
    grep -q "^FLOWLIGHT_AGENT=claude$" "$reported" \
        || fail "the environment does not say which agent it is for."
    if grep -qv "=" "$reported"; then
        fail "the printed environment has a line in it that is not a variable."
    fi
    echo "OK: the variables a launcher would set can be read by one"

    # And now the real thing. A rule that refuses the address for this agent alone, then a connection made
    # immediately, with no pause for any scan to have noticed anything.
    sudo "$binary" --database "$database" --certificates "$certificates" \
        block "$launch_address" --port 443 --agent claude --note "launch test" >/dev/null
    sleep 3
    # First: without launching, and with no pause, the same connection goes through. Without this the check
    # below could pass because of a rule rather than because of the mark — which is the way a test lies.
    curl -sS --max-time 8 "https://$launch_address/" -o /dev/null 2>/dev/null \
        || fail "the address used for the launch test is refused for everyone, so the test would prove nothing."
    echo "OK: the scoped rule leaves everything that is not the agent alone"

    if "$binary" --socket "$socket" launch --agent claude -- \
        curl -sS --max-time 8 "https://$launch_address/" -o /dev/null 2>/dev/null; then
        fail "a connection made immediately by a launched agent was not refused, so the mark did not land before it ran."
    fi
    echo "OK: the mark is in the kernel before the agent runs, with no pause at all"

    # A process somebody else owns is not theirs to name.
    other=$(ask '{"op":"mark","pid":1,"agent":"claude"}')
    printf '%s' "$other" | grep -q "belongs to uid" \
        || fail "marking init as an agent was not refused. It said: $other"
    echo "OK: a process somebody else owns cannot be marked as your agent"

    # And the agent's exit status is the agent's, because something is watching it.
    launched=0
    "$binary" --socket "$socket" launch --agent claude -- /bin/sh -c "exit 42" 2>/dev/null || launched=$?
    [ "$launched" = 42 ] || fail "a launched agent's exit status came back as $launched, not 42."
    echo "OK: what the agent exited with is what launching exits with"

    for id in $(ask '{"op":"rules"}' | jq -r '.ok[] | select(.scope == "agent:claude") | .id'); do
        ask "{\"op\":\"forget\",\"id\":$id}" >/dev/null
    done
    sleep 3
else
    echo "SKIP: no fake agent, or $launch_address is not reachable, so launching could not be exercised"
fi

# Interception: the one thing Flowlight does that changes what an application sees. Off, and off by default,
# so the first thing asserted is that it is off and says so.
sudo "$binary" --database "$database" --certificates "$certificates" --json intercept \
    | jq -e '.enabled == false and .running == false and (.why_not | test("off"))' >/dev/null \
    || fail "interception was not off to begin with."
sudo "$binary" --database "$database" --certificates "$certificates" intercept | grep -q "is not watching" \
    || fail "the disclosure does not distinguish interception from watching."
echo "OK: interception is off until somebody turns it on"

# A certificate authority, made on this machine the first time the daemon started with interception available.
certificate=$(sudo "$binary" --database "$database" --certificates "$certificates" --json intercept | jq -r '.certificate // empty')
[ -n "$certificate" ] || fail "no certificate authority was made."
sudo test -f "$certificate" || fail "the certificate is not at $certificate."
# The keys are beside the database, in the directory only root may enter.
keys="$(dirname "$database")/intercept"
ca_mode=$(sudo stat -c '%a' "$keys/flowlight-ca.key")
[ "$ca_mode" = 600 ] || fail "the authority's key is mode $ca_mode; anybody who can read it can impersonate every site on the internet."
leaf_mode=$(sudo stat -c '%a' "$keys/leaf.key")
[ "$leaf_mode" = 600 ] || fail "the shared leaf key is mode $leaf_mode."
keys_mode=$(sudo stat -c '%a' "$keys")
[ "$keys_mode" = 700 ] || fail "the keys' directory is mode $keys_mode."
echo "OK: the keys are beside the database, readable by nobody else"

# And the certificate is the other way round, because an agent runs as a person who has to read it. Asserted
# as that person rather than with sudo, which is the whole point.
[ -r "$certificate" ] || fail "the certificate at $certificate is not readable by the user an agent runs as."
published_mode=$(stat -c '%a' "$(dirname "$certificate")")
[ "$published_mode" = 755 ] || fail "the certificate's directory is mode $published_mode; it has to be readable."
echo "OK: the certificate is published where the person an agent runs as can read it"

bundle=$(sudo "$binary" --database "$database" --certificates "$certificates" --json intercept | jq -r '.bundle // empty')
[ -r "$bundle" ] || fail "the bundle at $bundle is not readable by the user an agent runs as."
roots=$(grep -c "BEGIN CERTIFICATE" "$bundle")
[ "$roots" -gt 1 ] || fail "the bundle holds only $roots certificate(s); it must be this machine's roots plus Flowlight's."
echo "OK: the bundle is this machine's roots plus Flowlight's, so nothing else stops working"

# `trust` says what it can do and what it cannot, and never touches a store without being asked.
sudo "$binary" --database "$database" --certificates "$certificates" --json trust | jq -e '.steps | length >= 6' >/dev/null \
    || fail "trust does not list what has to be told."
sudo "$binary" --database "$database" --certificates "$certificates" --json trust \
    | jq -e '[.steps[] | select(.what == "Node")] | .[0].how | test("NODE_EXTRA_CA_CERTS")' >/dev/null \
    || fail "trust does not say how to tell Node."
sudo "$binary" --database "$database" --certificates "$certificates" --json trust | jq -e '.installed == false' >/dev/null \
    || fail "trust reported the certificate as installed before anybody asked for it."
echo "OK: trust says what it can do and has not done any of it"

# A canned answer. Written before interception is on, which is the order somebody would do it in, so the
# answer has to say that it cannot fire yet.
sudo "$binary" --database "$database" --certificates "$certificates" mock "$target_host" --path '/mocked*' --status 503 \
    --header 'Retry-After: 30' --body '{"error":"mocked by flowlight"}' --note "smoke test" \
    | grep -q "cannot answer anything yet" \
    || fail "a canned answer written while interception is off did not say that it cannot fire."
sudo "$binary" --database "$database" --certificates "$certificates" --json mocks \
    | jq -e '.subject == "'"$target_host"'" and .status == 503 and .path == "/mocked*"' >/dev/null \
    || fail "the canned answer was not stored."
echo "OK: a canned answer is written, and says it cannot fire until interception is on"

# A mock for `*` is refused: it would answer every request from every agent in scope, which is not a test of
# anything and is very hard to notice.
if sudo "$binary" --database "$database" --certificates "$certificates" mock '*' --status 500 2>/dev/null; then
    fail "a canned answer for every host was accepted."
fi
echo "OK: a canned answer has to name a host"

# And now the whole thing, against a real kernel: scope it to the fake agent, turn it on, and make a request
# from that agent.
if [ "$agent_tested" = yes ]; then
    sudo "$binary" --database "$database" --certificates "$certificates" intercept --agent claude --on >/dev/null
    sudo "$binary" --database "$database" --certificates "$certificates" --json intercept \
        | jq -e '.running == true and (.agents | index("claude"))' >/dev/null \
        || fail "interception would not turn on."
    # The daemon reads this on the same two-second timer as the rules.
    sleep 4
    await "Connections from claude"

    # curl trusting Flowlight's bundle, run as the fake agent so the kernel's scope matches. `sleep 3` because
    # an agent is noticed by a scan that runs once a second, and its mark has to be in the kernel before it
    # connects.
    mocked=$("$fake_agent" -c "sleep 3; curl -sS --cacert '$bundle' -o /dev/null -w '%{http_code}' --max-time 15 'https://$target_host/mocked-path' 2>/dev/null; exit \$?" || true)
    printf 'the agent got: %s\n' "$mocked"
    [ "$mocked" = 503 ] || fail "a mocked request answered $mocked; it should have been the canned 503."
    echo "OK: a request from an agent in scope was answered by Flowlight rather than by the server"

    # The answer names itself, so a log kept elsewhere on this machine can also tell.
    headers=$("$fake_agent" -c "sleep 1; curl -sS --cacert '$bundle' -D - -o /dev/null --max-time 15 'https://$target_host/mocked-path' 2>/dev/null; exit \$?" || true)
    printf '%s' "$headers" | grep -qi "X-Flowlight-Mock" \
        || fail "the canned answer did not name itself in the response."
    printf '%s' "$headers" | grep -qi "Retry-After: 30" \
        || fail "the canned answer's own headers were not sent."
    echo "OK: the answer says it came from Flowlight and carries the headers the rule named"

    # A path no answer covers is not terminated at all: no certificate is presented for it, so the real one is
    # what curl sees — and curl trusting only Flowlight's bundle still works, because the bundle holds the
    # machine's roots too.
    passed=$("$fake_agent" -c "sleep 1; curl -sS --cacert '$bundle' -o /dev/null -w '%{http_code}' --max-time 15 'https://$target_host/' 2>/dev/null; exit \$?" || true)
    printf 'a path nothing mocks got: %s\n' "$passed"
    case "$passed" in
        2*|3*|4*) echo "OK: a request no answer covers reached the real server" ;;
        *) fail "a request no answer covers came back as $passed; it should have reached the server." ;;
    esac

    # And nothing outside the scope is touched. `curl` is not an agent, so its connection is never redirected
    # and it does not need Flowlight's certificate at all.
    outside=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 "https://$target_host/mocked-path" || true)
    [ "$outside" != 503 ] \
        || fail "a process outside the scope was intercepted."
    echo "OK: a process outside the scope is not intercepted, and needs no certificate"

    # What Flowlight did is recorded. Not what it passed through: a note per connection would bury the ones
    # that matter.
    ask '{"op":"requests","since":600,"limit":400}' >/dev/null
    sudo "$binary" --database "$database" --certificates "$certificates" --json coverage --since 600 >/dev/null

    # Guardrails: which tools an agent may use, which is a different question from which hosts it may reach.
    # A guardrail is decided in the proxy, so this needs interception on — which it still is.
    guard_secret="do-not-repeat-this-argument"
    sudo "$binary" --database "$database" --certificates "$certificates" \
        guardrail --tool 'smoke_*' --agent claude --note "smoke test" >/dev/null
    sudo "$binary" --database "$database" --certificates "$certificates" --json guardrails \
        | jq -e '.tool == "smoke_*" and .agent == "claude" and .hits == 0' >/dev/null \
        || fail "the guardrail was not stored."
    echo "OK: a guardrail is written, and has refused nothing yet"

    # One that names nothing would refuse every tool of every agent.
    if sudo "$binary" --database "$database" --certificates "$certificates" guardrail 2>/dev/null; then
        fail "a guardrail naming nothing at all was accepted."
    fi
    echo "OK: a guardrail has to name a tool, a server or a resource"

    sleep 4
    # The agent asks to use the tool. The answer has to be a JSON-RPC error it understands, not a dropped
    # connection it would retry.
    refused_body=$("$fake_agent" -c "sleep 1; curl -sS --cacert '$bundle' --max-time 15 -X POST \
        -H 'Content-Type: application/json' \
        --data '{\"jsonrpc\":\"2.0\",\"id\":77,\"method\":\"tools/call\",\"params\":{\"name\":\"smoke_tool\",\"arguments\":{\"secret\":\"$guard_secret\"}}}' \
        'https://$target_host/mcp' 2>/dev/null; exit \$?" || true)
    printf 'the agent got: %s\n' "$refused_body"
    printf '%s' "$refused_body" | jq -e '.error.code == -32000 and .id == 77' >/dev/null \
        || fail "a guarded tool call did not come back as a JSON-RPC error answering the call."
    printf '%s' "$refused_body" | jq -e '.error.data.refusedBy == "flowlight"' >/dev/null \
        || fail "the refusal does not say who refused it."
    echo "OK: a guarded tool call is refused with an error the agent understands"

    # And the thing the tool was asked to do is in none of it. This is the property the whole design rests on:
    # reading a call's method and its tool's name must not mean reading its arguments.
    if printf '%s' "$refused_body" | grep -qF "$guard_secret"; then
        fail "the refusal repeated the tool's arguments back."
    fi
    sleep 2
    if sudo "$binary" --database "$database" --certificates "$certificates" --json history --since 600 \
        | grep -qF "$guard_secret"; then
        fail "a guarded call's arguments were recorded."
    fi
    echo "OK: what the tool was asked to do was never read"

    sudo "$binary" --database "$database" --certificates "$certificates" --json guardrails \
        | jq -e '.hits >= 1' >/dev/null \
        || fail "the guardrail did not count the call it refused."
    echo "OK: a refusal is counted against the guardrail that made it"

    # A tool no guardrail names is not refused.
    allowed=$("$fake_agent" -c "sleep 1; curl -sS --cacert '$bundle' --max-time 15 -o /dev/null -w '%{http_code}' -X POST \
        -H 'Content-Type: application/json' \
        --data '{\"jsonrpc\":\"2.0\",\"id\":78,\"method\":\"tools/call\",\"params\":{\"name\":\"other_tool\"}}' \
        'https://$target_host/mcp' 2>/dev/null; exit \$?" || true)
    printf 'a tool nothing names got: %s\n' "$allowed"
    [ "$allowed" != 200 ] || fail "a tool no guardrail names was answered by Flowlight rather than the server."
    echo "OK: a tool no guardrail names reaches the server"

    for id in $(sudo "$binary" --database "$database" --certificates "$certificates" --json guardrails | jq -r '.id'); do
        sudo "$binary" --database "$database" --certificates "$certificates" forget-guardrail "$id" >/dev/null
    done

    sudo "$binary" --database "$database" --certificates "$certificates" intercept --off >/dev/null
    sleep 4
    after=$("$fake_agent" -c "sleep 1; curl -sS --cacert '$bundle' -o /dev/null -w '%{http_code}' --max-time 15 'https://$target_host/mocked-path' 2>/dev/null; exit \$?" || true)
    [ "$after" != 503 ] || fail "a request was still mocked after interception was turned off."
    echo "OK: turning it off stops the redirect"
else
    echo "SKIP: there is no fake agent here, so interception's scope could not be exercised"
fi

# Ask: a question about this machine, answered by a model somebody configured. There is no model in
# Flowlight for Linux -- that is the one deliberate difference from the macOS build -- so the first thing
# asserted is that asking without one is refused rather than quietly sent somewhere.
if sudo "$binary" --database "$database" --certificates "$certificates" query "what happened today?" 2>/dev/null; then
    fail "a question was answered with no model configured."
fi
# Captured rather than piped: `pipefail` is on, the command is supposed to fail, and a pipeline that
# reports the failure of the thing it is asserting about tells you nothing.
refusal=$(sudo "$binary" --database "$database" --certificates "$certificates" query "what happened?" 2>&1 || true)
printf '%s\n' "$refusal"
printf '%s' "$refusal" | grep -q "no model" \
    || fail "asking with no model configured did not say that there is no model."
echo "OK: there is no model until somebody configures one"

# A key and a question about this machine must not cross the network in the clear.
if sudo "$binary" --database "$database" --certificates "$certificates" model --kind compatible \
    --endpoint "http://a-collector.example/v1/chat/completions" 2>/dev/null; then
    fail "a plain http endpoint on the internet was accepted."
fi
echo "OK: a plain http endpoint that is not local is refused"

# A key goes in a file, mode 600, next to the database -- never in the database, which gets copied.
printf 'a-smoke-test-key\n' >"$model_key"
sudo "$binary" --database "$database" --certificates "$certificates" model --kind anthropic --key-file "$model_key" >/dev/null
key_file="$(dirname "$database")/ask.key"
sudo test -f "$key_file" || fail "the key was not written beside the database."
key_mode=$(sudo stat -c '%a' "$key_file")
[ "$key_mode" = 600 ] || fail "the key file is mode $key_mode; anybody on this machine could read it."
if sudo grep -qF "a-smoke-test-key" "$database"; then
    fail "the key was written into the database."
fi
echo "OK: a key is a file of its own, mode 600, and is not in the database"

sudo "$binary" --database "$database" --certificates "$certificates" --json model | jq -e '.key_on_file == true' >/dev/null \
    || fail "the key on file was not reported."
if sudo "$binary" --database "$database" --certificates "$certificates" --json model | grep -qF "a-smoke-test-key"; then
    fail "the key was printed back."
fi
echo "OK: whether there is a key is reported; the key never is"

sudo "$binary" --database "$database" --certificates "$certificates" model --forget-key >/dev/null
if sudo test -f "$key_file"; then
    fail "the key was not forgotten."
fi

# And now a model that is not a model: a loopback server speaking the OpenAI shape, so the whole loop runs
# against the real daemon, the real socket and the real query runner.
python3 "$(dirname "$0")/fake-model.py" "$model_log" "$model_port_file" &
model_server=$!
for _ in $(seq 40); do
    if [ -s "$model_port_file" ]; then break; fi
    sleep 0.25
done
model_port=$(cat "$model_port_file")
[ -n "$model_port" ] || fail "the fake model server never started."
echo "A model server that is not a model, on port $model_port"

sudo "$binary" --database "$database" --certificates "$certificates" model --kind local \
    --endpoint "http://127.0.0.1:$model_port/v1/chat/completions" --model smoke-model \
    | grep -q "Nothing crosses the internet" \
    || fail "a local endpoint was not described as local."
sudo "$binary" --database "$database" --certificates "$certificates" --json model | jq -e '.ready == true and .sends_off_the_machine == false' \
    >/dev/null || fail "a configured local model is not ready."
echo "OK: a local model server is configured, and is described as sending nothing anywhere"

answer=$(sudo "$binary" --database "$database" --certificates "$certificates" query "how much happened today?")
printf '%s\n' "$answer"
printf '%s' "$answer" | grep -q "FLOWLIGHT-SAW" \
    || fail "the model's answer did not come back."
printf '%s' "$answer" | grep -q "totals" \
    || fail "the answer did not say which queries produced it."
echo "OK: a question goes to the model, the model names a query, Flowlight runs it and the answer comes back"

# The same question over the socket, which is the path the window takes.
ask "{\"op\":\"question\",\"question\":\"how much happened today?\"}" \
    | jq -e '.ok.answer | test("FLOWLIGHT-SAW")' >/dev/null \
    || fail "the socket would not answer a question."
ask "{\"op\":\"question\",\"question\":\"how much happened today?\"}" \
    | jq -e '[.ok.calls[] | select(.query == "totals")] | length > 0' >/dev/null \
    || fail "the socket did not report which queries ran."
echo "OK: the window's path answers the same question the same way"

# The boundary, end to end: everything the daemon sent to the model, checked for the things a model must
# never be handed. A request target is the one that matters -- it is in the database and in no query result.
grep -q '"runQuery"' "$model_log" || fail "the model was never offered Flowlight's query tool."
grep -q '"totals"' "$model_log" || fail "the model was never told which queries exist."
for forbidden in "/budget-test-path" "$secret" "$mcp_secret" "a-smoke-test-key"; do
    if grep -qF "$forbidden" "$model_log"; then
        fail "'$forbidden' was sent to the model."
    fi
done
# And no SQL, because there is no way to express it: the tool takes a name from a list.
if grep -qi "SELECT " "$model_log"; then
    fail "something that looks like SQL was sent to the model."
fi
echo "OK: what reached the model was the question, the query list and the totals -- and nothing else"

# A model that answers with a query nobody wrote gets a sentence back, not an empty result. Asserted through
# the real loop by naming a query that does not exist in a second fake reply would need a second server, so
# this is the unit-tested half; what is asserted here is the shape of the tool the model was handed.
sudo "$binary" --database "$database" --certificates "$certificates" model --off >/dev/null
if sudo "$binary" --database "$database" --certificates "$certificates" query "anything?" 2>/dev/null; then
    fail "a question was answered after Ask was turned off."
fi
echo "OK: turning it off stops questions being answered"
# Back on for the rest of the run, without needing to be reconfigured.
sudo "$binary" --database "$database" --certificates "$certificates" model --model smoke-model >/dev/null

echo "Turning payload capture off..."
ask '{"op":"set-budget","payloads":false}' | jq -e '.ok.payloads == false and .ok.reading == false' >/dev/null \
    || fail "payload capture would not turn off."
# The daemon reads the budget back on the same two-second timer as the rules.
sleep 4
curl -sS --http1.1 --max-time 10 "https://$target_host/after-capture-off" -o /dev/null
sleep 2
# Asked of a short window rather than by comparing two counts of a long one. Counting `curl` rows inside the
# newest four hundred was a flake: this machine's own background traffic pushes older rows out of that window,
# so the count moved without anything having been read. What is actually being claimed is that nothing was read
# *after* capture was turned off, and a window of the last few seconds says exactly that.
ask '{"op":"requests","since":5,"limit":400}' \
    | jq -e '[.ok[] | select(.process == "curl")] | length == 0' >/dev/null \
    || fail "a payload was read after capture was turned off."
echo "OK: nothing is read once capture is off, and the kernel is what stops it"

# The interface, while it is still up. The daemon flushes a partial batch once a second, so the page sees
# what was just read rather than what was read a batch ago.
sleep 2
# And the page's own data, read back through the API the browser uses.
if ! curl -sS "$base/api/coverage?token=$token&since=600" | jq -e '.requests >= 0 and (.unread | type) == "array"' >/dev/null; then
    fail "the coverage API did not answer with a coverage object."
fi
if ! curl -sS "$base/api/requests?token=$token&since=600" | jq -e 'map(select(.process == "curl" and .method == "GET")) | length > 0' >/dev/null; then
    fail "the interface's own API does not show the request that was read."
fi
echo "OK: the interface serves what was read, through the API its page uses"

wait "$watcher"

echo "--- what this machine's TLS libraries are:"
ldd "$(command -v curl)" 2>/dev/null | grep -E "ssl|gnutls|nspr" || true
ldd "$(command -v gnutls-cli)" 2>/dev/null | grep -E "ssl|gnutls|nspr" || true
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
if [ "$gnutls_tested" = yes ]; then
    check "gnutls-cli's request was read through GnuTLS" \
        ".process == \"gnutls-cli\" and .method == \"GET\" and .host == \"$target_host\""
else
    echo "SKIP: gnutls-cli is not installed, so GnuTLS was not exercised"
fi

check "the MCP tool call was read out of the plaintext" \
    '.rpc_method == "tools/call" and .rpc_tool == "smoke_tool"'

# The whole shape of the parser, asked of everything it produced: a tool's name is a fact about what an
# agent is doing; the argument it was given is the contents of somebody's work.
if grep -q "$mcp_secret" "$output"; then
    echo "FAIL: an MCP call's arguments were reported." >&2
    exit 1
fi
if sudo grep -qa "$mcp_secret" "$database"; then
    echo "FAIL: an MCP call's arguments were stored." >&2
    exit 1
fi
echo "OK: the tool's name was kept and its arguments were not, anywhere"

check "the credential in the query string was redacted" \
    '.process == "curl" and ((.target // "") | contains("token=…"))'

# The strongest form of the same question, asked of the whole output rather than one record: the secret must
# appear nowhere in anything this tool produced.
if grep -q "$secret" "$output"; then
    echo "FAIL: the credential appeared in the output." >&2
    exit 1
fi
echo "OK: the credential appears nowhere in the output"

# Storage. The database is the reason a question can be asked an hour later, so the check is not "a file
# appeared" but "the request that was just read comes back out of it".
echo "--- what the database remembers:"
sudo "$binary" --database "$database" --certificates "$certificates" history --since 10m --json | tee "$stored"

if ! jq -s -e 'map(select(.process == "curl" and .method == "GET")) | length > 0' "$stored" >/dev/null; then
    echo "FAIL: the request was read and then not stored." >&2
    exit 1
fi
echo "OK: the request came back out of the database"

if grep -q "$secret" "$stored"; then
    echo "FAIL: the credential was stored." >&2
    exit 1
fi
echo "OK: the credential was not stored either"

echo "--- what Flowlight says it could not see:"
sudo "$binary" --database "$database" --certificates "$certificates" coverage --since 10m | tee "$reported"
sudo "$binary" --database "$database" --certificates "$certificates" --json coverage --since 10m > "$coverage_json"

if ! grep -q "0 record(s) were lost by the kernel" "$reported"; then
    echo "FAIL: the kernel dropped records, or the line that would say so is missing." >&2
    exit 1
fi
echo "OK: nothing was dropped, and the report says so rather than staying quiet"

if [ "$go_tested" = yes ]; then
    if ! jq -e '[.unread[] | select(.process == "gh")] | length > 0' "$coverage_json" >/dev/null; then
        echo "FAIL: gh opened HTTPS connections that were not read, and Coverage did not say so." >&2
        exit 1
    fi
    echo "OK: Coverage named the Go program whose traffic could not be read"
else
    echo "SKIP: gh or its token is unavailable, so the unreadable-process case was not exercised"
fi

if [ "$agent_tested" = yes ]; then
    if ! jq -s -e 'map(select(.agent == "claude" and .process == "curl")) | length > 0' "$stored" >/dev/null; then
        echo "FAIL: a request made by a process an agent started was not attributed to the agent." >&2
        exit 1
    fi
    echo "OK: a request from an agent's child was attributed to the agent"

    echo "--- what each agent reached, against what it was configured to reach:"
    sudo "$binary" --database "$database" --certificates "$certificates" agents --since 10m | tee /dev/stderr
    sudo "$binary" --database "$database" --certificates "$certificates" --json agents --since 10m > "$agents_json"
    if ! jq -s -e "map(select(.agent == \"claude\")) | length > 0" "$agents_json" >/dev/null; then
        echo "FAIL: the agent was not listed." >&2
        exit 1
    fi
    if ! jq -s -e "[.[] | select(.agent == \"claude\") | .domains[] | select(.host == \"$target_host\" and .standing == \"used\")] | length > 0" "$agents_json" >/dev/null; then
        echo "FAIL: a configured MCP host that was reached was not reported as used." >&2
        cat "$agents_json" >&2
        exit 1
    fi
    echo "OK: a configured MCP server that was reached is reported as used"
else
    echo "SKIP: a home directory without an existing ~/.claude.json was not available"
fi

if [ "$block_tested" = yes ]; then
    if ! jq -s -e "map(select(.blocked == true and .destination == \"$blocked_address\")) | length > 0" "$output" >/dev/null; then
        echo "FAIL: a connection was refused and Flowlight did not report refusing it." >&2
        exit 1
    fi
    echo "OK: the refusal was reported, with the process that was refused"

    # A count rather than a number: there are three refusals in this file now, and an assertion that knows
    # how many is an assertion that breaks every time one is added.
    if ! jq -e '.refused > 0' "$coverage_json" >/dev/null; then
        echo "FAIL: Coverage did not account for the refused connections." >&2
        cat "$reported" >&2
        exit 1
    fi
    echo "OK: Coverage accounts for what was refused"

    id=$(sudo "$binary" --database "$database" --certificates "$certificates" --json rules | jq -rs '.[0].id')
    sudo "$binary" --database "$database" --certificates "$certificates" forget "$id"
    if sudo "$binary" --database "$database" --certificates "$certificates" rules 2>&1 | grep -q "$blocked_address"; then
        echo "FAIL: the rule survived being removed." >&2
        exit 1
    fi
    echo "OK: the rule can be taken away again"
fi

mode=$(sudo stat -c '%a' "$database")
if [ "$mode" != "600" ]; then
    echo "FAIL: the database is mode $mode; it holds every host every process reached." >&2
    exit 1
fi
echo "OK: the database is readable only by its owner"
