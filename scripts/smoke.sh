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
cleanup() {
    rm -f "$output" "$log" "$stored" "$reported" "$coverage_json" "$agents_json"
    rm -rf "$(dirname "$fake_agent")"
    [ "${agent_tested:-no}" = yes ] && rm -f "$agent_config"
    sudo rm -rf "$(dirname "$database")"
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
sudo "$binary" --json --seconds 70 --database "$database" --socket "$socket" --web 127.0.0.1:0 >"$output" 2>"$log" &
watcher=$!

# The probes are attached by the time the daemon prints its banner, but the banner goes to stderr and the
# library scan happens after it. Three seconds is generous and the total cost is three seconds.
sleep 3

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
refusal=$(sudo "$binary" --database "$database" --web 0.0.0.0:0 --seconds 1 2>&1 || true)
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

    sudo "$binary" --database "$database" rules
    scoped_rule=$(ask '{"op":"rules"}' | jq -r '.ok[] | select(.scope == "agent:claude") | .id')
    ask "{\"op\":\"forget\",\"id\":$scoped_rule}" | jq -e '.ok == true' >/dev/null \
        || fail "the socket would not forget a rule."
    echo "OK: a rule can be written and forgotten over the interface socket"

    # And now for everyone, which is the simpler half and the one somebody will try first.
    echo "Blocking $blocked_address for everyone..."
    sudo "$binary" --database "$database" block "$blocked_address" --port 443 --note "smoke test"
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

echo "Turning payload capture off..."
before=$(ask '{"op":"requests","since":600,"limit":400}' | jq '[.ok[] | select(.process == "curl")] | length')
ask '{"op":"set-budget","payloads":false}' | jq -e '.ok.payloads == false and .ok.reading == false' >/dev/null \
    || fail "payload capture would not turn off."
sleep 4
curl -sS --http1.1 --max-time 10 "https://$target_host/after-capture-off" -o /dev/null
sleep 2
after=$(ask '{"op":"requests","since":600,"limit":400}' | jq '[.ok[] | select(.process == "curl")] | length')
[ "$before" = "$after" ] \
    || fail "payloads were still read after capture was turned off ($before then $after)."
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
sudo "$binary" --database "$database" history --since 10m --json | tee "$stored"

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
sudo "$binary" --database "$database" coverage --since 10m | tee "$reported"
sudo "$binary" --database "$database" --json coverage --since 10m > "$coverage_json"

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
    sudo "$binary" --database "$database" agents --since 10m | tee /dev/stderr
    sudo "$binary" --database "$database" --json agents --since 10m > "$agents_json"
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

    id=$(sudo "$binary" --database "$database" --json rules | jq -rs '.[0].id')
    sudo "$binary" --database "$database" forget "$id"
    if sudo "$binary" --database "$database" rules 2>&1 | grep -q "$blocked_address"; then
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
