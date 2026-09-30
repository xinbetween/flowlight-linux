# Flowlight for Linux

Per-process network visibility and HTTPS inspection for AI agents, on eBPF.

Early, and already doing the thing the design note argues for: **reading HTTPS in the clear without
terminating it, installing a certificate, or defeating anything.**

```text
curl                     pid 18422    → GET example.com/
claude/node              pid 17903    → POST api.anthropic.com/v1/messages
claude/node              pid 17903    ← 200  8214 bytes
claude/git-remote-https  pid 18055    → POST github.com/xinbetween/flowlight.git/git-upload-pack
```

[docs/DESIGN.md](docs/DESIGN.md) is the design note behind it: what was researched, what was measured, and
which decisions are still open.

## The short version

The target is that every application's traffic goes through Flowlight, HTTPS payloads are readable, and
requests can be refused or answered with a mock.

There are two ways to read TLS on Linux and they fail in opposite directions. Terminating it — redirect to a
local proxy, present a certificate, forward upstream — is what the macOS build does, and it is the only way to
modify a response. Reading it before encryption, by attaching a uprobe to `SSL_write`, sees everything and can
change nothing.

The plan leads with the second. It needs no certificate authority, so the Linux trust problem — Python's
bundled certifi and Java's own keystore, the two that ignore everything installed system-wide — becomes
optional rather than a prerequisite for seeing anything. It reads NSS, so Firefox needs no certificate
installed. It reads QUIC, which termination cannot. And it runs on kernel 4.18 where the redirect path needs
6.8.

Termination becomes a second, narrower mode that states what it costs.

## Running it on Ubuntu

Tested on Ubuntu 24.04. Needs root, because loading an eBPF program does — there is no version of this that
does not.

There is no `.deb` yet, so this is the way in: clone it and build it. A package and an apt repository are
[0.3 on the roadmap](ROADMAP.md) — worth saying that nothing has to be compiled on the machine that *runs*
Flowlight even now, because the eBPF programs are compiled into the binary rather than built against the
running kernel. The nightly toolchain below is a build-time requirement, not a runtime one.

```sh
sudo apt-get install -y build-essential curl jq zstd git libgtk-4-dev libadwaita-1-dev

# Rust, plus a nightly toolchain: the BPF target has no prebuilt `core`, so it is compiled from source.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup toolchain install nightly --profile minimal --component rust-src

# bpf-linker, which turns the compiler's output into something the kernel's verifier will accept.
curl -fsSLO https://github.com/aya-rs/bpf-linker/releases/download/v0.11.1/bpf-linker-x86_64-unknown-linux-musl.tar.zst
mkdir -p ~/.local/bin && tar -xpf bpf-linker-*.tar.zst -C ~/.local/bin
export PATH="$HOME/.local/bin:$PATH"

git clone https://github.com/xinbetween/flowlight-linux
cd flowlight-linux
cargo build --release --package flowlight-daemon --package flowlight-gui
```

Naming the packages is not optional: a bare `cargo build` builds only the crates that compile on any
machine, because most of this is written on a Mac where the rest cannot be.

Then watch:

```sh
sudo ./target/release/flowlightd
```

```text
flowlightd 0.2.2: watching sock/inet_sock_set_state. Outbound TCP only; inbound connections are not
attributed.
storing to /var/lib/flowlight/flowlight.db, keeping individual requests for 7 days, and a daily summary
for 90 days
interface socket at /run/flowlight/flowlight.sock, owned by uid 1000
reading openssl through /usr/lib/x86_64-linux-gnu/libssl.so.3 (SSL_write, SSL_write_ex, SSL_read, SSL_read_ex)
curl                     pid 18422    → 93.184.216.34:443
curl                     pid 18422    → GET example.com/
curl                     pid 18422    ← 200  1256 bytes
claude                   pid 17903    → POST api.anthropic.com/v1/messages
```

Then open the window, as yourself — not as root:

```sh
./target/release/flowlight
```

Or ask it from the terminal:

```sh
sudo ./target/release/flowlightd history --since 6h
sudo ./target/release/flowlightd summary
sudo ./target/release/flowlightd coverage
```

The name column is what the process is called. When a fourth column appears on a connection line — `[comm]`
or `[pid]` — it says the name is worth less than usual: `[comm]` means the process was gone by the time
Flowlight looked it up, so the name is the one the kernel captured, which it cuts at fifteen characters.

Nothing is modified.

### What is read, and for how long

Up to 0.2.3 the answer was "everything, forever". That is defensible for a tool somebody has just started
and indefensible for one that has been running since March.

```sh
sudo ./target/release/flowlightd budget
```

```text
Payloads are being read for another 7 hours and 12 minutes.
After 64 MB in a day, a process stops having its payloads captured until tomorrow.
Request paths are kept in full, with credentials removed from them.
Individual requests are kept for 7 days, and a daily summary for 90 days.
```

Four limits, each a number rather than a principle:

- **A session.** Payload capture stops after eight hours unless it is renewed. You turned this on to look at
  something; it should not still be reading your traffic next week. The kernel is what stops — a switch it
  checks *before* anything is copied out of an application's memory.
- **A daily ceiling per process.** After 64 MB in a day, that process stops having its payloads captured
  until tomorrow. Its connections are still attributed. One chatty program should not be able to fill a
  disk, and nothing needs a gigabyte of somebody's traffic to be useful.
- **What of a request is kept.** The whole path, the host only, or neither. Credentials are already removed;
  a path can still say more about what somebody was doing than they would choose to write down.
- **Retention.** Seven days of detail, ninety of summary, folded into the summary rather than deleted.

```sh
sudo ./target/release/flowlightd budget --paths host-only
sudo ./target/release/flowlightd budget --session 120 --daily 16
sudo ./target/release/flowlightd budget --payloads no
sudo ./target/release/flowlightd budget --renew
```

The **Budget** page in the window does the same, and a running daemon picks any change up within a couple of
seconds. `--no-store` keeps nothing at all, and reads no payloads either.

The database is created mode `600` in a directory mode `700`, because it holds every host every process on
the machine reached — on a shared machine, a list of what everyone was doing.

Useful flags:

| | |
| --- | --- |
| `--json` | one JSON object per line, for anything that is not a person |
| `--all` | include buffers that do not begin a request or response — the middles of bodies, mostly |
| `--no-payloads` | connections only; do not touch the TLS libraries |
| `--libssl PATH` | probe a TLS library the search did not find. May be repeated |
| `--seconds N` | stop after N seconds |
| `--count N` | stop after N records |
| `--tracefs PATH` | if tracefs is mounted somewhere unusual |
| `--socket PATH` | where the interface connects. Default `/run/flowlight/flowlight.sock` |
| `--no-socket` | do not open a control socket, so no interface can connect |
| `--web [ADDRESS]` | also serve the web page, for a machine with no desktop session |
| `--no-block` | do not enforce rules; nothing is refused whatever the rules say |
| `--database PATH` | where to keep what is seen. Default `/var/lib/flowlight/flowlight.db` |
| `--no-store` | keep nothing; watch the terminal and let it scroll |


Plus subcommands that read the database rather than the kernel — `history --since 6h`, `agents`, `summary`,
`coverage --since 24h`, `budget`, `export`, `model`, `query`, `intercept`, `trust`, `mock`, `mocks`,
`forget-mock`, `guardrail`, `guardrails`, `forget-guardrail`, `owners`, `alerts` — and six for rules: `block`, `allow`, `ask`,
`simulate`, `rules`, `forget`. `--json` works on all
of them. One subcommand is not like the others: `launch` runs as you rather than as root, because the agent it
starts has to.

If it refuses to start, the message says why — an unmounted tracefs, a kernel built without the tracepoint,
and a policy that forbids loading programs are three different problems and it will not conflate them.

### How the payloads are read

Not by a proxy. A uprobe on the TLS library's write function sees the buffer an application hands it, before
it is encrypted; a uretprobe on the read function sees the buffer it has just filled. There is no certificate
to install, no trust store to modify, and nothing for certificate pinning to object to — the plaintext is
read where the application already has it.

Three libraries, which between them cover nearly everything on a Linux machine:

| | Covers | Read at |
| --- | --- | --- |
| **OpenSSL** | curl, Python, Node, Ruby, PHP, most of everything | `SSL_write`, `SSL_write_ex`, `SSL_read`, `SSL_read_ex` |
| **GnuTLS** | wget, much of GNOME | `gnutls_record_send`, `gnutls_record_recv` |
| **NSS** | Firefox, Thunderbird | `PR_Write`, `PR_Send`, `PR_Read`, `PR_Recv` |

NSS is read one layer below where its TLS is, in the portable runtime underneath, because that is where the
plaintext crosses a function boundary. The consequence is that Firefox's *non*-TLS socket traffic is read
too — plain HTTP, mostly. More than was asked for rather than less, and said here rather than left to be
discovered.

Flowlight finds the TLS libraries two ways, because neither is enough alone: it reads `/proc/*/maps` to see
what processes have actually loaded, wherever that is, and it scans the usual library directories so that a
program started in a minute is already covered. Both are repeated every five seconds, because an agent
started after the daemon is the normal case.

### How HTTP/2 is read

Every current agent API speaks HTTP/2, and an HTTP/2 request line is not text in the stream. It is HPACK:
indices into a compression table both ends build as they go, across the whole connection, in order. Reading
it means following the frames and rebuilding that table.

Which in turn means the per-connection identity matters more than it looks. One process with two connections
open interleaves their buffers, and two connections through one decoder do not produce slightly worse output
— they produce confident nonsense. So every captured buffer carries the `SSL *` it was written on, and each
connection and direction gets its own decoder.

### Credentials do not come back out

A tool that watches traffic in order to make it safer cannot become a new way for credentials to escape. The
first CI run that read plaintext successfully also read the CI runner's own traffic, and printed a live Azure
shared-access signature into the build log — a URL that anyone reading the log could have used.

So request targets are redacted before they are printed, by name (`sig`, `token`, `api_key` and relatives,
including vendor-prefixed forms like `X-Amz-Signature`) and by shape (a long mixed-case value with digits in
it is not a word, a date or an identifier). The parts of a URL that make it worth reading — the path, the
model name, a UUID, a page number — are left alone.

```text
claude    pid 17903    → PUT productionresultssa17.blob.core.windows.net/…/logs.txt?se=2026-09-29T08%3A31%3A14Z&sig=…&sp=cw
```

### What an agent said to an MCP server

MCP is JSON-RPC, so a request to an MCP server carries a method and, for a tool call, the name of the tool —
in plaintext a uprobe has already copied. Both are read out of it.

```text
claude/node              pid 17903    → tools/call  read_file
claude/node              pid 17903    → tools/list
```

**Never the arguments.** A tool called `read_file` is a fact about what an agent is doing; the path it was
given is the contents of somebody's work, and a monitoring tool that quietly kept that would be a worse
problem than the one it was installed to solve. The parser reads two fields and does not know the others
exist — which is the difference between something that cannot leak arguments and something that merely does
not. Under `--paths none` the tool's name goes too, and only the method stays.

The Agents page lists what each agent said, per server. CI makes a real tool call over TLS and checks the
argument it passed appears neither in the output nor in the database.

### Rules

A `cgroup/connect` hook refuses a connection **before the SYN**. The application gets `EPERM` from
`connect()` — the same answer a firewall gives, and one every network client already knows how to report.

```sh
sudo ./target/release/flowlightd block telemetry.example.com
sudo ./target/release/flowlightd block '*' --agent claude            # and nothing else
sudo ./target/release/flowlightd allow api.anthropic.com --agent claude
sudo ./target/release/flowlightd ask mcp.example.com
sudo ./target/release/flowlightd rules
sudo ./target/release/flowlightd forget 3
```

Three actions — **allow**, **ask**, **block** — each scoped to everyone or to one agent, naming a host, a
`*.subdomain` pattern, a literal address or `*`, and one port or all of them.

**The most specific rule wins**, and specificity reads in a fixed order: **subject, then port, then scope**.
That order is a claim about what people mean. A rule about a host is a rule about the thing being reached,
which is the strongest statement anyone writes; a rule about an agent is a statement about who is asking,
which is weaker than a statement about what they are asking for. So `block telemetry.example` for everyone
beats `allow *` for one agent, and `allow mcp.sentry.dev for claude` beats `block mcp.sentry.dev` for
everyone. Both are what somebody writing those two rules meant.

Two rules of equal specificity that disagree are a contradiction, and a contradiction resolves the careful
way: **block, then ask, then allow**. And the default is allow — nothing is refused unless a rule says so.
This is a tool for watching that can also refuse, not a firewall with a default-deny posture, and the
difference should not be discovered by a machine losing its network.

```text
claude/curl              pid 18422    ⊘ 198.51.100.7:443
```

Rules live in the database, so they survive restarts and can be written before the daemon starts. A running
daemon picks a change up within a couple of seconds. Refusals appear in the live view and in Coverage.

#### Trying a rule before writing it

```sh
sudo ./target/release/flowlightd simulate block telemetry.example.com --since 24h
```

```text
412 request(s) or connection(s) in the last 24h would have been decided differently:

     allow → block    telemetry.example.com                        398  (claude)
     allow → block    198.51.100.7:443                              14

This is a claim about the past, not a promise about the future. A host that was not reached in this
window does not appear here.
```

Every piece of traffic in the window is decided twice — once with the rules as they are, once with the
candidate added — and only the answers that move are reported. The commonest answer is "nothing", and that
is the useful one: it means either a rule you already have covers it, or this machine has never reached it.

The window's block buttons do this for you: clicking one shows what it would have changed and writes the
rule only if you say so. A rule nobody can preview is a rule nobody enables.

One honest limit. A stored request records the host it went to and **not the port**, because a probe on a TLS
library never sees one. So a rule naming a port claims nothing about a request — only about a connection,
where the port is known. Saying "this might have changed" would be worse than saying nothing.

#### What `ask` means here

On macOS a connection can be held open while somebody decides. Here it cannot: the decision happens inside
`connect()`, in a BPF program, which may not sleep and may not talk to anyone. So `ask` **refuses, and
records the question**. Answering it with `allow` or `block` settles the next attempt, which every network
client makes. That is a weaker promise than the macOS one, and what it is not is a connection that silently
hangs.

#### How an agent-scoped rule reaches an agent's children

The kernel has to know, inside `connect()`, whether the calling process is working for an agent. Userspace
cannot tell it in time — an agent spawns a process and that process connects milliseconds later. So
userspace marks the agents themselves, which it has all the time in the world to notice, and a **fork
tracepoint copies the mark to the child in the kernel**. Everything an agent starts is therefore marked
before it can run.

An agent is noticed within a second of starting. Its children are marked instantly.

#### What it costs, stated plainly

The kernel does not have a hostname at `connect()` — the name was resolved and thrown away before this
point. So blocking `api.example.com` means resolving it here and refusing what it currently resolves to:
exactly right for a host with a stable address, and imprecise for anything behind a large content network,
where addresses rotate and are shared with everything else on it. Names are re-resolved every minute.

A `*.subdomain` pattern cannot be refused before the handshake at all, for the same reason — there is no set
of addresses to write down. The daemon says so when it loads such a rule rather than leaving it silently
unenforced; the rule still matches and is reported when it is reached. `--no-block` turns enforcement off
entirely.

### What an agent is set up to do

Flowlight reads the MCP servers out of an agent's configuration to compare what it was *given* with what it
*reached*. The same files say a great deal more, and two parts of it are worth attention before a single
request has been made:

```console
$ flowlightd agents --since 24h

claude
  412 request(s) from 7 process(es), 19 host(s), last 8 seconds ago

  Set up to:
      12 skill(s)
       3 command(s)
    hook        PreToolUse · Bash              /usr/local/bin/audit.sh
    permission  Bash(git push:*)               allow
       4 permission(s) that ask or refuse, which are not listed
```

A **hook** is a program the agent runs on its own behalf, at a moment it chooses. A **permission** is a
decision somebody made once and has not looked at since. Neither is visible from any amount of watching the
network — the traffic a hook causes looks exactly like traffic the agent caused, because it is.

So those two are written out and the rest is counted: a person with forty skills does not want forty lines, and
a person with one hook wants to know what it runs. A permission is flagged only when it **grants** rather than
refuses, so `Bash(git push:*)` in `allow` stands out and `Bash(rm:*)` in `deny` does not.

What is kept is the name and one line: a hook's command, a permission's decision, a skill's description. Not the
contents of a skill, which is somebody's writing, and not the body of an instruction file, which is usually most
of what they know about their own work. Paths are shown as `.claude/settings.json` rather than spelling out
whose home they are in, because a path with a username in it ends up in a screenshot.

### Agents

`claude` does not make requests. It spawns `node`, which spawns `bash`, which spawns `git`, which spawns
`git-remote-https`, which makes the request. Attributing that to `git-remote-https` is true and useless — so
every record carries the agent that caused it, found by walking up the process tree and stopping at the first
one Flowlight recognises.

```sh
sudo ./target/release/flowlightd agents --since 24h
```

```text
claude
  142 request(s) from 4 process(es), 6 host(s), last 12 seconds ago

  2 MCP server(s) run locally and never touch the network, so nothing here can see them: filesystem, git

  Hosts, against what this agent was configured to reach:

    unexpected  telemetry.example.com                            18 request(s)
    used        mcp.sentry.dev                                   12 request(s)  (sentry)
    unused      mcp.linear.app                                    0 request(s)  (linear)
    endpoint    api.anthropic.com                               340 request(s)
```

The standings are the point. **unexpected** is reached and in no configuration — the one worth a second look.
**unused** is configured and never reached: clutter, or something that stopped working. **endpoint** is the
agent's own service, which is neither MCP nor a surprise; without that distinction every agent's model API
would read as unexpected, which is the fastest possible way to teach somebody to ignore this screen.

Configured servers are read from the agents' own files — `~/.claude.json`, `~/.codex/config.toml`,
`~/.cursor/mcp.json`, `~/.gemini/settings.json`, VS Code's, Zed's, Windsurf's and Claude Desktop's — across
every home directory on the machine,
because the daemon runs as root and the agents belong to users. A server that runs locally over a pipe is
listed as invisible rather than omitted: nothing here can ever see it, and leaving it off the screen invites
the conclusion that Flowlight looked and found nothing.

### The interface

A native window, GTK4, running **as you** while the daemon runs as root.

```sh
flowlight
```

Eight pages — **Live**, **Agents**, **Rules**, **Coverage**, **Budget**, **Export**, **Ask**, **Intercept** — and a window selector from fifteen
minutes to seven days. On the Agents page each host an agent reached carries the two buttons the macOS build settled
on: block it **for this agent**, or block it **everywhere**.

#### Why it is two programs

Loading a probe needs root. Drawing a window does not, and should not. So the daemon keeps the privileges,
the probes and the database, and the interface keeps a list and four buttons. Between them is a Unix socket
at `/run/flowlight/flowlight.sock`, owned by whoever ran `sudo flowlightd`, mode `600`.

That is a real permission boundary, which is what the page it replaces never had. **Loopback is not one** —
anything served on `127.0.0.1` is reachable by every local user of the machine, and a token in a URL is a
secret that leaks into shell history, process listings and screenshots. A socket has an owner and a mode,
the kernel enforces them, and there is no secret to leak. Every connection is asked who it is a second time
through `SO_PEERCRED`, which the kernel fills in and the peer cannot forge.

#### The web page is still there

It is the only one of the two that works over `ssh` on a machine with no desktop session — which is most
machines actually running agents. It is off unless asked for:

```sh
sudo ./target/release/flowlightd --web
```

and it prints its own warning, because on a shared machine it is a disclosure.

### Starting an agent through Flowlight

Two things have to be true before an agent makes its first request, and neither can be arranged afterwards.

The **mark** — which processes belong to which agent — is written into a kernel map, and until now that happened
on a timer: a scan notices a new agent within a second and the kernel carries the mark to everything it forks.
That is right for a long-lived agent and has a hole at the beginning. An agent that connects immediately
connects *unmarked*, so a rule scoped to it does not apply to that connection.

The **environment** is the other. A certificate is trusted at launch by whatever started the process, and Node
reads no trust store at all — `NODE_EXTRA_CA_CERTS` is the only way in. A variable cannot be put into a process
that is already running, which is why `trust` can only tell you about those and this can do them.

```console
$ flowlightd launch -- claude
starting claude, marked before it runs
  SSL_CERT_FILE — OpenSSL, and most things that link it
  NODE_EXTRA_CA_CERTS — Node, which reads no trust store at all
  …
```

The order is the whole feature, and it is arranged by marking *this* process and then forking. The kernel's
fork tracepoint copies an agent's mark from parent to child at the moment the child is created — the same
machinery that already carries a mark from an agent to everything it starts — so the agent is marked before it
has run an instruction. If the mark cannot be written, nothing is started at all.

The obvious alternative does not work, which is worth writing down: holding the child between `fork` and
`exec` on a pipe deadlocks, because `Command::spawn` does not return until the child execs — that is how it
reports whether the exec succeeded. The parent would wait for the child to exec and the child for the parent
to release it. Marking the parent needs none of that.

**This is the one Flowlight command that must not be run as root.** Everything else needs it, because loading a
probe does; this needs the opposite, since an agent started by root would run as root, read root's
configuration and write root's files. It refuses, and says to run it as the person the agent belongs to. It
needs no root of its own: it asks the running daemon over the interface socket, which that person owns.

`--agent NAME` says what to call it; otherwise the name is worked out from the command, stepping over an
interpreter the same way the process-tree attribution does — `node /usr/lib/claude/cli.js` is an agent called
`claude`, not one called `node`.

The agent's exit status is what `launch` exits with, so a supervisor watching exit statuses sees the agent's.

#### When Flowlight cannot be the parent

A desktop entry, a systemd unit, a session manager that outlives any window — sometimes the thing that starts
agents is not something you can put `flowlightd launch` in front of. For those, the environment half is
available on its own:

```console
$ flowlightd launch --agent claude --print-environment
FLOWLIGHT_AGENT=claude
NODE_EXTRA_CA_CERTS=/usr/local/share/flowlight/ca-bundle.pem
SSL_CERT_FILE=/usr/local/share/flowlight/ca-bundle.pem
…
```

Variables on standard output, the explanations on standard error, so something can read the one without the
other. It says plainly that a process started this way is **not** marked: only being its parent can do that.

#### Marking is checked against who is asking

`launch` asks the daemon to mark a process, and that is the one request over the socket that changes something
outside the database — so it is the one that is checked against the asker. Marking a process makes every rule
scoped to that agent apply to it and, when interception is on, redirects its connections. Root may name any
process; anybody else may name only their own, by real uid, read from `/proc`.

### Guardrails

Which tools an agent may use is a different question from which hosts it may reach, and answering it means
reading what the agent *says* rather than where it connects.

```console
$ sudo flowlightd guardrail --tool '*write*' --agent claude --note "read-only this week"
added

$ flowlightd guardrails
   1  claude: no *write*  — refused 3 call(s)
```

The agent asks to use the tool and gets back an answer:

```json
{"jsonrpc":"2.0","id":77,"error":{"code":-32000,"message":"claude: no *write*",
 "data":{"refusedBy":"flowlight"}}}
```

**A refusal is an answer, not a failure.** It carries the call's own `id`, because that is how a JSON-RPC
client matches an answer to its question — get it wrong and the agent waits for one that never comes, which is
the same as a dropped connection and worse than an error. And a dropped connection teaches an agent to retry;
an error teaches it the tool is not available, which is what is true.

Guardrails need interception, because refusing a call means reading it. What is read is the JSON-RPC method,
the tool's name and a resource URI — by the same scanner that feeds the MCP columns, which structurally cannot
read an argument. **What the tool was asked to do passes through unread**, exactly as it does when nothing is
intercepting, and the smoke test asserts that a refused call's arguments appear in neither the answer nor the
database.

Four decisions, each of which could have gone the other way:

- **There is no allow.** A guardrail is subtractive by nature: it is applied to a list the agent itself
  declares, and an "allow" would only ever mean "do not subtract this", which is what leaving it out already
  says. One action also means no precedence — the first guardrail that refuses a call refuses it.
- **`tools/list` is never refused.** Refusing a *question* tells an agent that a tool exists and is forbidden,
  which invites working around it. A guardrail is about what an agent does.
- **One that names nothing is refused as unfinished**, not accepted as very strict. A guardrail naming neither
  tool, server nor resource would refuse every tool of every agent, and that is never one keystroke away.
- **A body larger than sixteen megabytes is forwarded unread.** A deliberate hole, and the safe direction: a
  guardrail that can be evaded by an enormous request is better than a proxy that can be stopped by one.

`--server` names the host the MCP server is at — what the proxy actually knows, rather than the name an agent's
configuration gives it. A server with no tool refuses the whole server. `--resource` covers `resources/read`,
matched by URI. Everything is matched without regard to case and with `*` standing for any run of characters,
because a tool's name is written by hand in one place and generated in another.

### Interception

The one thing here that changes what an application sees. Everything else reads what a process hands its TLS
library, before encryption, and alters nothing on the wire. This stands in the middle of a connection, presents
a certificate of its own, and can answer a request the server never received.

So it is a different switch, with its own scope, and it is off:

```console
$ sudo flowlightd intercept
Interception is not watching. Everything else Flowlight does reads what an application hands its TLS library
and changes nothing that crosses the network.
No agents are named, so nothing is redirected. Interception applies to the agents it names and to nothing else
on this machine.
That proxy presents a certificate signed by a certificate authority created on this machine. Anything that does
not trust it will refuse the connection, which is what a pinned certificate is supposed to do.
A host nobody has written a mock for is passed through without being terminated at all, so the certificate is
only ever presented where there is a reason to.
Turning it off stops the redirect immediately. Removing the certificate authority is a separate step, because
trusting one and untrusting it are both things somebody should do on purpose.

Nothing is being terminated: Interception is off. Nothing is terminated, and no certificate of Flowlight's is
presented to anything.
```

A canned answer, and then the scope:

```console
$ sudo flowlightd mock api.example.com --path '/v1/*' --method POST --status 503 \
      --header 'Retry-After: 30' --body '{"error":"the API is having a bad day"}'
added

$ sudo flowlightd intercept --agent claude --on
```

From then on, `claude` and everything it starts get the canned 503 for that request and the real server for
everything else. The answer names itself in a header — `X-Flowlight-Mock`, or `X-Flowlight-Refused` when the
rule calls itself a refusal — so a log kept elsewhere on the machine can tell too.

#### Why the kernel redirects rather than an environment variable

`HTTPS_PROXY` has to be set before a process starts, by whoever starts it, and is honoured by curl and Python
and ignored by plenty of other things. A `cgroup/connect4` hook is none of that: it rewrites the destination
inside `connect()`, so it applies to a process that is **already running**, to everything it starts, and to
every library any of them use — because it is below all of them.

The original destination cannot survive that rewrite, so the program writes it down. It is remembered twice:
first against the socket's cookie, because inside `connect()` the source port does not exist yet, and then
against the source port, because that is the only handle the proxy has on a connection it accepts from
`127.0.0.1`. `SO_ORIGINAL_DST` is no help here — nothing was translated by netfilter, so there is no conntrack
entry to ask.

**The blocking programs are attached first, deliberately.** Both hang off the same hook and the kernel runs them
in attach order. Blocking decides about the address in the context; redirect *changes* that address. The other
way round, a rule refusing `1.2.3.4` would be asked about `127.0.0.1` instead — so turning interception on would
quietly disable blocking for everything in its scope.

#### What is terminated, and what is not

- **Only the agents named.** Empty means nobody, not everybody. A scope that meant the machine would redirect
  the package manager, which pins certificates, and the first symptom would be a machine that cannot update
  itself.
- **Only a host some rule could answer for.** The proxy reads the server name out of the handshake, and if no
  canned answer covers that host the connection is relayed as ciphertext — the bytes copied both ways, nothing
  decrypted, no certificate presented. A host nobody mocks never pays for the feature.
- **Never `--never` hosts**, whatever else says so.
- **Only HTTPS**, and only HTTP/1.1. The proxy offers `http/1.1` in ALPN and nothing else, so an HTTP/2 client
  negotiates down for the hosts in scope. Plain HTTP is not redirected at all: there is nothing to terminate and
  the payload probes already read it.
- **Never loopback.** A connection to this machine includes every connection to the proxy, and redirecting
  those is a loop.

#### The certificate

Created on this machine the first time interception is available, and never leaves it. Its key signs a
short-lived certificate for each host that is terminated; one key is shared by all of them, because the leaves
live for a fortnight and a key per host would be the slowest thing in the connection.

The keys live beside the database, mode 600 in a directory of 700, created that way rather than created and then
restricted — and narrowed again on every open, because a directory somebody widened later is the same problem as
one that was never narrowed. Anybody who can read the authority's key can impersonate every site on the internet
to anything that trusts it.

The certificate itself goes somewhere else: `/usr/local/share/flowlight/`, readable by everybody, because an
agent runs as a person who has to be able to read the certificate they are being asked to trust. Beside it is
`ca-bundle.pem` — this machine's own roots **plus** Flowlight's, so a tool pointed at it does not stop trusting
everything else.

```console
$ sudo flowlightd trust
The certificate is at /usr/local/share/flowlight/flowlight-ca.pem
A bundle of this machine's roots plus it is at /usr/local/share/flowlight/ca-bundle.pem

the machine's trust store — present on this machine, and Flowlight can do it
    `sudo flowlightd trust --install` copies it to /usr/local/share/ca-certificates/flowlight.crt and runs
    `update-ca-certificates`. That covers OpenSSL, curl, git and anything else that reads the machine's store.

Node — present on this machine
    Node does not read the machine's trust store. `NODE_EXTRA_CA_CERTS=…` is the only way in, and it has to be
    set before node starts — which is what `flowlightd launch` will be for.
…
```

`trust` installs into the distribution's store and **reports** everything else: Python's certifi, Java's
keystore, NSS. Those are somebody else's files, replaced by the next upgrade of whatever owns them, and a tool
that edits them quietly is a tool nobody can reason about. The two that need an environment variable cannot be
done from here at all — a variable is set before a process starts, by whoever starts it, which is the next
release.

#### Interception does not record anything

Worth stating plainly: the payload probes see every request whether interception is on or off, so the proxy does
no recording. A proxy that also recorded would put a second copy of every request into the database with no way
to tell the two apart. What it writes down is only what it *did* — a request it answered and the rule that
answered it — and a connection it merely passed on is counted rather than kept, because a note per connection
would bury the ones that matter.

### Ask — with your own model

The one feature that is deliberately not parity with macOS. The macOS build leans on a model the operating
system provides; Linux has none, so Flowlight does not carry one either. **No bundled weights, and no default
endpoint pointing at somebody's API.** Until a model is configured, the feature is off and says so:

```console
$ flowlightd query "what did claude reach today?"
Error: Ask is off. There is no model in Flowlight for Linux, so one has to be configured: `flowlightd model
--kind local --model <name>` for a server on this machine, or a provider and a key.
```

A model server already running on this machine is the case that sends nothing anywhere:

```console
$ sudo flowlightd model --kind local --model llama3.2
Your question goes to http://127.0.0.1:11434/v1/chat/completions, which is on this machine or this network.
Nothing crosses the internet.
What is sent is the question, the instructions, and the totals and names that Flowlight's own queries return.
Never a row of history, never a request target, and never anything the model did not ask for.
The model cannot see the database. It may name one of a fixed list of queries, which Flowlight runs; there is
no query language and no way to write one.

Ready. `flowlightd query "…"` asks llama3.2 a question.

$ flowlightd query "which hosts are new today, and for which agent?"
claude reached two hosts today it had never reached before: telemetry.example (14 requests) and
registry.npmjs.org (3). Nothing else was new.

(from agents, newHosts, agentHosts)
```

`--kind anthropic`, `--kind gemini` and `--kind compatible --endpoint URL` send somewhere else, and say so.

#### What the model is given, and what it is not

It is given the question, a set of instructions, and the results of queries it names from a fixed list. It is
not given the database, a table, or a query language. That list is a Rust enum with twelve cases and no `sql`
one, so "the model never sees your history" is a property of the types rather than a promise:

| | |
| --- | --- |
| `totals` | requests, connections, bytes and processes in a window |
| `topProcesses` `topHosts` | the busiest, with their counts |
| `newHosts` | hosts reached in this window and never before it |
| `agents` `agentHosts` `agentTools` | what an agent did, and what it said to MCP servers |
| `coverage` | what was **not** read |
| `overTime` | requests and bytes per bucket |
| `rules` `settings` | how this machine is configured |
| `howTo` | Flowlight's own guide, so a model never invents a flag |

Every one returns counts, totals and names. None returns a request, a target, a header or a tool's arguments.
Every window has an end and every list has a limit, so a model cannot ask for the database one page at a time.
`flowlightd query --show-work "…"` prints the exact body that was sent and every query that ran.

Three more decisions worth stating:

- **A key is a file, not a setting.** It lives beside the database, mode 600, created restricted rather than
  created and then restricted — and Flowlight refuses to read it if the mode is wider. It is not in the
  database, because a database gets copied: this one holds a history somebody may reasonably attach to a bug
  report. `flowlightd model --key-file PATH` puts one there; nothing ever reads one back out.
- **Plain HTTP only where there is no network to listen on.** `http://` is accepted for loopback, `.local`
  and the private ranges — that is how somebody points this at their own machine. Anywhere else it is refused,
  because a key and a question about this machine's own traffic would cross the network in the clear.
- **Flowlight's connection to the model is recorded like anybody else's**, attributed to `flowlightd`. A tool
  that hid its own traffic would have no business showing yours.

And one about answers rather than privacy: the queries that produced an answer are printed under it, always.
An answer with nothing under it is a sentence a model made up, and that is the only way to tell.

### Export

What was seen, sent somewhere else: a file on this machine, one JSON object per line, or an OTLP collector
over HTTP. Off until it is configured, and configured is not the same as sending.

```console
$ sudo flowlightd export --to /var/log/flowlight.jsonl
Every request Flowlight reads will be written to /var/log/flowlight.jsonl, one line each. Nothing crosses the
network.
Eight fields travel: when it happened, what the process is called, the agent that caused it, out or in, the
host, the request method, the response status, how many bytes.
These do not: where that name came from, the process identifier, the request target, whether the connection
was HTTP/2, the JSON-RPC method, the tool for an MCP call.
This agreement is bound to exactly that. Changing the destination, the fields or the headers stops the export
until somebody agrees again.

Nothing is being sent: Nobody has agreed to this yet. Nothing is sent until somebody does.

Fields available: at, process, confidence, pid, agent, direction, host, method, target, status, bytes,
protocol, rpc_method, rpc_tool
```

Naming a destination discloses and sends nothing. Agreeing is a second command:

```console
$ sudo flowlightd export --consent
```

The agreement is bound to the disclosure, not to the act of exporting. It is a hash of the destination, the
transport, the field list and the header *names*; change any of them and the agreement is gone and nothing is
sent until somebody agrees to the new sentences. That is the failure this exists to prevent: somebody agrees
to four fields going to their own collector, and three weeks later eleven fields go to somebody else's under
the same yes.

Header values are not part of it, and are never shown back — not in the disclosure, not in the window, not in
this tool's output. A token is a secret, not a description of where data goes, and rotating one is not a change
anybody should have to agree to again.

```console
$ sudo flowlightd export --to https://collector.example/v1/logs \
      --header "Authorization=Bearer …" --fields at,process,agent,host,method,status
```

Three more things are true of it, because they are the ones that go wrong:

- **A record is sent once.** The high-water mark is the row identifier, not a timestamp — two records can
  share a second, and a mark on time either sends one of them twice or neither.
- **A batch that failed has not been sent.** The mark moves after delivery, so a collector that was down for
  an hour receives that hour when it comes back.
- **Flowlight's own traffic is not in it.** Exporting is itself an HTTPS request from this machine. Left in,
  a record of a batch being sent is a record in the next batch, for ever.

The Export page in the window says the same sentences, and its Agree button opens a dialog containing them.

### Who operates an address

Every connection Flowlight records at `connect()` has an address and no name: the name was resolved and thrown
away before the kernel saw it. Coverage can say how many such connections a process made. Saying *whose* they
were is the difference between a number and a lead.

```console
$ sudo flowlightd owners --on
$ flowlightd owners
  AS13335   Cloudflare, Inc.                         4 address(es), 31 connection(s)
  AS16509   Amazon.com, Inc.                         2 address(es), 9 connection(s)
  AS15169   Google LLC                               1 address(es), 3 connection(s)
```

**This is the one thing Flowlight does that tells a third party anything**, so it is off until it is asked for
and it says what asking means first:

- The question is a DNS lookup of Team Cymru's public routing data, sent to this machine's own resolver.
- What is sent is **an address**. Not which process reached it, not when, not how often.
- An address on this machine or this network is never asked about: the answer is already known, and the
  question would be about your network.
- Four addresses a minute at most, busiest first, never the same one twice — a resolver asked about every
  connection as it happened would be a second, chattier record of this machine's traffic leaving it.

The DNS client is written out rather than pulled in: a resolver crate brings an async runtime, a configuration
language and a cache of its own, for a feature that asks two short questions a minute. What is here is a query
builder and a parser, both pure, both tested against bytes — including a reply that points its compression
pointer forwards, which is how a parser is made to loop for ever.

An address nobody announces is recorded as such rather than left unknown, because otherwise it would be asked
about again on every pass for ever. A resolver that is temporarily unreachable is a different thing and is
*not* recorded, so it is asked again later — conflating the two would make a transient failure permanent.

### Alerts

Things worth saying, each carrying the arithmetic that produced it.

```console
$ flowlightd alerts --since 24h
!!  claude sent 200.0 MB to somewhere.example and received 1.0 MB back — 200 times as much out as in
!   node moved 400.0 MB in the hour from Tuesday 29 September 2026, 14:00 UTC — 4.2 deviations above its
    baseline of 30.0 MB an hour, over 48 hours of history
    curl reached telemetry.example, which nothing on this machine had reached before
    curl was refused 1.1.1.1:443 by a rule
```

A ranked list with no numbers behind it is a horoscope, so every alert names what it compared against and what
it found. Somebody who disagrees can go and check.

Eight signals. Three are statistical — a process moving much more than it usually does in an hour, reaching many
more hosts than usual in a day, and an agent sending far more than it receives. Five are about a single event: a
host nothing had reached before, a process new to the network, a port nothing usually reaches, an agent reaching
an *address* rather than a name, and a connection a rule refused.

The baseline is an exponentially weighted moving average with its variance — cumulative while it is young, so an
hour is not compared against a single earlier hour and called a spike, then weighted with about a week's memory
so that last month does not outvote this week. It is the same arithmetic the macOS build uses, deliberately: a
spike has to be a spike on both, or the two tools disagree about what a machine is doing, and each is confirmed
by the other's silence.

Three decisions that decide whether this is useful or noise:

- **The floor under the deviation is proportional to the thing measured** — a tenth of the mean, or 64 KB,
  whichever is larger. Without it, something perfectly steady calls its first variation infinite, and a backup
  job that normally moves a gigabyte an hour gets an alert for moving 1.1 GB.
- **The window in progress is never judged.** Half an hour of traffic compared against whole ones is a spike
  every time.
- **The same thing is not said twice within an hour.** A list that repeats itself is one nobody reads to the
  bottom of.

**Two of the macOS build's signals deliberately do not port.** "Traffic while nobody was at the keyboard" and
"an agent was active while you were away" both rest on there being a keyboard and a session to be away from, and
this runs on servers. They are absent rather than approximated, because a signal that fires because a machine has
no display is not a signal.

A refusal is not an anomaly — it is Flowlight doing what it was told. It is recorded because the person it
happens to is usually the person who wrote the rule, and an hour spent on a network that appears to be broken is
an hour nobody gets back.

### Coverage: what was *not* seen

The screen that makes the rest worth trusting. An empty result means "this agent made no requests" and "this
agent made four hundred requests nothing could read" equally well, and only one of those is worth knowing.

```text
Coverage for the last 24h

  Read          1284 request(s) from 7 process(es), over 1901 connection(s)
  Not read
                gh                       412 connection(s), nothing read

                A process that opened HTTPS connections and had nothing read from them is
                using a TLS implementation there is no probe for. Go links its own into the
                binary, and so does Chrome.

  Truncated     18 call(s) carried more than four kilobytes; the rest was not captured
  Undecodable   2 HTTP/2 connection(s) could not be followed
  Named weakly  31 record(s) name a process by its comm, which the kernel cuts at fifteen
                characters; 0 have no name at all
  Dropped       0 record(s) were lost by the kernel before Flowlight read them
```

Zeroes are printed rather than omitted. A line that disappears when it reads zero turns "nothing was dropped"
into "nobody checked".

### What it does not see yet

Stated here rather than discovered later:

- **A connection that was already open.** HTTP/2 compresses headers against a table both ends build as they
  go, from the first request onwards. Flowlight cannot rebuild a table it did not watch being built, so a
  connection that predates the daemon says so rather than showing a request line invented from the wrong
  table:

  ```text
  node    pid 18004    → HTTP/2 — this connection's header compression could not be followed…
  ```

- **The body of a request larger than four kilobytes.** Only the first four kilobytes of any one call are
  captured. Frames are length-prefixed, so the gap is stepped over exactly and the headers around it are
  still read — a 60KB prompt costs the prompt and nothing else. A gap that lands inside a *header* block is
  different: it leaves the compression table behind the sender's, and the connection is reported unreadable
  from that point rather than decoded into something plausible and wrong.
- **Go programs, and Chrome.** Go's TLS is written in Go and linked into the binary, and Chrome's BoringSSL
  is linked into Chrome. Both need symbols resolved per binary rather than per library, and Go additionally
  uses a calling convention that is not the C one. Each is its own piece of work.
- **Inbound connections.** Attribution is taken at `connect()`, in the calling process's own context. An
  inbound connection is established in a softirq, where the running task is whoever was unlucky — so naming
  it would mean naming the wrong process.
- **UDP and QUIC.** TCP only for now. The payload probes are indifferent to transport, so a QUIC request
  through OpenSSL is readable; the connection behind it is not yet attributed.
- **More than four kilobytes of any one call.** Captured buffers are cut there and the line says
  `[truncated]` when they were.

## Where it is going

Four milestones, released a feature at a time: **0.1 — see everything, honestly**, then **0.2 — parity with the
macOS build**, then **0.3 — installing it without a compiler**, then **0.4 — the parity the first pass missed**.
That last one exists because 0.2 was built from the macOS build's roadmap and 0.4 was built by reading its source
tree, and the second list is longer: guardrails on agents' tools, alerts, who owns an address, and the rest.
[ROADMAP.md](ROADMAP.md) has the sequence and, more usefully, what this will not do.

One thing in 0.2 is deliberately not parity, and it is done: macOS has a system model that the Ask feature
leans on, so on Linux you configure one — local or remote — or the feature stays off. No bundled weights, and
no quiet fallback to somebody's API.

## Relationship to the macOS build

[xinbetween/flowlight](https://github.com/xinbetween/flowlight) is the macOS application, written in Swift.
This is a separate implementation in Rust, sharing no code with it.

What must not diverge is not code but **semantics**: what `block` means against `allow`, how rule precedence
resolves, what a pattern covers. Those are decisions, and a decision written down in two languages is one that
will be made twice and eventually differently — so they live in [`conformance/`](conformance/) as data, and
both test suites load the same file. A divergence is a failing test rather than a support thread eighteen
months later.

Thirty-two cases so far, each carrying the reason its answer is what it is: that a subdomain pattern does not
cover the apex, that subject beats port beats scope, that an exception has to be *more specific* than what it is
an exception to, and that a rule naming a port cannot be judged against a stored request, because a probe on a
TLS library never saw one. When a question about semantics comes up, the answer goes there first and into the
code second.

## Licence

GPL-3.0, as the macOS build is. See [LICENSE](LICENSE).
