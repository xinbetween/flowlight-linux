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

### What is kept, and for how long

Two tiers, both with a number attached, and both printed at startup rather than left in a manual:

- **Detail** — every connection and every request, for **seven days**. Hosts, paths, methods, statuses, byte
  counts. The tier that answers *what happened*.
- **Summary** — one row per day per process per host, for **ninety days**. Counts and totals, no paths. The
  tier that answers *is this normal*, and what the detail is folded into rather than what replaces it after
  the fact.

Nothing is kept forever. The database is created mode `600` in a directory mode `700`, because it holds every
host every process on the machine reached — on a shared machine, a list of what everyone was doing. Credentials
are redacted before a record is made, so they are not in it either.

`--no-store` keeps nothing at all.

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
| `--retention-days N` | days of individual requests. Default 7 |
| `--summary-days N` | days of the daily summary. Default 90 |

Plus subcommands that read the database rather than the kernel — `history --since 6h`, `agents`, `summary`,
`coverage --since 24h` — and six for rules: `block`, `allow`, `ask`, `simulate`, `rules`, `forget`. `--json` works on
all of them.

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
`~/.cursor/mcp.json`, `~/.gemini/settings.json` and the rest — across every home directory on the machine,
because the daemon runs as root and the agents belong to users. A server that runs locally over a pipe is
listed as invisible rather than omitted: nothing here can ever see it, and leaving it off the screen invites
the conclusion that Flowlight looked and found nothing.

### The interface

A native window, GTK4, running **as you** while the daemon runs as root.

```sh
flowlight
```

Four pages — **Live**, **Agents**, **Rules**, **Coverage** — and a window selector from fifteen minutes to
seven days. On the Agents page each host an agent reached carries the two buttons the macOS build settled
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

Two milestones, released a feature at a time: **0.1 — see everything, honestly**, then **0.2 — parity with the
macOS build**. [ROADMAP.md](ROADMAP.md) has the sequence and, more usefully, what this will not do.

One thing in 0.2 is deliberately not parity. macOS has a system model that the Ask feature leans on; Linux has
none, so on Linux you configure a model — local or remote — or the feature stays off. No bundled weights, and
no quiet fallback to somebody's API.

## Relationship to the macOS build

[xinbetween/flowlight](https://github.com/xinbetween/flowlight) is the macOS application, written in Swift.
This is a separate implementation in Rust, sharing no code with it.

What must not diverge is not code but **semantics**: what `block` means against `refuse`, how rule precedence
resolves, what Coverage is permitted to claim. The design note proposes a language-neutral conformance suite —
cases as data, run by both test suites — so that a divergence is a failing test rather than a support thread
eighteen months later.

## Licence

GPL-3.0, as the macOS build is. See [LICENSE](LICENSE).
