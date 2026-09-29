# Flowlight for Linux

Per-process network visibility and HTTPS inspection for AI agents, on eBPF.

Early. Today it answers one question — **which process opened which connection** — and answers it from the
kernel rather than by guessing. [docs/DESIGN.md](docs/DESIGN.md) is the design note behind it: what was
researched, what was measured, and which decisions are still open.

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
sudo apt-get install -y build-essential curl jq zstd git

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
cargo build --release --package flowlight-daemon
```

`--package flowlight-daemon` is not optional: a bare `cargo build` builds only the crate that compiles on any
machine, because most of this is written on a Mac where the rest cannot be.

Then watch:

```sh
sudo ./target/release/flowlightd
```

```text
curl                     pid 18422    → 93.184.216.34:443
python3.12               pid 18455    → 104.18.32.47:443
claude                   pid 17903    → 160.79.104.10:443
node                     pid 18004    → 140.82.113.4:443  [comm]
```

The fourth column, when it appears, is where the name came from. `[comm]` means the process was gone by the
time Flowlight looked it up, so the name is the one the kernel captured — which it cuts at fifteen characters.
`[pid]` means there was no name at all. Nothing is stored, nothing is blocked, and no payload is read.

Useful flags:

| | |
| --- | --- |
| `--json` | one JSON object per line, for anything that is not a person |
| `--seconds N` | stop after N seconds |
| `--count N` | stop after N connections |
| `--tracefs PATH` | if tracefs is mounted somewhere unusual |

If it refuses to start, the message says why — an unmounted tracefs, a kernel built without the tracepoint, or
a policy that forbids loading programs are three different problems and it will not conflate them.

### What it does not see yet

Stated here rather than discovered later:

- **Inbound connections.** Attribution is taken at `connect()`, in the calling process's own context. An
  inbound connection is established in a softirq, where the running task is whoever was unlucky — so naming it
  would mean naming the wrong process.
- **UDP and QUIC.** TCP only for now.
- **Payloads.** That is 0.1.2.

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
