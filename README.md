# Flowlight for Linux

Per-process network visibility and HTTPS inspection for AI agents, on eBPF.

Nothing is built yet. This repository currently holds one thing: **[docs/DESIGN.md](docs/DESIGN.md)**, a design
note recording what was researched, what was measured, and which decisions are still open — written before the
first line of code so that the first commit is not also the first time anyone asks these questions.

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

## Where it is going

One milestone — **0.1, see everything honestly** — released a feature at a time. [ROADMAP.md](ROADMAP.md) has
the sequence and, more usefully, what this will not do.

## Relationship to the macOS build

[xinbetween/flowlight](https://github.com/xinbetween/flowlight) is the macOS application, written in Swift.
This is a separate implementation in Rust, sharing no code with it.

What must not diverge is not code but **semantics**: what `block` means against `refuse`, how rule precedence
resolves, what Coverage is permitted to claim. The design note proposes a language-neutral conformance suite —
cases as data, run by both test suites — so that a divergence is a failing test rather than a support thread
eighteen months later.

## Licence

GPL-3.0, as the macOS build is. See [LICENSE](LICENSE).
