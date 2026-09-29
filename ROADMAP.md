# Roadmap

One milestone: **0.1 — see everything, honestly.**

A daemon that shows every HTTPS request every application on the machine makes, without installing a
certificate anywhere, and that states plainly what it could not see. No interception, no certificate authority,
no blocking. Those come after, and each says what it costs.

That target is chosen because it is the one the [design note](docs/DESIGN.md) argues is both the most useful
and the least dangerous: reading before encryption needs no trust setup, is not defeated by certificate
pinning, covers QUIC, runs on kernel 4.18, and cannot strand the machine's network if it crashes.

Releases go out one feature at a time. Each is built, tested on Linux by CI, and published before the next one
starts — the same cycle the macOS build uses, for the same reason: a release that bundles four features is a
release where nobody can tell which one broke something.

## 0.1.x — seeing

| | | |
| --- | --- | --- |
| **0.1.0** | **Identity** | What to call a process and what to key a rule on. Versioned installs, Nix store hashes, the kernel's fifteen-character `comm` limit, and an honest confidence level attached to every name. Pure logic, no kernel. |
| **0.1.1** | **Process and connection attribution** | Which process opened which connection, from eBPF on the socket path. The thing `nettop` does badly on macOS and the kernel does properly here. |
| **0.1.2** | **TLS plaintext capture** | uprobes on `SSL_write`/`SSL_read` for OpenSSL. Requests and responses in the clear, with no certificate installed anywhere. |
| **0.1.3** | **The other TLS libraries** | GnuTLS, NSS and BoringSSL, so Firefox and Chrome are covered. Go's static TLS, which needs symbol resolution per binary and will be the hardest. |
| **0.1.4** | **Storage and retention** | SQLite, the rollup tiers, and a retention policy that is stated rather than assumed. |
| **0.1.5** | **Coverage** | What was not seen, and why: a TLS library with no probe, a container in another namespace, a process that exited before attribution landed. The screen that makes the rest trustworthy. |
| **0.1.6** | **The local interface** | A web UI on loopback. Live, agents, and what each one reached. |
| **0.1.7** | **Agent attribution** | Which agent a process works for, MCP servers from their configuration files, tool calls read out of the payloads already being captured. |

## After 0.1

Not scheduled, and deliberately so — each needs the layer below it to be trustworthy first.

- **Blocking.** A `cgroup/connect` hook that refuses before the SYN. Independent of how traffic is read, and
  better than the macOS equivalent: flow-level and request-level refusal compose here.
- **Interception.** Redirect and terminate, for the cases that need a mocked response or refusal of a single
  request. Carries the certificate-trust work with it, and is opt-in for that reason.
- **Conformance with the macOS build.** Rule semantics as language-neutral cases, run by both test suites, so
  that two implementations of "block" cannot quietly come to mean different things.

## What this will not do

Recorded here so that it is a decision rather than a disappointment:

- **Break certificate pinning.** Reading before encryption sidesteps it; interception will not attack it.
- **Run unprivileged.** Loading a probe needs root or `CAP_BPF`. There is no version of this that does not.
- **Work where policy forbids BPF.** A managed fleet can disable program loading outright. The answer is to
  say so, not to retry.
