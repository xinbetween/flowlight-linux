# Roadmap

Two milestones. **0.1 — see everything, honestly**, then **0.2 — parity with the macOS build**.

## 0.1 — see everything, honestly

A daemon that shows every HTTPS request every application on the machine makes, without installing a
certificate anywhere, and that states plainly what it could not see. No interception, no certificate authority,
no blocking. Those come after, and each says what it costs.

That target is chosen because it is the one the [design note](docs/DESIGN.md) argues is both the most useful
and the least dangerous: reading before encryption needs no trust setup, is not defeated by certificate
pinning, covers QUIC, runs on kernel 4.18, and cannot strand the machine's network if it crashes.

Releases go out one feature at a time. Each is built, tested on Linux by CI, and published before the next one
starts — the same cycle the macOS build uses, for the same reason: a release that bundles four features is a
release where nobody can tell which one broke something.

### The features

| | | | |
| --- | --- | --- | --- |
| **0.1.0** | **Identity** | What to call a process and what to key a rule on. Versioned installs, Nix store hashes, the kernel's fifteen-character `comm` limit, and an honest confidence level attached to every name. Pure logic, no kernel. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.0) |
| **0.1.1** | **Process and connection attribution** | Which process opened which connection, from eBPF on the socket path. The thing `nettop` does badly on macOS and the kernel does properly here. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.1) |
| **0.1.2** | **TLS plaintext capture** | uprobes on `SSL_write`/`SSL_read` for OpenSSL. Requests and responses in the clear, with no certificate installed anywhere. | |
| **0.1.3** | **The other TLS libraries** | GnuTLS, NSS and BoringSSL, so Firefox and Chrome are covered. Go's static TLS, which needs symbol resolution per binary and will be the hardest. | |
| **0.1.4** | **Storage and retention** | SQLite, the rollup tiers, and a retention policy that is stated rather than assumed. | |
| **0.1.5** | **Coverage** | What was not seen, and why: a TLS library with no probe, a container in another namespace, a process that exited before attribution landed. The screen that makes the rest trustworthy. | |
| **0.1.6** | **The local interface** | A web UI on loopback. Live, agents, and what each one reached. | |
| **0.1.7** | **Agent attribution** | Which agent a process works for, MCP servers from their configuration files, tool calls read out of the payloads already being captured. | |

## 0.2.x — parity with the macOS build

Everything [xinbetween/flowlight](https://github.com/xinbetween/flowlight) does, with one deliberate
difference noted below. Ordered so that each item has a trustworthy layer underneath it: there is no point
blocking traffic you cannot attribute, and no point simulating a rule against history you are not keeping.

| | | |
| --- | --- | --- |
| **0.2.0** | **Blocking** | A `cgroup/connect` hook that refuses before the SYN. Independent of how traffic is read, and better than the macOS equivalent: flow-level and request-level refusal compose here. |
| **0.2.1** | **Rules** | Allow, block, ask; precedence; scope by agent, host and port. The semantics are the macOS `RuleBook`'s, and they are not reimplemented from memory — see conformance below. |
| **0.2.2** | **Rule simulation** | What a rule would have changed, as a delta against real history: decide every recent flow twice and report only the verdicts that moved. The macOS build learnt this the hard way; a rule nobody can preview is a rule nobody enables. |
| **0.2.3** | **Budget and retention** | A header allowlist, a daily body-byte ceiling per application, a session window, and a retention period that is stated rather than assumed. Reading everything by default is not a feature. |
| **0.2.4** | **MCP domains** | The servers an agent is configured for, the ones it actually reached, and the gap between them — with the two buttons the macOS build settled on: block for this agent, or block everywhere. |
| **0.2.5** | **Export** | OTLP and JSON, behind the disclosure the macOS build established in 0.9.5: what leaves, where it goes, and a consent that is bound to that answer rather than to the act of exporting. |
| **0.2.6** | **Ask — with your own model** | macOS has a system model to lean on and Linux has none, so this is the one feature that is deliberately different: you configure a model, local or remote, or the feature stays off. No bundled weights and no silent fallback to somebody's API. |
| **0.2.7** | **Interception** | Redirect and terminate, for the cases that need a mocked response or refusal of one request rather than a whole connection. Carries the certificate-trust work — Python's certifi, Java's keystore, NSS — and is opt-in for exactly that reason. |
| **0.2.8** | **Launching an agent through Flowlight** | The Linux answer to 0.9.7: start an agent in an environment Flowlight already governs, without assuming a terminal, so that a graphical launcher or a supervisor works too. |
| **0.2.9** | **Conformance with macOS** | Rule semantics as language-neutral cases, run by both test suites, so that two implementations of "block" cannot quietly come to mean different things. Late on purpose: there has to be something to conform to. |

## What this will not do

Recorded here so that it is a decision rather than a disappointment:

- **Break certificate pinning.** Reading before encryption sidesteps it; interception will not attack it.
- **Run unprivileged.** Loading a probe needs root or `CAP_BPF`. There is no version of this that does not.
- **Work where policy forbids BPF.** A managed fleet can disable program loading outright. The answer is to
  say so, not to retry.
