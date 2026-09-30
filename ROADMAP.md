# Roadmap

Four milestones. **0.1 — see everything, honestly**, then **0.2 — parity with the macOS build**, then
**0.3 — installing it without a compiler**, then **0.4 — the parity the first pass missed**.

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
| **0.1.2** | **TLS plaintext capture** | uprobes on `SSL_write`/`SSL_read` for OpenSSL. Requests and responses in the clear, with no certificate installed anywhere. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.2) |
| **0.1.3** | **HTTP/2 and HPACK** | Every current agent API speaks HTTP/2, whose headers are compressed against a table built across the whole connection. Without this, the method and path of a request to `api.anthropic.com` are not readable — which makes it the difference between a demonstration and a tool. Inserted here after 0.1.2 proved the capture works and showed exactly what it cannot say. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.3) |
| **0.1.4** | **The other TLS libraries** | GnuTLS and NSS, so wget, Firefox and Thunderbird are covered. Go's static TLS and Chrome's linked-in BoringSSL need symbols resolved per binary rather than per library, and Go a calling convention that is not the C one — each is its own piece of work, and neither is in this. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.4) |
| **0.1.5** | **Storage and retention** | SQLite, the rollup tiers, and a retention policy that is stated rather than assumed. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.5) |
| **0.1.6** | **Coverage** | What was not seen, and why: a TLS library with no probe, a container in another namespace, a process that exited before attribution landed. The screen that makes the rest trustworthy. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.6) |
| **0.1.7** | **The local interface** | A web UI on loopback. Live, processes, and Coverage, behind a token because loopback is not a permission boundary. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.7) |
| **0.1.8** | **Agent attribution** | Which agent a process works for, from the process tree. MCP servers read out of the agents' own configuration files, compared with the hosts they actually reached. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.1.8) |

## 0.2.x — parity with the macOS build

Everything [xinbetween/flowlight](https://github.com/xinbetween/flowlight) does, with one deliberate
difference noted below. Ordered so that each item has a trustworthy layer underneath it: there is no point
blocking traffic you cannot attribute, and no point simulating a rule against history you are not keeping.

| | | | |
| --- | --- | --- | --- |
| **0.2.0** | **Blocking** | A `cgroup/connect` hook that refuses before the SYN. Independent of how traffic is read, and better than the macOS equivalent: flow-level and request-level refusal compose here. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.0) |
| **0.2.1** | **Rules** | Allow, block, ask; precedence; scope by agent, host and port. The semantics are the macOS `RuleBook`'s, and they are not reimplemented from memory — see conformance below. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.1) |
| **0.2.2** | **A native interface** | A GTK4 window that runs as you, talking over a socket to a daemon that runs as root. Loopback is not a permission boundary and the web page it replaces was guarded by a token; a socket has an owner and a mode. Inserted here because an interface that has to be reached through a browser is one nobody opens. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.2) |
| **0.2.3** | **Rule simulation** | What a rule would have changed, as a delta against real history: decide every recent flow twice and report only the verdicts that moved. The macOS build learnt this the hard way; a rule nobody can preview is a rule nobody enables. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.3) |
| **0.2.4** | **Budget and retention** | A session that runs out, a daily byte ceiling per process, how much of a request target is kept, and a retention period — each a number rather than a principle. Reading everything by default is not a feature. A header allowlist is not among them because no headers are kept at all; that decision belongs to whichever release starts keeping them. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.4) |
| **0.2.5** | **MCP domains** | The servers an agent is configured for, the ones it reached, the gap between them, and — the part that needed the payloads — what it actually *said*: MCP is JSON-RPC, so the method and the tool are in plaintext already captured. Never the arguments. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.5) |
| **0.2.6** | **Export** | OTLP and JSON, behind the disclosure the macOS build established in 0.9.5: what leaves, where it goes, and a consent that is bound to that answer rather than to the act of exporting. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.6) |
| **0.2.7** | **Ask — with your own model** | macOS has a system model to lean on and Linux has none, so this is the one feature that is deliberately different: you configure a model, local or remote, or the feature stays off. No bundled weights and no silent fallback to somebody's API. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.7) |
| **0.2.8** | **Interception** | Redirect and terminate, for the cases that need a mocked response or refusal of one request rather than a whole connection. Carries the certificate-trust work — Python's certifi, Java's keystore, NSS — and is opt-in for exactly that reason. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.8) |
| **0.2.9** | **Launching an agent through Flowlight** | The Linux answer to 0.9.7: start an agent in an environment Flowlight already governs, without assuming a terminal, so that a graphical launcher or a supervisor works too. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.9) |
| **0.2.10** | **Conformance with macOS** | Rule semantics as language-neutral cases, run by both test suites, so that two implementations of "block" cannot quietly come to mean different things. Late on purpose: there has to be something to conform to. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.2.10) |

## 0.3.x — installing it without a compiler

Today the only way to get this is to clone it and build it, which means a nightly toolchain and `bpf-linker` on
the machine that runs it. That is a reasonable thing to ask of somebody trying it out and an unreasonable thing
to ask of everybody else, so the next milestone is `apt install flowlight`.

The good news first: **nothing has to be compiled on the machine that runs it.** The eBPF programs are compiled
into the binary by `aya-build` and loaded from it, so there are no kernel headers to match, no DKMS, no clang at
install time, and no module to rebuild when the kernel is upgraded. A package is two binaries, a unit file and a
directory.

| | | | |
| --- | --- | --- | --- |
| **0.3.0** | **A `.deb`** | `flowlightd` and a systemd unit, `amd64` and `arm64`, attached to each release. The unit ships **disabled**: a tool that reads every HTTPS request on a machine must not start doing it because somebody installed it. Two packages, not one — `flowlight` for the daemon, `flowlight-gui` for the window — because a server has no reason to pull in GTK 4 and libadwaita, and the window needs libadwaita 1.5 (Ubuntu 24.04 and later) while the daemon needs only a kernel of 4.18. | [released as v0.4.5](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.4.5) |
| **0.3.1** | **An apt repository** | A signed archive so `apt-get update` finds new versions: an `InRelease` signed with a key published beside it, served as static files. Adding a third-party repository is a decision to trust whoever holds that key for as long as it is in your sources, which is a larger thing to ask than downloading one file — so the `.deb` comes first and stays a first-class way to install. | |

Neither is parity with anything; the macOS build ships a signed `.dmg` and a notarised app, which is the same
problem solved by a different distribution's rules.

## 0.4.x — the parity the first pass missed

0.2 was built from the macOS build's *roadmap*, which lists what was planned. This milestone was built by
reading its *source tree*, which is what exists — and there is more in the second list than in the first. None
of it is small, and none of it was a decision to leave out; it simply was not visible from where the first
comparison was made.

Ordered by what an agent monitor is for. The first two are the ones whose absence is felt.

The numbers in the first column are **plan** numbers, not release numbers. A version only ever goes forwards —
anything else is a package manager that refuses to upgrade — so an item built out of order ships under the next
free version, and the status column links to the release it actually shipped in.

| | | | |
| --- | --- | --- | --- |
| **0.4.0** | **Guardrails** | "This agent may not use that tool." The other half of the rule model, and its own idea rather than a special case of the network one: *which tools may this agent use* is a different question from *which hosts may it reach*, and answering it means reading what the agent says rather than where it connects. A guardrail names an agent, a server and a tool — any of them blank meaning all of them — and refuses it. There is no allow action, because a guardrail is subtractive by nature: it is applied to a list the agent itself declares, and "allow" would only ever mean "do not subtract this", which is what leaving it out already says. Linux can see MCP calls since 0.2.5 and can answer a single request since 0.2.8, so this is the two joined together: match the method and the tool in the proxy, and answer with a JSON-RPC error the agent will understand rather than a dropped connection it will retry. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.4.0) |
| **0.4.1** | **Alerts** | Anomalies, each carrying the arithmetic that produced it. The macOS build's list is the right one and was arrived at by use: a traffic spike against an EWMA baseline, an unusual number of destinations, first contact with a domain, a process new to the network, a non-standard port, an upload above the 99th percentile, and an agent reaching a sensitive channel. A ranked list with no numbers behind it is a horoscope, so every alert names what it compared against. The one signal that does not port is "traffic while nobody was at the keyboard": a desktop idea, and this runs on servers, so it is offered where there is a session to ask about and absent where there is not. | [released as v0.4.4](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.4.4) |
| **0.4.2** | **Who owns an address** | An autonomous system number and its operator, for the traffic that has no hostname — which on Linux is every connection recorded at `connect()`, because the name was resolved and thrown away before the kernel saw it. Coverage already says how many connections could not be read; saying *whose* they were is the difference between a number and a lead. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.4.2) |
| **0.4.3** | **What an agent is set up to do** | 0.2.5 reads the MCP servers out of an agent's configuration and compares them with what it reached. The same files say far more: skills, subagents, commands, hooks, plugins, permissions and instructions. A hook is a program an agent runs on its own behalf, and a permission is a decision somebody made once and has not looked at since — both worth being able to list without opening a dotfile. Pure parsing, in the crate that already does the parsing. | [released](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.4.3) |
| **0.4.4** | **Reports** | What the window can show that a table cannot: traffic sliced by process, destination, address or protocol, over a window somebody picks. And the profile that goes with it — why one process's destinations stand out, with the count behind each reason: many destinations, hostless traffic, generated-looking names, mostly uploading. Every signal carries its evidence for the same reason alerts do. | [released as v0.4.6](https://github.com/xinbetween/flowlight-linux/releases/tag/v0.4.6) |
| **0.4.5** | **Devices** | The channels that are not the network: what is attached over USB and what is paired over Bluetooth, and when that changed. Arrivals, departures and what a thing is — never how much went through it, because neither channel accounts for throughput per process on any platform. Off until it is switched on, like the macOS build, and for the same reason: it widens what is watched, and that should be a decision rather than a surprise in an update. | |
| **0.4.6** | **Nine languages** | The macOS build ships in German, Spanish, French, Italian, Japanese, Korean, Portuguese and simplified Chinese as well as English. This ships in English. Sentences are the interface here — the disclosures, the coverage explanations, the reason a rule did not bite — so translating it is translating most of what it says, which is why it is a release of its own and not a chore attached to another one. | |

Smaller than a release each, and recorded so they are not lost: a focus mode that narrows every screen to one
process or one destination; starter rules for the things everybody blocks first; and a demonstration mode, which
is how a tool that watches a private machine gets screenshotted at all.

### What this has that the macOS build does not

Recorded in the same spirit. Blocking happens in the kernel at `connect()` rather than in the proxy, so refusing
and inspecting are independent and a refusal costs no interception. Agent attribution is carried by the kernel
at `fork`, so anything an agent starts is attributed before it can run. `launch` marks a process before it
executes, which no amount of scanning can promise. And there is no built-in model: Ask runs against one you
configure, or not at all.

## What this will not do

Recorded here so that it is a decision rather than a disappointment:

- **Break certificate pinning.** Reading before encryption sidesteps it; interception will not attack it.
- **Run unprivileged.** Loading a probe needs root or `CAP_BPF`. There is no version of this that does not.
- **Work where policy forbids BPF.** A managed fleet can disable program loading outright. The answer is to
  say so, not to retry.
