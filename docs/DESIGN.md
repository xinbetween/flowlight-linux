# Flowlight on Linux

A design note, not a commitment. Written in the macOS repository and moved here when this one was created;
[xinbetween/flowlight](https://github.com/xinbetween/flowlight) remains the Swift implementation it refers to
throughout. It records what was researched, what was measured, and which decisions are
still open, so that the first commit is not also the first time anyone asks these questions.

The target: **every application's traffic goes through Flowlight, HTTPS payloads are readable, and requests can
be refused or answered with a mock.** On macOS only the first of those is partial and the rest are opt-in per
app. On Linux all four are achievable — but not by one mechanism, and the choice of mechanism is the whole
design.

## The decision that shapes everything else

There are two ways to read TLS on Linux, and they fail in opposite directions.

**Terminate it.** Redirect the connection to a local proxy, present a certificate from a CA the machine trusts,
read the plaintext, forward it on. This is what Flowlight does on macOS. It can modify — which is the only way
to mock a response or refuse a single request rather than a whole connection.

**Read it before it is encrypted.** Attach a uprobe to `SSL_write`/`SSL_read` in the TLS library and take the
buffer as the application hands it over. No proxy, no certificate, nothing to trust.

The second is strictly better at seeing and cannot change anything. The first can change things and is defeated
by the problems below. Neither is sufficient alone, which is why the proposal is to run both.

### What terminating costs

Redirecting bytes is a weekend. Making every client accept the CA is the project, because Linux has no single
trust store:

| Client | Reads | Work |
| --- | --- | --- |
| curl, wget, Go binaries | `/etc/ssl/certs` | `update-ca-certificates` — free |
| Firefox, Thunderbird | per-profile NSS database | `policies.json` with `ImportEnterpriseRoots`, or `certutil` per profile |
| Chrome, Chromium | `~/.pki/nssdb` | `certutil`, per user |
| Node | system store, `NODE_EXTRA_CA_CERTS` | free-ish |
| **Python `requests`** | **bundled certifi — ignores the system store** | `sitecustomize.py` calling `truststore.inject_into_ssl()` |
| **Java** | **its own `cacerts` keystore** | `JAVA_TOOL_OPTIONS` pointing at a keystore we build |

Python and Java are exactly what agent tooling shells out to, and they are the two that ignore everything
installed system-wide. Appending to certifi works until the next `pip install -U certifi` silently reverts it;
`sitecustomize.py` survives upgrades, which is why it is the one to build.

And when all of that is done, **certificate pinning still wins**, as it should — Flowlight's threat model
refuses to break a pinned connection because breaking it breaks the app.

### What reading-before-encryption costs

It cannot modify. That is the entire cost, and it is a real one: no mocked responses, no refusing one request
out of a connection. Blocking still works, because blocking does not happen in the TLS layer at all.

## Architecture

Three layers, each replaceable, each with a different privilege and a different failure mode.

```
                         ┌──────────────────────────────┐
  cgroup/connect hook ──►│ refuse before the SYN        │   blocking, both modes
                         └──────────────────────────────┘
  uprobe on libssl    ──►  plaintext, read-only            default: universal
  redirect → proxy    ──►  plaintext, modifiable           opt-in: scoped
                         ┌──────────────────────────────┐
                         │ analysis, storage, UI        │
                         └──────────────────────────────┘
```

**Read by default, terminate on request.** Turning inspection on gives visibility everywhere with no trust
setup and no pinning failures. Turning on *modification* — for one app, one agent, one cgroup — is a second,
narrower decision that carries the CA work with it. That inverts the difficulty: the hard part becomes optional
and scoped rather than a prerequisite for seeing anything.

It also matches how the product already thinks. 0.9.5 established that Flowlight discloses what it does before
it does it; "you are now reading every HTTPS request on this machine" deserves at least that much.

## What we would embed rather than write

Flowlight is GPL-3.0, so MIT and Apache-2.0 both compose without friction.

| Project | License | What it gives us | Caveat |
| --- | --- | --- | --- |
| [eCapture](https://github.com/gojue/ecapture) | Apache-2.0 | uprobe TLS capture for OpenSSL, LibreSSL, BoringSSL, GnuTLS, NSPR/NSS and Go's own TLS; static binaries via an explicit `--libssl`; HTTP/1.1, HTTP/2 and **HTTP/3 over QUIC** | Written in Go. Read its eBPF programs and offset-resolution logic; do not link it |
| [mitmproxy_rs](https://github.com/mitmproxy/mitmproxy_rs) | MIT | a reusable **Rust** crate with `mitmproxy-linux-ebpf`: eBPF local redirect, interception by process name or PID | Needs kernel **6.8+**; egress only; process names matched on the first 16 bytes (`TASK_COMM_LEN`); containers need host networking |
| [hudsucker](https://github.com/omjadas/hudsucker) | MIT/Apache-2.0 | Rust MITM proxy: per-SNI certificates via `rcgen`, `rustls`, request/response/WebSocket modification | The TLS-termination half only; no interception |
| [aya](https://aya-rs.dev/) | MIT/Apache-2.0 | kernel and userspace eBPF in one language, shared type definitions across the boundary | Uprobe TLS capture is a proven pattern here but we would be writing it |

**The NSS line is the one worth noticing.** eCapture hooks NSPR/NSS, which means Firefox is readable through
uprobes *without* touching its certificate store — one of the two hardest trust targets disappears by choosing
the other mechanism. QUIC does the same: unreadable by termination, readable by uprobe.

## Kernel requirements are the real constraint

- uprobe capture: **4.18+** on x86_64, **5.5+** on aarch64
- mitmproxy's redirect: **6.8+**

That gap decides the default. Read-by-uprobe runs on anything from Ubuntu 18.04 onward; redirect-and-terminate
effectively means Ubuntu 24.04 or a recent Fedora. Shipping the universal layer as the default and termination
as opt-in also happens to be the one that works on more machines.

Both need root or `CAP_BPF` + `CAP_NET_ADMIN`. There is no unprivileged mode, and pretending otherwise on the
Capture screen would be the kind of claim this project does not make.

## Blocking

Independent of both read paths, and better than macOS: a `cgroup/connect4`/`connect6` hook refuses before the
SYN leaves. It sees the connecting process's own identity, which means **flow-level refusal and request-level
refusal compose** — a limitation the macOS threat model documents today ("inspection and refusal do not
combine", because proxied traffic leaves as Flowlight's own) simply does not exist here.

Request-level refusal and mocked responses still require the termination path, because you cannot rewrite a
buffer you are only observing.

## What stays unreadable, and must be said so

- **Pinned certificates** under termination — by design, we do not break them. Readable under uprobes.
- **A TLS library we have no probe for** — anything statically linked with symbols stripped, or a stack we do
  not recognise.
- **Protocols that are not HTTP** — SSH, DNS-over-TLS, arbitrary TCP. Metadata only, both modes.
- **Traffic in another network namespace**, unless we attach there too.

Coverage already exists to answer "what would you not have been told". On Linux it gains a column: *seen*,
*named*, *readable*, **modifiable**. Those last two are different questions here and conflating them would be
the Linux version of the claims this project has spent its releases correcting.

## Fail-open is a requirement, not a nicety

Once every connection routes through us, **we are the machine's network**. A crash, a stall, or a leaked file
descriptor takes the box off the internet — including SSH, if nobody thought about it.

Non-negotiable from the first commit: a watchdog that detaches the eBPF programs if the proxy stops answering;
the proxy's own uid excluded to prevent loops; an explicit never-touch list. Test the teardown path before the
happy path.

The uprobe layer does not have this property, which is another argument for it being the default: observing
cannot strand the machine.

## The open problem: identity

macOS has bundle identifiers. Linux has executable paths, cgroups, systemd units, and the same versioned-install
problem that produced `ProcessNaming` — except now it is npm global installs, asdf, nix store paths, Flatpak
and containers. `mitmproxy`'s 16-byte `TASK_COMM_LEN` limit is a preview: `claude` fits, a wrapper script's name
may not.

This is not a porting detail. Every allowlist, rule, guardrail and MCP attribution is keyed on identity, and
getting it wrong means rules that silently match nothing. It deserves its own design before any of the above is
built.

## What I would build first

A read-only daemon: uprobe capture, the existing analysis and storage, a local web UI, no redirect, no CA, no
blocking. It proves the capture layer, the identity model and the honesty of Coverage against real traffic —
and it is useful on its own, because seeing every HTTPS request on a Linux box without installing a certificate
anywhere is already more than the macOS build can do.

Termination, blocking and mocking come after, as a second mode that states what it costs.

## References

- [eCapture](https://github.com/gojue/ecapture) — uprobe TLS capture, Apache-2.0
- [mitmproxy_rs](https://github.com/mitmproxy/mitmproxy_rs) — Rust crate, eBPF local redirect, MIT
- [Intercepting Linux Applications](https://www.mitmproxy.org/posts/local-capture/linux/) — mitmproxy's local mode and its limits
- [hudsucker](https://github.com/omjadas/hudsucker) — Rust MITM proxy library
- [aya](https://aya-rs.dev/) — eBPF in Rust
- [Capturing HTTPS Traffic: A Rust and eBPF Odyssey](https://www.kungfudev.com/blog/2023/12/07/https-sniffer-with-rust-aya) — worked uprobe example with aya
