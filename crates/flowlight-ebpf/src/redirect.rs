//! Sending an agent's connection to Flowlight's proxy, in the kernel, inside `connect()`.
//!
//! Three programs. Two rewrite the destination — one per address family, for the same reason the blocking
//! programs are two — and the third moves the note about where the connection was actually going from the
//! socket's cookie to its source port, which is the only handle the proxy has on it.
//!
//! # Why this rather than an environment variable
//!
//! Because an environment variable has to be set before a process starts, by whoever starts it, and has to be
//! understood by whatever library that process uses. `HTTPS_PROXY` is honoured by curl and Python and ignored
//! by plenty of things; `NODE_EXTRA_CA_CERTS` exists because Node ignores the machine's trust store. A
//! `cgroup/connect` hook is none of that: it applies to a process that is already running, to everything it
//! starts, and to every library any of them use, because it is below all of them.
//!
//! # Why so little happens here
//!
//! Every path that is not a redirect returns `ALLOW` and changes nothing, including every path that fails. A
//! bug in this file must not be a machine whose processes cannot open a connection, so there is no `?` below
//! and no branch that can end anywhere other than allowing the connection to proceed.

use crate::tasks::PID_AGENT;
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_socket_cookie},
    macros::{cgroup_sock_addr, map, sock_ops},
    maps::{Array, HashMap},
    programs::{SockAddrContext, SockOpsContext},
};
use core::ptr::{read_volatile, write_volatile};
use flowlight_common::block::EVERYONE;
use flowlight_common::connection::{AF_INET, AF_INET6};
use flowlight_common::redirect::{IN_SCOPE, Original, PROXY_PORT};

/// Let the connection proceed. Every path here returns this.
const ALLOW: i32 = 1;

/// What a `sock_ops` program returns when it has nothing to say.
const NOTHING: u32 = 0;

/// The callback that fires once the kernel has chosen a source port and is about to connect.
///
/// Taken from the binding rather than written as a number. The first version of this said 5, which is
/// `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` — so the program loaded, attached, ran on every inbound connection
/// and never once on an outbound one. Nothing failed; the proxy simply never learnt where anything was going.
const TCP_CONNECT_CB: u32 = aya_ebpf::bindings::BPF_SOCK_OPS_TCP_CONNECT_CB;

/// Which agents' connections are redirected, by the identifier userspace gives each agent.
///
/// Empty means nobody. That is the default and it is the safe reading: a scope that meant everybody would
/// redirect the package manager, which pins certificates, and the first symptom would be a machine that
/// cannot update itself.
#[map]
static REDIRECT_AGENTS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Which destination ports are redirected. In practice 443.
#[map]
static REDIRECT_PORTS: HashMap<u16, u8> = HashMap::with_max_entries(64, 0);

/// Where the proxy listens, in host order. Zero means it is not listening, and nothing is redirected.
#[map]
static REDIRECT_TO: Array<u16> = Array::with_max_entries(1, 0);

/// Where a connection was going, keyed by the socket's cookie.
///
/// Only until the kernel picks a source port, which is a few instructions later in the same syscall.
#[map]
static PENDING: HashMap<u64, Original> = HashMap::with_max_entries(16384, 0);

/// Where a connection was going, keyed by its source port.
///
/// The proxy reads this. A connection it accepts is from `127.0.0.1:something`, and `something` is the key.
#[map]
static ORIGINALS: HashMap<u16, Original> = HashMap::with_max_entries(16384, 0);

/// IPv4.
#[cgroup_sock_addr(connect4)]
pub fn redirect4(ctx: SockAddrContext) -> i32 {
    let sock = ctx.sock_addr;
    // SAFETY: the kernel hands this program a valid context for the duration of the call, and each read is a
    // direct load at a constant offset — the only kind the verifier will rewrite. See `block.rs` for what
    // happens when this is written any other way.
    let (raw_address, raw_port) = unsafe {
        (
            read_volatile(&raw const (*sock).user_ip4),
            read_volatile(&raw const (*sock).user_port),
        )
    };
    let [a, b, c, d] = raw_address.to_ne_bytes();
    let address = [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let port = port_of(raw_port);

    // Loopback is never redirected. A connection to this machine includes every connection to the proxy
    // itself, and redirecting those is a loop that ends with a machine doing nothing else.
    if a == 127 {
        return ALLOW;
    }
    // SAFETY: the helper reads the cookie of the socket this call is for, out of the context it was given.
    let cookie = unsafe { bpf_get_socket_cookie(sock.cast()) };
    let Some(proxy) = wanted(cookie, AF_INET, address, port) else {
        return ALLOW;
    };
    // SAFETY: two direct stores at constant offsets, which is what the verifier permits for these two
    // fields in a `connect4` program. The bytes are written in the order they are read above.
    unsafe {
        write_volatile(
            &raw mut (*sock).user_ip4,
            u32::from_ne_bytes([127, 0, 0, 1]),
        );
        write_volatile(&raw mut (*sock).user_port, u32::from(proxy.to_be()));
    }
    ALLOW
}

/// IPv6.
#[cgroup_sock_addr(connect6)]
pub fn redirect6(ctx: SockAddrContext) -> i32 {
    let sock = ctx.sock_addr;
    // SAFETY: as above. Constant indices into the array, so each is still a constant offset.
    let (w0, w1, w2, w3, raw_port) = unsafe {
        (
            read_volatile(&raw const (*sock).user_ip6[0]),
            read_volatile(&raw const (*sock).user_ip6[1]),
            read_volatile(&raw const (*sock).user_ip6[2]),
            read_volatile(&raw const (*sock).user_ip6[3]),
            read_volatile(&raw const (*sock).user_port),
        )
    };
    let [a, b, c, d] = w0.to_ne_bytes();
    let [e, f, g, h] = w1.to_ne_bytes();
    let [i, j, k, l] = w2.to_ne_bytes();
    let [m, n, o, p] = w3.to_ne_bytes();
    let address = [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p];
    let port = port_of(raw_port);

    // `::1`, and a v4-mapped loopback written as a v6 address.
    let loopback = address == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        || (address[10] == 0xff && address[11] == 0xff && address[12] == 127);
    if loopback {
        return ALLOW;
    }
    // SAFETY: as above.
    let cookie = unsafe { bpf_get_socket_cookie(sock.cast()) };
    let Some(proxy) = wanted(cookie, AF_INET6, address, port) else {
        return ALLOW;
    };
    // SAFETY: four direct stores at constant offsets, and then the port. `::1`.
    unsafe {
        write_volatile(&raw mut (*sock).user_ip6[0], 0);
        write_volatile(&raw mut (*sock).user_ip6[1], 0);
        write_volatile(&raw mut (*sock).user_ip6[2], 0);
        write_volatile(
            &raw mut (*sock).user_ip6[3],
            u32::from_ne_bytes([0, 0, 0, 1]),
        );
        write_volatile(&raw mut (*sock).user_port, u32::from(proxy.to_be()));
    }
    ALLOW
}

/// Moves the note from the socket's cookie to its source port, now that there is one.
#[sock_ops]
pub fn redirect_ops(ctx: SockOpsContext) -> u32 {
    if ctx.op() != TCP_CONNECT_CB {
        return NOTHING;
    }
    // SAFETY: the helper takes the context it was given, for the duration of the call.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.ops.cast()) };
    // SAFETY: an `Original` written by `redirect4` or `redirect6` a few instructions ago, in this syscall.
    let Some(original) = unsafe { PENDING.get(&cookie) }.copied() else {
        return NOTHING;
    };
    let _ = PENDING.remove(&cookie);
    let source = ctx.local_port() as u16;
    if source != 0 {
        // Overwritten rather than skipped if something is already there: a source port is reused eventually,
        // and the newer connection is the one the proxy is about to accept.
        let _ = ORIGINALS.insert(&source, &original, 0);
    }
    NOTHING
}

/// The port in host order.
///
/// `user_port` holds a sixteen-bit port in network order in its low half, which is why the kernel's own
/// examples compare it against `bpf_htons(port)` rather than against the port.
fn port_of(raw: u32) -> u16 {
    u16::from_be((raw & 0xffff) as u16)
}

/// Whether this connection is one to redirect, and to which port.
///
/// Four questions, each of which can only make the answer "no": is the proxy listening, is this a port that is
/// redirected, does this process belong to an agent, and is that agent in scope. The note about where the
/// connection was going is written here, because this is the last point at which anything knows.
fn wanted(cookie: u64, family: u16, address: [u8; 16], port: u16) -> Option<u16> {
    let proxy = REDIRECT_TO.get(PROXY_PORT).copied().unwrap_or(0);
    if proxy == 0 || proxy == port {
        return None;
    }
    // SAFETY: a `u8` written by userspace; the reference does not outlive the lookup.
    if unsafe { REDIRECT_PORTS.get(&port) }.copied().unwrap_or(0) != IN_SCOPE {
        return None;
    }
    let thread = bpf_get_current_pid_tgid();
    let tgid = (thread >> 32) as u32;
    // SAFETY: a `u32` written by userspace or by the fork tracepoint.
    let agent = unsafe { PID_AGENT.get(&tgid) }.copied().unwrap_or(EVERYONE);
    if agent == EVERYONE {
        return None;
    }
    // SAFETY: as above.
    if unsafe { REDIRECT_AGENTS.get(&agent) }.copied().unwrap_or(0) != IN_SCOPE {
        return None;
    }

    // Written before the address is rewritten, because afterwards nothing knows what it was.
    let original = Original {
        address,
        tgid,
        agent,
        port,
        family,
    };
    if cookie != 0 {
        let _ = PENDING.insert(&cookie, &original, 0);
    }
    Some(proxy)
}
