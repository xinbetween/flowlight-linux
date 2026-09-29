//! Refusing a connection before the SYN, in the kernel.
//!
//! Two programs, one per address family, attached to the root cgroup. They run inside `connect()`, before
//! anything has been sent, and returning zero makes the syscall fail with `EPERM` — the same answer a
//! firewall gives, and one every network client already knows how to report.
//!
//! # Why the decision is a map lookup and not a rule engine
//!
//! A BPF program may not loop over a table, and the verifier is right to insist: this runs inside every
//! `connect()` on the machine, and the one thing worse than a connection being wrongly refused is every
//! connection on the machine taking a millisecond longer. So userspace does the thinking — resolving hosts,
//! working out precedence — and writes the answers in. The kernel does two hash lookups.
//!
//! Two, not one, because a rule naming a port is more specific than one that does not, and both have to be
//! askable without iterating.

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{cgroup_sock_addr, map},
    maps::{HashMap, PerfEventArray},
    programs::SockAddrContext,
};
use flowlight_common::block::{BlockEvent, BlockKey, EVERYONE};
use flowlight_common::connection::{AF_INET, AF_INET6};

/// Allow the connection.
const ALLOW: i32 = 1;
/// Refuse it. The application sees `EPERM` from `connect()`.
const REFUSE: i32 = 0;

/// The rules, written by userspace.
#[map]
static BLOCKED: HashMap<BlockKey, u8> = HashMap::with_max_entries(65536, 0);

/// Connections that were refused, on their way up to be reported.
///
/// A refusal nobody is told about is indistinguishable from a network that is down, and the person it
/// happens to is usually the person who wrote the rule.
#[map]
static BLOCK_EVENTS: PerfEventArray<BlockEvent> = PerfEventArray::new(0);

/// IPv4.
#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    decide(&ctx, AF_INET)
}

/// IPv6.
#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    decide(&ctx, AF_INET6)
}

/// Whether this connection may proceed.
///
/// Every path that is not a match allows, including every path that fails: a bug in here must not be a
/// machine that cannot reach the network. That asymmetry is deliberate and is the reason there is no `?`
/// anywhere below.
fn decide(ctx: &SockAddrContext, family: u16) -> i32 {
    // SAFETY: the kernel hands this program a valid `bpf_sock_addr` for the duration of the call, and
    // nothing here holds the reference past it.
    let sock = unsafe { &*ctx.sock_addr };

    let address = if family == AF_INET {
        // `user_ip4` is a `__be32` held in a native `u32`, so its in-memory bytes are already the address
        // in the order an address is written. Converting would reverse it.
        let [a, b, c, d] = sock.user_ip4.to_ne_bytes();
        [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    } else {
        let [a, b, c, d] = sock.user_ip6[0].to_ne_bytes();
        let [e, f, g, h] = sock.user_ip6[1].to_ne_bytes();
        let [i, j, k, l] = sock.user_ip6[2].to_ne_bytes();
        let [m, n, o, p] = sock.user_ip6[3].to_ne_bytes();
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]
    };

    // `user_port` holds a sixteen-bit port in network order in its low half.
    let port = u16::from_be((sock.user_port & 0xffff) as u16);

    let keyed = BlockKey::new(EVERYONE, family, address, port);
    // SAFETY for both: the values are `u8` written by userspace, and neither reference outlives its lookup.
    let matched = unsafe { BLOCKED.get(&keyed) }.is_some()
        || unsafe { BLOCKED.get(&keyed.any_port()) }.is_some();
    if !matched {
        return ALLOW;
    }

    let thread = bpf_get_current_pid_tgid();
    let event = BlockEvent {
        tgid: (thread >> 32) as u32,
        pid: thread as u32,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        address,
        port,
        family,
        agent: EVERYONE,
    };
    BLOCK_EVENTS.output(ctx, &event, 0);
    REFUSE
}
