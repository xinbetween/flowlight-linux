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
//!
//! # Why every field is read with `read_volatile`, unconditionally, at the top
//!
//! A `cgroup_sock_addr` context is not memory. The verifier rewrites each field access into a load the
//! kernel synthesises, and it will only do that for a load whose offset is a constant in the instruction.
//! Holding a `&bpf_sock_addr` and reading fields off it lets the optimiser hoist the address arithmetic into
//! a register shared between branches — and the verifier then refuses the whole program with
//! `dereference of modified ctx ptr`, which is what happened the first time this was written.
//!
//! So: no references to the context, no branch between the reads, and `read_volatile` to stop the optimiser
//! rearranging them into something the verifier will not take.

use crate::tasks::{FORK_COUNTS, PID_AGENT};
use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{cgroup_sock_addr, map},
    maps::{HashMap, PerfEventArray},
    programs::SockAddrContext,
};
use core::ptr::read_volatile;
use flowlight_common::block::{ANY_PORT, BlockEvent, BlockKey, EVERYONE};
use flowlight_common::connection::{AF_INET, AF_INET6};

/// Allow the connection.
const ALLOW: i32 = 1;
/// Refuse it. The application sees `EPERM` from `connect()`.
const REFUSE: i32 = 0;

/// The answers, written by userspace.
///
/// Not the rules — the *answers*. Userspace resolves names, works out which rule wins and writes the
/// verdict for each address and port it knows about, so that a value of zero here is an explicit allow that
/// stops the search rather than an absence that lets a broader block through.
#[map]
static VERDICTS: HashMap<BlockKey, u8> = HashMap::with_max_entries(65536, 0);

/// Connections that were refused, on their way up to be reported.
///
/// A refusal nobody is told about is indistinguishable from a network that is down, and the person it
/// happens to is usually the person who wrote the rule.
#[map]
static BLOCK_EVENTS: PerfEventArray<BlockEvent> = PerfEventArray::new(0);

/// Index of the count of connects seen by the hook.
pub const CONNECTS_SEEN: u32 = 8;
/// Index of the count of connects whose caller turned out to be marked.
pub const CONNECTS_MARKED: u32 = 9;
/// Index of the last thread group the hook looked up.
pub const LAST_CONNECT_TGID: u32 = 10;
/// Index of the last thread group whose caller was marked.
pub const LAST_MARKED_CONNECT: u32 = 11;
/// Index of the agent identifier that caller was marked with.
pub const LAST_MARKED_AGENT: u32 = 12;
/// Index of the last thread group whose agent-scoped key was found.
pub const LAST_SCOPED_HIT: u32 = 13;

/// Records what the hook saw, in the same array the fork tracepoint uses.
fn note(index: u32, value: u64, add: bool) {
    if let Some(slot) = FORK_COUNTS.get_ptr_mut(index) {
        // SAFETY: a plain array value these programs alone write. Not atomic, and does not need to be:
        // these are diagnostics, and losing one to a race changes nothing they are for.
        unsafe {
            if add {
                *slot += value;
            } else {
                *slot = value;
            }
        }
    }
}

/// IPv4.
#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    let sock = ctx.sock_addr;
    // SAFETY: the kernel hands this program a valid context for the duration of the call, and each read is
    // a direct load at a constant offset — which is the only kind the verifier will rewrite.
    let (raw_address, raw_port) = unsafe {
        (
            read_volatile(&raw const (*sock).user_ip4),
            read_volatile(&raw const (*sock).user_port),
        )
    };
    // `user_ip4` is a `__be32` held in a native `u32`, so its in-memory bytes are already the address in
    // the order an address is written. Converting would reverse it.
    let [a, b, c, d] = raw_address.to_ne_bytes();
    let address = [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    decide(&ctx, AF_INET, address, port_of(raw_port))
}

/// IPv6.
#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
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
    decide(&ctx, AF_INET6, address, port_of(raw_port))
}

/// The port in host order.
///
/// `user_port` holds a sixteen-bit port in network order in its low half, which is why the kernel's own
/// examples compare it against `bpf_htons(port)` rather than the port.
fn port_of(raw: u32) -> u16 {
    u16::from_be((raw & 0xffff) as u16)
}

/// Whether this connection may proceed.
///
/// Eight lookups, most specific first, and the first key that exists decides. That order *is* precedence:
/// it is the same ordering [`flowlight_rules::Rule::specificity`] defines — subject, then port, then scope
/// — written out as a sequence, because a BPF program may not sort a table and may not loop over one.
///
/// A key whose value is zero is an explicit allow and stops the search. Without that, an exception for one
/// port would be defeated by a block on every port, and an exception for one agent by a block on everyone.
///
/// Every path that is not a match allows, including every path that fails: a bug in here must not be a
/// machine that cannot reach the network. That asymmetry is deliberate and is the reason there is no `?`
/// anywhere below.
fn decide(ctx: &SockAddrContext, family: u16, address: [u8; 16], port: u16) -> i32 {
    let thread = bpf_get_current_pid_tgid();
    let tgid = (thread >> 32) as u32;
    // SAFETY: a `u32` written by userspace or by the fork tracepoint; the reference does not outlive it.
    let agent = unsafe { PID_AGENT.get(&tgid) }.copied().unwrap_or(EVERYONE);
    let scoped = agent != EVERYONE;
    note(CONNECTS_SEEN, 1, true);
    note(LAST_CONNECT_TGID, u64::from(tgid), false);
    if scoped {
        note(CONNECTS_MARKED, 1, true);
        note(LAST_MARKED_CONNECT, u64::from(tgid), false);
        note(LAST_MARKED_AGENT, u64::from(agent), false);
    }

    let mut matched = EVERYONE;
    let mut verdict = None;

    // Specificity 7 down to 0. Each pair is the same question asked first about this agent and then about
    // everyone, because an agent-scoped rule is the more specific of two that otherwise say the same.
    if scoped {
        verdict = look(&BlockKey::new(agent, family, address, port));
        if verdict.is_some() {
            matched = agent;
            note(LAST_SCOPED_HIT, u64::from(tgid), false);
        }
    }
    if verdict.is_none() {
        verdict = look(&BlockKey::new(EVERYONE, family, address, port));
    }
    if verdict.is_none() && scoped {
        verdict = look(&BlockKey::new(agent, family, address, ANY_PORT));
        if verdict.is_some() {
            matched = agent;
        }
    }
    if verdict.is_none() {
        verdict = look(&BlockKey::new(EVERYONE, family, address, ANY_PORT));
    }
    if verdict.is_none() && scoped {
        verdict = look(&BlockKey::anything(agent, port));
        if verdict.is_some() {
            matched = agent;
        }
    }
    if verdict.is_none() {
        verdict = look(&BlockKey::anything(EVERYONE, port));
    }
    if verdict.is_none() && scoped {
        verdict = look(&BlockKey::anything(agent, ANY_PORT));
        if verdict.is_some() {
            matched = agent;
        }
    }
    if verdict.is_none() {
        verdict = look(&BlockKey::anything(EVERYONE, ANY_PORT));
    }

    match verdict {
        Some(refuse) if refuse != 0 => {}
        _ => return ALLOW,
    }

    let event = BlockEvent {
        tgid,
        pid: thread as u32,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        address,
        port,
        family,
        agent: matched,
    };
    BLOCK_EVENTS.output(ctx, &event, 0);
    REFUSE
}

/// One lookup in the table.
fn look(key: &BlockKey) -> Option<u8> {
    // SAFETY: the value is a `u8` written by userspace, and the reference does not outlive the lookup.
    unsafe { VERDICTS.get(key) }.copied()
}
