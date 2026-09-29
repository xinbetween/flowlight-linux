//! Attribution, in the kernel.
//!
//! One tracepoint program. It fires on every TCP state change on the machine — a busy server does tens of
//! thousands a second — so the first thing it does is decide whether this is the one transition worth a
//! record, and the overwhelmingly common answer is no.
//!
//! The transition is `CLOSE → SYN_SENT`, which happens inside `connect()` on the calling thread. That is the
//! only point in a connection's life where the running task is the task that wanted it. See
//! [`flowlight_common::connection`] for why the more obvious choices are wrong.
//!
//! Nothing here reads a fixed offset. The kernel's record layout changed in 5.6 and the daemon hands us the
//! real one through [`LAYOUT`] before the program is attached.

#![no_std]
#![no_main]
// The `#[tracepoint]` macro generates the `extern "C"` entry point the kernel actually calls, and it has no
// doc comment to give it. The crate has three items of its own and all three are documented.
#![allow(
    missing_docs,
    reason = "the attribute macro generates an undocumented entry point"
)]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{map, tracepoint},
    maps::{Array, PerfEventArray},
    programs::TracePointContext,
};
use flowlight_common::connection::{
    AF_INET, AF_INET6, ConnectionEvent, IPPROTO_TCP, Layout, ipv4_bytes, is_outbound_connect,
};

/// Where the fields are on this kernel. Written once by the daemon before the program is attached.
///
/// An array of one rather than a compile-time constant, because the answer is not known until the daemon has
/// read the kernel's own description of its tracepoint.
#[map]
static LAYOUT: Array<Layout> = Array::with_max_entries(1, 0);

/// Connections on their way out, one per `connect()`.
///
/// A perf array rather than a ring buffer: ring buffers need Linux 5.8, and the point of taking this route at
/// all is that it works on 4.18.
#[map]
static EVENTS: PerfEventArray<ConnectionEvent> = PerfEventArray::new(0);

/// The entry point. Its return value is ignored for tracepoints; failures are silent by design, because the
/// alternative in this context is a kernel log line per dropped event on a machine already under load.
#[tracepoint]
pub fn inet_sock_set_state(ctx: TracePointContext) -> u32 {
    let _ = observe(&ctx);
    0
}

/// Reads the record, and emits one event if it describes a process opening a connection.
fn observe(ctx: &TracePointContext) -> Result<(), i64> {
    // Absent until the daemon has written it. Before that we are attached and deliberately doing nothing,
    // which is the right order: a program that guessed a layout until it was told the real one would emit a
    // burst of wrong rows at every startup.
    let layout = LAYOUT.get(0).ok_or(0_i64)?;

    // SAFETY for every `read_at` below: the offsets come from the kernel's own `format` file for this
    // tracepoint, and the daemon has already refused to load us if any field was missing or an unexpected
    // width. The verifier bounds-checks the context access regardless.
    let oldstate: u32 = unsafe { ctx.read_at(layout.oldstate as usize) }?;
    let newstate: u32 = unsafe { ctx.read_at(layout.newstate as usize) }?;
    if !is_outbound_connect(oldstate, newstate) {
        return Ok(());
    }

    // One byte from 5.6, two before it. Reading the wrong width here reads the first byte of an address as
    // part of the protocol number, and the result is a number that looks fine.
    let protocol = if layout.protocol_size == 1 {
        unsafe { ctx.read_at::<u8>(layout.protocol as usize) }?
    } else {
        let wide: u16 = unsafe { ctx.read_at(layout.protocol as usize) }?;
        // Little-endian, which every target this is built for is.
        wide as u8
    };
    if protocol != IPPROTO_TCP {
        return Ok(());
    }

    let family: u16 = unsafe { ctx.read_at(layout.family as usize) }?;
    let (saddr, daddr) = match family {
        AF_INET => (
            ipv4_bytes(unsafe { ctx.read_at(layout.saddr as usize) }?),
            ipv4_bytes(unsafe { ctx.read_at(layout.daddr as usize) }?),
        ),
        AF_INET6 => (unsafe { ctx.read_at(layout.saddr_v6 as usize) }?, unsafe {
            ctx.read_at(layout.daddr_v6 as usize)
        }?),
        _ => return Ok(()),
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    let event = ConnectionEvent {
        tgid: (pid_tgid >> 32) as u32,
        pid: pid_tgid as u32,
        comm: bpf_get_current_comm()?,
        saddr,
        daddr,
        // The tracepoint converts both to host order before recording them, so there is no byte swap here
        // and there should not be one. CI asserts the port of a real connection rather than trusting this
        // sentence.
        sport: unsafe { ctx.read_at(layout.sport as usize) }?,
        dport: unsafe { ctx.read_at(layout.dport as usize) }?,
        family,
        protocol,
        padding: 0,
    };

    EVENTS.output(ctx, &event, 0);
    Ok(())
}

/// Never reached: nothing in this program can panic, and there is nothing to unwind into if it did.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // The verifier would reject an infinite loop if it were reachable. It is not, and the linker drops it.
    loop {}
}

/// Tells the kernel this object is GPL, without which it refuses every helper that matters. The string is
/// the plain `GPL` rather than the template's dual licence, because this project is GPL-3.0 and nothing here
/// is offered under anything else.
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
