//! The eBPF programs Flowlight loads into the kernel.
//!
//! Two things, and they are independent of each other. [`attribution`] answers which process opened which
//! connection, from a tracepoint on the socket path. [`tls`] answers what was actually sent, from uprobes on
//! the TLS library — before the encryption, which is why it needs no certificate and no trust store and
//! cannot be defeated by pinning.
//!
//! Everything in here runs under the kernel's verifier, which is a stricter reviewer than any person: it
//! rejects unbounded loops, unbounded memory access, and reads it cannot prove are in range. Code that looks
//! needlessly careful below is usually code that was rejected until it was.

#![no_std]
#![no_main]
// The probe macros generate the `extern "C"` entry points the kernel actually calls, and there is no way to
// give those a doc comment. Everything written by hand here is documented.
#![allow(
    missing_docs,
    reason = "the attribute macros generate undocumented entry points"
)]

mod attribution;
mod tls;

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
