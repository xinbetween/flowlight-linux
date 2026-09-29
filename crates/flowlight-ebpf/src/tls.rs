//! Plaintext, taken from OpenSSL before it encrypts anything.
//!
//! `SSL_write(ssl, buf, num)` is straightforward: on entry the buffer already holds what the application
//! wants to send, so the plaintext is read and sent up there and then.
//!
//! `SSL_read(ssl, buf, num)` is not. On entry the buffer is uninitialised — `num` is its *capacity*, not its
//! contents — so reading it would send up whatever was on that part of the application's heap. The pointer is
//! stashed instead and the buffer read on the way out, where the return value says how much of it became
//! real. That is what [`PENDING_READS`] is for, and it is keyed on the thread rather than the process because
//! two threads of one program can be inside `SSL_read` at once.
//!
//! # Why four functions and not two
//!
//! OpenSSL 1.1.1 added `SSL_write_ex` and `SSL_read_ex`, which take a `size_t` instead of an `int` and report
//! the count through an out-parameter instead of the return value. Modern callers use them. Probing only the
//! original pair means seeing nothing at all from a program that took the newer one, and seeing nothing is
//! indistinguishable from there being nothing to see — which is the failure this project exists to avoid.
//!
//! # Why not read the socket instead
//!
//! Because the socket carries ciphertext. This is the whole argument of the design note: the only place the
//! plaintext exists is in the application's own buffer on its way past the TLS library, and the only way to
//! see it there without becoming a man in the middle is to be standing at that function when it is called.

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user,
        bpf_probe_read_user_buf,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, PerCpuArray, PerfEventArray},
    programs::{ProbeContext, RetProbeContext},
};
use flowlight_common::tls::{DIRECTION_IN, DIRECTION_OUT, TLS_CHUNK_BYTES, TlsChunk};

/// Plaintext on its way up.
#[map]
static TLS_EVENTS: PerfEventArray<TlsChunk> = PerfEventArray::new(0);

/// One chunk per CPU, to build events in.
///
/// Not a local variable: a [`TlsChunk`] is four kilobytes and change, and a BPF program's whole stack is five
/// hundred and twelve bytes. This is the standard way around that, and the reason the type has a `zeroed`
/// constructor at all.
#[map]
static SCRATCH: PerCpuArray<TlsChunk> = PerCpuArray::with_max_entries(1, 0);

/// Buffers handed to a read, waiting for the call to return and say how much of one is real.
///
/// Keyed on `pid_tgid` — the thread, not the process. Ten thousand entries is far more than the number of
/// threads that can be inside a read simultaneously on any real machine, and an entry that somehow outlives
/// its call is overwritten by that thread's next read rather than leaked.
#[map]
static PENDING_READS: HashMap<u64, PendingRead> = HashMap::with_max_entries(10240, 0);

/// Where a read will put its answer, and where it will say how much of it there is.
#[repr(C)]
#[derive(Clone, Copy)]
struct PendingRead {
    /// The `SSL *` the read was made on, kept so that the chunk sent on the way out can name its connection.
    ssl: u64,
    /// The application's buffer.
    buffer: u64,
    /// `SSL_read_ex`'s `size_t *readbytes`, or zero for `SSL_read`, which returns the count instead.
    written: u64,
}

/// `SSL_write(SSL *ssl, const void *buf, int num)` — the plaintext is already there.
#[uprobe]
pub fn ssl_write(ctx: ProbeContext) -> u32 {
    let _ = on_write(&ctx, ctx.arg::<i32>(2).map(i64::from));
    0
}

/// `SSL_write_ex(SSL *ssl, const void *buf, size_t num, size_t *written)` — the same, with a wider count.
#[uprobe]
pub fn ssl_write_ex(ctx: ProbeContext) -> u32 {
    // The count before the call is what the application intends to write. `*written` afterwards could be
    // less, but the bytes we copy are the ones at the front of the buffer either way, and capping the length
    // here rather than waiting for the return means one probe instead of two.
    let _ = on_write(
        &ctx,
        ctx.arg::<u64>(2).map(|n| n.min(i64::MAX as u64) as i64),
    );
    0
}

fn on_write(ctx: &ProbeContext, length: Option<i64>) -> Result<(), i32> {
    let ssl: u64 = ctx.arg(0).ok_or(0_i32)?;
    let buffer: *const u8 = ctx.arg(1).ok_or(0_i32)?;
    capture(ctx, ssl, buffer, length.ok_or(0_i32)?, DIRECTION_OUT)
}

/// `SSL_read(SSL *ssl, void *buf, int num)` — remember where the answer will go.
#[uprobe]
pub fn ssl_read(ctx: ProbeContext) -> u32 {
    remember(&ctx, 0);
    0
}

/// `SSL_read_ex(SSL *ssl, void *buf, size_t num, size_t *readbytes)` — and where the count will go.
#[uprobe]
pub fn ssl_read_ex(ctx: ProbeContext) -> u32 {
    let written = ctx.arg::<u64>(3).unwrap_or(0);
    remember(&ctx, written);
    0
}

fn remember(ctx: &ProbeContext, written: u64) {
    if let (Some(ssl), Some(buffer)) = (ctx.arg::<u64>(0), ctx.arg::<u64>(1)) {
        let pending = PendingRead {
            ssl,
            buffer,
            written,
        };
        // Failure here means the map is full, so this one read goes unseen. There is nothing better to do
        // about it from in here, and 0.1.5 is where not-seeing becomes something to report.
        let _ = PENDING_READS.insert(&bpf_get_current_pid_tgid(), &pending, 0);
    }
}

/// `SSL_read` on its way out: the return value is how many bytes arrived.
#[uretprobe]
pub fn ssl_read_return(ctx: RetProbeContext) -> u32 {
    let _ = on_read_return(&ctx, |_| Some(i64::from(ctx.ret::<i32>())));
    0
}

/// `SSL_read_ex` on its way out: the return value is one or zero, and the count is where we were told.
#[uretprobe]
pub fn ssl_read_ex_return(ctx: RetProbeContext) -> u32 {
    let _ = on_read_return(&ctx, |pending| {
        if ctx.ret::<i32>() != 1 {
            return None;
        }
        // SAFETY: the pointer came from the application's own call and is read with the user-memory helper,
        // which faults safely rather than trapping if it is not readable.
        let written: u64 = unsafe { bpf_probe_read_user(pending.written as *const u64) }.ok()?;
        Some(written.min(i64::MAX as u64) as i64)
    });
    0
}

fn on_read_return<F>(ctx: &RetProbeContext, length: F) -> Result<(), i32>
where
    F: FnOnce(&PendingRead) -> Option<i64>,
{
    let thread = bpf_get_current_pid_tgid();
    // SAFETY: the value is a `PendingRead` written by the matching entry probe on this same thread. The
    // reference does not outlive the lookup, and nothing else writes this key.
    let pending = unsafe { PENDING_READS.get(&thread) }.copied();
    let _ = PENDING_READS.remove(&thread);
    // A read already in progress when the probe attached has no stashed pointer, and is skipped rather than
    // guessed at.
    let pending = pending.ok_or(0_i32)?;
    let length = length(&pending).ok_or(0_i32)?;
    capture(
        ctx,
        pending.ssl,
        pending.buffer as *const u8,
        length,
        DIRECTION_IN,
    )
}

/// Copies a buffer out of the application and sends it up.
fn capture<C: EbpfContext>(
    ctx: &C,
    ssl: u64,
    buffer: *const u8,
    length: i64,
    direction: u8,
) -> Result<(), i32> {
    // A write returns the count; a read returns zero on a clean close and negative on a retry or an error.
    // Neither is a buffer, and a negative length cast to a size is how a probe reads the whole heap.
    if length <= 0 {
        return Ok(());
    }

    let chunk = SCRATCH.get_ptr_mut(0).ok_or(0_i32)?;
    // SAFETY: a per-CPU map value, so this CPU is the only thing that can be writing it, and a BPF program
    // is not preempted by another BPF program on the same CPU.
    let chunk = unsafe { &mut *chunk };

    let thread = bpf_get_current_pid_tgid();
    chunk.ssl = ssl;
    chunk.tgid = (thread >> 32) as u32;
    chunk.pid = thread as u32;
    chunk.comm = bpf_get_current_comm()?;
    chunk.total = length.min(u32::MAX as i64) as u32;
    chunk.direction = direction;
    chunk.padding = [0; 3];

    // The branch rather than a `min`, because what the verifier needs is a proof that the length is bounded,
    // and a branch is a proof it can follow.
    let captured = if length > TLS_CHUNK_BYTES as i64 {
        TLS_CHUNK_BYTES
    } else {
        length as usize
    };
    chunk.len = captured as u32;
    let destination = chunk.data.get_mut(..captured).ok_or(0_i32)?;
    // SAFETY: `buffer` points into the probed process's address space, which is the address space this
    // program is running in the context of. `bpf_probe_read_user` faults safely rather than trapping if it
    // is not readable, and the error is returned.
    unsafe { bpf_probe_read_user_buf(buffer, destination) }?;

    TLS_EVENTS.output(ctx, chunk, 0);
    Ok(())
}
