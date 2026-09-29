//! Keeping the kernel's idea of which process belongs to which agent up to date.
//!
//! A rule scoped to an agent has to be enforced at `connect()`, which means the kernel has to know, at that
//! instant, whether the calling process is working for one. Userspace cannot tell it in time: an agent
//! spawns a process and that process connects milliseconds later, and by the time anything in userspace has
//! noticed the fork, the connection it was meant to decide about has been made.
//!
//! So the propagation happens in the kernel. Userspace marks the agents themselves — it has all the time in
//! the world to notice a long-lived process — and a fork copies the mark to the child. Everything an agent
//! starts is therefore marked before it can run, which is the only ordering that works.
//!
//! The alternative would be walking the process tree from the `connect()` hook, which needs
//! `task_struct` offsets, which needs BTF, which this project deliberately does not require.

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, LruHashMap},
    programs::TracePointContext,
};
use flowlight_common::connection::TaskLayout;

/// Which agent each process is working for, as an identifier userspace assigns.
///
/// Least-recently-used rather than a plain hash: a machine forks constantly, and a map that filled up would
/// stop marking new children — silently, and exactly when the machine is busiest. Eviction under pressure
/// loses the oldest mark, which is the least likely to matter.
#[map]
pub static PID_AGENT: LruHashMap<u32, u32> = LruHashMap::with_max_entries(20480, 0);

/// Where the scheduler's tracepoints keep their fields on this kernel.
#[map]
static TASK_LAYOUT: Array<TaskLayout> = Array::with_max_entries(1, 0);

/// How many forks were seen, and how many of them carried a mark.
///
/// Two numbers, read by the daemon and shown in Coverage. They answer a question nothing else can: whether
/// an agent-scoped rule failed to bite because the agent was not recognised, or because the propagation
/// that is supposed to reach its children never ran. Without them the two look identical from outside.
#[map]
pub static FORK_COUNTS: Array<u64> = Array::with_max_entries(4, 0);

/// Index of the count of forks seen.
pub const FORKS_SEEN: u32 = 0;
/// Index of the count of marks copied to a child.
pub const MARKS_COPIED: u32 = 1;
/// Index of the count of forks where the layout had been written.
pub const LAYOUT_READY: u32 = 2;
/// Index of the last parent identifier read out of a fork record.
///
/// Not a count. A number that should look like a process identifier, so that "the reads are wrong" and
/// "the lookup missed" can be told apart without another round trip.
pub const LAST_PARENT: u32 = 3;

/// Adds one to a counter, as far as the verifier is concerned safely.
fn bump(index: u32) {
    if let Some(slot) = FORK_COUNTS.get_ptr_mut(index) {
        // SAFETY: a plain array value this program alone writes. Not atomic, and does not need to be: it
        // is a diagnostic, and losing one increment to a race on another CPU changes nothing it is for.
        unsafe { *slot += 1 };
    }
}

/// Records a value rather than counting one.
fn record(index: u32, value: u64) {
    if let Some(slot) = FORK_COUNTS.get_ptr_mut(index) {
        // SAFETY: as above.
        unsafe { *slot = value };
    }
}

/// A process forked. The child inherits whatever the parent was working for.
///
/// The category and name are given to the macro, not just to the attach call, because without them every
/// tracepoint program in the object is emitted into one ELF section called `tracepoint` — and three
/// functions in one section is one program with three names. That failed exactly as quietly as it sounds:
/// the programs loaded, attached, and ran somebody else's code.
#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn sched_fork(ctx: TracePointContext) -> u32 {
    let _ = on_fork(&ctx);
    0
}

fn on_fork(ctx: &TracePointContext) -> Result<(), i64> {
    bump(FORKS_SEEN);
    let layout = TASK_LAYOUT.get(0).ok_or(0_i64)?;
    bump(LAYOUT_READY);
    // SAFETY for both: the offsets come from the kernel's own description of this tracepoint, and the
    // daemon refused to load this program if either field was missing or an unexpected width.
    let parent: u32 = unsafe { ctx.read_at(layout.fork_parent as usize) }?;
    let child: u32 = unsafe { ctx.read_at(layout.fork_child as usize) }?;
    record(LAST_PARENT, u64::from(parent));
    // SAFETY: the value is a `u32` and the reference does not outlive the lookup.
    let agent = unsafe { PID_AGENT.get(&parent) }.copied().ok_or(0_i64)?;
    // A full map means this child goes unmarked, which means an agent-scoped rule does not reach it. That
    // is a hole, and 0.2.x's Coverage is where holes are reported rather than papered over.
    let _ = PID_AGENT.insert(&child, &agent, 0);
    bump(MARKS_COPIED);
    Ok(())
}

/// A process exited. Its mark goes with it, because process identifiers are reused and a stale mark is a
/// rule applied to a stranger.
#[tracepoint(category = "sched", name = "sched_process_exit")]
pub fn sched_exit(ctx: TracePointContext) -> u32 {
    let _ = on_exit(&ctx);
    0
}

fn on_exit(ctx: &TracePointContext) -> Result<(), i64> {
    let layout = TASK_LAYOUT.get(0).ok_or(0_i64)?;
    // SAFETY: as above.
    let pid: u32 = unsafe { ctx.read_at(layout.exit_pid as usize) }?;
    let _ = PID_AGENT.remove(&pid);
    Ok(())
}
