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

/// A process forked. The child inherits whatever the parent was working for.
#[tracepoint]
pub fn sched_fork(ctx: TracePointContext) -> u32 {
    let _ = on_fork(&ctx);
    0
}

fn on_fork(ctx: &TracePointContext) -> Result<(), i64> {
    let layout = TASK_LAYOUT.get(0).ok_or(0_i64)?;
    // SAFETY for both: the offsets come from the kernel's own description of this tracepoint, and the
    // daemon refused to load this program if either field was missing or an unexpected width.
    let parent: u32 = unsafe { ctx.read_at(layout.fork_parent as usize) }?;
    let child: u32 = unsafe { ctx.read_at(layout.fork_child as usize) }?;
    // SAFETY: the value is a `u32` and the reference does not outlive the lookup.
    let agent = unsafe { PID_AGENT.get(&parent) }.copied().ok_or(0_i64)?;
    // A full map means this child goes unmarked, which means an agent-scoped rule does not reach it. That
    // is a hole, and 0.2.x's Coverage is where holes are reported rather than papered over.
    let _ = PID_AGENT.insert(&child, &agent, 0);
    Ok(())
}

/// A process exited. Its mark goes with it, because process identifiers are reused and a stale mark is a
/// rule applied to a stranger.
#[tracepoint]
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
