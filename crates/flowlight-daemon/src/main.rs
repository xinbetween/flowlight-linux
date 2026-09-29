//! `flowlightd` — which process opened which connection.
//!
//! The first thing this project does that needs a kernel. It loads one tracepoint program, tells it where the
//! fields are on *this* kernel, and prints every outbound TCP connection with the name of the process that
//! asked for it.
//!
//! What it does not do yet is as important: no storage, no payloads, no blocking. Those are 0.1.2 onwards,
//! and each arrives on its own so that when something breaks there is one candidate.
//!
//! Needs root, or `CAP_BPF` and `CAP_PERFMON`. There is no version of loading a probe that does not.

mod record;
mod tracefs;

use anyhow::{Context as _, anyhow, bail};
use aya::maps::{
    Array, PerfEventArray,
    perf::{PerfEvent, PerfEventArrayBuffer},
};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{Ebpf, maps::MapData};
use clap::Parser;
use flowlight_common::connection::{ConnectionEvent, Layout};
use flowlight_common::tracepoint::Format;
use record::Record;
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

/// The tracepoint everything here hangs off.
const CATEGORY: &str = "sock";
/// ditto.
const TRACEPOINT: &str = "inet_sock_set_state";

#[derive(Parser)]
#[command(
    version,
    about = "Which process opened which connection, from the kernel.",
    long_about = "Watches every outbound TCP connection on the machine and names the process that opened \
                  it. Needs root: loading an eBPF program does.\n\nThis is Flowlight 0.1.x — seeing only. \
                  Nothing is stored, no payloads are read, and nothing is blocked."
)]
struct Args {
    /// One JSON object per line, for anything that is not a person.
    #[arg(long)]
    json: bool,

    /// Stop after this many connections.
    #[arg(long, value_name = "N")]
    count: Option<u64>,

    /// Stop after this many seconds.
    #[arg(long, value_name = "SECONDS")]
    seconds: Option<u64>,

    /// Where tracefs is mounted, if it is somewhere unusual.
    #[arg(long, value_name = "PATH")]
    tracefs: Option<PathBuf>,
}

/// What a reader thread sends back.
enum Message {
    /// A connection.
    Event(Box<ConnectionEvent>),
    /// The kernel had connections to report and nowhere to put them.
    ///
    /// Carried rather than swallowed. A tool whose entire claim is "this is what your machine did" has to be
    /// able to say when that claim has a hole in it, and this is the first hole 0.1.5 will have to account
    /// for.
    Lost(u64),
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let format_text = tracefs::format_text(args.tracefs.as_deref(), CATEGORY, TRACEPOINT)?;
    let layout = Layout::from_format(&Format::new(&format_text))?;

    raise_memlock_limit();

    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/flowlight-ebpf"
    )))
    .map_err(explain_load_failure)?;

    // Before the attach, deliberately. The program does nothing until this map is populated, so populating it
    // first means there is no window in which it is attached and guessing.
    let mut layouts: Array<_, Layout> = Array::try_from(
        ebpf.map_mut("LAYOUT")
            .ok_or_else(|| anyhow!("the compiled program has no LAYOUT map"))?,
    )?;
    layouts
        .set(0, layout, 0)
        .context("telling the program where this kernel's tracepoint fields are")?;

    let program: &mut TracePoint = ebpf
        .program_mut(TRACEPOINT)
        .ok_or_else(|| anyhow!("the compiled program has no {TRACEPOINT} function"))?
        .try_into()?;
    program.load().map_err(explain_load_failure)?;
    program
        .attach(CATEGORY, TRACEPOINT)
        .with_context(|| format!("attaching to {CATEGORY}/{TRACEPOINT}"))?;

    let events = ebpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow!("the compiled program has no EVENTS map"))?;
    let mut perf: PerfEventArray<MapData> = PerfEventArray::try_from(events)?;

    let (sender, receiver) = channel();
    let cpus = online_cpus().map_err(|(path, err)| anyhow!("reading {path}: {err}"))?;
    for cpu in cpus {
        let buffer = perf
            .open(cpu, None)
            .with_context(|| format!("opening the perf buffer for CPU {cpu}"))?;
        let sender = sender.clone();
        std::thread::Builder::new()
            .name(format!("flowlight-cpu{cpu}"))
            .spawn(move || read_events(buffer, &sender))
            .with_context(|| format!("starting the reader for CPU {cpu}"))?;
    }
    // Every remaining sender lives in a reader thread. Dropping ours means the channel closes if they all
    // die, rather than leaving the main loop waiting on a thread that is not coming back.
    drop(sender);

    eprintln!(
        "flowlightd {}: watching {CATEGORY}/{TRACEPOINT}. Outbound TCP only; \
         inbound connections are not attributed. Nothing is stored.",
        env!("CARGO_PKG_VERSION")
    );

    report(&receiver, &args)
}

/// Prints what the readers send until the limits the caller set are reached.
fn report(receiver: &Receiver<Message>, args: &Args) -> anyhow::Result<()> {
    let deadline = args
        .seconds
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    let mut stdout = std::io::stdout().lock();
    let mut seen = 0_u64;
    let mut lost = 0_u64;

    loop {
        let timeout = match deadline {
            Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                Some(remaining) => remaining,
                None => break,
            },
            None => Duration::from_secs(3600),
        };

        match receiver.recv_timeout(timeout) {
            Ok(Message::Lost(count)) => lost += count,
            Ok(Message::Event(event)) => {
                let exe = std::fs::read_link(format!("/proc/{}/exe", event.tgid)).ok();
                let record = Record::describe(&event, exe.as_deref().and_then(|p| p.to_str()));
                if args.json {
                    serde_json::to_writer(&mut stdout, &record)?;
                    stdout.write_all(b"\n")?;
                } else {
                    writeln!(stdout, "{}", record.human())?;
                }
                stdout.flush()?;
                seen += 1;
                if args.count.is_some_and(|limit| seen >= limit) {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if deadline.is_some() {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                bail!("every reader thread stopped; nothing is watching the kernel any more")
            }
        }
    }

    if lost > 0 {
        eprintln!(
            "{lost} connection(s) were dropped by the kernel before Flowlight read them. \
             The machine was opening connections faster than this buffer could be drained."
        );
    }
    Ok(())
}

/// Drains one CPU's perf buffer for as long as anyone is listening.
fn read_events(mut buffer: PerfEventArrayBuffer<MapData>, sender: &Sender<Message>) {
    let mut scratch = [0_u8; size_of::<ConnectionEvent>()];
    loop {
        if !wait_until_readable(&buffer) {
            return;
        }
        // `for_each` cannot stop early, so a closed channel is noticed rather than returned through.
        let mut listening = true;
        buffer.for_each(|event| {
            if !listening {
                return;
            }
            let message = match event {
                PerfEvent::Lost { count } => Some(Message::Lost(count)),
                PerfEvent::Sample { head, tail } => {
                    decode(head, tail, &mut scratch).map(|event| Message::Event(Box::new(event)))
                }
            };
            if let Some(message) = message
                && sender.send(message).is_err()
            {
                listening = false;
            }
        });
        if !listening {
            return;
        }
    }
}

/// Reassembles one event out of the ring buffer's bytes.
///
/// A sample that reaches the end of the ring is handed over in two pieces, and the second piece is where the
/// sixty-four bytes of an event can end up split down the middle. It happens once per ring's worth of
/// traffic, which is rarely enough that a version of this that only handled the contiguous case would look
/// correct for a long time.
fn decode(
    head: &[u8],
    tail: &[u8],
    scratch: &mut [u8; size_of::<ConnectionEvent>()],
) -> Option<ConnectionEvent> {
    let size = size_of::<ConnectionEvent>();
    let bytes = if head.len() >= size {
        head
    } else {
        // The split case. Anything shorter than an event even after rejoining is not one, and is dropped
        // rather than read past — this process runs as root.
        let (front, back) = scratch.split_at_mut_checked(head.len())?;
        front.copy_from_slice(head);
        back.copy_from_slice(tail.get(..size - head.len())?);
        scratch.as_slice()
    };
    // SAFETY: the eBPF program wrote exactly one `ConnectionEvent`, and `bytes` is at least that long.
    // `read_unaligned` because the ring buffer makes no alignment promise about where a record starts.
    Some(unsafe { bytes.as_ptr().cast::<ConnectionEvent>().read_unaligned() })
}

/// Blocks until the buffer has something in it. Returns false if it will never have anything again.
///
/// Without this the reader spins: `read_events` returns immediately with nothing, forever, and a tool for
/// watching an idle machine burns a core doing it.
fn wait_until_readable(buffer: &PerfEventArrayBuffer<MapData>) -> bool {
    let mut poll = libc::pollfd {
        fd: buffer.as_fd().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // A timeout rather than an indefinite wait, so that a reader notices a closed channel on an idle machine
    // instead of sitting in the kernel until something happens to connect somewhere.
    // SAFETY: one initialised `pollfd`, and the count matches.
    let result = unsafe { libc::poll(&mut poll, 1, 250) };
    result >= 0
}

/// Raises the locked-memory limit, which is what map allocation is charged against before Linux 5.11.
///
/// On 5.11 and later maps are charged to the cgroup's memory instead and this does nothing. On 4.18 through
/// 5.10 its absence is a load failure with a message about memory that has nothing to do with the problem,
/// which is the sort of thing that costs somebody an afternoon.
fn raise_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: a correctly initialised `rlimit` for the resource named. Failure is not an error here — it
    // means we are on a kernel that does not need it, or lack the privilege, and both show up later as a
    // better message than this one could give.
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit);
    }
}

/// Turns the kernel's refusal into the sentence that explains it.
///
/// `EPERM` from a BPF syscall means one of three quite different things and the raw error names none of them.
fn explain_load_failure<E: std::error::Error + Send + Sync + 'static>(err: E) -> anyhow::Error {
    let text = err.to_string();
    let hint = if text.contains("Operation not permitted") || text.contains("os error 1") {
        if unsafe { libc::geteuid() } != 0 {
            "Flowlight needs root to load an eBPF program. Try again with sudo."
        } else {
            "Running as root and still refused. Either the kernel was built without BPF, or policy on this \
             machine forbids loading programs — check /proc/sys/kernel/unprivileged_bpf_disabled and any \
             lockdown or LSM policy. This is not something to retry."
        }
    } else {
        "The kernel refused the program. `dmesg` usually carries the verifier's reason."
    };
    anyhow!(err).context(hint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowlight_common::connection::{AF_INET, ipv4_bytes};

    fn sample() -> ConnectionEvent {
        ConnectionEvent {
            tgid: 4711,
            pid: 4711,
            family: AF_INET,
            daddr: ipv4_bytes([93, 184, 216, 34]),
            dport: 443,
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
            ..ConnectionEvent::zeroed()
        }
    }

    fn bytes_of(event: &ConnectionEvent) -> &[u8] {
        // SAFETY: `ConnectionEvent` is `repr(C)` and contains only integers, so every byte of it is
        // initialised and readable. This is what the kernel hands us, read back the same way.
        unsafe {
            std::slice::from_raw_parts(
                std::ptr::from_ref(event).cast::<u8>(),
                size_of::<ConnectionEvent>(),
            )
        }
    }

    #[test]
    fn a_contiguous_sample_is_read_directly() {
        let event = sample();
        let mut scratch = [0; size_of::<ConnectionEvent>()];
        assert_eq!(decode(bytes_of(&event), &[], &mut scratch), Some(event));
    }

    /// The case that happens once per ring's worth of traffic and would otherwise be found in production.
    #[test]
    fn a_sample_split_across_the_ring_boundary_is_rejoined() {
        let event = sample();
        let raw = bytes_of(&event);
        for split in [1, 17, 30, 63] {
            let (head, tail) = raw.split_at(split);
            let mut scratch = [0; size_of::<ConnectionEvent>()];
            assert_eq!(
                decode(head, tail, &mut scratch),
                Some(event),
                "split at {split}"
            );
        }
    }

    /// The kernel may pad a sample. Extra bytes after the event are not part of it and change nothing.
    #[test]
    fn trailing_padding_is_ignored() {
        let event = sample();
        let mut padded = bytes_of(&event).to_vec();
        padded.extend_from_slice(&[0; 8]);
        let mut scratch = [0; size_of::<ConnectionEvent>()];
        assert_eq!(decode(&padded, &[], &mut scratch), Some(event));
    }

    #[test]
    fn a_sample_too_short_to_be_an_event_is_dropped() {
        let event = sample();
        let short = bytes_of(&event).get(..20).unwrap();
        let mut scratch = [0; size_of::<ConnectionEvent>()];
        assert_eq!(decode(short, &[], &mut scratch), None);
    }
}
