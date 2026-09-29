//! `flowlightd` — what every process on this machine is doing on the network, and what it is saying.
//!
//! Two independent probes. A tracepoint on the socket path answers *which process opened which connection*.
//! uprobes on the TLS library answer *what was actually sent*, by reading the buffer on its way into OpenSSL,
//! before encryption — which is why there is no certificate to install, no trust store to modify, and nothing
//! for certificate pinning to reject.
//!
//! What it does not do yet is as important: no storage, no blocking, nothing modified. Those are later, and
//! each arrives on its own so that when something breaks there is one candidate.
//!
//! Needs root, or `CAP_BPF` and `CAP_PERFMON`. There is no version of loading a probe that does not.

mod history;
mod http2;
mod libraries;
mod payload;
mod record;
mod tracefs;

use anyhow::{Context as _, anyhow, bail};
use aya::Ebpf;
use aya::maps::perf::{PerfEvent, PerfEventArrayBuffer};
use aya::maps::{Array, MapData, PerfEventArray};
use aya::programs::uprobe::UProbeScope;
use aya::programs::{TracePoint, UProbe};
use aya::util::online_cpus;
use clap::{Parser, Subcommand};
use flowlight_common::connection::{ConnectionEvent, Layout};
use flowlight_common::procmaps::TlsLibrary;
use flowlight_common::tls::TlsChunk;
use flowlight_common::tracepoint::Format;
use flowlight_store::{Retention, Store};
use payload::Payloads;
use record::Record;
use std::collections::BTreeSet;
use std::io::Write as _;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The tracepoint attribution hangs off.
const CATEGORY: &str = "sock";
/// ditto.
const TRACEPOINT: &str = "inet_sock_set_state";

/// How often to look for TLS libraries that have appeared since the last look.
///
/// An agent started after the daemon is the normal case, not the exception, so a one-shot scan at startup
/// would miss the thing anybody actually ran this to watch.
const RESCAN: Duration = Duration::from_secs(5);

/// Where the database lives, unless told otherwise. Under `/var/lib` rather than a home directory because
/// this daemon runs as root and watches the whole machine, so it is not any one user's data.
const DEFAULT_DATABASE: &str = "/var/lib/flowlight/flowlight.db";

/// How often expired detail is folded into the summary and removed.
const SWEEP: Duration = Duration::from_secs(3600);

/// Pages per CPU for each perf buffer. A [`TlsChunk`] is four kilobytes, so the two-page default would hold
/// one and a bit of them and drop the rest of any burst.
const PERF_PAGES: usize = 64;

#[derive(Parser)]
#[command(
    version,
    about = "What every process on this machine is doing on the network, and what it is saying.",
    long_about = "Watches outbound TCP connections and reads HTTPS payloads as the application hands them \
                  to OpenSSL — before encryption, so no certificate is installed anywhere and certificate \
                  pinning is not involved. Needs root: loading an eBPF program does.\n\nThis is Flowlight \
                  0.1.x — seeing only. Nothing is stored, and nothing is blocked or modified."
)]
struct Args {
    /// One JSON object per line, for anything that is not a person.
    #[arg(long)]
    json: bool,

    /// Include buffers that do not begin a request or a response — the middles of bodies, mostly.
    #[arg(long)]
    all: bool,

    /// Do not read payloads. Connections only.
    #[arg(long)]
    no_payloads: bool,

    /// An extra TLS library to probe, for one the search did not find. May be repeated.
    #[arg(long, value_name = "PATH")]
    libssl: Vec<PathBuf>,

    /// Stop after this many records.
    #[arg(long, value_name = "N")]
    count: Option<u64>,

    /// Stop after this many seconds.
    #[arg(long, value_name = "SECONDS")]
    seconds: Option<u64>,

    /// Where tracefs is mounted, if it is somewhere unusual.
    #[arg(long, value_name = "PATH")]
    tracefs: Option<PathBuf>,

    /// Where to keep what is seen.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_DATABASE)]
    database: PathBuf,

    /// Keep nothing. Watch the terminal and let it scroll.
    #[arg(long)]
    no_store: bool,

    /// Days to keep individual requests.
    #[arg(long, value_name = "DAYS", default_value_t = flowlight_store::DEFAULT_RETENTION_DAYS)]
    retention_days: u32,

    /// Days to keep the daily summary that expired requests are folded into.
    #[arg(long, value_name = "DAYS", default_value_t = flowlight_store::DEFAULT_SUMMARY_DAYS)]
    summary_days: u32,

    /// Ask the database a question instead of watching.
    #[command(subcommand)]
    command: Option<Command>,
}

/// What to do instead of watching.
#[derive(Subcommand)]
enum Command {
    /// What was requested recently.
    History {
        /// How far back to look: `30m`, `6h`, `2d`, or a number of seconds.
        #[arg(long, value_name = "WINDOW", default_value = "1h")]
        since: String,
        /// At most this many.
        #[arg(long, default_value_t = 200)]
        limit: usize,
    },
    /// The daily summary that expired detail was folded into.
    Summary {
        /// At most this many rows.
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

impl Args {
    /// How long things are kept, as the store wants it.
    fn retention(&self) -> Retention {
        Retention {
            detail_days: self.retention_days,
            summary_days: self.summary_days,
        }
    }
}

/// Now, in seconds since the epoch.
///
/// Returns zero if the clock is before 1970, which is not a case worth an error path: every comparison this
/// feeds is against another timestamp from the same clock.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
}

/// What a reader thread sends back.
enum Message {
    /// A process opened a connection.
    Connection(Box<ConnectionEvent>),
    /// A process wrote or read plaintext.
    Payload(Box<TlsChunk>),
    /// The kernel had something to report and nowhere to put it.
    ///
    /// Carried rather than swallowed. A tool whose entire claim is "this is what your machine did" has to be
    /// able to say when that claim has a hole in it, and this is the first hole 0.1.5 will account for.
    Lost(u64),
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if let Some(command) = &args.command {
        return history::run(command, &args.database, args.json);
    }

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

    let tracepoint: &mut TracePoint = ebpf
        .program_mut(TRACEPOINT)
        .ok_or_else(|| anyhow!("the compiled program has no {TRACEPOINT} function"))?
        .try_into()?;
    tracepoint.load().map_err(explain_load_failure)?;
    tracepoint
        .attach(CATEGORY, TRACEPOINT)
        .with_context(|| format!("attaching to {CATEGORY}/{TRACEPOINT}"))?;

    if !args.no_payloads {
        for program in PROGRAMS {
            let probe: &mut UProbe = ebpf
                .program_mut(program)
                .ok_or_else(|| anyhow!("the compiled program has no {program} function"))?
                .try_into()?;
            probe.load().map_err(explain_load_failure)?;
        }
    }

    let (sender, receiver) = channel();
    spawn_readers(&mut ebpf, "EVENTS", Kind::Connection, &sender)?;
    if !args.no_payloads {
        spawn_readers(&mut ebpf, "TLS_EVENTS", Kind::Payload, &sender)?;
    }
    // Every remaining sender lives in a reader thread. Dropping ours means the channel closes if they all
    // die, rather than leaving the main loop waiting on threads that are not coming back.
    drop(sender);

    let mut store = if args.no_store {
        None
    } else {
        Some(Store::open(&args.database).with_context(|| {
            format!(
                "opening the database at {}. Use --database to put it elsewhere, or --no-store to keep \
                 nothing.",
                args.database.display()
            )
        })?)
    };

    eprintln!(
        "flowlightd {}: watching {CATEGORY}/{TRACEPOINT}. Outbound TCP only; inbound connections are not \
         attributed.",
        env!("CARGO_PKG_VERSION")
    );
    match &store {
        // Said every time rather than written in a manual. A tool that reads every HTTPS request on a
        // machine and quietly accumulates them is a liability however good its intentions.
        Some(_) => eprintln!(
            "storing to {}, {}",
            args.database.display(),
            args.retention().describe()
        ),
        None => eprintln!("storing nothing"),
    }

    run(&mut ebpf, &receiver, &args, store.as_mut())
}

/// Which map a reader thread is draining, and therefore what its records are.
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// `EVENTS`, carrying [`ConnectionEvent`].
    Connection,
    /// `TLS_EVENTS`, carrying [`TlsChunk`].
    Payload,
}

/// Opens one perf buffer per CPU and starts a thread draining each.
fn spawn_readers(
    ebpf: &mut Ebpf,
    map: &str,
    kind: Kind,
    sender: &Sender<Message>,
) -> anyhow::Result<()> {
    let events = ebpf
        .take_map(map)
        .ok_or_else(|| anyhow!("the compiled program has no {map} map"))?;
    let mut perf: PerfEventArray<MapData> = PerfEventArray::try_from(events)?;
    for cpu in online_cpus().map_err(|(path, err)| anyhow!("reading {path}: {err}"))? {
        let buffer = perf
            .open(cpu, Some(PERF_PAGES))
            .with_context(|| format!("opening the {map} buffer for CPU {cpu}"))?;
        let sender = sender.clone();
        std::thread::Builder::new()
            .name(format!("flowlight-{map}-{cpu}"))
            .spawn(move || read_events(buffer, kind, &sender))
            .with_context(|| format!("starting the {map} reader for CPU {cpu}"))?;
    }
    Ok(())
}

/// Prints what the readers send, and keeps looking for TLS libraries, until the caller's limits are reached.
fn run(
    ebpf: &mut Ebpf,
    receiver: &Receiver<Message>,
    args: &Args,
    mut store: Option<&mut Store>,
) -> anyhow::Result<()> {
    let deadline = args
        .seconds
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    let mut stdout = std::io::stdout().lock();
    let mut payloads = Payloads::new();
    let mut probed = BTreeSet::new();
    let mut next_scan = Instant::now();
    let mut next_sweep = Instant::now();
    let mut seen = 0_u64;
    let mut lost = 0_u64;

    loop {
        if !args.no_payloads && Instant::now() >= next_scan {
            attach_new_libraries(ebpf, &mut probed, &args.libssl);
            next_scan = Instant::now() + RESCAN;
        }

        if let Some(store) = store.as_deref_mut()
            && Instant::now() >= next_sweep
        {
            match store.sweep(now(), args.retention()) {
                Ok(swept) if swept.requests_rolled > 0 || swept.connections_removed > 0 => {
                    eprintln!(
                        "folded {} expired request(s) into the daily summary and removed {} \
                         connection(s) past their retention",
                        swept.requests_rolled, swept.connections_removed
                    );
                }
                Ok(_) => {}
                Err(err) => eprintln!("could not sweep expired records: {err:#}"),
            }
            next_sweep = Instant::now() + SWEEP;
        }

        let until = match deadline {
            Some(deadline) if deadline <= Instant::now() => break,
            Some(deadline) => deadline.min(next_scan).min(next_sweep),
            None => next_scan.min(next_sweep),
        };
        let timeout = until.saturating_duration_since(Instant::now());

        match receiver.recv_timeout(timeout) {
            Ok(Message::Lost(count)) => {
                lost += count;
                continue;
            }
            Ok(Message::Connection(event)) => {
                let exe = executable_of(event.tgid);
                let record = Record::describe(&event, exe.as_deref());
                if let Some(store) = store.as_deref_mut() {
                    keep(store.record_connection(record.stored(now())));
                }
                render(&mut stdout, args.json, &record, &record.human())?;
            }
            Ok(Message::Payload(chunk)) => {
                let exe = executable_of(chunk.tgid);
                let records = payloads.observe(&chunk, exe.as_deref());
                if records.is_empty() {
                    if !args.all {
                        continue;
                    }
                    let plain = Payloads::plain(&chunk, exe.as_deref());
                    render(&mut stdout, args.json, &plain, &plain.human())?;
                } else {
                    for record in &records {
                        if let Some(store) = store.as_deref_mut() {
                            keep(store.record_request(record.stored(now())));
                        }
                        render(&mut stdout, args.json, record, &record.human())?;
                    }
                    // One buffer can complete more than one request, and each is a record.
                    seen += records.len() as u64 - 1;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                bail!("every reader thread stopped; nothing is watching the kernel any more")
            }
        }

        seen += 1;
        if args.count.is_some_and(|limit| seen >= limit) {
            break;
        }
    }

    if let Some(store) = store {
        store.flush().context("writing the last of what was seen")?;
    }

    if lost > 0 {
        eprintln!(
            "{lost} record(s) were dropped by the kernel before Flowlight read them. The machine was \
             producing them faster than these buffers could be drained."
        );
    }
    Ok(())
}

/// Writes one record, as JSON or as a line.
fn render<T: serde::Serialize>(
    out: &mut std::io::StdoutLock<'_>,
    json: bool,
    record: &T,
    human: &str,
) -> anyhow::Result<()> {
    if json {
        serde_json::to_writer(&mut *out, record)?;
    } else {
        out.write_all(human.as_bytes())?;
    }
    out.write_all(b"\n")?;
    // Flushed per record: this is a live view, and a line that arrives when the buffer happens to fill is
    // not a live view of anything.
    out.flush()?;
    Ok(())
}

/// Attaches probes to any TLS library that has appeared since the last look.
///
/// Failures are reported once and then forgotten about: a library whose symbols are stripped will never
/// resolve, and saying so every five seconds would be the only thing on the screen.
fn attach_new_libraries(ebpf: &mut Ebpf, probed: &mut BTreeSet<PathBuf>, extra: &[PathBuf]) {
    for (path, library) in libraries::discover(extra) {
        if !probed.insert(path.clone()) {
            continue;
        }
        match attach_probes(ebpf, library, &path) {
            Ok(symbols) => eprintln!(
                "reading {} through {} ({})",
                library.as_str(),
                path.display(),
                symbols.join(", ")
            ),
            Err(err) => eprintln!(
                "not reading {}: {err:#}. Traffic through this library will be invisible.",
                path.display()
            ),
        }
    }
}

/// Every program in the object, each of which is loaded once and then attached wherever it fits.
const PROGRAMS: &[&str] = &[
    "write_int",
    "write_size",
    "read_enter",
    "read_ex_enter",
    "read_return",
    "read_ex_return",
];

/// Which program goes on which symbol, for one library.
struct Probe {
    /// The program's name in the compiled object.
    program: &'static str,
    /// The function in the library.
    symbol: &'static str,
}

/// A probe, written shortly.
const fn probe(program: &'static str, symbol: &'static str) -> Probe {
    Probe { program, symbol }
}

/// OpenSSL. Six rather than three because 1.1.1 added `SSL_write_ex` and `SSL_read_ex` — a `size_t` count
/// and an out-parameter instead of an `int` and a return value — and modern callers use them.
const OPENSSL: &[Probe] = &[
    probe("write_int", "SSL_write"),
    probe("write_size", "SSL_write_ex"),
    probe("read_enter", "SSL_read"),
    probe("read_return", "SSL_read"),
    probe("read_ex_enter", "SSL_read_ex"),
    probe("read_ex_return", "SSL_read_ex"),
];

/// GnuTLS. `gnutls_record_send(session, data, size)` has exactly OpenSSL's shape with a `size_t` length, and
/// `gnutls_record_recv` reports its count the way `SSL_read` does.
const GNUTLS: &[Probe] = &[
    probe("write_size", "gnutls_record_send"),
    probe("read_enter", "gnutls_record_recv"),
    probe("read_return", "gnutls_record_recv"),
];

/// NSS, at its portable-runtime layer.
///
/// `libnss3` is where the TLS is, but the plaintext crosses the boundary one layer below it, in NSPR. The
/// consequence is that these also see Firefox's *non*-TLS socket writes — plain HTTP, mostly — which is more
/// than was asked for rather than less, and is stated in the README rather than left to be discovered.
const NSS: &[Probe] = &[
    probe("write_int", "PR_Write"),
    probe("write_int", "PR_Send"),
    probe("read_enter", "PR_Read"),
    probe("read_return", "PR_Read"),
    probe("read_enter", "PR_Recv"),
    probe("read_return", "PR_Recv"),
];

/// The probes a library needs.
const fn probes_for(library: TlsLibrary) -> &'static [Probe] {
    match library {
        TlsLibrary::OpenSsl => OPENSSL,
        TlsLibrary::GnuTls => GNUTLS,
        TlsLibrary::Nss => NSS,
    }
}

/// Attaches what this particular library has.
///
/// Best effort by design: OpenSSL 1.1.0 has no `_ex` functions, a stripped build may export neither, and a
/// missing symbol is a fact about that file rather than a reason to stop. What is *not* best effort is the
/// verdict — a library where nothing attached is reported as unprobed, because a silent failure here looks
/// exactly like an application that is not making requests.
fn attach_probes(
    ebpf: &mut Ebpf,
    library: TlsLibrary,
    path: &Path,
) -> anyhow::Result<Vec<&'static str>> {
    let mut attached: Vec<&'static str> = Vec::new();
    let mut last_error = None;
    for Probe { program, symbol } in probes_for(library) {
        let probe: &mut UProbe = ebpf
            .program_mut(program)
            .ok_or_else(|| anyhow!("no {program} program"))?
            .try_into()?;
        match probe.attach(*symbol, path, UProbeScope::AllProcesses) {
            Ok(_) => {
                if !attached.contains(symbol) {
                    attached.push(symbol);
                }
            }
            Err(err) => last_error = Some(err),
        }
    }
    if attached.is_empty() {
        let detail = last_error.map_or_else(
            || "no probe could be attached".to_owned(),
            |err| format!("{err}"),
        );
        bail!(
            "none of {}'s read or write functions could be found: {detail}",
            library.as_str()
        );
    }
    Ok(attached)
}

/// Reports a write that failed without stopping the watch.
///
/// A database that cannot be written is a real problem and not a reason to stop watching: the terminal is
/// still showing what is happening, which is most of the value, and a daemon that exits because a disk
/// filled up has turned a degraded service into no service.
fn keep(result: anyhow::Result<()>) {
    if let Err(err) = result {
        eprintln!("could not store a record: {err:#}. Still watching.");
    }
}

/// `/proc/<pid>/exe`, if the process is still there and we may read it.
fn executable_of(tgid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{tgid}/exe"))
        .ok()?
        .to_str()
        .map(str::to_owned)
}

/// Drains one CPU's perf buffer for as long as anyone is listening.
fn read_events(mut buffer: PerfEventArrayBuffer<MapData>, kind: Kind, sender: &Sender<Message>) {
    // One buffer, sized for the larger record, reused for every sample that arrives split.
    let mut scratch = vec![0_u8; size_of::<TlsChunk>()];
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
                PerfEvent::Sample { head, tail } => match kind {
                    Kind::Connection => decode::<ConnectionEvent>(head, tail, &mut scratch)
                        .map(|event| Message::Connection(Box::new(event))),
                    Kind::Payload => decode::<TlsChunk>(head, tail, &mut scratch)
                        .map(|chunk| Message::Payload(Box::new(chunk))),
                },
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

/// Reassembles one record out of the ring buffer's bytes.
///
/// A sample that reaches the end of the ring is handed over in two pieces, and the second piece is where a
/// record can end up split down the middle. It happens once per ring's worth of traffic, which is rarely
/// enough that a version of this that only handled the contiguous case would look correct for a long time.
fn decode<T: Copy>(head: &[u8], tail: &[u8], scratch: &mut [u8]) -> Option<T> {
    let size = size_of::<T>();
    let bytes = if head.len() >= size {
        head
    } else {
        // The split case. Anything shorter than a record even after rejoining is not one, and is dropped
        // rather than read past — this process runs as root.
        let (front, back) = scratch.get_mut(..size)?.split_at_mut_checked(head.len())?;
        front.copy_from_slice(head);
        back.copy_from_slice(tail.get(..size - head.len())?);
        scratch.get(..size)?
    };
    // SAFETY: the eBPF program wrote exactly one `T`, and `bytes` is at least that long. `read_unaligned`
    // because the ring buffer makes no alignment promise about where a record starts.
    Some(unsafe { bytes.as_ptr().cast::<T>().read_unaligned() })
}

/// Blocks until the buffer has something in it. Returns false if it will never have anything again.
///
/// Without this the reader spins: draining returns immediately with nothing, forever, and a tool for watching
/// an idle machine burns a core doing it.
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
fn explain_load_failure<E: std::fmt::Display>(err: E) -> anyhow::Error {
    let text = err.to_string();
    let hint = if text.contains("Operation not permitted") || text.contains("os error 1") {
        // SAFETY: `geteuid` reads this process's own credentials and cannot fail.
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
    anyhow!(text).context(hint)
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
        let mut scratch = vec![0; size_of::<TlsChunk>()];
        assert_eq!(
            decode::<ConnectionEvent>(bytes_of(&event), &[], &mut scratch),
            Some(event)
        );
    }

    /// The case that happens once per ring's worth of traffic and would otherwise be found in production.
    #[test]
    fn a_sample_split_across_the_ring_boundary_is_rejoined() {
        let event = sample();
        let raw = bytes_of(&event);
        for split in [1, 17, 30, 63] {
            let (head, tail) = raw.split_at(split);
            let mut scratch = vec![0; size_of::<TlsChunk>()];
            assert_eq!(
                decode::<ConnectionEvent>(head, tail, &mut scratch),
                Some(event),
                "split at {split}"
            );
        }
    }

    /// The kernel may pad a sample. Extra bytes after the record are not part of it and change nothing.
    #[test]
    fn trailing_padding_is_ignored() {
        let event = sample();
        let mut padded = bytes_of(&event).to_vec();
        padded.extend_from_slice(&[0; 8]);
        let mut scratch = vec![0; size_of::<TlsChunk>()];
        assert_eq!(
            decode::<ConnectionEvent>(&padded, &[], &mut scratch),
            Some(event)
        );
    }

    #[test]
    fn a_sample_too_short_to_be_a_record_is_dropped() {
        let event = sample();
        let short = bytes_of(&event).get(..20).unwrap();
        let mut scratch = vec![0; size_of::<TlsChunk>()];
        assert_eq!(decode::<ConnectionEvent>(short, &[], &mut scratch), None);
    }

    /// The scratch buffer is sized for the largest record. A caller that sized it for a smaller one should
    /// get nothing rather than a record built out of whatever fitted.
    #[test]
    fn a_scratch_buffer_too_small_for_the_record_produces_nothing() {
        let event = sample();
        let raw = bytes_of(&event);
        let (head, tail) = raw.split_at(10);
        let mut scratch = vec![0; 8];
        assert_eq!(decode::<ConnectionEvent>(head, tail, &mut scratch), None);
    }
}
