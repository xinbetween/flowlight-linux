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

mod agent;
mod alerting;
mod asking;
mod blocking;
mod checking;
mod client;
mod control;
mod exporting;
mod history;
mod http2;
mod intercepting;
mod launching;
mod libraries;
mod owning;
mod payload;
mod record;
mod spending;
mod tracefs;
mod trusting;
mod ui;
mod views;

use agent::Agents;
use anyhow::{Context as _, anyhow, bail};
use aya::Ebpf;
use aya::maps::perf::{PerfEvent, PerfEventArrayBuffer};
use aya::maps::{Array, HashMap as BpfHashMap, MapData, PerfEventArray};
use aya::programs::uprobe::UProbeScope;
use aya::programs::{CgroupAttachMode, CgroupSockAddr, TracePoint, UProbe};
use aya::util::online_cpus;
use blocking::Blocking;
use clap::{Parser, Subcommand};
use flowlight_common::block::{BlockEvent, BlockKey};
use flowlight_common::connection::{ConnectionEvent, Layout, TaskLayout};
use flowlight_common::procmaps::TlsLibrary;
use flowlight_common::tls::TlsChunk;
use flowlight_common::tracepoint::Format;
use flowlight_store::Store;
use payload::Payloads;
use record::Record;
use spending::Spending;
use std::collections::BTreeSet;
use std::io::Write as _;
use std::net::SocketAddr;
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

/// Where the certificate anything has to trust is published, unless told otherwise.
///
/// `/etc/flowlight`, which is what the unit file grants this write access to — `ConfigurationDirectory` — and
/// is readable by everybody, which a certificate has to be.
///
/// It was `/usr/local/share/flowlight`, which is the better answer on paper: a file this machine's
/// administrator put there is exactly what that directory is for. It is the wrong answer in practice, because
/// the unit sets `ProtectSystem=full` and `/usr` is therefore read-only to the service — so interception could
/// never start the way almost everybody runs this, and said so in a line of the journal nobody reads:
/// `creating /usr/local/share/flowlight: Read-only file system`. Found by installing the package on a machine
/// and starting the service, which neither the smoke test nor CI had ever done: the smoke test passes
/// `--certificates` explicitly, so the default was the one path nothing exercised.
const DEFAULT_CERTIFICATES: &str = "/etc/flowlight";

/// How often expired detail is folded into the summary and removed.
const SWEEP: Duration = Duration::from_secs(3600);

/// How often the rules are read back and the kernel's table brought into line with them.
///
/// A rule is written by a separate invocation of this binary into the database, so this is how long it
/// takes to come into force. Two seconds is short enough that `block` feels like it did something and long
/// enough that the query is free.
const RULES: Duration = Duration::from_secs(2);

/// Where cgroup v2 is mounted on anything current.
/// Where a machine mounts its cgroup hierarchy. Which *part* of it the hooks attach to is read rather than
/// assumed — see [`flowlight_platform::hierarchy`] — because a hybrid hierarchy keeps the v2 tree one
/// directory down and an attach to the top of one fails with a path in the message and no explanation.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// How often the channels that are not the network are looked at.
///
/// Five seconds. Fast enough that plugging something in and looking at the screen shows it; slow enough that a
/// directory listing every five seconds is not something anybody would notice.
const DEVICES: Duration = Duration::from_secs(5);

/// How often the closed hours and days are judged against what is usual.
///
/// A minute. The judging itself only happens when a window has closed, so this is how long after an hour ends
/// that anything is said about it.
const ALERTS: Duration = Duration::from_secs(60);

/// How often Flowlight asks who operates an address it has connected to.
///
/// A minute, and four addresses at a time. Slower than anything else here on purpose: this is the one pass
/// that tells a third party something.
const OWNERS: Duration = Duration::from_secs(60);

/// How often the machine is scanned for agents that have started.
///
/// An agent is a long-lived process, so noticing it a second late is fine. Its children are another matter,
/// and they are marked in the kernel at fork — which is the only ordering that works, because a child can
/// connect before anything in userspace has noticed it exists.
const AGENT_SCAN: Duration = Duration::from_secs(1);

/// How often a partial batch is written even though it is not full.
///
/// The interface reads the database rather than sharing memory with the watcher, so an unflushed batch is a
/// batch the screen cannot see. A second is short enough to read as live and long enough that a busy machine
/// is not one transaction per request.
const FLUSH: Duration = Duration::from_secs(1);

/// Where the web page listens when it is asked for.
///
/// Not served unless asked. The native interface talks over a socket with an owner and a mode, which the
/// kernel enforces; a page on loopback is reachable by every local user and guarded only by a token, which
/// is a secret that leaks into shell history and screenshots. The page remains because it is the only one
/// of the two that works over `ssh` on a machine with no desktop session.
const DEFAULT_WEB: &str = "127.0.0.1:7890";

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
    ///
    /// Global, so it reads the same before or after a subcommand. `flowlightd history --json` is what
    /// people type, and being told it belongs three words earlier is a small insult.
    #[arg(long, global = true)]
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
    #[arg(long, value_name = "PATH", default_value = DEFAULT_DATABASE, global = true)]
    database: PathBuf,

    /// Keep nothing. Watch the terminal and let it scroll.
    #[arg(long)]
    no_store: bool,

    /// Where the native interface connects. An owner and a mode, which the kernel enforces.
    #[arg(long, value_name = "PATH", default_value = control::DEFAULT_SOCKET)]
    socket: PathBuf,

    /// Do not open a control socket, so no interface can connect.
    #[arg(long)]
    no_socket: bool,

    /// Also serve the web page, for a machine with no desktop session.
    ///
    /// Loopback only, and refused otherwise. Off unless asked for: loopback is not a permission boundary.
    #[arg(long, value_name = "ADDRESS", num_args = 0..=1, default_missing_value = DEFAULT_WEB)]
    web: Option<SocketAddr>,

    /// Do not enforce rules. Nothing is refused, whatever the rules say.
    #[arg(long)]
    no_block: bool,

    /// Where the interception proxy listens, when interception is on.
    ///
    /// Loopback, always. It is reached only by the kernel's own redirect, so there is nothing to be gained by
    /// putting it anywhere else and a great deal to lose.
    #[arg(long, value_name = "PORT", default_value_t = flowlight_store::intercept::DEFAULT_PORT)]
    intercept_port: u16,

    /// Where the certificate anything has to trust is published.
    ///
    /// Not beside the database: that directory is root's alone, and an agent runs as a person who has to be
    /// able to read the certificate they are being asked to trust.
    #[arg(long, value_name = "PATH", default_value = DEFAULT_CERTIFICATES, global = true)]
    certificates: PathBuf,

    /// Do not intercept, whatever the configuration says.
    ///
    /// Interception is the one thing Flowlight does that changes what an application sees, so there is a flag
    /// that takes it off the table for a whole run rather than only a setting in a database.
    #[arg(long)]
    no_intercept: bool,

    /// How often a batch is sent to whatever export is configured.
    ///
    /// Ten seconds unless told otherwise. Shorter is for a test that cannot wait; much shorter would make
    /// this daemon's own traffic the loudest thing on a quiet machine.
    #[arg(long, value_name = "SECONDS", default_value_t = 10)]
    export_seconds: u64,

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
    /// Refuse connections to a host or address, before the handshake starts.
    Block(RuleArgs),
    /// Allow connections that a broader rule would refuse.
    ///
    /// An exception, not a deletion: `forget` removes a rule. Allowing is the default, so an allow rule
    /// only means something alongside something stricter.
    Allow(RuleArgs),
    /// Refuse, and record the question.
    ///
    /// A connection cannot be held open while somebody decides — the decision happens inside `connect()`,
    /// in a program that may not sleep. So this refuses and writes the question down; answering it with
    /// `allow` or `block` settles the next attempt, which every network client makes.
    Ask(RuleArgs),
    /// Every rule, with the identifiers `forget` takes.
    Rules,
    /// What Flowlight is allowed to read, and for how long.
    ///
    /// With no options, says what the budget is. With any, changes it.
    Budget {
        /// Read payloads, or stop reading them.
        #[arg(long, value_name = "yes|no")]
        payloads: Option<String>,
        /// Minutes before payload capture has to be renewed. Zero for no limit.
        #[arg(long, value_name = "MINUTES")]
        session: Option<u32>,
        /// Start the session again from now.
        #[arg(long)]
        renew: bool,
        /// Megabytes of payload one process may contribute in a day. Zero for no ceiling.
        #[arg(long, value_name = "MB")]
        daily: Option<i64>,
        /// How much of a request target to keep.
        #[arg(long, value_parser = ["full", "host-only", "none"])]
        paths: Option<String>,
        /// Days to keep individual requests.
        #[arg(long, value_name = "DAYS")]
        detail_days: Option<u32>,
        /// Days to keep the daily summary that expired requests are folded into.
        #[arg(long, value_name = "DAYS")]
        summary_days: Option<u32>,
    },
    /// Where what was seen is sent, and what was agreed to.
    ///
    /// With no options, says what the configuration is and what agreeing to it would mean. With any, changes
    /// it — and changing it takes away an agreement that was to something else.
    Export {
        /// An absolute path for a file, one JSON object per line, or an http(s) URL for an OTLP collector.
        #[arg(long, value_name = "PATH|URL")]
        to: Option<String>,
        /// The whole list of fields, comma-separated. `export` with no options prints the ones there are.
        #[arg(long, value_name = "LIST", value_delimiter = ',')]
        fields: Option<Vec<String>>,
        /// A header to send with each batch, as `Name=value`. May be repeated. An empty value removes one.
        ///
        /// The names are disclosed and the values never are, so a token here does not end up in a
        /// disclosure, a screenshot or this tool's own output.
        #[arg(long = "header", value_name = "NAME=VALUE")]
        headers: Vec<String>,
        /// Agree to the configuration as it stands, which is what lets anything be sent.
        #[arg(long)]
        consent: bool,
        /// Stop sending, keeping the destination and the agreement.
        #[arg(long)]
        off: bool,
    },
    /// Start an agent so that Flowlight is already governing it before it runs.
    ///
    /// The one command here that must **not** be run as root: an agent started by root would run as root. It
    /// talks to a running daemon over the interface socket, which it owns, and needs nothing else.
    Launch {
        /// What to call the agent. Worked out from the command when it is not given.
        #[arg(long, value_name = "NAME")]
        agent: Option<String>,
        /// Print the variables an agent would be started with, and start nothing.
        ///
        /// For a launcher or a supervisor that starts the agent itself — a desktop entry, a systemd unit, a
        /// session manager. The mark cannot be arranged that way, but the environment can.
        #[arg(long)]
        print_environment: bool,
        /// The command, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Whether Flowlight terminates connections, and whose.
    ///
    /// The one thing here that changes what an application sees. Off, and off by default. With no options,
    /// says what is configured and what turning it on would mean.
    Intercept {
        /// Turn it on.
        #[arg(long)]
        on: bool,
        /// Turn it off, keeping the scope.
        #[arg(long)]
        off: bool,
        /// An agent whose connections are redirected. May be repeated; replaces the whole scope.
        #[arg(long = "agent", value_name = "NAME")]
        agents: Vec<String>,
        /// A host never terminated, whatever else says so. May be repeated; replaces the whole list.
        #[arg(long = "never", value_name = "HOST")]
        never: Vec<String>,
    },
    /// What anything has to be told in order to trust Flowlight's certificate.
    ///
    /// Says what it can do and does it; says what it cannot and gives you the exact commands. Nothing here
    /// touches a trust store without being asked.
    Trust {
        /// Install the certificate into the machine's trust store.
        #[arg(long)]
        install: bool,
        /// Take it out again.
        #[arg(long)]
        remove: bool,
    },
    /// Answer a request with something canned instead of passing it to the server.
    ///
    /// Needs interception, which `intercept` turns on. The first answer that matches a request wins.
    Mock {
        /// The host or `*.domain`, as a rule's subject is written.
        subject: String,
        /// A glob against the path. Every path by default.
        #[arg(long, default_value = "*")]
        path: String,
        /// The method. Every method by default.
        #[arg(long, default_value = "")]
        method: String,
        /// The status to answer with.
        #[arg(long, default_value_t = 503)]
        status: u16,
        /// A header, as `Name: value`. May be repeated.
        #[arg(long = "header", value_name = "NAME: VALUE")]
        headers: Vec<String>,
        /// The body.
        #[arg(long, default_value = "")]
        body: String,
        /// Seconds to wait before answering, so "the API stalls" is testable.
        #[arg(long, default_value_t = 0)]
        delay: u32,
        /// Call it a refusal rather than a stand-in for the server.
        #[arg(long)]
        refusal: bool,
        /// Why, for whoever reads the list later.
        #[arg(long)]
        note: Option<String>,
    },
    /// Refuse a tool an agent may not use.
    ///
    /// The other half of the rule model: which tools an agent may use is a different question from which
    /// hosts it may reach. Needs interception, because refusing a call means reading what the agent said.
    ///
    /// There is no allow. A guardrail is subtractive by nature — it is applied to a list the agent itself
    /// declares, and "allow" would only ever mean "do not subtract this".
    Guardrail {
        /// The tool, or a glob like `*write*`. Every tool on the named server when left out.
        #[arg(long, default_value = "")]
        tool: String,
        /// The agent this applies to. Every agent when left out.
        #[arg(long, value_name = "NAME", default_value = "")]
        agent: String,
        /// The host the MCP server is at. Every server when left out.
        #[arg(long, value_name = "HOST", default_value = "")]
        server: String,
        /// A resource URI or glob, for `resources/read`.
        #[arg(long, default_value = "")]
        resource: String,
        /// Why, for whoever reads the list later.
        #[arg(long)]
        note: Option<String>,
    },
    /// Every guardrail, with how often each has refused something.
    Guardrails,
    /// What this machine can and cannot do, and what each missing thing costs.
    ///
    /// Read-only and harmless: it loads nothing, attaches nothing and writes nothing, so it can be run by
    /// anybody before Flowlight has ever been started here. Run as a person rather than as root it says one
    /// thing less, and says that it cannot know it.
    ///
    /// Exits non-zero when something essential is missing, so that a script can ask.
    Check,
    /// Narrow every answer to one process or one host, until it is cleared.
    ///
    /// `history` and `report` then show that and nothing else, and say so above the rows: every count under a
    /// focus is a count of a subset, and a subset read as a total is the mistake worth one line of output.
    ///
    /// Coverage is deliberately not narrowed. Its job is to say what was *missed*, over everything, and a
    /// narrowed Coverage would hide the thing it exists to show.
    Focus {
        /// One process, by the name Flowlight calls it.
        #[arg(long, value_name = "NAME", conflicts_with_all = ["host", "clear"])]
        process: Option<String>,
        /// One host, as it was recorded.
        #[arg(long, value_name = "HOST", conflicts_with = "clear")]
        host: Option<String>,
        /// Show everything again.
        #[arg(long)]
        clear: bool,
    },
    /// The rules people write first, and a way to write them.
    ///
    /// Nothing is written by listing them. `--apply <name>` writes one starter's rules, one starter at a
    /// time: there is no `--all`, because a command that writes twenty-eight rules because somebody liked the
    /// idea of starter rules is a command that writes rules nobody read.
    Starters {
        /// Write this one's rules.
        #[arg(long, value_name = "NAME")]
        apply: Option<String>,
        /// Write them for one agent rather than for everything on this machine.
        #[arg(long, value_name = "AGENT")]
        agent: Option<String>,
    },
    /// Write a demonstration database: an afternoon that did not happen, to photograph.
    ///
    /// Every screenshot of Flowlight is otherwise a screenshot of whoever took it — the hosts their agent
    /// reached, the repositories it cloned, the paths it asked for.
    ///
    /// It writes to a file that does not exist yet, marks it as a demonstration for as long as it exists, and
    /// the daemon refuses to watch into one. Real traffic written into a demonstration would leave two things
    /// nobody can tell apart, and the one people would believe is the wrong one.
    Demo {
        /// Where to write it. Must not exist.
        #[arg(long, value_name = "PATH")]
        into: std::path::PathBuf,
        /// How far back the afternoon reaches.
        #[arg(long, default_value_t = 6)]
        hours: i64,
    },
    /// Which language Flowlight says things in.
    ///
    /// The sentences somebody is asked to agree to — what export sends, what a question to a model carries,
    /// what interception changes — in one of nine languages. English is the one the program is tested
    /// against; the other eight are translations, and a disclosure shown in one of them says so.
    ///
    /// A setting rather than a guess, because the daemon renders these sentences and the daemon's
    /// environment is not the reader's: it runs as root from a unit file, while the person reading is at a
    /// desktop with their own locale.
    Language {
        /// A tag: `en`, `de`, `es`, `fr`, `it`, `ja`, `ko`, `pt`, `zh-Hans`.
        #[arg(value_name = "TAG")]
        language: Option<String>,
        /// Follow the environment again instead of a fixed language.
        #[arg(long, conflicts_with = "language")]
        auto: bool,
    },
    /// What is attached by something other than the network: USB, Bluetooth, and volumes.
    ///
    /// Off until it is asked for. Not because it needs a permission Flowlight does not have, but because it
    /// widens what is watched, and that should be a decision rather than a surprise in an upgrade.
    ///
    /// Never how much went through any of it: Linux does not account for bytes per device in any way a
    /// process can be attributed, and a number nobody can stand behind is worse than no number.
    Devices {
        /// Start watching.
        #[arg(long)]
        on: bool,
        /// Stop watching. What was already seen is kept.
        #[arg(long)]
        off: bool,
        /// Everything ever seen, rather than only what is attached now.
        #[arg(long)]
        all: bool,
    },
    /// Traffic sliced one way, and the processes that do not look like the rest.
    Report {
        /// `process`, `host`, `address` or `protocol`.
        #[arg(long, default_value = "process", value_parser = ["process", "host", "address", "protocol"])]
        by: String,
        /// How far back to look: `30m`, `6h`, `2d`, or a number of seconds.
        #[arg(long, value_name = "WINDOW", default_value = "24h")]
        since: String,
        /// At most this many rows.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// What was noticed, and the numbers behind each of it.
    ///
    /// A spike against what a process usually moves, a host nothing had reached before, a port nothing usually
    /// reaches, an agent that reached an address rather than a name, a connection a rule refused.
    Alerts {
        /// How far back to look: `30m`, `6h`, `2d`, or a number of seconds.
        #[arg(long, value_name = "WINDOW", default_value = "24h")]
        since: String,
        /// At most this many.
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Only the ones about agents.
        #[arg(long)]
        agents: bool,
    },
    /// Who operates the addresses this machine has reached.
    ///
    /// Off until it is asked for: it is the one thing Flowlight does that tells a third party anything. With
    /// no options, says what asking would mean and what is already known.
    Owners {
        /// Start asking.
        #[arg(long)]
        on: bool,
        /// Stop asking. What has already been learnt is kept.
        #[arg(long)]
        off: bool,
        /// How far back to look: `30m`, `6h`, `2d`, or a number of seconds.
        #[arg(long, value_name = "WINDOW", default_value = "24h")]
        since: String,
    },
    /// Remove a guardrail.
    ForgetGuardrail {
        /// The identifier, as `guardrails` prints it.
        id: i64,
    },
    /// Every canned answer, with the identifiers `forget-mock` takes.
    Mocks,
    /// Remove a canned answer.
    ForgetMock {
        /// The identifier, as `mocks` prints it.
        id: i64,
    },
    /// Which model answers questions about this machine.
    ///
    /// Flowlight for Linux has no model of its own: there are no bundled weights, and no default pointing at
    /// somebody's API. With no options, says what is configured and what asking would mean.
    Model {
        /// `local` for a model server on this machine, `compatible` for an OpenAI-shaped endpoint,
        /// `anthropic`, or `gemini`.
        #[arg(long, value_parser = ["local", "compatible", "anthropic", "gemini"])]
        kind: Option<String>,
        /// Where the model is. A default is filled in for the kinds that have an obvious one.
        #[arg(long, value_name = "URL")]
        endpoint: Option<String>,
        /// Which model to name in the request. There is no default: the wrong guess is a 404 that reads
        /// like a broken feature.
        #[arg(long, value_name = "NAME")]
        model: Option<String>,
        /// A file holding the key, for a provider that needs one.
        ///
        /// A path rather than the key itself, because a key on a command line is a key in the shell's
        /// history and in every process listing on the machine for as long as the command runs.
        #[arg(long, value_name = "PATH")]
        key_file: Option<PathBuf>,
        /// Forget the key on file.
        #[arg(long)]
        forget_key: bool,
        /// Stop answering questions, keeping what is configured.
        #[arg(long)]
        off: bool,
    },
    /// Ask a question about what this machine has been doing.
    ///
    /// Needs a model, which `model` configures. The model never sees the database: it may name one of a
    /// fixed list of queries, which Flowlight runs and hands back totals and names.
    Query {
        /// The question, in plain English.
        question: Vec<String>,
        /// Show the exact body sent to the model, and every query it ran.
        #[arg(long)]
        show_work: bool,
    },
    /// What a rule would change, without writing it.
    ///
    /// The answer is a claim about the past: every piece of traffic in the window is decided twice, once
    /// with the rules as they are and once with this one added, and only the answers that move are
    /// reported.
    Simulate {
        /// `allow`, `ask` or `block`.
        #[arg(value_parser = ["allow", "ask", "block"])]
        action: String,
        /// What the rule would be about, as `block` takes it.
        #[command(flatten)]
        rule: RuleArgs,
        /// How far back to judge it against: `30m`, `6h`, `2d`, or a number of seconds.
        #[arg(long, value_name = "WINDOW", default_value = "24h")]
        since: String,
    },
    /// Remove a rule.
    Forget {
        /// The identifier, as `rules` prints it.
        id: i64,
    },
    /// Which agents have been running, and what each one reached against what it was configured to reach.
    Agents {
        /// How far back to look: `30m`, `6h`, `2d`, or a number of seconds.
        #[arg(long, value_name = "WINDOW", default_value = "24h")]
        since: String,
    },
    /// What was seen, and — more usefully — what was not.
    Coverage {
        /// How far back to look: `30m`, `6h`, `2d`, or a number of seconds.
        #[arg(long, value_name = "WINDOW", default_value = "24h")]
        since: String,
    },
}

/// What every rule-writing command takes.
#[derive(clap::Args)]
pub struct RuleArgs {
    /// A hostname, `*.a-domain.example`, a literal address, or `*` for anything.
    pub subject: String,
    /// Only this port. Every port by default.
    #[arg(long, default_value_t = 0)]
    pub port: u16,
    /// Only this agent, and anything it starts. Everyone by default.
    #[arg(long, value_name = "NAME")]
    pub agent: Option<String>,
    /// Why, for whoever reads the rules later.
    #[arg(long)]
    pub note: Option<String>,
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
    /// A process was refused one.
    Blocked(Box<BlockEvent>),
    /// A process wrote or read plaintext.
    Payload(Box<TlsChunk>),
    /// The proxy decided about a redirected connection.
    Intercepted(Box<intercepting::Happened>),
    /// Something asked for a process to be marked as an agent's, and is waiting to hear whether it was.
    Mark(Box<Marking>),
    /// One reader thread stopped. When the last one does, nothing is watching the kernel.
    ReaderStopped,
    /// The kernel had something to report and nowhere to put it.
    ///
    /// Carried rather than swallowed. A tool whose entire claim is "this is what your machine did" has to be
    /// able to say when that claim has a hole in it, and this is the first hole 0.1.5 will account for.
    Lost(u64),
}

/// A process to mark, and somewhere to say whether it was.
///
/// Answered rather than acknowledged: whoever asked is holding that process still until this comes back, and a
/// mark that might have landed is no use to something whose promise is that it landed first.
struct Marking {
    /// The process.
    pid: u32,
    /// What it is working for.
    agent: String,
    /// Where the answer goes.
    answer: std::sync::mpsc::Sender<Result<bool, String>>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Before everything else, and before the database is opened: this one runs as a person, asks a running
    // daemon what it needs to know, and must not touch anything root owns.
    if let Some(Command::Launch {
        agent,
        print_environment,
        command,
    }) = &args.command
    {
        return launch(&args, agent.as_deref(), *print_environment, command);
    }

    if let Some(command) = &args.command {
        return history::run(command, &args.database, &args.certificates, args.json);
    }

    // Refused rather than mixed, and refused before a single probe is loaded. Writing real traffic into a
    // demonstration would leave two things nobody can tell apart, and the one people would believe is the
    // wrong one — so this is a refusal to start rather than a warning printed while it starts anyway.
    if !args.no_store
        && args.database.exists()
        && Store::open_read_only(&args.database)
            .is_ok_and(|store| store.is_demonstration().unwrap_or(false))
    {
        bail!(
            "{} is a demonstration database. Nothing in it happened, and nothing that happens will be \
             written to it. Name another with --database, or delete that file.",
            args.database.display()
        );
    }

    // Checked here, before anything is loaded or attached, so that a mistyped address fails in a tenth of a
    // second rather than after the probes are in the kernel. `serve` checks it too, because a guard that
    // only exists at the call site is a guard the next caller does not get.
    if let Some(web) = args.web
        && !web.ip().is_loopback()
    {
        bail!(
            "the web page may only be served on loopback; {web} is not. What this knows is every host \
             every process on the machine reached, and there is no version of publishing that which is a \
             good idea."
        );
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

    let mut enforcing = None;
    if !args.no_block {
        match attach_blocking(&mut ebpf, args.tracefs.as_deref()) {
            Ok((verdicts, marks, counts)) => {
                enforcing = Some(Blocking::new(verdicts, marks, counts));
            }
            // Not fatal. A kernel or a container that will not take a cgroup hook is a machine that cannot
            // refuse connections, and that is a reason to say so rather than a reason to stop watching.
            Err(err) => eprintln!(
                "not enforcing rules: {err:#}. Nothing will be refused; watching continues."
            ),
        }
    }

    let (sender, receiver) = channel();
    let mut readers = spawn_readers(&mut ebpf, "EVENTS", Kind::Connection, &sender)?;
    if enforcing.is_some() {
        readers += spawn_readers(&mut ebpf, "BLOCK_EVENTS", Kind::Blocked, &sender)?;
    }
    if !args.no_payloads {
        readers += spawn_readers(&mut ebpf, "TLS_EVENTS", Kind::Payload, &sender)?;
    }
    // Kept for the control socket, which asks the loop to mark a process and waits for the answer.
    let marking = sender.clone();
    // Interception, which is the one thing here that changes what an application sees. Attached after the
    // blocking programs on purpose: the kernel runs them in the order they were attached, blocking decides
    // about the address in the context and redirect changes it, so the other order would quietly disable
    // blocking for everything in interception's scope.
    let mut intercepting = if args.no_intercept || args.no_store {
        if args.no_intercept {
            eprintln!("not intercepting: --no-intercept. Nothing will be terminated.");
        }
        None
    } else {
        match intercepting::Interception::attach(
            &mut ebpf,
            Path::new(CGROUP_ROOT),
            &args.database,
            &args.certificates,
            &machine_name(),
        ) {
            Ok(mut ready) => match take_originals(&mut ebpf).and_then(|originals| {
                intercepting::sensible_port(args.intercept_port)
                    .and_then(|port| ready.listen(port, originals, &sender))
            }) {
                Ok(port) => {
                    eprintln!(
                        "interception is available: a proxy on 127.0.0.1:{port}. Nothing is redirected                          until a rule and a scope say so — `flowlightd intercept` says what would happen."
                    );
                    Some(ready)
                }
                Err(err) => {
                    eprintln!("not intercepting: {err:#}. Watching continues.");
                    None
                }
            },
            // Not fatal, like blocking. A kernel that will not take these programs is a machine that cannot
            // intercept, which is a reason to say so rather than a reason to stop watching.
            Err(err) => {
                eprintln!("not intercepting: {err:#}. Watching continues.");
                None
            }
        }
    };

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
    // The budget, read before anything is captured and said out loud every time rather than written in a
    // manual. A tool that reads every HTTPS request on a machine and quietly accumulates them is a
    // liability however good its intentions.
    let mut spending = match store.as_mut() {
        Some(store) => {
            eprintln!("storing to {}", args.database.display());
            let budget = spending::begin_session(store, now())?;
            let language = store.speaking().unwrap_or_default();
            for line in budget.describe(now(), language) {
                eprintln!("  {line}");
            }
            match take_budget_maps(&mut ebpf) {
                Ok((capturing, spent)) => {
                    Some(Spending::new(capturing, spent, budget, store, now()))
                }
                Err(err) => {
                    // Without these the kernel's switch stays at zero, which means no payloads at all.
                    // Saying so beats a daemon that looks like it is reading and is not.
                    eprintln!("no payloads: {err:#}");
                    None
                }
            }
        }
        None => {
            eprintln!("storing nothing, so no payloads are read either");
            None
        }
    };

    // Flowlight's own traffic, which is only there because Flowlight is exporting. Left in, a record of a
    // batch being sent becomes a record in the next batch, for ever, at whatever rate the loop can manage.
    // The kernel is told once, here, rather than filtered in userspace: the point is not to tidy the output,
    // it is to not copy this process's own TLS buffers out of its memory in the first place.
    if let Some(spending) = spending.as_mut() {
        spending.ignore(std::process::id());
    }

    if !args.no_socket {
        if store.is_none() {
            eprintln!(
                "not opening a control socket: an interface reads the database, and --no-store means \
                 there is not one."
            );
        } else {
            let owner = control::intended_owner();
            let hello = control::Hello {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                enforcing: enforcing.is_some(),
                storing: true,
            };
            match control::serve(
                &args.socket,
                args.database.clone(),
                args.certificates.clone(),
                owner,
                hello,
                marking,
            ) {
                Ok(()) => eprintln!(
                    "interface socket at {}, owned by uid {}",
                    args.socket.display(),
                    owner.0
                ),
                // Not fatal. Having no interface is a reason to say so, not a reason to stop watching the
                // machine.
                Err(err) => eprintln!("no control socket: {err:#}. Still watching."),
            }
        }
    }

    if let Some(store) = store.as_mut() {
        let language = store.speaking().unwrap_or_default();
        match store.export() {
            // Said out loud on every start, like the budget, and for the same reason: a tool that sends what
            // it saw somewhere else should never be quiet about doing it.
            Ok(export) if export.may_send() => {
                eprintln!(
                    "exporting to {} ({}), fields: {}",
                    export.destination.as_deref().unwrap_or("nowhere"),
                    export
                        .transport()
                        .map_or("unknown", flowlight_store::export::Transport::as_str),
                    export
                        .fields
                        .iter()
                        .map(|field| field.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
            Ok(export) => {
                if let Some(reason) = export
                    .why_not(language)
                    .filter(|_| export.destination.is_some())
                {
                    eprintln!("not exporting: {reason}");
                }
            }
            Err(err) => eprintln!("could not read the export configuration: {err:#}"),
        }
    }

    if let Some(address) = args.web {
        if store.is_none() {
            eprintln!(
                "not serving the web page: it reads the database, and --no-store means there is not one."
            );
        } else {
            let token = ui::token()?;
            match ui::serve(address, args.database.clone(), token.clone()) {
                Ok(bound) => eprintln!(
                    "web page at http://{bound}/?token={token} — reachable by every local user on this \
                     machine, which the socket above is not"
                ),
                Err(err) => eprintln!("not serving the web page: {err:#}. Still watching."),
            }
        }
    }

    run(
        &mut ebpf,
        &receiver,
        &args,
        Watching {
            store: store.as_mut(),
            enforcing: enforcing.as_mut(),
            spending: spending.as_mut(),
            intercepting: intercepting.as_mut(),
            readers,
        },
    )
}

/// Starts an agent, or says what starting one would set.
fn launch(
    args: &Args,
    agent: Option<&str>,
    print_environment: bool,
    command: &[String],
) -> anyhow::Result<()> {
    let named = match (
        agent,
        flowlight_agents::launch::name_of(command, flowlight_agents::ancestry::KNOWN),
    ) {
        (Some(given), _) => given.trim().to_owned(),
        (None, Some(worked_out)) => worked_out,
        (None, None) => bail!(
            "nothing to start and no agent named. `flowlightd launch -- claude`, or `--agent NAME \
             --print-environment` to see what starting one would set."
        ),
    };
    if named.is_empty() {
        bail!("an agent needs a name");
    }

    let governing = launching::governing(&args.socket, &named)?;
    let environment = flowlight_agents::launch::Environment::for_agent(
        &named,
        governing.bundle.as_deref(),
        governing.terminated,
    );

    if print_environment {
        // Only the variables, on standard output, because something else is reading them. Everything said to
        // a person goes to standard error.
        print!("{}", environment.as_lines());
        for line in &environment.because {
            eprintln!("{line}");
        }
        eprintln!(
            "\nA process started with these is not marked as {named}'s: only starting it through \
             `flowlightd launch` can do that, because the mark has to be in the kernel before it runs."
        );
        return Ok(());
    }
    if command.is_empty() {
        bail!("nothing to start. `flowlightd launch -- claude`");
    }

    eprintln!("starting {named}, marked before it runs");
    for line in &environment.because {
        eprintln!("  {line}");
    }
    let status = launching::run(&args.socket, &named, command, &environment)?;
    // Transparent: whatever started this sees what the agent exited with, not what Flowlight thinks of it.
    std::process::exit(status.code().unwrap_or(1));
}

/// What this machine is called, for the certificate authority's name.
///
/// A certificate somebody finds in a trust store two years from now should say where it came from without
/// anybody having to guess.
fn machine_name() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|name| name.trim().to_owned())
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "this machine".to_owned())
}

/// Takes the map the kernel writes redirected destinations into.
fn take_originals(
    ebpf: &mut Ebpf,
) -> anyhow::Result<aya::maps::HashMap<aya::maps::MapData, u16, flowlight_common::redirect::Original>>
{
    let map = ebpf
        .take_map("ORIGINALS")
        .ok_or_else(|| anyhow!("the compiled program has no ORIGINALS map"))?;
    Ok(aya::maps::HashMap::try_from(map)?)
}

/// Which map a reader thread is draining, and therefore what its records are.
#[derive(Debug, Clone, Copy)]
enum Kind {
    /// `EVENTS`, carrying [`ConnectionEvent`].
    Connection,
    /// `TLS_EVENTS`, carrying [`TlsChunk`].
    Payload,
    /// `BLOCK_EVENTS`, carrying [`BlockEvent`].
    Blocked,
}

/// Opens one perf buffer per CPU and starts a thread draining each.
fn spawn_readers(
    ebpf: &mut Ebpf,
    map: &str,
    kind: Kind,
    sender: &Sender<Message>,
) -> anyhow::Result<usize> {
    let events = ebpf
        .take_map(map)
        .ok_or_else(|| anyhow!("the compiled program has no {map} map"))?;
    let mut perf: PerfEventArray<MapData> = PerfEventArray::try_from(events)?;
    let mut started = 0;
    for cpu in online_cpus().map_err(|(path, err)| anyhow!("reading {path}: {err}"))? {
        let buffer = perf
            .open(cpu, Some(PERF_PAGES))
            .with_context(|| format!("opening the {map} buffer for CPU {cpu}"))?;
        let sender = sender.clone();
        std::thread::Builder::new()
            .name(format!("flowlight-{map}-{cpu}"))
            .spawn(move || {
                read_events(buffer, kind, &sender);
                // Announced rather than inferred from the channel closing. The control socket holds a sender
                // of its own — it is a producer too — so the channel no longer closes when every reader has
                // stopped, and "nothing is watching the kernel any more" has to be counted instead.
                let _ = sender.send(Message::ReaderStopped);
            })
            .with_context(|| format!("starting the {map} reader for CPU {cpu}"))?;
        started += 1;
    }
    Ok(started)
}

/// Prints what the readers send, and keeps looking for TLS libraries, until the caller's limits are reached.
/// Everything the loop holds for as long as it runs.
///
/// A struct rather than five more parameters. `run` had eight and each release added one; a parameter list that
/// long is one where two of them get swapped and nothing says so.
struct Watching<'a> {
    /// Where what is seen goes, unless nothing is being kept.
    store: Option<&'a mut Store>,
    /// The kernel's table of what to refuse, when rules are being enforced.
    enforcing: Option<&'a mut Blocking>,
    /// What Flowlight is allowed to read, held against the kernel.
    spending: Option<&'a mut Spending>,
    /// The redirect and the proxy, when interception is available.
    intercepting: Option<&'a mut intercepting::Interception>,
    /// How many threads are draining the kernel's buffers. When the last one stops, nothing is watching.
    readers: usize,
}

fn run(
    ebpf: &mut Ebpf,
    receiver: &Receiver<Message>,
    args: &Args,
    watching: Watching<'_>,
) -> anyhow::Result<()> {
    let Watching {
        mut store,
        mut enforcing,
        mut spending,
        mut intercepting,
        mut readers,
    } = watching;
    let deadline = args
        .seconds
        .map(|seconds| Instant::now() + Duration::from_secs(seconds));
    let mut stdout = std::io::stdout().lock();
    let mut agents = Agents::new();
    let mut payloads = Payloads::new();
    let mut probed = BTreeSet::new();
    let mut next_scan = Instant::now();
    let mut next_sweep = Instant::now();
    let mut next_flush = Instant::now() + FLUSH;
    let mut next_rules = Instant::now();
    let export_every = Duration::from_secs(args.export_seconds.max(1));
    let mut next_export = Instant::now() + export_every;
    let mut next_owners = Instant::now() + OWNERS;
    let owners = flowlight_owners::Lookup::new();
    let mut next_alerts = Instant::now() + ALERTS;
    let mut next_devices = Instant::now();
    // What has been seen before, read once. A host recorded before a restart is not new after one.
    let mut noticing = store.as_deref_mut().map(|store| {
        let seen = alerting::Seen::new(store, now());
        let (hosts, processes) = seen.counts();
        eprintln!(
            "watching for anything unusual against {hosts} host(s) and {processes} process(es) already seen"
        );
        seen
    });
    let mut next_agent_scan = Instant::now();
    let mut last_propagation = blocking::Propagation::default();
    let mut seen = 0_u64;
    let mut lost = 0_u64;

    loop {
        if !args.no_payloads && Instant::now() >= next_scan {
            attach_new_libraries(ebpf, &mut probed, &args.libssl, store.as_deref_mut());
            next_scan = Instant::now() + RESCAN;
        }

        if let Some(store) = store.as_deref_mut()
            && Instant::now() >= next_sweep
        {
            let retention = spending
                .as_deref()
                .map_or_else(flowlight_store::Retention::default, |spending| {
                    spending.budget().retention()
                });
            match store.sweep(now(), retention) {
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

        if let Some(enforcing) = enforcing.as_deref_mut()
            && Instant::now() >= next_agent_scan
        {
            // Printed when it moves, not on a timer: the numbers answer a question that only comes up
            // when a rule scoped to an agent does not appear to bite, and the answer has to already be in
            // the log by the time anybody asks.
            for (pid, agent) in enforcing.mark_all(&agent::running_agents()) {
                // Which processes are treated as agents decides which rules reach them, and a rule that
                // appears to do nothing is usually a process nobody recognised as the thing it names.
                eprintln!(
                    "marking {agent} (pid {pid}); rules scoped to it now reach anything it starts"
                );
            }
            // After the marking, not before it. Printed first, this described the state of a moment that
            // had already passed.
            let propagation = enforcing.propagation();
            if propagation != last_propagation {
                eprintln!(
                    "the kernel has seen {} fork(s) and carried an agent's mark to {} child process(es)",
                    propagation.forks, propagation.copied
                );
                last_propagation = propagation;
            }
            next_agent_scan = Instant::now() + AGENT_SCAN;
        }

        // The budget lives in the database, so an interface or a subcommand can change it while this is
        // running. Read back on the same timer as the rules, for the same reason: a change somebody just
        // made should take effect without them having to restart anything.
        if let (Some(store), Some(spending)) = (store.as_deref_mut(), spending.as_deref_mut())
            && Instant::now() >= next_rules
            && let Ok(budget) = store.budget()
            && budget != spending.budget()
        {
            spending.set(budget, now());
            eprintln!("the budget changed:");
            let language = store.speaking().unwrap_or_default();
            for line in budget.describe(now(), language) {
                eprintln!("  {line}");
            }
        }

        // On the same timer as the rules, and for the same reason: a mock somebody just wrote should take
        // effect without them restarting anything.
        //
        // Needs the enforcing half as well, and not only for the numbering: which processes belong to an
        // agent is written into the kernel by the blocking module and by the fork tracepoint it attaches. With
        // `--no-block` there are no marks at all, so there is nothing for a scope to match and interception
        // cannot work however it is configured.
        if let (Some(store), Some(intercepting), Some(enforcing)) = (
            store.as_deref_mut(),
            intercepting.as_deref_mut(),
            enforcing.as_deref_mut(),
        ) && Instant::now() >= next_rules
        {
            match (store.intercept(), store.mocks(), store.guardrails()) {
                (Ok(intercept), Ok(mocks), Ok(guardrails)) => {
                    // The agent numbering is the blocking module's, shared on purpose: two numberings for one
                    // agent would be a scope naming a different process from the rules.
                    let language = store.speaking().unwrap_or_default();
                    match intercepting.apply(&intercept, mocks, guardrails, |agent| {
                        enforcing.identity(agent)
                    }) {
                        Ok(true) => {
                            for line in intercept.disclose(language) {
                                eprintln!("  {line}");
                            }
                            if let Some(reason) = intercept.why_not(language) {
                                eprintln!("not intercepting: {reason}");
                            }
                        }
                        Ok(false) => {}
                        Err(err) => eprintln!("could not change what is intercepted: {err:#}"),
                    }
                }
                (Err(err), _, _) | (_, Err(err), _) | (_, _, Err(err)) => {
                    eprintln!("could not read what is intercepted: {err:#}");
                }
            }
        }

        if let (Some(store), Some(enforcing)) = (store.as_deref_mut(), enforcing.as_deref_mut())
            && Instant::now() >= next_rules
        {
            match store.rules() {
                Ok(rules) => {
                    let report = enforcing.apply(&rules);
                    if !report.is_quiet() {
                        eprintln!(
                            "rules: {} key(s) written, {} taken away",
                            report.added, report.removed
                        );
                        for subject in &report.unresolved {
                            eprintln!(
                                "  {subject} could not be resolved, so the rule naming it is not in force"
                            );
                        }
                        for id in &report.unenforceable {
                            eprintln!(
                                "  rule {id} names a pattern, which cannot be refused before the \
                                 handshake: the name is resolved and thrown away before connect() is \
                                 called. It is still reported when it is reached."
                            );
                        }
                        for id in &report.unreadable {
                            eprintln!(
                                "  rule {id} says something this version does not understand, so it is \
                                 not enforced at all"
                            );
                        }
                    }
                }
                Err(err) => eprintln!("could not read the rules: {err:#}"),
            }
            next_rules = Instant::now() + RULES;
        }

        if let Some(spending) = spending.as_deref_mut() {
            let change = spending.tick(now());
            if !change.is_quiet() {
                if change.session_ended {
                    eprintln!(
                        "payload capture has run out and has stopped. Connections are still attributed. \
                         `flowlightd budget --renew` starts it again."
                    );
                }
                if change.day_began {
                    eprintln!("a new day: every process has its share of payload capture back.");
                }
            }
        }

        if let Some(store) = store.as_deref_mut()
            && Instant::now() >= next_devices
        {
            next_devices = Instant::now() + DEVICES;
            if store.watching_devices().unwrap_or(false) {
                let attached = flowlight_devices::attached(Path::new("/sys"), Path::new("/proc"));
                match store.record_devices(&attached, now()) {
                    Ok(changed) if !changed.is_quiet() => {
                        for device in &changed.arrived {
                            eprintln!(
                                "{} attached: {}{}",
                                device.channel.as_str(),
                                device.name,
                                device
                                    .detail
                                    .as_deref()
                                    .map(|detail| format!(" ({detail})"))
                                    .unwrap_or_default()
                            );
                        }
                        for device in &changed.departed {
                            eprintln!("{} gone: {}", device.channel.as_str(), device.name);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => eprintln!("could not record what is attached: {err:#}"),
                }
            }
        }

        if let (Some(store), Some(seen)) = (store.as_deref_mut(), noticing.as_mut())
            && Instant::now() >= next_alerts
        {
            next_alerts = Instant::now() + ALERTS;
            let said = seen.about_windows(store, now());
            let kept = alerting::keep(store, &said, now());
            for alert in said.iter().take(kept) {
                eprintln!("{}", alerting::line(alert));
            }
        }

        if let Some(store) = store.as_deref_mut()
            && Instant::now() >= next_owners
        {
            next_owners = Instant::now() + OWNERS;
            if store.owner_lookup().unwrap_or(false) {
                let learnt = owning::pass(store, &owners, now());
                if !learnt.is_quiet() {
                    if learnt.named > 0 {
                        eprintln!(
                            "looked up who operates {} of {} address(es)",
                            learnt.named, learnt.asked
                        );
                    }
                    if let Some(failure) = &learnt.failure {
                        eprintln!("could not look up who operates an address: {failure}");
                    }
                }
            }
        }

        if let Some(store) = store.as_deref_mut()
            && Instant::now() >= next_export
        {
            // After the flush interval has had a chance to run, because what is in the batch is not yet in
            // the database, and `requests_after` flushes anyway rather than trusting that ordering.
            match exporting::pass(store) {
                Some(report) if !report.is_quiet() => {
                    if report.sent > 0 {
                        eprintln!("exported {} record(s)", report.sent);
                    }
                    if let Some(failure) = &report.failure {
                        eprintln!(
                            "export failed: {failure}. The records are kept and tried again."
                        );
                    }
                    // A backlog drains in batches; waiting the full interval between them would take a day
                    // to catch up on an hour of traffic.
                    next_export = if report.more {
                        Instant::now()
                    } else {
                        Instant::now() + export_every
                    };
                }
                _ => next_export = Instant::now() + export_every,
            }
        }

        if let Some(store) = store.as_deref_mut()
            && Instant::now() >= next_flush
        {
            if store.has_pending() {
                keep(store.flush());
            }
            next_flush = Instant::now() + FLUSH;
        }

        let until = match deadline {
            Some(deadline) if deadline <= Instant::now() => break,
            Some(deadline) => deadline
                .min(next_scan)
                .min(next_sweep)
                .min(next_flush)
                .min(next_rules)
                .min(next_agent_scan)
                .min(next_export)
                .min(next_owners)
                .min(next_alerts)
                .min(next_devices),
            None => next_scan
                .min(next_sweep)
                .min(next_flush)
                .min(next_rules)
                .min(next_agent_scan)
                .min(next_export)
                .min(next_owners)
                .min(next_alerts)
                .min(next_devices),
        };
        let timeout = until.saturating_duration_since(Instant::now());

        match receiver.recv_timeout(timeout) {
            Ok(Message::Lost(count)) => {
                lost += count;
                // Kept as well as counted. A drop is the one hole in this tool's account of a machine that
                // nothing else can reveal afterwards, so it outlives the session that saw it.
                if let Some(store) = store.as_deref_mut() {
                    keep(store.record_drop(count));
                }
                continue;
            }
            Ok(Message::Blocked(event)) => {
                let exe = executable_of(event.tgid);
                let mut record = Record::refused(&event, exe.as_deref());
                record.agent = agents.of(event.tgid);
                if let Some(store) = store.as_deref_mut() {
                    keep(store.record_connection(record.stored(now())));
                    if let Some(seen) = noticing.as_mut() {
                        let alert = seen.about_refusal(
                            &record.process,
                            record.destination.as_deref().unwrap_or("an address"),
                            record.port,
                            record.agent.as_deref(),
                        );
                        let _ = store.record_alert(&alert, now());
                    }
                }
                render(&mut stdout, args.json, &record, &record.human())?;
            }
            Ok(Message::Mark(asked)) => {
                let answer = match enforcing.as_deref_mut() {
                    Some(enforcing) => {
                        // Written whether or not this process is already marked: `mark` returns whether it
                        // changed anything, and what the caller needs to know is that the kernel now says so.
                        enforcing.mark(asked.pid, &asked.agent);
                        eprintln!(
                            "{} (pid {}) was marked before it ran; rules scoped to it reach it and \
                             everything it starts",
                            asked.agent, asked.pid
                        );
                        Ok(true)
                    }
                    None => Err(
                        "this daemon is not enforcing rules, so there is nowhere to write a mark. \
                         Interception and agent-scoped rules both need it."
                            .to_owned(),
                    ),
                };
                let _ = asked.answer.send(answer);
                continue;
            }
            Ok(Message::Intercepted(happened)) => {
                let (kind, subject, detail) = happened.describe();
                let agent = agents.of(happened.tgid);
                if happened.is_worth_keeping() {
                    if let Some(store) = store.as_deref_mut() {
                        keep(store.record_note(&kind, &subject, &detail));
                        // Counted against the guardrail that made the refusal. A list of guardrails nobody
                        // can tell has ever fired is a list nobody trusts.
                        for id in happened.guardrails() {
                            keep(store.record_guardrail_hit(*id, now()));
                        }
                    }
                    eprintln!(
                        "{subject}: {detail}{}",
                        agent
                            .as_deref()
                            .map(|agent| format!(" (for {agent})"))
                            .unwrap_or_default()
                    );
                } else if args.all {
                    eprintln!("{subject}: {detail}");
                }
                continue;
            }
            Ok(Message::Connection(event)) => {
                let exe = executable_of(event.tgid);
                let mut record = Record::describe(&event, exe.as_deref());
                record.agent = agents.of(event.tgid);
                if let Some(store) = store.as_deref_mut() {
                    keep(store.record_connection(record.stored(now())));
                    if let Some(seen) = noticing.as_mut() {
                        let said = seen.about_connection(
                            &record.process,
                            record.destination.as_deref().unwrap_or_default(),
                            record.port,
                            record.agent.as_deref(),
                        );
                        let kept = alerting::keep(store, &said, now());
                        for alert in said.iter().take(kept) {
                            eprintln!("{}", alerting::line(alert));
                        }
                    }
                }
                render(&mut stdout, args.json, &record, &record.human())?;
            }
            Ok(Message::Payload(chunk)) => {
                let exe = executable_of(chunk.tgid);
                let agent = agents.of(chunk.tgid);
                let mut records = payloads.observe(&chunk, exe.as_deref());
                let paths = spending
                    .as_deref()
                    .map_or(flowlight_store::Paths::Full, |spending| {
                        spending.budget().paths
                    });
                for record in &mut records {
                    record.agent.clone_from(&agent);
                    // Applied before the record exists in any form that could be printed, stored or
                    // exported, so there is no copy of the path anywhere for the policy to have missed.
                    record.target = paths.apply(record.target.take());
                    if !paths.keeps_tool_names() {
                        record.rpc_tool = None;
                    }
                }
                if let Some(spending) = spending.as_deref_mut()
                    && let Some(stopped) = records.first().and_then(|record| {
                        spending.record(&record.process, chunk.tgid, chunk.total)
                    })
                {
                    eprintln!(
                        "{stopped} has reached its share of payload capture for today. Its connections \
                         are still attributed; nothing more of what it sends is read until tomorrow."
                    );
                }
                if records.is_empty() {
                    if !args.all {
                        continue;
                    }
                    let mut plain = Payloads::plain(&chunk, exe.as_deref());
                    plain.agent = agent;
                    render(&mut stdout, args.json, &plain, &plain.human())?;
                } else {
                    for record in &records {
                        if let Some(store) = store.as_deref_mut() {
                            keep(store.record_request(record.stored(now())));
                            if let Some(seen) = noticing.as_mut() {
                                let said =
                                    seen.about_request(&record.process, record.host.as_deref());
                                let kept = alerting::keep(store, &said, now());
                                for alert in said.iter().take(kept) {
                                    eprintln!("{}", alerting::line(alert));
                                }
                            }
                        }
                        render(&mut stdout, args.json, record, &record.human())?;
                    }
                    // One buffer can complete more than one request, and each is a record.
                    seen += records.len() as u64 - 1;
                }
            }
            Ok(Message::ReaderStopped) => {
                readers = readers.saturating_sub(1);
                if readers == 0 {
                    bail!("every reader thread stopped; nothing is watching the kernel any more")
                }
                continue;
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

    if let Some(enforcing) = enforcing {
        let propagation = enforcing.propagation();
        eprintln!(
            "the kernel saw {} fork(s) and carried a mark to {} child process(es)",
            propagation.forks, propagation.copied
        );
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
fn attach_new_libraries(
    ebpf: &mut Ebpf,
    probed: &mut BTreeSet<PathBuf>,
    extra: &[PathBuf],
    mut store: Option<&mut Store>,
) {
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
            Err(err) => {
                eprintln!(
                    "not reading {}: {err:#}. Traffic through this library will be invisible.",
                    path.display()
                );
                // Written down, because by the time anyone asks why an application seems silent this line
                // has scrolled away and the answer is in it.
                if let Some(store) = store.as_deref_mut() {
                    keep(store.record_note(
                        "unprobed-library",
                        &path.display().to_string(),
                        &format!("{err:#}"),
                    ));
                }
            }
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

/// Takes the two maps the budget is held against.
fn take_budget_maps(ebpf: &mut Ebpf) -> anyhow::Result<spending::Maps> {
    let capturing = ebpf
        .take_map("CAPTURING")
        .ok_or_else(|| anyhow!("the compiled program has no CAPTURING map"))?;
    let spent = ebpf
        .take_map("SPENT")
        .ok_or_else(|| anyhow!("the compiled program has no SPENT map"))?;
    Ok((Array::try_from(capturing)?, BpfHashMap::try_from(spent)?))
}

/// Loads the two `connect` hooks and attaches them to the root cgroup.
///
/// Not displacing what is already there matters: a machine may already have a cgroup program attached —
/// systemd's own filtering, a container runtime's — and quietly replacing it would turn a monitoring tool
/// into the reason something else stopped working.
///
/// Which flag says that depends on how the kernel is asked. From 5.7 aya attaches through a BPF *link*,
/// and the kernel refuses `BPF_F_ALLOW_MULTI` there with `EINVAL` — because a link is already multi:
/// `cgroup_bpf_link_attach` passes that flag itself. Before 5.7 it attaches the old way, where the flag is
/// the only thing standing between this and evicting somebody else's program. So: ask for no flags, and
/// fall back to asking for multi, which is exactly one of those two answers on any given kernel.
/// The two maps enforcement needs: the answers, and who is who.
///
/// Both are `HashMap` here even though `PID_AGENT` is a least-recently-used map in the kernel — aya's typed
/// wrapper covers both, and the eviction is the kernel's business rather than this side's.
type Enforcement = (
    BpfHashMap<MapData, BlockKey, u8>,
    BpfHashMap<MapData, u32, u32>,
    Array<MapData, u64>,
);

fn attach_blocking(ebpf: &mut Ebpf, tracefs: Option<&Path>) -> anyhow::Result<Enforcement> {
    // The scheduler's two tracepoints, read the same way as the socket one and for the same reason.
    let fork_text = tracefs::format_text(tracefs, "sched", "sched_process_fork")?;
    let exit_text = tracefs::format_text(tracefs, "sched", "sched_process_exit")?;
    let task_layout = TaskLayout::from_formats(&Format::new(&fork_text), &Format::new(&exit_text))?;
    let mut layouts: Array<_, TaskLayout> = Array::try_from(
        ebpf.map_mut("TASK_LAYOUT")
            .ok_or_else(|| anyhow!("the compiled program has no TASK_LAYOUT map"))?,
    )?;
    layouts
        .set(0, task_layout, 0)
        .context("telling the program where this kernel's scheduler tracepoint fields are")?;

    for (program, category, name) in [
        ("sched_fork", "sched", "sched_process_fork"),
        ("sched_exit", "sched", "sched_process_exit"),
    ] {
        let tracepoint: &mut TracePoint = ebpf
            .program_mut(program)
            .ok_or_else(|| anyhow!("the compiled program has no {program} function"))?
            .try_into()?;
        tracepoint.load().map_err(explain_load_failure)?;
        tracepoint
            .attach(category, name)
            .with_context(|| format!("attaching to {category}/{name}"))?;
    }

    // The v2 tree, wherever it is. On everything current that is `/sys/fs/cgroup`; on a hybrid hierarchy —
    // RHEL 8's default, and Ubuntu's before 21.10 — it is `/sys/fs/cgroup/unified`, and attaching to the top
    // of one fails. A machine with no v2 tree at all can watch but not refuse, and says so.
    let layout = flowlight_platform::hierarchy(Path::new(CGROUP_ROOT));
    let attach_to = layout
        .root()
        .ok_or_else(|| anyhow!("{}", layout.described()))?;
    let cgroup = std::fs::File::open(attach_to).with_context(|| {
        format!(
            "opening {}, which is this machine's cgroup v2 tree",
            attach_to.display()
        )
    })?;
    for name in ["connect4", "connect6"] {
        let program: &mut CgroupSockAddr = ebpf
            .program_mut(name)
            .ok_or_else(|| anyhow!("the compiled program has no {name} function"))?
            .try_into()?;
        program.load().map_err(explain_load_failure)?;
        if let Err(link_error) = program.attach(&cgroup, CgroupAttachMode::Single) {
            program
                .attach(&cgroup, CgroupAttachMode::AllowMultiple)
                .map_err(|prog_attach_error| {
                    anyhow!(
                        "attaching {name} to {} failed both ways: as a link, {link_error}; and as a \
                         program attachment, {prog_attach_error}",
                        attach_to.display()
                    )
                })?;
        }
    }
    let verdicts = ebpf
        .take_map("VERDICTS")
        .ok_or_else(|| anyhow!("the compiled program has no VERDICTS map"))?;
    let marks = ebpf
        .take_map("PID_AGENT")
        .ok_or_else(|| anyhow!("the compiled program has no PID_AGENT map"))?;
    let counts = ebpf
        .take_map("FORK_COUNTS")
        .ok_or_else(|| anyhow!("the compiled program has no FORK_COUNTS map"))?;
    Ok((
        BpfHashMap::try_from(verdicts)?,
        BpfHashMap::try_from(marks)?,
        Array::try_from(counts)?,
    ))
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
                    Kind::Blocked => decode::<BlockEvent>(head, tail, &mut scratch)
                        .map(|event| Message::Blocked(Box::new(event))),
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
