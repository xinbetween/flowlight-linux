//! The socket the native interface talks to.
//!
//! The daemon runs as root because loading a probe needs it. An interface does not, and should not: a
//! program drawing windows on somebody's desktop session has no business holding the privileges this one
//! does. So they are two programs, and this is the boundary between them.
//!
//! # Why a socket in the filesystem rather than a port on loopback
//!
//! The web page this replaces was served on `127.0.0.1` behind a token, and the README had to admit that
//! **loopback is not a permission boundary** — anything served there is reachable by every local user, and
//! a token in a URL is a secret that leaks into shell history, process listings and screenshots.
//!
//! A Unix socket has an owner and a mode. The kernel enforces them, there is no secret to leak, and the
//! answer to "who may ask this daemon what the machine has been doing" becomes a question with a real
//! answer rather than a token somebody might have.
//!
//! Belt and braces: the mode says who may connect, and every connection is then asked who it is through
//! `SO_PEERCRED`, which the kernel fills in and the peer cannot forge.
//!
//! # The shape of it
//!
//! One JSON object per line in, one per line out. Not because JSON is fast — it is a handful of requests a
//! second from one program — but because it can be read by a person, spoken by a shell script, and tested
//! without linking anything.

use anyhow::{Context as _, Result, bail};
use flowlight_store::Store;
use serde::{Deserialize, Serialize};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Sender, channel};

/// Where the socket lives unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/flowlight/flowlight.sock";

/// What an interface can ask for.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Request {
    /// Who is on the other end, and what it can do.
    Hello,
    /// Recent requests and responses.
    Requests {
        /// How far back, in seconds.
        #[serde(default = "an_hour")]
        since: i64,
        /// At most this many.
        #[serde(default = "three_hundred")]
        limit: usize,
    },
    /// Processes, busiest first.
    Processes {
        /// How far back, in seconds.
        #[serde(default = "an_hour")]
        since: i64,
    },
    /// The hosts one process reached.
    Hosts {
        /// The process.
        process: String,
        /// How far back, in seconds.
        #[serde(default = "an_hour")]
        since: i64,
    },
    /// Agents, with what each reached against what it was configured to reach.
    Agents {
        /// How far back, in seconds.
        #[serde(default = "a_day")]
        since: i64,
    },
    /// What was seen, and what was not.
    Coverage {
        /// How far back, in seconds.
        #[serde(default = "a_day")]
        since: i64,
    },
    /// Every rule.
    Rules,
    /// What Flowlight is allowed to read, and for how long.
    Budget,
    /// Change what Flowlight is allowed to read.
    SetBudget {
        /// The fields to change. Anything left out is left alone.
        #[serde(flatten)]
        change: crate::views::BudgetChange,
    },
    /// Where what was seen is sent, and what was agreed to.
    Export,
    /// Change where what was seen is sent.
    SetExport {
        /// The fields to change. Anything left out is left alone.
        #[serde(flatten)]
        change: crate::views::ExportChange,
    },
    /// Which model answers questions, and what asking one would mean.
    Model,
    /// Change which model answers.
    SetModel {
        /// The fields to change. Anything left out is left alone.
        #[serde(flatten)]
        change: crate::views::AskChange,
        /// A key for a provider that needs one. Never returned, by anything.
        ///
        /// It crosses a socket whose mode is 600 and whose owner the kernel checks, which is the same
        /// boundary the database is behind. An empty string forgets the one on file.
        #[serde(default)]
        key: Option<String>,
    },
    /// Ask a question about what this machine has been doing.
    Question {
        /// The question, in plain English.
        question: String,
    },
    /// Whether connections are terminated, and whose.
    Intercept,
    /// Change what is intercepted.
    SetIntercept {
        /// The fields to change. Anything left out is left alone.
        #[serde(flatten)]
        change: crate::views::InterceptChange,
    },
    /// Tell the kernel that a process belongs to an agent, before it has run.
    ///
    /// The one request that changes something outside the database, so it is the one request that is checked
    /// against who is asking: a process somebody else owns is not theirs to name.
    Mark {
        /// The process.
        pid: u32,
        /// What it is working for.
        agent: String,
    },
    /// Every guardrail, with how often each has refused something.
    Guardrails,
    /// Write a guardrail.
    WriteGuardrail {
        /// What it refuses.
        #[serde(flatten)]
        guardrail: crate::views::GuardrailWrite,
    },
    /// Remove a guardrail.
    ForgetGuardrail {
        /// The identifier.
        id: i64,
    },
    /// Every canned answer.
    Mocks,
    /// Write a canned answer.
    WriteMock {
        /// What it answers for.
        #[serde(flatten)]
        mock: crate::views::MockWrite,
    },
    /// Remove a canned answer.
    ForgetMock {
        /// The identifier.
        id: i64,
    },
    /// Write a rule.
    Write {
        /// `allow`, `ask` or `block`.
        action: String,
        /// A host, a pattern, an address or `*`.
        subject: String,
        /// The port, or zero for any.
        #[serde(default)]
        port: u16,
        /// One agent, or everyone.
        #[serde(default)]
        agent: Option<String>,
        /// Why.
        #[serde(default)]
        note: Option<String>,
    },
    /// What a rule would change, without writing it.
    Simulate {
        /// `allow`, `ask` or `block`.
        action: String,
        /// A host, a pattern, an address or `*`.
        subject: String,
        /// The port, or zero for any.
        #[serde(default)]
        port: u16,
        /// One agent, or everyone.
        #[serde(default)]
        agent: Option<String>,
        /// How far back to judge it against, in seconds.
        #[serde(default = "a_day")]
        since: i64,
    },
    /// Remove a rule.
    Forget {
        /// Its identifier.
        id: i64,
    },
}

fn an_hour() -> i64 {
    3_600
}
fn a_day() -> i64 {
    86_400
}
fn three_hundred() -> usize {
    300
}

/// What the daemon says about itself.
#[derive(Debug, Serialize)]
pub struct Hello {
    /// The daemon's version, so an interface can refuse to guess at a protocol it does not know.
    pub version: String,
    /// Whether rules are being enforced, which decides whether writing one does anything.
    pub enforcing: bool,
    /// Whether anything is being stored, which decides whether asking anything does.
    pub storing: bool,
}

/// Starts the socket on a thread.
///
/// `owner` is the user the socket belongs to — the one who ran `sudo`, when there was one. Root otherwise,
/// which on a machine with no desktop session is the honest answer.
pub fn serve(
    path: &Path,
    database: PathBuf,
    certificates: PathBuf,
    owner: (u32, u32),
    hello: Hello,
    marking: Sender<crate::Message>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // A socket left behind by a daemon that was killed rather than stopped. Binding over it fails with
    // "address already in use", which is a confusing thing to say about a file.
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("removing the socket left at {}", path.display()))?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("listening on {}", path.display()))?;

    // Mode before owner, so there is no instant at which it is both reachable and unrestricted.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("restricting {}", path.display()))?;
    chown(path, owner).with_context(|| format!("giving {} to uid {}", path.display(), owner.0))?;

    std::thread::Builder::new()
        .name("flowlight-control".to_owned())
        .spawn(move || {
            accept(
                &listener,
                &database,
                &certificates,
                owner.0,
                &hello,
                &marking,
            )
        })
        .context("starting the control thread")?;
    Ok(())
}

/// Answers connections until the process ends.
fn accept(
    listener: &UnixListener,
    database: &Path,
    certificates: &Path,
    owner: u32,
    hello: &Hello,
    marking: &Sender<crate::Message>,
) {
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let asking = match peer(&stream) {
            // Root may always ask; so may the user the socket belongs to. Anyone else has got here past a
            // mode of 0600, which should not be possible, and is told nothing about why.
            Some(uid) if uid == owner || uid == 0 => uid,
            _ => continue,
        };
        let database = database.to_path_buf();
        let certificates = certificates.to_path_buf();
        let marking = marking.clone();
        let hello = Hello {
            version: hello.version.clone(),
            enforcing: hello.enforcing,
            storing: hello.storing,
        };
        // A thread per connection. There is one interface, and a handful of requests a second from it.
        let _ = std::thread::Builder::new()
            .name("flowlight-client".to_owned())
            .spawn(move || converse(stream, &database, &certificates, &hello, asking, &marking));
    }
}

/// Reads the peer's user, which the kernel fills in and the peer cannot forge.
fn peer(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd as _;
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a correctly sized `ucred` and its length, for a socket this process owns.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut(&mut credentials).cast(),
            &raw mut length,
        )
    };
    (result == 0).then_some(credentials.uid)
}

/// Handles one connection.
fn converse(
    stream: UnixStream,
    database: &Path,
    certificates: &Path,
    hello: &Hello,
    asking: u32,
    marking: &Sender<crate::Message>,
) {
    let Ok(writer) = stream.try_clone() else {
        return;
    };
    let reader = BufReader::new(stream);
    let mut writer = writer;
    for line in reader.lines() {
        let Ok(line) = line else { return };
        if line.trim().is_empty() {
            continue;
        }
        let reply = answer(&line, database, certificates, hello, asking, marking);
        if writeln!(writer, "{reply}").is_err() || writer.flush().is_err() {
            return;
        }
    }
}

/// One request, one line of reply.
fn answer(
    line: &str,
    database: &Path,
    certificates: &Path,
    hello: &Hello,
    asking: u32,
    marking: &Sender<crate::Message>,
) -> String {
    match handle(line, database, certificates, hello, asking, marking) {
        Ok(payload) => format!(r#"{{"ok":{payload}}}"#),
        // The message goes to the interface, because the interface is the only thing looking, and it is
        // this machine's own error about this machine's own database shown to somebody who has already
        // passed the kernel's check on who they are.
        Err(err) => serde_json::to_string(&Failure {
            error: format!("{err:#}"),
        })
        .unwrap_or_else(|_| r#"{"error":"the error could not be described"}"#.to_owned()),
    }
}

/// Tells the kernel that a process belongs to an agent, and waits to find out whether it did.
///
/// Synchronous on purpose. The caller is holding the process still until this answers, and a mark that might
/// have landed is no use to something whose whole promise is that it landed before the process ran.
fn mark(pid: u32, agent: &str, asking: u32, marking: &Sender<crate::Message>) -> Result<bool> {
    let agent = agent.trim();
    if agent.is_empty() {
        bail!("a mark needs an agent to name");
    }
    // Whose process it is. Root may name anything; anybody else may name only their own, because marking a
    // process makes every rule scoped to that agent apply to it — and, if interception is on, redirects it.
    if asking != 0 {
        match owner_of(pid) {
            Some(uid) if uid == asking => {}
            Some(uid) => bail!("process {pid} belongs to uid {uid}, not to uid {asking}"),
            None => bail!("there is no process {pid}"),
        }
    }

    let (answer, answered) = channel();
    marking
        .send(crate::Message::Mark(Box::new(crate::Marking {
            pid,
            agent: agent.to_owned(),
            answer,
        })))
        .map_err(|_| {
            anyhow::anyhow!("the daemon is no longer watching, so nothing can be marked")
        })?;
    // Bounded, because the alternative is a client held open for ever by a daemon that has stopped reading.
    answered
        .recv_timeout(std::time::Duration::from_secs(5))
        .map_err(|_| anyhow::anyhow!("the daemon did not answer within five seconds"))?
        .map_err(|why| anyhow::anyhow!("{why}"))
}

/// Which user a process belongs to, from `/proc`.
///
/// The real uid, which is the first of the four on that line. A process that has dropped privileges is still
/// the user's, and one that has gained them is not somebody else's to name.
fn owner_of(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// A failure, in the shape the interface reads.
#[derive(Serialize)]
struct Failure {
    error: String,
}

/// Does what was asked and returns the payload as JSON.
fn handle(
    line: &str,
    database: &Path,
    certificates: &Path,
    hello: &Hello,
    asking: u32,
    marking: &Sender<crate::Message>,
) -> Result<String> {
    let request: Request = serde_json::from_str(line)
        .context("reading the request; it is one JSON object per line")?;
    let now = crate::views::now();

    if let Request::Hello = request {
        return Ok(serde_json::to_string(hello)?);
    }

    if let Request::Mark { pid, agent } = &request {
        return mark(*pid, agent, asking, marking).map(|marked| marked.to_string());
    }

    let mut store = match &request {
        // Writing a rule is the one thing that needs to write, and it is also the one thing worth doing
        // when nothing has been recorded yet.
        Request::Write { .. }
        | Request::Forget { .. }
        | Request::SetBudget { .. }
        | Request::SetExport { .. }
        | Request::SetModel { .. }
        | Request::SetIntercept { .. }
        | Request::WriteMock { .. }
        | Request::ForgetMock { .. }
        | Request::WriteGuardrail { .. }
        | Request::ForgetGuardrail { .. } => Store::open(database)?,
        _ => Store::open_read_only(database)?,
    };

    let payload = match request {
        Request::Hello => unreachable!("answered above"),
        // Both answered before the database was opened, because neither needs it.
        Request::Mark { .. } => unreachable!("answered above"),
        Request::Requests { since, limit } => serde_json::to_string(&crate::views::requests(
            &mut store,
            crate::views::window(now, since),
            limit,
        )?)?,
        Request::Processes { since } => serde_json::to_string(&crate::views::processes(
            &mut store,
            crate::views::window(now, since),
        )?)?,
        Request::Hosts { process, since } => serde_json::to_string(&crate::views::hosts(
            &mut store,
            &process,
            crate::views::window(now, since),
        )?)?,
        Request::Agents { since } => serde_json::to_string(&crate::views::agents(
            &mut store,
            crate::views::window(now, since),
            &crate::views::homes(),
        )?)?,
        Request::Coverage { since } => serde_json::to_string(&crate::views::coverage(
            &mut store,
            crate::views::window(now, since),
        )?)?,
        Request::Rules => serde_json::to_string(&crate::views::rules(&mut store)?)?,
        Request::Budget => serde_json::to_string(&crate::views::budget(&mut store, now)?)?,
        Request::SetBudget { change } => {
            serde_json::to_string(&crate::views::set_budget(&mut store, &change, now)?)?
        }
        Request::Export => serde_json::to_string(&crate::views::export(&mut store)?)?,
        Request::Intercept => serde_json::to_string(&crate::views::intercept(
            &mut store,
            crate::history::authority_paths(database, certificates),
        )?)?,
        Request::SetIntercept { change } => serde_json::to_string(&crate::views::set_intercept(
            &mut store,
            &change,
            crate::history::authority_paths(database, certificates),
        )?)?,
        Request::Guardrails => serde_json::to_string(&crate::views::guardrails(&mut store)?)?,
        Request::WriteGuardrail { guardrail } => {
            serde_json::to_string(&crate::views::write_guardrail(&mut store, &guardrail, now)?)?
        }
        Request::ForgetGuardrail { id } => serde_json::to_string(&store.forget_guardrail(id)?)?,
        Request::Mocks => serde_json::to_string(&crate::views::mocks(&mut store)?)?,
        Request::WriteMock { mock } => {
            serde_json::to_string(&crate::views::write_mock(&mut store, &mock, now)?)?
        }
        Request::ForgetMock { id } => serde_json::to_string(&store.forget_mock(id)?)?,
        Request::Model => serde_json::to_string(&crate::views::ask(
            &mut store,
            crate::asking::have_key(database),
        )?)?,
        Request::SetModel { change, key } => {
            // The key first, so what comes back describes the state including it.
            if let Some(key) = key {
                crate::asking::set_key(database, &key)?;
            }
            serde_json::to_string(&crate::views::set_ask(
                &mut store,
                &change,
                crate::asking::have_key(database),
            )?)?
        }
        Request::Question { question } => {
            let configuration = store.ask()?;
            let on_file = crate::asking::have_key(database);
            if let Some(reason) = configuration.why_not(on_file) {
                anyhow::bail!("{reason}");
            }
            let key = crate::asking::key(database)?;
            let answered = flowlight_ask::answer(
                &configuration,
                &key,
                &question,
                &mut store,
                now,
                &flowlight_ask::window::clock(now),
            )?;
            serde_json::to_string(&crate::views::answered(&question, &answered))?
        }
        Request::SetExport { change } => {
            serde_json::to_string(&crate::views::set_export(&mut store, &change)?)?
        }
        Request::Simulate {
            action,
            subject,
            port,
            agent,
            since,
        } => serde_json::to_string(&crate::views::simulate(
            &mut store,
            &action,
            &subject,
            port,
            agent.as_deref(),
            crate::views::window(now, since),
        )?)?,
        Request::Write {
            action,
            subject,
            port,
            agent,
            note,
        } => {
            // Checked here rather than taken on trust: an action this version does not understand would be
            // written into the database and then not enforced, which is the worst of both.
            let action = flowlight_rules::Action::parse(&action)
                .with_context(|| format!("`{action}` is not allow, ask or block"))?;
            let scope = agent
                .as_ref()
                .map_or_else(|| "everyone".to_owned(), |agent| format!("agent:{agent}"));
            let wrote = store.put_rule(action.as_str(), &subject, port, &scope, note.as_deref())?;
            serde_json::to_string(&format!("{wrote:?}").to_lowercase())?
        }
        Request::Forget { id } => serde_json::to_string(&store.forget_rule(id)?)?,
    };
    Ok(payload)
}

/// Gives a path to a user and group.
fn chown(path: &Path, owner: (u32, u32)) -> Result<()> {
    let text = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
        .context("the socket path contains a NUL")?;
    // SAFETY: a NUL-terminated path this process just created, and two identifiers from the environment.
    let result = unsafe { libc::chown(text.as_ptr(), owner.0, owner.1) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

/// The user the socket should belong to.
///
/// The one who ran `sudo`, when there was one: they are the person at the machine, and the interface will
/// run as them. Root otherwise, which on a box with no desktop session is the honest answer rather than a
/// guess at who might want it.
pub fn intended_owner() -> (u32, u32) {
    let read = |name: &str| {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
    };
    match (read("SUDO_UID"), read("SUDO_GID")) {
        (Some(uid), Some(gid)) => (uid, gid),
        // SAFETY: both read this process's own credentials and cannot fail.
        _ => unsafe { (libc::geteuid(), libc::getegid()) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The socket's answer, for a test that does not care where certificates are published.
    ///
    /// One helper rather than eleven call sites: the last time this signature grew it grew in eleven places,
    /// and two of them were wrong.
    fn answered(line: &str, database: &Path) -> String {
        let (marking, _held) = channel();
        answer(
            line,
            database,
            Path::new("/nonexistent"),
            &hello(),
            0,
            &marking,
        )
    }

    fn hello() -> Hello {
        Hello {
            version: "test".to_owned(),
            enforcing: true,
            storing: true,
        }
    }

    #[test]
    fn a_request_that_is_not_json_is_refused_with_a_reason() {
        let reply = answered("not json", Path::new("/nonexistent"));
        assert!(reply.contains("one JSON object per line"), "{reply}");
    }

    #[test]
    fn hello_needs_no_database() {
        let reply = answered(r#"{"op":"hello"}"#, Path::new("/nonexistent"));
        assert!(reply.contains(r#""version":"test""#), "{reply}");
        assert!(reply.contains(r#""enforcing":true"#), "{reply}");
    }

    /// An action this version does not understand would be written into the database and then not
    /// enforced, which is the worst of both.
    #[test]
    fn an_action_that_is_not_one_is_refused_before_it_is_written() {
        let directory = std::env::temp_dir().join("flowlight-control-action");
        let _ = std::fs::remove_dir_all(&directory);
        let database = directory.join("flowlight.db");
        let reply = answered(
            r#"{"op":"write","action":"maybe","subject":"example.com"}"#,
            &database,
        );
        assert!(reply.contains("not allow, ask or block"), "{reply}");

        let mut store = Store::open(&database).unwrap();
        assert!(store.rules().unwrap().is_empty());
    }

    #[test]
    fn a_rule_written_over_the_socket_is_a_rule_in_the_database() {
        let directory = std::env::temp_dir().join("flowlight-control-write");
        let _ = std::fs::remove_dir_all(&directory);
        let database = directory.join("flowlight.db");

        let reply = answered(
            r#"{"op":"write","action":"block","subject":"example.com","agent":"claude"}"#,
            &database,
        );
        assert!(reply.contains("added"), "{reply}");

        let mut store = Store::open(&database).unwrap();
        let rules = store.rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].scope, "agent:claude");
        assert_eq!(rules[0].action, "block");

        // And it can be taken away again by the identifier the interface was given.
        let forget = format!(r#"{{"op":"forget","id":{}}}"#, rules[0].id);
        assert!(answered(&forget, &database).contains("true"));
    }

    /// Asking a question of a database that does not exist is a missing answer, not a created file: a
    /// reader must never bring one into being.
    #[test]
    fn reading_does_not_create_a_database() {
        let directory = std::env::temp_dir().join("flowlight-control-readonly");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let database = directory.join("flowlight.db");
        let reply = answered(r#"{"op":"rules"}"#, &database);
        assert!(reply.contains("error"), "{reply}");
        assert!(!database.exists());
    }

    /// Changing one field must leave the others alone, over the socket as much as anywhere.
    #[test]
    fn the_budget_can_be_read_and_changed_over_the_socket() {
        let directory = std::env::temp_dir().join("flowlight-control-budget");
        let _ = std::fs::remove_dir_all(&directory);
        let database = directory.join("flowlight.db");
        // Brought into being by a write, as the daemon would.
        drop(Store::open(&database).unwrap());

        let reply = answered(r#"{"op":"budget"}"#, &database);
        assert!(reply.contains(r#""paths":"full""#), "{reply}");

        let reply = answered(
            r#"{"op":"set-budget","paths":"none","payloads":false}"#,
            &database,
        );
        assert!(reply.contains(r#""paths":"none""#), "{reply}");
        assert!(reply.contains(r#""payloads":false"#), "{reply}");
        // And the retention it never mentioned is untouched.
        assert!(reply.contains(r#""detail_days":7"#), "{reply}");
    }

    /// Asked before writing, which is what makes a rule something somebody will enable.
    #[test]
    fn a_rule_can_be_tried_before_it_is_written() {
        let directory = std::env::temp_dir().join("flowlight-control-simulate");
        let _ = std::fs::remove_dir_all(&directory);
        let database = directory.join("flowlight.db");

        // Some history to judge against.
        {
            let mut store = Store::open(&database).unwrap();
            store
                .record_request(flowlight_store::RequestRow {
                    at: crate::views::now(),
                    process: "node".to_owned(),
                    confidence: "path".to_owned(),
                    pid: 1,
                    agent: Some("claude".to_owned()),
                    direction: "out".to_owned(),
                    protocol: None,
                    method: Some("GET".to_owned()),
                    target: Some("/".to_owned()),
                    host: Some("telemetry.example".to_owned()),
                    status: None,
                    bytes: 10,
                    truncated: false,
                    unreadable: None,
                    rpc_method: None,
                    rpc_tool: None,
                })
                .unwrap();
            store.flush().unwrap();
        }

        let reply = answered(
            r#"{"op":"simulate","action":"block","subject":"telemetry.example"}"#,
            &database,
        );
        assert!(reply.contains(r#""after":"block""#), "{reply}");
        assert!(reply.contains(r#""occurrences":1"#), "{reply}");

        // And asking does not write it.
        let mut store = Store::open(&database).unwrap();
        assert!(store.rules().unwrap().is_empty());
    }

    /// The defaults matter: an interface that asks for "requests" without saying how far back should get
    /// an hour, not everything ever recorded.
    #[test]
    fn a_request_with_nothing_said_about_it_gets_sensible_defaults() {
        let request: Request = serde_json::from_str(r#"{"op":"requests"}"#).unwrap();
        match request {
            Request::Requests { since, limit } => {
                assert_eq!(since, 3_600);
                assert_eq!(limit, 300);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_owner_is_the_person_who_ran_sudo_when_there_was_one() {
        // Not settable from here without racing every other test, so this checks the shape rather than
        // the value: whatever it returns must be a real pair of identifiers.
        let (uid, gid) = intended_owner();
        assert!(uid != u32::MAX && gid != u32::MAX);
    }
}
