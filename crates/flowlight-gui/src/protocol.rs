//! Talking to the daemon.
//!
//! One JSON object per line over a Unix socket. The daemon holds the privileges and the database; this
//! holds a window. Everything crossing between them is here, so that the part that can be wrong in an
//! interesting way is one file with no widgets in it.

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;

/// Where the daemon listens unless told otherwise.
pub const DEFAULT_SOCKET: &str = "/run/flowlight/flowlight.sock";

/// What the daemon said about itself.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Hello {
    /// The daemon's version.
    pub version: String,
    /// Whether rules are being enforced, which decides whether writing one does anything.
    pub enforcing: bool,
    /// Whether anything is being stored.
    pub storing: bool,
}

/// One request or response, as the daemon reports it.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Request {
    /// When, in seconds since the epoch.
    pub at: i64,
    /// What the process is called.
    pub process: String,
    /// Where that name came from.
    pub confidence: String,
    /// The process.
    pub pid: u32,
    /// The agent that caused it.
    pub agent: Option<String>,
    /// `out` or `in`.
    pub direction: String,
    /// `http/2` when the connection was one.
    pub protocol: Option<String>,
    /// The method.
    pub method: Option<String>,
    /// The target, already redacted.
    pub target: Option<String>,
    /// The host.
    pub host: Option<String>,
    /// The status.
    pub status: Option<u16>,
    /// How many bytes the call carried.
    pub bytes: u32,
    /// Whether more was carried than captured.
    #[serde(default)]
    pub truncated: bool,
    /// Why this connection could not be read.
    pub unreadable: Option<String>,
    /// The JSON-RPC method, for something said to an MCP server.
    pub rpc_method: Option<String>,
    /// The tool, for an MCP `tools/call`. Never its arguments.
    pub rpc_tool: Option<String>,
}

/// One agent.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Agent {
    /// The agent.
    pub agent: String,
    /// Requests read from it or anything it started.
    pub requests: i64,
    /// Distinct hosts reached.
    pub hosts: i64,
    /// Distinct processes doing the work.
    pub processes: i64,
    /// Bytes those requests carried.
    pub bytes: i64,
    /// The most recent one.
    pub last_seen: i64,
    /// Configured servers nothing here can see.
    pub local: Vec<String>,
    /// Hosts, and how each stands.
    pub domains: Vec<Domain>,
    /// What it actually said to them.
    pub tools: Vec<Tool>,
}

/// One thing an agent said to an MCP server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Tool {
    /// The JSON-RPC method.
    pub method: String,
    /// The tool, for a `tools/call`.
    pub tool: Option<String>,
    /// The host it was said to.
    pub host: String,
    /// How many times.
    pub calls: i64,
    /// The most recent one.
    pub last_seen: i64,
}

/// One host an agent reached or was configured to reach.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Domain {
    /// The host.
    pub host: String,
    /// `used`, `unused`, `unexpected` or `endpoint`.
    pub standing: String,
    /// Requests to it.
    pub requests: i64,
    /// The configured servers that name it.
    pub servers: Vec<String>,
}

/// What Flowlight is allowed to read, and for how long.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Budget {
    /// Whether payloads are read at all.
    pub payloads: bool,
    /// Whether they are being read now, which the session can decide otherwise.
    pub reading: bool,
    /// Minutes before capture has to be renewed. Zero for no limit.
    pub session_minutes: u32,
    /// Seconds of the session left, if it ends.
    pub session_remaining: Option<i64>,
    /// Bytes one process may contribute in a day.
    pub daily_bytes: i64,
    /// `full`, `host-only` or `none`.
    pub paths: String,
    /// Days of individual requests.
    pub detail_days: u32,
    /// Days of the daily summary.
    pub summary_days: u32,
    /// The whole thing in sentences, which is what to show rather than seven numbers.
    pub described: Vec<String>,
}

/// Where what was seen is sent, and what was agreed to.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Export {
    /// Whether export is wanted.
    pub enabled: bool,
    /// Whether anything may actually be sent.
    pub sending: bool,
    /// Where to, if anywhere.
    pub destination: Option<String>,
    /// `file` or `otlp`.
    pub transport: Option<String>,
    /// What travels.
    pub fields: Vec<String>,
    /// Every field there is, so this does not carry its own copy of the list.
    pub every_field: Vec<String>,
    /// The names of the headers sent. Never the values.
    pub headers: Vec<String>,
    /// Whether what is configured is what was agreed to.
    pub consented: bool,
    /// Why nothing is being sent, when nothing is.
    pub why_not: Option<String>,
    /// The identifier of the last record sent.
    pub sent_through: i64,
    /// What agreeing would mean, in sentences.
    pub disclosure: Vec<String>,
}

/// Which model answers questions, and what asking one would mean.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Ask {
    /// Whether the feature is on.
    pub enabled: bool,
    /// Whether a question could be asked right now.
    pub ready: bool,
    /// `local`, `compatible`, `anthropic` or `gemini`.
    pub kind: String,
    /// Every kind there is.
    pub every_kind: Vec<String>,
    /// Where the model is.
    pub endpoint: Option<String>,
    /// Which model.
    pub model: Option<String>,
    /// Whether this kind needs a key.
    pub needs_key: bool,
    /// Whether there is one on file. Never the key.
    pub key_on_file: bool,
    /// Whether asking sends anything off this machine.
    pub sends_off_the_machine: bool,
    /// Why a question cannot be asked, when it cannot.
    pub why_not: Option<String>,
    /// What asking would mean, in sentences.
    pub disclosure: Vec<String>,
}

/// A question, its answer, and the work behind it.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Answered {
    /// What was asked.
    pub question: String,
    /// What the model said.
    pub answer: String,
    /// Which queries ran.
    pub calls: Vec<Ran>,
    /// The exact bodies that left this machine, if any did.
    pub sent: Vec<String>,
}

/// One query a model asked for.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Ran {
    /// Which query.
    pub query: String,
    /// What it filled in.
    pub arguments: std::collections::BTreeMap<String, String>,
    /// What came back, when there is a sentence for it.
    #[serde(default)]
    pub summary: String,
    /// Whether it was refused.
    pub failed: bool,
}

/// Whether connections are terminated, and whose.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Intercept {
    /// Whether the feature is on.
    pub enabled: bool,
    /// Whether anything is actually being terminated.
    pub running: bool,
    /// Where the proxy listens.
    pub port: u16,
    /// The agents in scope. Empty means nobody.
    pub agents: Vec<String>,
    /// Hosts never terminated.
    pub never: Vec<String>,
    /// Why nothing is being terminated, when nothing is.
    pub why_not: Option<String>,
    /// What turning it on would mean, in sentences.
    pub disclosure: Vec<String>,
    /// Where the certificate is, when there is one.
    pub certificate: Option<String>,
    /// Where the bundle is.
    pub bundle: Option<String>,
}

/// One canned answer.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Mock {
    /// Its identifier.
    pub id: i64,
    /// Whether it answers.
    pub enabled: bool,
    /// The host or pattern.
    pub subject: String,
    /// The path glob.
    pub path: String,
    /// The method, or empty for any.
    pub method: String,
    /// The status.
    pub status: u16,
    /// How long it waits first.
    pub delay: u32,
    /// Whether it calls itself a refusal.
    pub refusal: bool,
    /// The header names. Never their values.
    pub headers: Vec<String>,
    /// How many bytes of body.
    pub body_bytes: usize,
    /// Why.
    pub note: Option<String>,
}

/// Interception and its canned answers together, which is what one page draws.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Interception {
    /// The configuration.
    pub intercept: Intercept,
    /// The answers.
    pub mocks: Vec<Mock>,
}

/// One thing a candidate rule would change.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Change {
    /// The host or address this is about.
    pub subject: String,
    /// The agent, if the traffic belonged to one.
    pub agent: Option<String>,
    /// The port, when the history recorded one.
    pub port: Option<u16>,
    /// What happens today.
    pub before: String,
    /// What would happen with the rule in place.
    pub after: String,
    /// How many times this traffic occurred.
    pub occurrences: i64,
}

/// One rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    /// Its identifier.
    pub id: i64,
    /// `allow`, `ask` or `block`.
    pub action: String,
    /// A host, a pattern, an address or `*`.
    pub subject: String,
    /// The port, or zero for any.
    pub port: u16,
    /// `everyone` or `agent:<name>`.
    pub scope: String,
    /// Why.
    pub note: Option<String>,
}

/// What was seen, and what was not.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Coverage {
    /// Requests read.
    pub requests: i64,
    /// Distinct processes something was read from.
    pub processes_read: i64,
    /// Connections opened.
    pub connections: i64,
    /// Calls that carried more than was captured.
    pub truncated: i64,
    /// Connections whose HTTP/2 could not be decoded.
    pub undecodable: i64,
    /// Records naming a process by its `comm`.
    pub named_by_comm: i64,
    /// Records naming a process by its pid.
    pub named_by_pid: i64,
    /// Connections refused because a rule said so.
    pub refused: i64,
    /// Records the kernel had nowhere to put.
    pub dropped: i64,
    /// Processes that opened HTTPS connections and had nothing read.
    pub unread: Vec<Unread>,
    /// Libraries found and not probed.
    pub unprobed: Vec<Unprobed>,
}

/// One process nothing was read from.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Unread {
    /// The process.
    pub process: String,
    /// Connections it opened.
    pub connections: i64,
}

/// One library that could not be probed.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Unprobed {
    /// Where it is.
    pub path: String,
    /// Why not.
    pub reason: String,
}

/// A reply: one or the other, never both.
#[derive(Deserialize)]
struct Reply {
    ok: Option<serde_json::Value>,
    error: Option<String>,
}

/// A connection to the daemon.
#[derive(Debug)]
pub struct Daemon {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Daemon {
    /// Connects, or explains why not.
    ///
    /// The three ways this fails are three different problems, and a reader who is told "connection
    /// refused" learns none of them.
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => anyhow::anyhow!(
                "there is no daemon at {}. Start one with `sudo flowlightd`.",
                path.display()
            ),
            std::io::ErrorKind::PermissionDenied => anyhow::anyhow!(
                "{} belongs to somebody else. The socket is given to whoever ran `sudo flowlightd`, so \
                 run this as that person — or as them, not as root.",
                path.display()
            ),
            _ => anyhow::anyhow!("{err}"),
        })?;
        let reader = BufReader::new(stream.try_clone().context("duplicating the socket")?);
        Ok(Self { stream, reader })
    }

    /// Asks one question and reads one answer.
    pub fn ask<T: serde::de::DeserializeOwned>(&mut self, request: &str) -> Result<T> {
        writeln!(self.stream, "{request}").context("writing to the daemon")?;
        self.stream.flush().context("writing to the daemon")?;
        let mut line = String::new();
        let read = self
            .reader
            .read_line(&mut line)
            .context("reading from the daemon")?;
        if read == 0 {
            bail!("the daemon closed the connection");
        }
        let reply: Reply = serde_json::from_str(&line)
            .with_context(|| format!("reading the daemon's answer: {}", line.trim()))?;
        match (reply.ok, reply.error) {
            (Some(payload), _) => Ok(serde_json::from_value(payload)
                .context("the daemon's answer was not the shape this version expects")?),
            (None, Some(error)) => bail!(error),
            (None, None) => bail!("the daemon answered with neither an answer nor an error"),
        }
    }
}

/// Builds the request for a window of recent traffic.
pub fn recent(seconds: i64, limit: usize) -> String {
    format!(r#"{{"op":"requests","since":{seconds},"limit":{limit}}}"#)
}

/// Builds a request that takes only a window.
pub fn windowed(op: &str, seconds: i64) -> String {
    format!(r#"{{"op":"{op}","since":{seconds}}}"#)
}

/// Builds the request that writes a rule.
pub fn write_rule(action: &str, subject: &str, port: u16, agent: Option<&str>) -> String {
    let scope = agent.map_or_else(
        || "null".to_owned(),
        |agent| serde_json::to_string(agent).unwrap_or_else(|_| "null".to_owned()),
    );
    let subject = serde_json::to_string(subject).unwrap_or_else(|_| "\"\"".to_owned());
    format!(
        r#"{{"op":"write","action":"{action}","subject":{subject},"port":{port},"agent":{scope}}}"#
    )
}

/// Builds a request that changes one thing about the budget.
///
/// One field at a time. Restating the others would silently overwrite whatever somebody else had changed in
/// between, and the daemon is explicit that anything left out is left alone.
pub fn set_budget(field: &str, value: &str) -> String {
    format!(r#"{{"op":"set-budget","{field}":{value}}}"#)
}

/// Builds the request that changes where what was seen is sent.
///
/// The value is JSON, so a caller decides between a string, a list and a boolean.
pub fn set_export(field: &str, value: &str) -> String {
    format!(r#"{{"op":"set-export","{field}":{value}}}"#)
}

/// Builds the request that changes which model answers.
pub fn set_model(field: &str, value: &str) -> String {
    format!(r#"{{"op":"set-model","{field}":{value}}}"#)
}

/// Builds the request that asks a question.
pub fn question(asked: &str) -> String {
    let asked = serde_json::to_string(asked).unwrap_or_else(|_| "\"\"".to_owned());
    format!(r#"{{"op":"question","question":{asked}}}"#)
}

/// Builds the request that changes what is intercepted.
pub fn set_intercept(field: &str, value: &str) -> String {
    format!(r#"{{"op":"set-intercept","{field}":{value}}}"#)
}

/// Builds the request that removes a canned answer.
pub fn forget_mock(id: i64) -> String {
    format!(r#"{{"op":"forget-mock","id":{id}}}"#)
}

/// Builds the request that asks what a rule would change without writing it.
pub fn simulate(
    action: &str,
    subject: &str,
    port: u16,
    agent: Option<&str>,
    seconds: i64,
) -> String {
    let agent = agent.map_or_else(
        || "null".to_owned(),
        |agent| serde_json::to_string(agent).unwrap_or_else(|_| "null".to_owned()),
    );
    let subject = serde_json::to_string(subject).unwrap_or_else(|_| "\"\"".to_owned());
    format!(
        r#"{{"op":"simulate","action":"{action}","subject":{subject},"port":{port},"agent":{agent},"since":{seconds}}}"#
    )
}

/// Builds the request that removes a rule.
pub fn forget(id: i64) -> String {
    format!(r#"{{"op":"forget","id":{id}}}"#)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host is typed by a person and goes into a JSON document. A quote in it would otherwise end the
    /// string and the rest would be read as something else.
    #[test]
    fn a_subject_with_a_quote_in_it_survives_being_a_request() {
        let request = write_rule("block", r#"a"b"#, 443, None);
        assert!(request.contains(r#""subject":"a\"b""#), "{request}");
        let parsed: serde_json::Value = serde_json::from_str(&request).unwrap();
        assert_eq!(parsed["subject"], r#"a"b"#);
    }

    #[test]
    fn a_rule_can_be_scoped_to_an_agent_or_to_nobody() {
        let everyone: serde_json::Value =
            serde_json::from_str(&write_rule("block", "example.com", 0, None)).unwrap();
        assert!(everyone["agent"].is_null());
        let scoped: serde_json::Value =
            serde_json::from_str(&write_rule("allow", "example.com", 443, Some("claude"))).unwrap();
        assert_eq!(scoped["agent"], "claude");
        assert_eq!(scoped["port"], 443);
    }

    #[test]
    fn the_windowed_requests_are_what_the_daemon_reads() {
        for op in ["processes", "agents", "coverage"] {
            let parsed: serde_json::Value = serde_json::from_str(&windowed(op, 900)).unwrap();
            assert_eq!(parsed["op"], op);
            assert_eq!(parsed["since"], 900);
        }
        let parsed: serde_json::Value = serde_json::from_str(&recent(60, 10)).unwrap();
        assert_eq!(parsed["limit"], 10);
    }

    #[test]
    fn forgetting_names_the_rule() {
        let parsed: serde_json::Value = serde_json::from_str(&forget(7)).unwrap();
        assert_eq!(parsed["op"], "forget");
        assert_eq!(parsed["id"], 7);
    }

    #[test]
    fn asking_what_a_rule_would_change_is_not_asking_to_write_it() {
        let parsed: serde_json::Value =
            serde_json::from_str(&simulate("block", "a.example", 443, Some("claude"), 3_600))
                .unwrap();
        assert_eq!(parsed["op"], "simulate");
        assert_eq!(parsed["action"], "block");
        assert_eq!(parsed["subject"], "a.example");
        assert_eq!(parsed["agent"], "claude");
        assert_eq!(parsed["since"], 3_600);
    }

    /// The three ways connecting fails are three different problems, and "connection refused" teaches none
    /// of them.
    #[test]
    fn a_missing_daemon_says_how_to_start_one() {
        let err = Daemon::connect(Path::new("/nonexistent/flowlight.sock")).unwrap_err();
        assert!(format!("{err}").contains("sudo flowlightd"), "{err}");
    }
}
