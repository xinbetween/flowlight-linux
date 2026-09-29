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

    /// The three ways connecting fails are three different problems, and "connection refused" teaches none
    /// of them.
    #[test]
    fn a_missing_daemon_says_how_to_start_one() {
        let err = Daemon::connect(Path::new("/nonexistent/flowlight.sock")).unwrap_err();
        assert!(format!("{err}").contains("sudo flowlightd"), "{err}");
    }
}
