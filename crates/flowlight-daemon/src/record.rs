//! Turning what the kernel reported into something a person or a program can read.
//!
//! The kernel gives a pid, a `comm` and two addresses. Everything else — what the process is *called*, and
//! how much that name is worth — is resolved here, from `/proc`, after the fact. "After the fact" is the
//! interesting part: a short-lived process can be gone by the time we look, and then the only name available
//! is the truncated one the kernel captured at the time. That is not a failure to report, it is a fact to
//! report, which is why [`Record::confidence`] is a field rather than a log line.

use flowlight_common::block::BlockEvent;
use flowlight_common::connection::ConnectionEvent;
use flowlight_common::identity::{Confidence, Identity, executable_was_replaced};
use flowlight_store::ConnectionRow;
use serde::Serialize;

/// One attributed connection, in the shape it is printed or serialised in.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Record {
    /// What the process is called: the key a rule would be written against.
    pub process: String,
    /// Where that name came from — `path`, `comm` or `pid`, worst last.
    pub confidence: &'static str,
    /// Set when the name came from `comm` and fills it, so it may be missing its tail.
    #[serde(skip_serializing_if = "is_false")]
    pub name_may_be_truncated: bool,
    /// Set when the executable behind the process has been unlinked — usually an upgrade in progress.
    #[serde(skip_serializing_if = "is_false")]
    pub executable_replaced: bool,
    /// The process.
    pub pid: u32,
    /// The agent this process is working for, filled in after the fact from the process tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The thread that called `connect()`, which is the process itself more often than not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread: Option<u32>,
    /// The name the kernel captured at the time, kept even when a better one was found, because it is the
    /// only field here that is a fact about the moment rather than about now.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    /// Where it was connecting to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// The port it was connecting to.
    pub port: u16,
    /// Set when the connection was refused before the handshake rather than opened.
    #[serde(skip_serializing_if = "is_false")]
    pub blocked: bool,
}

/// serde needs a function, and `bool::not` is not one it will take by path.
fn is_false(value: &bool) -> bool {
    !*value
}

impl Record {
    /// Builds a record from an event and whatever `/proc/<pid>/exe` resolved to.
    ///
    /// `exe` is passed in rather than read here so that this is testable without a `/proc` — which is to say,
    /// on the machine most of this is written on.
    pub fn describe(event: &ConnectionEvent, exe: Option<&str>) -> Self {
        let comm = event.comm_str();
        let identity = Identity::derive(exe, comm, event.tgid as i32);
        Self {
            process: identity.key.clone(),
            confidence: identity.confidence.as_str(),
            name_may_be_truncated: identity.may_be_truncated(),
            executable_replaced: exe.is_some_and(executable_was_replaced),
            pid: event.tgid,
            agent: None,
            thread: (event.pid != event.tgid).then_some(event.pid),
            // Redundant when it matches the name, and the one thing worth keeping when it does not.
            comm: comm
                .filter(|c| *c != identity.key || identity.confidence != Confidence::Path)
                .map(str::to_owned),
            destination: event.destination().map(|address| address.to_string()),
            port: event.dport,
            blocked: false,
        }
    }

    /// A connection that was refused before the SYN.
    ///
    /// A separate constructor rather than a flag on the other one, because it is a different event from a
    /// different program: there is no thread to report, no source address, and nothing was sent.
    pub fn refused(event: &BlockEvent, exe: Option<&str>) -> Self {
        let comm = event.comm_str();
        let identity = Identity::derive(exe, comm, event.tgid as i32);
        Self {
            process: identity.key.clone(),
            confidence: identity.confidence.as_str(),
            name_may_be_truncated: identity.may_be_truncated(),
            executable_replaced: exe.is_some_and(executable_was_replaced),
            pid: event.tgid,
            agent: None,
            thread: (event.pid != event.tgid).then_some(event.pid),
            comm: comm
                .filter(|c| *c != identity.key || identity.confidence != Confidence::Path)
                .map(str::to_owned),
            destination: event.destination().map(|address| address.to_string()),
            port: event.port,
            blocked: true,
        }
    }

    /// The name column: the agent and the process, when they are not the same thing.
    ///
    /// `claude/node` rather than `node`, because `node` is true and answers nobody's question.
    pub fn who(&self) -> String {
        match &self.agent {
            Some(agent) if *agent != self.process => format!("{agent}/{}", self.process),
            _ => self.process.clone(),
        }
    }

    /// The same thing, in the shape the database keeps.
    pub fn stored(&self, at: i64) -> ConnectionRow {
        ConnectionRow {
            at,
            process: self.process.clone(),
            confidence: self.confidence.to_owned(),
            pid: self.pid,
            agent: self.agent.clone(),
            destination: self.destination.clone(),
            port: self.port,
            blocked: self.blocked,
        }
    }

    /// One line, for a person.
    pub fn human(&self) -> String {
        let destination = self.destination.as_deref().unwrap_or("?");
        // Brackets rather than a column, because the confidence is the thing a reader should notice when it
        // is not `path` and should be able to ignore entirely when it is.
        let note = match self.confidence {
            "path" => String::new(),
            other if self.name_may_be_truncated => {
                format!("  [{other}, may be cut short]")
            }
            other => format!("  [{other}]"),
        };
        let separator = if destination.contains(':') {
            "  port "
        } else {
            ":"
        };
        // A different arrow, because a refusal is not a slower connection — it is one that did not happen,
        // and the application has already been told so.
        let arrow = if self.blocked { "⊘" } else { "→" };
        format!(
            "{:<24} pid {:<8} {arrow} {destination}{separator}{}{note}",
            self.who(),
            self.pid,
            self.port
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowlight_common::connection::{AF_INET, AF_INET6, ipv4_bytes};

    fn event(comm: &str, tgid: u32) -> ConnectionEvent {
        let mut ev = ConnectionEvent {
            tgid,
            pid: tgid,
            family: AF_INET,
            daddr: ipv4_bytes([93, 184, 216, 34]),
            dport: 443,
            ..ConnectionEvent::zeroed()
        };
        let bytes = comm.as_bytes();
        let len = bytes.len().min(16);
        ev.comm[..len].copy_from_slice(&bytes[..len]);
        ev
    }

    #[test]
    fn a_process_with_a_readable_path_is_named_from_it() {
        let record = Record::describe(&event("curl", 4711), Some("/usr/bin/curl"));
        assert_eq!(record.process, "curl");
        assert_eq!(record.confidence, "path");
        assert_eq!(record.destination.as_deref(), Some("93.184.216.34"));
        assert_eq!(record.port, 443);
        // The name and the `comm` agree, so repeating it would be noise.
        assert_eq!(record.comm, None);
    }

    /// A process that exits before we look is the normal case for anything an agent shells out to. The
    /// record still has to say something, and it has to say how much that something is worth.
    #[test]
    fn a_process_that_has_already_exited_is_still_named() {
        let record = Record::describe(&event("git-remote-http", 4711), None);
        assert_eq!(record.process, "git-remote-http");
        assert_eq!(record.confidence, "comm");
        assert!(record.name_may_be_truncated);
        assert!(record.human().contains("may be cut short"));
    }

    /// The shell wrapper's name and the binary's name differ often enough that keeping both is worth a field.
    #[test]
    fn a_comm_that_disagrees_with_the_path_is_kept() {
        let record = Record::describe(&event("node", 4711), Some("/usr/bin/claude"));
        assert_eq!(record.process, "claude");
        assert_eq!(record.comm.as_deref(), Some("node"));
    }

    #[test]
    fn a_connection_from_a_thread_records_which_thread() {
        let mut ev = event("worker", 4711);
        ev.pid = 4718;
        let record = Record::describe(&ev, Some("/usr/bin/curl"));
        assert_eq!(record.thread, Some(4718));
    }

    /// An IPv6 destination and a port are ambiguous when joined with a colon, and the one place that matters
    /// is the line a person reads.
    #[test]
    fn an_ipv6_destination_is_not_printed_as_an_ambiguous_colon() {
        let ev = ConnectionEvent {
            family: AF_INET6,
            daddr: [
                0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x41,
            ],
            dport: 443,
            ..event("curl", 4711)
        };
        let line = Record::describe(&ev, Some("/usr/bin/curl")).human();
        assert!(line.contains("2606:4700::6441  port 443"), "{line}");
    }

    /// A refusal is a connection that did not happen, and the line has to read as one.
    #[test]
    fn a_refused_connection_is_reported_as_refused() {
        let mut event = flowlight_common::block::BlockEvent {
            tgid: 4711,
            pid: 4711,
            family: AF_INET,
            address: ipv4_bytes([93, 184, 216, 34]),
            port: 443,
            ..flowlight_common::block::BlockEvent::zeroed()
        };
        event.comm[..4].copy_from_slice(b"curl");
        let record = Record::refused(&event, Some("/usr/bin/curl"));
        assert!(record.blocked);
        assert_eq!(record.process, "curl");
        assert_eq!(record.port, 443);
        assert!(record.human().contains("⊘"), "{}", record.human());
        assert!(record.stored(0).blocked);

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains(r#""blocked":true"#), "{json}");
    }

    #[test]
    fn a_replaced_executable_is_flagged_without_changing_the_name() {
        let record = Record::describe(&event("curl", 4711), Some("/usr/bin/curl (deleted)"));
        assert_eq!(record.process, "curl");
        assert!(record.executable_replaced);
    }

    /// The JSON is an interface. Fields that are false or absent should not be in it, or every consumer
    /// learns to ignore a column that is empty 99% of the time.
    #[test]
    fn the_json_carries_only_what_is_true() {
        let record = Record::describe(&event("curl", 4711), Some("/usr/bin/curl"));
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("name_may_be_truncated"), "{json}");
        assert!(!json.contains("executable_replaced"), "{json}");
        assert!(!json.contains("thread"), "{json}");
        assert!(json.contains(r#""process":"curl""#), "{json}");
        assert!(json.contains(r#""confidence":"path""#), "{json}");
    }
}
