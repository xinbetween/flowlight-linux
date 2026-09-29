//! Turning a buffer of plaintext into a line that says something.
//!
//! The kernel hands over four kilobytes of whatever an application passed to `SSL_write`. Most of it is not
//! the start of anything: response bodies, HTTP/2 frames, the second half of a request. Printing all of it
//! would bury the few lines that matter, so by default only the chunks that *begin* something recognisable
//! are shown, and `--all` says otherwise.
//!
//! The honesty problem here is specific. Every current agent API speaks HTTP/2, whose headers are HPACK —
//! compressed against a table built over the whole connection, not readable from one buffer. So the method
//! and path of a request to `api.anthropic.com` are not in what this can see. Saying "HTTP/2, not decoded
//! yet" is the truthful report of that, and it is better than an empty screen that implies nothing happened.

use flowlight_common::http::{Summary, summarise};
use flowlight_common::identity::Identity;
use flowlight_common::tls::TlsChunk;
use serde::Serialize;

/// One captured buffer, in the shape it is printed or serialised in.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Payload {
    /// What the process is called.
    pub process: String,
    /// Where that name came from.
    pub confidence: &'static str,
    /// The process.
    pub pid: u32,
    /// `out` for a write, `in` for a read.
    pub direction: &'static str,
    /// How many bytes the call carried, which is not always how many were captured.
    pub bytes: u32,
    /// Set when the call carried more than four kilobytes and the rest was left behind.
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
    /// The request method, for HTTP/1.x.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The request target, for HTTP/1.x.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The `Host` header, when it was in the same buffer as the request line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The response status, for HTTP/1.x.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// `http/2` when this was the connection preface, which is as much as one buffer can say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<&'static str>,
}

/// serde needs a function.
fn is_false(value: &bool) -> bool {
    !*value
}

impl Payload {
    /// Builds a payload record from a chunk and whatever `/proc/<pid>/exe` resolved to.
    pub fn describe(chunk: &TlsChunk, exe: Option<&str>) -> Self {
        let identity = Identity::derive(exe, chunk.comm_str(), chunk.tgid as i32);
        let mut payload = Self {
            process: identity.key,
            confidence: identity.confidence.as_str(),
            pid: chunk.tgid,
            direction: if chunk.is_outbound() { "out" } else { "in" },
            bytes: chunk.total,
            truncated: chunk.is_truncated(),
            method: None,
            target: None,
            host: None,
            status: None,
            protocol: None,
        };
        match summarise(chunk.bytes()) {
            Some(Summary::Request {
                method,
                target,
                host,
            }) => {
                payload.method = Some(method.to_owned());
                payload.target = Some(target.to_owned());
                payload.host = host.map(str::to_owned);
            }
            Some(Summary::Response { status, .. }) => payload.status = Some(status),
            Some(Summary::Http2Preface) => payload.protocol = Some("http/2"),
            None => {}
        }
        payload
    }

    /// Whether this buffer began something, and is therefore worth a line without `--all`.
    pub fn is_notable(&self) -> bool {
        self.method.is_some() || self.status.is_some() || self.protocol.is_some()
    }

    /// One line, for a person.
    pub fn human(&self) -> String {
        let arrow = if self.direction == "out" {
            "→"
        } else {
            "←"
        };
        let what = if let Some(method) = &self.method {
            let target = self.target.as_deref().unwrap_or("");
            match &self.host {
                Some(host) => format!("{method} {host}{target}"),
                None => format!("{method} {target}"),
            }
        } else if let Some(status) = self.status {
            format!("{status}  {} bytes", self.bytes)
        } else if self.protocol.is_some() {
            // Said in full rather than abbreviated, because a reader who does not already know why the
            // request is missing deserves the reason on the line where it is missing.
            "HTTP/2 — headers are HPACK-compressed and not decoded yet".to_owned()
        } else {
            format!("{} bytes", self.bytes)
        };
        let truncated = if self.truncated { "  [truncated]" } else { "" };
        format!(
            "{:<24} pid {:<8} {arrow} {what}{truncated}",
            self.process, self.pid
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowlight_common::tls::{DIRECTION_IN, TLS_CHUNK_BYTES};

    fn chunk(comm: &str, body: &[u8]) -> TlsChunk {
        let mut chunk = TlsChunk {
            tgid: 4711,
            pid: 4711,
            len: body.len() as u32,
            total: body.len() as u32,
            ..TlsChunk::zeroed()
        };
        chunk.data[..body.len()].copy_from_slice(body);
        let comm = comm.as_bytes();
        chunk.comm[..comm.len()].copy_from_slice(comm);
        chunk
    }

    #[test]
    fn a_request_is_reported_with_its_host_and_path() {
        let chunk = chunk(
            "curl",
            b"GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
        );
        let payload = Payload::describe(&chunk, Some("/usr/bin/curl"));
        assert_eq!(payload.method.as_deref(), Some("GET"));
        assert_eq!(payload.host.as_deref(), Some("api.openai.com"));
        assert!(payload.is_notable());
        assert!(payload.human().contains("GET api.openai.com/v1/models"));
    }

    #[test]
    fn a_response_is_reported_with_its_status_and_size() {
        let mut chunk = chunk("curl", b"HTTP/1.1 200 OK\r\n\r\n");
        chunk.direction = DIRECTION_IN;
        chunk.total = 1256;
        let payload = Payload::describe(&chunk, Some("/usr/bin/curl"));
        assert_eq!(payload.status, Some(200));
        assert_eq!(payload.direction, "in");
        assert!(
            payload.human().contains("← 200  1256 bytes"),
            "{}",
            payload.human()
        );
    }

    /// The case that covers essentially all agent traffic. An empty line here would read as "nothing
    /// happened", which is the opposite of the truth.
    #[test]
    fn http2_says_why_there_is_no_request_to_show() {
        let chunk = chunk("node", b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        let payload = Payload::describe(&chunk, Some("/usr/bin/node"));
        assert_eq!(payload.protocol, Some("http/2"));
        assert!(payload.is_notable());
        assert!(payload.human().contains("HPACK"), "{}", payload.human());
    }

    /// The middle of a body is not notable, and without `--all` it should not produce a line at all.
    #[test]
    fn a_buffer_that_begins_nothing_is_not_notable() {
        let payload = Payload::describe(&chunk("node", b"\x00\x00\x12\x04\x00"), None);
        assert!(!payload.is_notable());
        assert!(payload.method.is_none());
        assert!(payload.protocol.is_none());
    }

    /// Four kilobytes of a sixty-kilobyte POST is four kilobytes of it, and the line has to say so.
    #[test]
    fn a_truncated_call_is_marked_as_one() {
        let mut chunk = chunk(
            "claude",
            b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
        );
        chunk.len = TLS_CHUNK_BYTES as u32;
        chunk.total = 61_440;
        let payload = Payload::describe(&chunk, Some("/usr/bin/claude"));
        assert!(payload.truncated);
        assert_eq!(payload.bytes, 61_440);
        assert!(payload.human().ends_with("[truncated]"));
    }

    #[test]
    fn the_json_carries_only_what_is_true() {
        let payload =
            Payload::describe(&chunk("curl", b"GET / HTTP/1.1\r\n"), Some("/usr/bin/curl"));
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("status"), "{json}");
        assert!(!json.contains("truncated"), "{json}");
        assert!(!json.contains("host"), "{json}");
        assert!(json.contains(r#""method":"GET""#), "{json}");
    }
}
