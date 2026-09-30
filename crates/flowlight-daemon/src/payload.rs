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

use crate::http2::{Connections, Event, Headers};
use flowlight_common::http::{Summary, summarise};
use flowlight_common::http2::{FrameHeader, PREFACE};
use flowlight_common::identity::Identity;
use flowlight_common::redact::redact_target;
use flowlight_common::tls::TlsChunk;
use flowlight_store::RequestRow;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Instant;

/// One captured buffer, in the shape it is printed or serialised in.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Payload {
    /// What the process is called.
    pub process: String,
    /// Where that name came from.
    pub confidence: &'static str,
    /// The process.
    pub pid: u32,
    /// The agent this process is working for, filled in after the fact from the process tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
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
    /// The request target, for HTTP/1.x, with any credentials in its query string removed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The `Host` header, when it was in the same buffer as the request line.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The response status, for HTTP/1.x.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// `http/2` when the connection is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<&'static str>,
    /// The JSON-RPC method, for something said to an MCP server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_method: Option<String>,
    /// The tool, for an MCP `tools/call`. Never its arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_tool: Option<String>,
    /// Why this connection cannot be read, when it cannot.
    ///
    /// A sentence rather than a flag, because the two reasons — joined late, or a large write cut through a
    /// header block — lead a reader to different conclusions about their own machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<&'static str>,
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
            agent: None,
            direction: if chunk.is_outbound() { "out" } else { "in" },
            bytes: chunk.total,
            truncated: chunk.is_truncated(),
            method: None,
            target: None,
            host: None,
            status: None,
            protocol: None,
            rpc_method: None,
            rpc_tool: None,
            unreadable: None,
        };
        match summarise(chunk.bytes()) {
            Some(Summary::Request {
                method,
                target,
                host,
            }) => {
                payload.method = Some(method.to_owned());
                // Redacted here, on the way in, rather than at each of the places it is eventually shown.
                // A signed URL is entirely a credential, and CI caught this tool printing one.
                payload.target = Some(redact_target(target));
                payload.host = host.map(str::to_owned);
            }
            Some(Summary::Response { status, .. }) => payload.status = Some(status),
            Some(Summary::Http2Preface) => payload.protocol = Some("http/2"),
            None => {}
        }
        payload
    }

    /// The fields every record has, with nothing read out of the buffer yet.
    fn bare(chunk: &TlsChunk, exe: Option<&str>) -> Self {
        let identity = Identity::derive(exe, chunk.comm_str(), chunk.tgid as i32);
        Self {
            process: identity.key,
            confidence: identity.confidence.as_str(),
            pid: chunk.tgid,
            agent: None,
            direction: if chunk.is_outbound() { "out" } else { "in" },
            bytes: chunk.total,
            truncated: chunk.is_truncated(),
            method: None,
            target: None,
            host: None,
            status: None,
            protocol: None,
            rpc_method: None,
            rpc_tool: None,
            unreadable: None,
        }
    }

    /// The name column: the agent and the process, when they are not the same thing.
    pub fn who(&self) -> String {
        match &self.agent {
            Some(agent) if *agent != self.process => format!("{agent}/{}", self.process),
            _ => self.process.clone(),
        }
    }

    /// An HTTP/2 request or response, from its decoded headers.
    fn from_http2(chunk: &TlsChunk, exe: Option<&str>, headers: Headers) -> Self {
        Self {
            protocol: Some("http/2"),
            method: headers.method,
            target: headers.target.as_deref().map(redact_target),
            host: headers.authority,
            status: headers.status,
            ..Self::bare(chunk, exe)
        }
    }

    /// A connection that cannot be decoded, and the reason.
    fn unreadable(chunk: &TlsChunk, exe: Option<&str>, reason: &'static str) -> Self {
        Self {
            protocol: Some("http/2"),
            unreadable: Some(reason),
            ..Self::bare(chunk, exe)
        }
    }

    /// The same thing, in the shape the database keeps.
    ///
    /// The target is already redacted — that happens on the way in, in `describe` and `from_http2`, so the
    /// credential never reaches a record that could be written, printed or exported.
    pub fn stored(&self, at: i64) -> RequestRow {
        RequestRow {
            at,
            process: self.process.clone(),
            confidence: self.confidence.to_owned(),
            pid: self.pid,
            agent: self.agent.clone(),
            direction: self.direction.to_owned(),
            protocol: self.protocol.map(str::to_owned),
            method: self.method.clone(),
            target: self.target.clone(),
            host: self.host.clone(),
            status: self.status,
            bytes: self.bytes,
            truncated: self.truncated,
            unreadable: self.unreadable.map(str::to_owned),
            rpc_method: self.rpc_method.clone(),
            rpc_tool: self.rpc_tool.clone(),
        }
    }

    /// Something an agent said to an MCP server.
    ///
    /// A record of its own rather than a field on the request that carried it: one write can carry a batch,
    /// and a tool call is the event somebody is looking for.
    fn from_call(chunk: &TlsChunk, exe: Option<&str>, call: flowlight_agents::wire::Call) -> Self {
        Self {
            rpc_method: Some(call.method),
            rpc_tool: call.tool,
            ..Self::bare(chunk, exe)
        }
    }

    /// Whether this buffer began something, and is therefore worth a line without `--all`.
    pub fn is_notable(&self) -> bool {
        self.method.is_some()
            || self.status.is_some()
            || self.unreadable.is_some()
            || self.protocol.is_some()
            || self.rpc_method.is_some()
    }

    /// One line, for a person.
    pub fn human(&self) -> String {
        let arrow = if self.direction == "out" {
            "→"
        } else {
            "←"
        };
        let what = if let Some(rpc) = &self.rpc_method {
            match &self.rpc_tool {
                Some(tool) => format!("{rpc} {tool}"),
                None => rpc.clone(),
            }
        } else if let Some(method) = &self.method {
            let target = self.target.as_deref().unwrap_or("");
            match &self.host {
                Some(host) => format!("{method} {host}{target}"),
                None => format!("{method} {target}"),
            }
        } else if let Some(status) = self.status {
            format!("{status}  {} bytes", self.bytes)
        } else if let Some(reason) = self.unreadable {
            // Said in full rather than abbreviated, because a reader who does not already know why the
            // request is missing deserves the reason on the line where it is missing.
            format!("HTTP/2 — {reason}")
        } else if self.protocol.is_some() {
            format!("HTTP/2  {} bytes", self.bytes)
        } else {
            format!("{} bytes", self.bytes)
        };
        let truncated = if self.truncated { "  [truncated]" } else { "" };
        format!(
            "{:<24} pid {:<8} {arrow} {what}{truncated}",
            self.who(),
            self.pid
        )
    }
}

/// How much is known about what a connection is speaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    /// Text, one request per buffer, readable directly.
    Http1,
    /// Frames and HPACK, which need the whole connection followed.
    Http2,
}

/// How many connections to remember the protocol of.
const MAX_REMEMBERED: usize = 8192;

/// Decides what each connection is speaking, and reads it accordingly.
///
/// The decision is made once per connection and then kept, because the evidence is at the start: a client
/// sends the HTTP/2 preface before anything else, and an HTTP/1 request is a line of text. A connection that
/// was already open when Flowlight started shows neither, and is classified by whether its first captured
/// buffer parses as a frame — which for HTTP/2 means it is then reported as undecodable, which is the
/// correct answer rather than a failure.
#[derive(Default)]
pub struct Payloads {
    connections: Connections,
    protocols: HashMap<(u32, u64), (Protocol, Instant)>,
}

impl Payloads {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reads one captured buffer, and returns whatever it completed.
    ///
    /// Usually nothing: most buffers are the middles of bodies. One request produces one record when the
    /// headers land, however many buffers the rest of it takes.
    pub fn observe(&mut self, chunk: &TlsChunk, exe: Option<&str>) -> Vec<Payload> {
        let mut records = match self.protocol_of(chunk) {
            Some(Protocol::Http1) => {
                let payload = Payload::describe(chunk, exe);
                if payload.is_notable() {
                    vec![payload]
                } else {
                    Vec::new()
                }
            }
            Some(Protocol::Http2) => self
                .connections
                .feed(chunk)
                .into_iter()
                .map(|event| match event {
                    Event::Message(headers) => Payload::from_http2(chunk, exe, headers),
                    Event::Unreadable(reason) => Payload::unreadable(chunk, exe, reason),
                })
                .collect(),
            None => Vec::new(),
        };

        // MCP is JSON-RPC, and the envelope is somewhere in the same bytes whichever protocol carried it.
        // Looked for regardless, and after the rest, so that a buffer which is *only* a tool call still
        // produces a record where it would otherwise have produced none.
        records.extend(
            flowlight_agents::wire::calls(chunk.bytes())
                .into_iter()
                .map(|call| Payload::from_call(chunk, exe, call)),
        );
        records
    }

    /// A record for a buffer that produced nothing, for `--all`.
    pub fn plain(chunk: &TlsChunk, exe: Option<&str>) -> Payload {
        Payload::bare(chunk, exe)
    }

    /// What this connection is speaking, deciding if it has not been decided.
    fn protocol_of(&mut self, chunk: &TlsChunk) -> Option<Protocol> {
        let key = (chunk.tgid, chunk.ssl);
        if let Some((protocol, last_seen)) = self.protocols.get_mut(&key) {
            *last_seen = Instant::now();
            return Some(*protocol);
        }

        let bytes = chunk.bytes();
        let protocol = if bytes.starts_with(PREFACE) {
            Protocol::Http2
        } else if matches!(
            summarise(bytes),
            Some(Summary::Request { .. } | Summary::Response { .. })
        ) {
            Protocol::Http1
        } else if FrameHeader::parse(bytes).is_some_and(|header| header.carries_headers()) {
            // No preface and something that looks like a header-carrying frame: a connection that was
            // already open. Classifying it lets it say so, which is better than silence.
            Protocol::Http2
        } else {
            // The middle of something, on a connection nothing has been decided about. Deciding from the
            // middle of a body is how a tool starts reporting frames that are not there.
            return None;
        };

        if self.protocols.len() >= MAX_REMEMBERED {
            self.forget_oldest();
        }
        self.protocols.insert(key, (protocol, Instant::now()));
        Some(protocol)
    }

    /// Drops the least recently used entry when there are too many.
    fn forget_oldest(&mut self) {
        if let Some(oldest) = self
            .protocols
            .iter()
            .min_by_key(|(_, (_, last_seen))| *last_seen)
            .map(|(key, _)| *key)
        {
            self.protocols.remove(&oldest);
        }
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

    /// The case that covers essentially all agent traffic: the request is HPACK, not text, and decoding it
    /// is what this release is for.
    #[test]
    fn an_http2_request_is_decoded_into_a_line() {
        use flowlight_common::http2::{FLAG_END_HEADERS, FRAME_HEADERS};
        let mut encoder = loona_hpack::Encoder::new();
        let block = encoder.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (b":path", b"/v1/messages"),
            (b":authority", b"api.anthropic.com"),
        ]);
        let length = block.len() as u32;
        let mut bytes = flowlight_common::http2::PREFACE.to_vec();
        bytes.extend_from_slice(&[
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            FRAME_HEADERS,
            FLAG_END_HEADERS,
            0,
            0,
            0,
            1,
        ]);
        bytes.extend_from_slice(&block);

        let mut payloads = Payloads::new();
        let records = payloads.observe(&chunk("claude", &bytes), Some("/usr/bin/claude"));
        assert_eq!(records.len(), 1, "{records:?}");
        let line = records[0].human();
        assert!(
            line.contains("POST api.anthropic.com/v1/messages"),
            "{line}"
        );
        assert_eq!(records[0].protocol, Some("http/2"));
    }

    /// A connection already open when Flowlight started has a compression table nobody here watched being
    /// built. Decoding it would produce a plausible wrong request line, so it says why instead.
    #[test]
    fn a_connection_joined_late_says_why_it_cannot_be_read() {
        // A header frame containing indexed references to a dynamic table this side never saw built.
        let bytes = [0, 0, 2, 0x01, 0x04, 0, 0, 0, 1, 0xbe, 0xbf];
        let mut payloads = Payloads::new();
        let records = payloads.observe(&chunk("node", &bytes), Some("/usr/bin/node"));
        assert_eq!(records.len(), 1, "{records:?}");
        assert!(records[0].unreadable.is_some());
        assert!(
            records[0].human().contains("HTTP/2 —"),
            "{}",
            records[0].human()
        );
    }

    /// Deciding a connection's protocol from the middle of a body is how a tool starts reporting frames
    /// that were never there.
    #[test]
    fn a_buffer_from_the_middle_of_something_decides_nothing() {
        let mut payloads = Payloads::new();
        let records = payloads.observe(&chunk("node", b"{\"partial\": \"json"), None);
        assert!(records.is_empty(), "{records:?}");
    }

    /// Once decided, a connection stays decided: later buffers of an HTTP/1 connection are read as HTTP/1
    /// even when they are the middle of a body.
    #[test]
    fn a_connection_keeps_the_protocol_it_was_decided_to_be() {
        let mut payloads = Payloads::new();
        let first = payloads.observe(
            &chunk("curl", b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Some("/usr/bin/curl"),
        );
        assert_eq!(first.len(), 1);
        let second = payloads.observe(
            &chunk("curl", b"\x00\x00\x12\x04\x00"),
            Some("/usr/bin/curl"),
        );
        assert!(second.is_empty(), "{second:?}");
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
