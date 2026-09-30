//! Reading MCP out of the plaintext that is already being captured.
//!
//! [`crate::mcp`] reads what an agent was *configured* to talk to. This reads what it actually *said*: MCP
//! is JSON-RPC, and a request to an MCP server over HTTP carries a method name and, for a tool call, the
//! name of the tool. Both are in the payload a uprobe already copied.
//!
//! # What is taken, and what is deliberately not
//!
//! The method, and the tool's name. **Never the arguments.** A tool called `read_file` is a fact about what
//! an agent is doing; the path it was given is the contents of somebody's work, and a monitoring tool that
//! quietly kept it would be a worse problem than the one it was installed to solve. The same reasoning as
//! [`flowlight_common::redact`]: the parts that make a line legible, and nothing beyond them.
//!
//! # Why this scans bytes rather than parsing a protocol
//!
//! The same envelope arrives three ways — a bare JSON body over HTTP/1.1, a `DATA` frame over HTTP/2, and a
//! `data:` line in a server-sent event stream — and in each the JSON-RPC object is simply somewhere in the
//! bytes. Following the framing for each would be three parsers to keep correct; finding the object is one.
//!
//! What that costs is stated: a call whose envelope is split across two writes is not seen, and neither is
//! one that begins past [`SCAN_LIMIT`]. Both are misses, not mistakes — nothing is invented.

use serde::Deserialize;

/// How far into a payload to look for an envelope.
///
/// A JSON-RPC envelope puts `method` near the front; four kilobytes is the whole of a captured chunk anyway.
/// The limit exists so that a large body cannot make this expensive rather than because anything useful
/// lives further in.
pub const SCAN_LIMIT: usize = 4_096;

/// The marker every JSON-RPC envelope carries, which is what makes finding one cheap.
const MARKER: &[u8] = b"\"jsonrpc\"";

/// One thing an agent said to an MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// The JSON-RPC method: `tools/call`, `tools/list`, `initialize`, and so on.
    pub method: String,
    /// The tool, for a `tools/call`. Never its arguments.
    pub tool: Option<String>,
}

/// What a JSON-RPC envelope carries that is worth keeping.
///
/// Every other field is ignored by omission rather than by being read and dropped, which is the difference
/// between a parser that cannot leak arguments and one that merely does not.
#[derive(Deserialize)]
struct Envelope {
    jsonrpc: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    params: Option<Params>,
}

/// The one parameter worth keeping.
#[derive(Deserialize)]
struct Params {
    #[serde(default)]
    name: Option<String>,
}

/// Every MCP call in a payload.
///
/// Usually none: most captured plaintext is not MCP. Occasionally several, because JSON-RPC allows a batch
/// and a server-sent event stream carries one envelope per `data:` line.
pub fn calls(payload: &[u8]) -> Vec<Call> {
    let window = payload
        .get(..payload.len().min(SCAN_LIMIT))
        .unwrap_or(payload);
    let mut found = Vec::new();
    let mut at = 0;

    while let Some(offset) = find(window.get(at..).unwrap_or(&[]), MARKER) {
        let marker = at + offset;
        // The object starts at the brace before the marker, not at the marker: `serde_json` is given the
        // whole value or it is given nothing.
        let Some(start) = window
            .get(..marker)
            .and_then(|before| before.iter().rposition(|byte| *byte == b'{'))
        else {
            at = marker + MARKER.len();
            continue;
        };
        match read(window.get(start..).unwrap_or(&[])) {
            Some((call, consumed)) => {
                found.push(call);
                at = start + consumed.max(1);
            }
            // Not an envelope after all, or one cut short by the end of the capture. Either way, carry on
            // past the marker rather than past the brace, so a following envelope is still found.
            None => at = marker + MARKER.len(),
        }
    }
    found
}

/// Reads one envelope, and says how many bytes it took.
fn read(bytes: &[u8]) -> Option<(Call, usize)> {
    let mut stream = serde_json::Deserializer::from_slice(bytes).into_iter::<Envelope>();
    let envelope = stream.next()?.ok()?;
    // Anything without the version is not JSON-RPC, whatever else it is. Checked rather than assumed,
    // because `"jsonrpc"` appears in documentation, in logs, and in this file.
    if envelope.jsonrpc != "2.0" {
        return None;
    }
    let method = envelope.method?;
    Some((
        Call {
            tool: envelope.params.and_then(|params| params.name),
            method,
        },
        stream.byte_offset(),
    ))
}

/// Where a needle is in a haystack.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_call_gives_up_its_method_and_its_tool() {
        let body = br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/x/secrets.txt"}}}"#;
        let found = calls(body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "tools/call");
        assert_eq!(found[0].tool.as_deref(), Some("read_file"));
    }

    /// The whole point of the parser's shape. A tool's name is a fact about what an agent is doing; the
    /// path it was given is the contents of somebody's work.
    #[test]
    fn the_arguments_are_not_anywhere_in_what_comes_back() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/x/secrets.txt","token":"hunter2"}}}"#;
        let found = calls(body);
        let described = format!("{found:?}");
        assert!(!described.contains("secrets.txt"), "{described}");
        assert!(!described.contains("hunter2"), "{described}");
        assert!(!described.contains("arguments"), "{described}");
    }

    #[test]
    fn a_method_with_no_tool_is_still_a_method() {
        let found = calls(br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "tools/list");
        assert_eq!(found[0].tool, None);
    }

    /// A whole HTTP/1.1 request, headers and all, which is what a single `SSL_write` usually carries.
    #[test]
    fn an_envelope_is_found_inside_a_whole_http_request() {
        let body = b"POST /mcp HTTP/1.1\r\nHost: mcp.example.com\r\nContent-Type: application/json\r\n\r\n{\"jsonrpc\":\"2.0\",\"method\":\"initialize\",\"params\":{\"name\":\"x\"}}";
        let found = calls(body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "initialize");
    }

    /// An HTTP/2 `DATA` frame: nine bytes of binary header and then the body. Following the framing would
    /// be a third parser; finding the object is the same one.
    #[test]
    fn an_envelope_is_found_after_a_binary_frame_header() {
        let mut body = vec![0x00, 0x00, 0x2e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01];
        body.extend_from_slice(br#"{"jsonrpc":"2.0","method":"ping"}"#);
        let found = calls(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "ping");
    }

    /// Server-sent events, which is how an MCP server streams its answers: one envelope per `data:` line.
    #[test]
    fn every_envelope_in_an_event_stream_is_found() {
        let body = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n";
        let found = calls(body);
        // The first has no method — a result, not a call — so only the second is one.
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].method, "notifications/progress");
    }

    #[test]
    fn a_batch_of_calls_is_a_batch_of_calls() {
        let body = br#"[{"jsonrpc":"2.0","method":"tools/list"},{"jsonrpc":"2.0","method":"tools/call","params":{"name":"search"}}]"#;
        let found = calls(body);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].method, "tools/list");
        assert_eq!(found[1].tool.as_deref(), Some("search"));
    }

    /// `"jsonrpc"` appears in documentation, in logs, and in this file. Requiring the version and a method
    /// is what keeps those out.
    #[test]
    fn something_that_merely_mentions_jsonrpc_is_not_a_call() {
        for body in [
            br#"{"note":"we speak \"jsonrpc\" here"}"#.as_slice(),
            br#"{"jsonrpc":"1.0","method":"old"}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"result":{"ok":true}}"#.as_slice(),
            b"the word \"jsonrpc\" and nothing else",
            br#"{"jsonrpc":"2.0","method":"#.as_slice(),
        ] {
            assert!(calls(body).is_empty(), "{}", String::from_utf8_lossy(body));
        }
    }

    /// A payload cut off mid-envelope is a miss, not a mistake: nothing is invented from half an object.
    #[test]
    fn an_envelope_cut_short_yields_nothing_rather_than_a_guess() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_fi"#;
        assert!(calls(body).is_empty());
    }

    /// A following envelope must still be found after one that was not an envelope at all, or a single
    /// mention of the word in a log line would hide everything after it.
    #[test]
    fn a_false_start_does_not_hide_what_follows() {
        let mut body = br#"{"jsonrpc":"1.0","method":"old"} then "#.to_vec();
        body.extend_from_slice(
            br#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"grep"}}"#,
        );
        let found = calls(&body);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].tool.as_deref(), Some("grep"));
    }

    /// Nothing here may loop forever or panic on a payload chosen by whoever is on the other end.
    #[test]
    fn nothing_in_a_hostile_payload_causes_a_panic_or_a_loop() {
        for body in [
            b"".as_slice(),
            b"{",
            b"\"jsonrpc\"",
            br#"{"jsonrpc""#,
            &[b'{'; 2_000],
            &[0xff; 512],
        ] {
            let _ = calls(body);
        }
        // And a payload that is nothing but the marker, many times over.
        let repeated = b"\"jsonrpc\"".repeat(500);
        let _ = calls(&repeated);
    }

    /// The limit exists so that a large body cannot make this expensive, not because anything useful lives
    /// further in.
    #[test]
    fn an_envelope_past_the_limit_is_not_looked_for() {
        let mut body = vec![b' '; SCAN_LIMIT];
        body.extend_from_slice(br#"{"jsonrpc":"2.0","method":"tools/list"}"#);
        assert!(calls(&body).is_empty());
    }
}
