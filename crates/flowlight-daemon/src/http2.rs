//! Decoding HTTP/2 requests, which is what makes agent traffic legible at all.
//!
//! [`flowlight_common::http2`] follows the frames and hands over complete header blocks. This turns those
//! blocks into headers, which needs HPACK — and HPACK needs state that spans the whole connection in order,
//! which is why everything here is keyed on the connection rather than the process.
//!
//! # What goes wrong, and what is said about it
//!
//! HPACK is a compression table both ends build as they go. Three things can leave this side's copy
//! disagreeing with the sender's, and all three produce *plausible wrong headers* rather than an error:
//!
//! - **Joining late.** A connection already open when Flowlight started has a table we never saw built.
//!   The first block decodes to whatever our empty table happens to hold at those indices.
//! - **A hole.** A block that a large write cut through is skipped, and every block after it is decoded
//!   against a table one entry short.
//! - **Interleaving.** Two connections' blocks through one decoder. Prevented by keying on the `SSL *`.
//!
//! The first two cannot be prevented, only detected. A decode that fails marks the connection unreliable and
//! nothing further is claimed about it — because a request line invented from a desynchronised table is
//! worse than no request line, and much worse than a sentence saying so.

use flowlight_common::http2::{Record, Stream};
use flowlight_common::tls::TlsChunk;
use loona_hpack::Decoder;
use std::collections::HashMap;
use std::time::Instant;

/// How many connections to follow at once.
///
/// Each costs a few kilobytes of decoder table and buffer. A machine with more than this many concurrent
/// TLS connections exists, and on it the least recently used are dropped — which is visible, because a
/// dropped connection's next block cannot be decoded and says so.
const MAX_CONNECTIONS: usize = 2048;

/// What was read out of one header block.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Headers {
    /// `:method`, for a request.
    pub method: Option<String>,
    /// `:path`, for a request.
    pub target: Option<String>,
    /// `:authority`, which is HTTP/2's `Host`.
    pub authority: Option<String>,
    /// `:status`, for a response.
    pub status: Option<u16>,
}

/// What following one captured buffer produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A request or response, decoded.
    Message(Headers),
    /// The connection can no longer be decoded, and why.
    ///
    /// Reported once per connection. Repeating it every four kilobytes would be the only thing on the
    /// screen for the rest of a large upload.
    Unreadable(&'static str),
}

/// One direction of one connection.
struct Conversation {
    frames: Stream,
    decoder: Decoder<'static>,
    /// Set once the table can no longer be trusted. Nothing further is claimed about this direction.
    unreliable: bool,
    /// Whether the unreliability has already been reported.
    reported: bool,
    last_seen: Instant,
}

impl Conversation {
    fn new() -> Self {
        Self {
            frames: Stream::new(),
            decoder: Decoder::new(),
            unreliable: false,
            reported: false,
            last_seen: Instant::now(),
        }
    }
}

/// Every HTTP/2 connection currently being followed.
#[derive(Default)]
pub struct Connections {
    /// Keyed on process, `SSL *` and direction. All three are needed: one process has many connections, and
    /// each connection has two independent HPACK tables.
    conversations: HashMap<(u32, u64, bool), Conversation>,
}

/// How many connections are being followed.
///
/// Only the tests ask at the moment. Coverage — which is the release whose entire job is saying what was
/// and was not seen — will want it for real, and it is left here rather than deleted because the number is
/// the obvious thing that screen has to show.
#[cfg(test)]
impl Connections {
    fn len(&self) -> usize {
        self.conversations.len()
    }

    fn is_empty(&self) -> bool {
        self.conversations.is_empty()
    }
}

impl Connections {
    /// Feeds one captured buffer and returns whatever it completed.
    pub fn feed(&mut self, chunk: &TlsChunk) -> Vec<Event> {
        let key = (chunk.tgid, chunk.ssl, chunk.is_outbound());
        if !self.conversations.contains_key(&key) {
            self.evict_if_full();
        }
        let conversation = self
            .conversations
            .entry(key)
            .or_insert_with(Conversation::new);
        conversation.last_seen = Instant::now();

        let missing = chunk.total.saturating_sub(chunk.len) as usize;
        let records = conversation.frames.feed(chunk.bytes(), missing);
        let mut events = Vec::new();
        let mut finished = false;

        for record in records {
            match record {
                Record::Headers { block, .. } => {
                    if conversation.unreliable {
                        continue;
                    }
                    match conversation.decoder.decode(&block) {
                        Ok(list) => events.push(Event::Message(read_headers(&list))),
                        Err(_) => {
                            conversation.unreliable = true;
                            events.push(Event::Unreadable(
                                "this connection's header compression could not be followed — it was \
                                 already open when Flowlight started, or a large write cut through a \
                                 header block",
                            ));
                            conversation.reported = true;
                        }
                    }
                }
                Record::HeadersLost { .. } => {
                    // The table has advanced on the sender's side and not on ours. Everything after this
                    // would decode to something plausible and wrong.
                    conversation.unreliable = true;
                    if !conversation.reported {
                        events.push(Event::Unreadable(
                            "a large write cut through a header block, so the rest of this connection \
                             cannot be decoded",
                        ));
                        conversation.reported = true;
                    }
                }
                Record::GoAway { .. } => finished = true,
                Record::Data { .. } | Record::Reset { .. } => {}
                Record::Desynchronised | Record::Resynchronised => {}
            }
        }

        if finished {
            self.conversations.remove(&key);
        }
        events
    }

    /// Drops the least recently used connection when there are too many.
    fn evict_if_full(&mut self) {
        while self.conversations.len() >= MAX_CONNECTIONS {
            let Some(oldest) = self
                .conversations
                .iter()
                .min_by_key(|(_, conversation)| conversation.last_seen)
                .map(|(key, _)| *key)
            else {
                return;
            };
            self.conversations.remove(&oldest);
        }
    }
}

/// Picks the pseudo-headers out of a decoded list.
///
/// Only the four that say what the request or response *is*. The rest — `user-agent`, `accept`, and the
/// authorization header that is in there too — are deliberately not kept: 0.1.x stores nothing, and a header
/// allowlist is a decision for the release that starts storing things.
fn read_headers(list: &[(Vec<u8>, Vec<u8>)]) -> Headers {
    let mut headers = Headers::default();
    for (name, value) in list {
        let Ok(value) = std::str::from_utf8(value) else {
            continue;
        };
        match name.as_slice() {
            b":method" => headers.method = Some(value.to_owned()),
            b":path" => headers.target = Some(value.to_owned()),
            b":authority" => headers.authority = Some(value.to_owned()),
            b":status" => headers.status = value.parse().ok(),
            _ => {}
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowlight_common::http2::{FLAG_END_HEADERS, FRAME_HEADERS, PREFACE};
    use flowlight_common::tls::{DIRECTION_IN, TLS_CHUNK_BYTES};
    use loona_hpack::Encoder;

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let length = payload.len() as u32;
        let mut out = vec![
            (length >> 16) as u8,
            (length >> 8) as u8,
            length as u8,
            kind,
            flags,
        ];
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn chunk(ssl: u64, bytes: &[u8]) -> TlsChunk {
        let mut chunk = TlsChunk {
            ssl,
            tgid: 4711,
            pid: 4711,
            len: bytes.len().min(TLS_CHUNK_BYTES) as u32,
            total: bytes.len() as u32,
            ..TlsChunk::zeroed()
        };
        let take = bytes.len().min(TLS_CHUNK_BYTES);
        chunk.data[..take].copy_from_slice(&bytes[..take]);
        chunk
    }

    /// The request an agent actually makes, encoded the way a real client encodes it.
    #[test]
    fn a_real_request_is_decoded_to_its_method_and_path() {
        let mut encoder = Encoder::new();
        let block = encoder.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (b":path", b"/v1/messages"),
            (b":authority", b"api.anthropic.com"),
            (b"content-type", b"application/json"),
        ]);
        let mut bytes = PREFACE.to_vec();
        bytes.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block));

        let mut connections = Connections::default();
        let events = connections.feed(&chunk(0xdead, &bytes));
        assert_eq!(
            events,
            vec![Event::Message(Headers {
                method: Some("POST".to_owned()),
                target: Some("/v1/messages".to_owned()),
                authority: Some("api.anthropic.com".to_owned()),
                status: None,
            })]
        );
    }

    /// HPACK's whole point: the second request on a connection refers to the first by index. Decoding it
    /// requires the table the first one built, which is why this is keyed on the connection.
    #[test]
    fn a_second_request_that_refers_back_to_the_first_is_decoded() {
        let mut encoder = Encoder::new();
        let mut connections = Connections::default();

        let first = encoder.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (b":authority", b"api.anthropic.com"),
        ]);
        connections.feed(&chunk(
            1,
            &frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &first),
        ));

        let second = encoder.encode([
            (b":method".as_slice(), b"POST".as_slice()),
            (b":authority", b"api.anthropic.com"),
            (b":path", b"/v1/messages"),
        ]);
        let events = connections.feed(&chunk(
            1,
            &frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &second),
        ));
        assert_eq!(
            events,
            vec![Event::Message(Headers {
                method: Some("POST".to_owned()),
                target: Some("/v1/messages".to_owned()),
                authority: Some("api.anthropic.com".to_owned()),
                status: None,
            })]
        );
    }

    /// The failure this design is built to avoid. Two connections through one decoder do not produce
    /// slightly worse output — they produce confident nonsense.
    #[test]
    fn two_connections_of_one_process_do_not_share_a_table() {
        let mut connections = Connections::default();
        let mut first_encoder = Encoder::new();
        let mut second_encoder = Encoder::new();

        let a = first_encoder.encode([
            (b":method".as_slice(), b"GET".as_slice()),
            (b":authority", b"api.anthropic.com"),
        ]);
        let b = second_encoder.encode([
            (b":method".as_slice(), b"GET".as_slice()),
            (b":authority", b"api.openai.com"),
        ]);
        connections.feed(&chunk(1, &frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &a)));
        connections.feed(&chunk(2, &frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &b)));

        // Each connection's second request refers back to its own table.
        let a2 = first_encoder.encode([
            (b":method".as_slice(), b"GET".as_slice()),
            (b":authority", b"api.anthropic.com"),
            (b":path", b"/one"),
        ]);
        let b2 = second_encoder.encode([
            (b":method".as_slice(), b"GET".as_slice()),
            (b":authority", b"api.openai.com"),
            (b":path", b"/two"),
        ]);
        let first = connections.feed(&chunk(1, &frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &a2)));
        let second = connections.feed(&chunk(2, &frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &b2)));

        assert_eq!(
            first,
            vec![Event::Message(Headers {
                method: Some("GET".to_owned()),
                target: Some("/one".to_owned()),
                authority: Some("api.anthropic.com".to_owned()),
                status: None
            })]
        );
        assert_eq!(
            second,
            vec![Event::Message(Headers {
                method: Some("GET".to_owned()),
                target: Some("/two".to_owned()),
                authority: Some("api.openai.com".to_owned()),
                status: None
            })]
        );
    }

    /// The two directions of one connection have separate tables, and mixing them is the same bug in
    /// miniature.
    #[test]
    fn the_two_directions_of_a_connection_have_separate_tables() {
        let mut connections = Connections::default();
        let mut encoder = Encoder::new();
        let block = encoder.encode([(b":status".as_slice(), b"429".as_slice())]);
        let mut inbound = chunk(1, &frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block));
        inbound.direction = DIRECTION_IN;
        let events = connections.feed(&inbound);
        assert_eq!(
            events,
            vec![Event::Message(Headers {
                status: Some(429),
                ..Headers::default()
            })]
        );
        assert_eq!(connections.len(), 1);
    }

    /// Joining a connection that was already open. The table we would decode against is not the one the
    /// sender has, so the result is plausible and wrong — which has to be said rather than shown.
    #[test]
    fn a_connection_joined_late_is_reported_as_unreadable_rather_than_guessed_at() {
        let mut connections = Connections::default();
        // An indexed reference to a dynamic table entry that, from here, does not exist.
        let block = [0xbe_u8, 0xbf];
        let events = connections.feed(&chunk(
            1,
            &frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block),
        ));
        assert!(
            matches!(events.as_slice(), [Event::Unreadable(_)]),
            "{events:?}"
        );
    }

    /// Once a connection is unreliable it stays that way, and says so once rather than every four
    /// kilobytes for the rest of a large upload.
    #[test]
    fn an_unreadable_connection_says_so_once() {
        let mut connections = Connections::default();
        let block = [0xbe_u8, 0xbf];
        let first = connections.feed(&chunk(
            1,
            &frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block),
        ));
        assert_eq!(first.len(), 1);
        let second = connections.feed(&chunk(
            1,
            &frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, &block),
        ));
        assert!(second.is_empty(), "{second:?}");
    }

    /// A body big enough to be truncated cuts the frame stream. The headers before it were already
    /// decoded; what must not happen is a later block being decoded against a table that has fallen behind.
    #[test]
    fn a_hole_through_a_header_block_makes_the_connection_unreadable() {
        let mut connections = Connections::default();
        let mut encoder = Encoder::new();
        let block = encoder.encode([(b":method".as_slice(), b"POST".as_slice())]);
        let frame = frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block);

        // Only the first few bytes captured, the rest of the frame reported as missing.
        let mut cut = chunk(1, &frame);
        cut.len = 10;
        cut.total = frame.len() as u32;
        let events = connections.feed(&cut);
        assert!(
            events.iter().any(|e| matches!(e, Event::Unreadable(_))),
            "{events:?}"
        );
    }

    #[test]
    fn a_goaway_forgets_the_connection() {
        let mut connections = Connections::default();
        let mut encoder = Encoder::new();
        let block = encoder.encode([(b":method".as_slice(), b"GET".as_slice())]);
        connections.feed(&chunk(
            1,
            &frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &block),
        ));
        assert_eq!(connections.len(), 1);

        let mut payload = 1_u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&0_u32.to_be_bytes());
        connections.feed(&chunk(1, &frame(0x7, 0, 0, &payload)));
        assert!(connections.is_empty());
    }

    /// A header value that is not text is not a header value. It must not stop the rest of the list being
    /// read, and it must not panic.
    #[test]
    fn a_header_value_that_is_not_text_is_skipped() {
        let list = [
            (b":method".to_vec(), vec![0xff, 0xfe]),
            (b":path".to_vec(), b"/ok".to_vec()),
        ];
        let headers = read_headers(&list);
        assert_eq!(headers.method, None);
        assert_eq!(headers.target.as_deref(), Some("/ok"));
    }
}
