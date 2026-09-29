//! Following an HTTP/2 byte stream well enough to find the header blocks in it.
//!
//! This is the release that decides whether the project is a demonstration or a tool. Every current agent
//! API — Anthropic's, OpenAI's, Google's — speaks HTTP/2, and an HTTP/2 request's method and path are not
//! text in the stream. They are HPACK: indices into a table built across the whole connection, in order,
//! from the first header block onwards. Reading them requires following the frames.
//!
//! # The two things that make this harder than a frame parser
//!
//! **Interleaving.** One process's buffers from two connections arrive mixed together, and HPACK state is
//! per connection. Mixing two connections' header blocks into one decoder does not degrade the output, it
//! destroys it. So every stream here is keyed on the `SSL *` the call was made on, which [`crate::tls`]
//! carries for exactly this reason.
//!
//! **Holes.** Only the first four kilobytes of any one call are captured, so a large write leaves a gap in
//! the byte stream. Frames are length-prefixed, which means a gap of *known* size can be stepped over
//! exactly — and [`crate::tls::TlsChunk::total`] gives the size. A 60KB request body therefore costs the
//! body and nothing else: the headers around it are still found, because they were in their own small write.
//!
//! When a gap does land somewhere unrecoverable — across a frame header, so the next frame's position is
//! unknown — this says [`Record::Desynchronised`] rather than guessing. It then tries to pick the stream up
//! again at the start of the next call, because implementations write whole frames, and reports that too.
//! Both are facts about how much of the connection was seen, which is the whole subject of 0.1.6.

use alloc::vec::Vec;

/// The connection preface every HTTP/2 client sends before its first frame.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Every frame begins with nine bytes: length, type, flags, stream identifier.
pub const FRAME_HEADER_BYTES: usize = 9;

/// `DATA`.
pub const FRAME_DATA: u8 = 0x0;
/// `HEADERS`.
pub const FRAME_HEADERS: u8 = 0x1;
/// `RST_STREAM`.
pub const FRAME_RST_STREAM: u8 = 0x3;
/// `GOAWAY`.
pub const FRAME_GOAWAY: u8 = 0x7;
/// `CONTINUATION`.
pub const FRAME_CONTINUATION: u8 = 0x9;
/// The highest frame type RFC 9113 defines. Anything above it is an extension, and its presence at the front
/// of a buffer is good evidence that the buffer is not a frame at all.
pub const FRAME_TYPE_MAX: u8 = 0x9;

/// `END_STREAM`.
pub const FLAG_END_STREAM: u8 = 0x01;
/// `END_HEADERS`.
pub const FLAG_END_HEADERS: u8 = 0x04;
/// `PADDED`.
pub const FLAG_PADDED: u8 = 0x08;
/// `PRIORITY`, on a `HEADERS` frame.
pub const FLAG_PRIORITY: u8 = 0x20;

/// The largest frame anything sane negotiates. `SETTINGS_MAX_FRAME_SIZE` may be up to 2^24-1, but no
/// implementation asks for it, and the number is only used to decide whether a buffer plausibly begins a
/// frame when trying to recover from a hole.
const PLAUSIBLE_FRAME_LIMIT: u32 = 1 << 20;

/// A frame's nine-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// Payload length, not counting these nine bytes.
    pub length: u32,
    /// `DATA`, `HEADERS`, and so on.
    pub kind: u8,
    /// Type-specific flags.
    pub flags: u8,
    /// The stream, with the reserved bit already cleared.
    pub stream: u32,
}

impl FrameHeader {
    /// Reads a header out of the first nine bytes, or `None` if there are not nine.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let header: &[u8; FRAME_HEADER_BYTES] = bytes.get(..FRAME_HEADER_BYTES)?.try_into().ok()?;
        let [l0, l1, l2, kind, flags, s0, s1, s2, s3] = *header;
        Some(Self {
            length: u32::from_be_bytes([0, l0, l1, l2]),
            kind,
            flags,
            // The top bit is reserved and senders are required to leave it clear, but a reader that trusts
            // that reports stream 2147483649 the one time somebody does not.
            stream: u32::from_be_bytes([s0, s1, s2, s3]) & 0x7fff_ffff,
        })
    }

    /// The whole frame's size, header included.
    pub fn total(&self) -> usize {
        FRAME_HEADER_BYTES + self.length as usize
    }

    /// Whether this looks like a real frame header rather than the middle of something else.
    ///
    /// Only used when trying to pick a stream up after a hole, where the alternative is to interpret
    /// whatever bytes happen to be there as a frame and report the result.
    fn is_plausible(&self) -> bool {
        self.kind <= FRAME_TYPE_MAX && self.length <= PLAUSIBLE_FRAME_LIMIT
    }

    /// Whether this frame carries a piece of a header block.
    pub fn carries_headers(&self) -> bool {
        self.kind == FRAME_HEADERS || self.kind == FRAME_CONTINUATION
    }
}

/// The header block fragment inside a frame's payload, with padding and priority removed.
///
/// `HEADERS` may carry a pad length, five bytes of stream priority, and trailing padding, none of which is
/// part of the compressed header block. Feeding them to an HPACK decoder corrupts its table, and a corrupt
/// table means every subsequent request on the connection decodes to nonsense rather than failing.
pub fn header_block<'a>(header: &FrameHeader, payload: &'a [u8]) -> Option<&'a [u8]> {
    if header.kind == FRAME_CONTINUATION {
        return Some(payload);
    }
    if header.kind != FRAME_HEADERS {
        return None;
    }
    let mut rest = payload;
    let mut padding = 0_usize;
    if header.flags & FLAG_PADDED != 0 {
        let (first, tail) = rest.split_first()?;
        padding = *first as usize;
        rest = tail;
    }
    if header.flags & FLAG_PRIORITY != 0 {
        rest = rest.get(5..)?;
    }
    rest.get(..rest.len().checked_sub(padding)?)
}

/// What following the stream produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Record {
    /// A complete header block, ready for an HPACK decoder.
    Headers {
        /// The stream it belongs to.
        stream: u32,
        /// The concatenated fragments, with padding and priority already removed.
        block: Vec<u8>,
        /// Whether the request or response ends here, with no body.
        end_stream: bool,
    },
    /// A header block that a hole ran through, so it cannot be decoded.
    ///
    /// Worse than losing one request: HPACK's table advances with every block, so a block that is skipped
    /// leaves the decoder describing a table the sender does not have. Everything after it on this
    /// connection is unreliable, and saying so is the only honest response.
    HeadersLost {
        /// The stream it belonged to.
        stream: u32,
        /// How many bytes of it were never captured.
        missing: usize,
    },
    /// A body frame. The payload is not kept; only how much of it there was.
    Data {
        /// The stream.
        stream: u32,
        /// How many bytes the frame declared.
        length: u32,
        /// Whether the message ends here.
        end_stream: bool,
    },
    /// The peer is closing the connection.
    GoAway {
        /// The last stream it processed.
        last_stream: u32,
        /// The error code, zero for a clean shutdown.
        code: u32,
    },
    /// One stream was cancelled.
    Reset {
        /// The stream.
        stream: u32,
        /// The error code.
        code: u32,
    },
    /// A hole landed where the next frame's position could not be worked out.
    Desynchronised,
    /// The stream was picked up again at the start of a later call.
    Resynchronised,
}

/// Follows one direction of one HTTP/2 connection.
#[derive(Debug, Default)]
pub struct Stream {
    /// Captured bytes of the frame currently being assembled.
    buffer: Vec<u8>,
    /// Header block fragments collected so far, and the stream they belong to.
    block: Vec<u8>,
    /// The stream the block belongs to, and whether its frame carried `END_STREAM`.
    block_stream: u32,
    block_end_stream: bool,
    /// Whether a hole ran through the block being collected.
    block_holed: usize,
    /// Stream bytes still to be discarded before what is buffered continues.
    skip: usize,
    /// Whether the preface has been stepped over.
    saw_preface: bool,
    /// Whether the frame boundaries are currently unknown.
    lost: bool,
}

impl Stream {
    /// A new, empty stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether frame boundaries are currently unknown.
    pub fn is_desynchronised(&self) -> bool {
        self.lost
    }

    /// Feeds one captured buffer, followed by a hole of `missing` bytes that were not captured.
    pub fn feed(&mut self, bytes: &[u8], missing: usize) -> Vec<Record> {
        let mut records = Vec::new();
        let mut bytes = bytes;

        if self.lost {
            // Implementations write whole frames, so the start of a call is the likeliest place for a frame
            // to begin. If what is here looks like one, take it; otherwise wait for the next call.
            if FrameHeader::parse(bytes).is_some_and(|h| h.is_plausible()) {
                self.lost = false;
                self.skip = 0;
                self.buffer.clear();
                self.block.clear();
                records.push(Record::Resynchronised);
            } else {
                return records;
            }
        }

        if !self.saw_preface && self.buffer.is_empty() {
            if let Some(rest) = bytes.strip_prefix(PREFACE) {
                bytes = rest;
            }
            // Only the client sends it, so not seeing one is not an error — it is the server's direction.
            self.saw_preface = true;
        }

        let dropped = self.skip.min(bytes.len());
        self.skip -= dropped;
        bytes = bytes.get(dropped..).unwrap_or(&[]);
        if self.skip > 0 {
            // The whole call fell inside a hole we already knew about.
            self.skip += missing;
            return records;
        }

        self.buffer.extend_from_slice(bytes);
        self.drain(&mut records);
        if missing > 0 {
            self.absorb(missing, &mut records);
        }
        records
    }

    /// Consumes every frame that is complete in the buffer.
    fn drain(&mut self, records: &mut Vec<Record>) {
        let mut consumed = 0;
        while let Some(header) = FrameHeader::parse(self.buffer.get(consumed..).unwrap_or(&[])) {
            let Some(frame) = self
                .buffer
                .get(consumed..consumed + header.total())
                .map(<[u8]>::to_vec)
            else {
                break;
            };
            consumed += header.total();
            let payload = frame.get(FRAME_HEADER_BYTES..).unwrap_or(&[]);
            self.record(&header, payload, records);
        }
        self.buffer.drain(..consumed);
    }

    /// Steps over a hole of known size, reporting whatever it ran through.
    fn absorb(&mut self, mut missing: usize, records: &mut Vec<Record>) {
        // Anything left in the buffer is the start of a frame the hole interrupts. Without its header there
        // is no length, and without a length the next frame's position is unknown.
        let Some(header) = FrameHeader::parse(&self.buffer) else {
            self.desynchronise(records);
            return;
        };
        let outstanding = header.total().saturating_sub(self.buffer.len());
        if header.carries_headers() {
            // The block is ruined whether the hole ends inside this frame or past it.
            self.block_holed += outstanding.min(missing);
            self.block_stream = header.stream;
        } else if header.kind == FRAME_DATA {
            records.push(Record::Data {
                stream: header.stream,
                length: header.length,
                end_stream: header.flags & FLAG_END_STREAM != 0,
            });
        }
        self.buffer.clear();

        if outstanding > missing {
            // The hole ends inside this frame; the rest of it arrives next and is of no further interest.
            self.skip = outstanding - missing;
            return;
        }
        missing -= outstanding;
        if missing == 0 {
            // The hole ended exactly on a frame boundary, which is luck rather than design.
            self.flush_holed_block(records);
            return;
        }
        // Somewhere inside the next frame's header, so where it starts is unknown.
        self.desynchronise(records);
    }

    /// Gives up on following frames, and says so.
    fn desynchronise(&mut self, records: &mut Vec<Record>) {
        self.lost = true;
        self.buffer.clear();
        self.skip = 0;
        self.flush_holed_block(records);
        records.push(Record::Desynchronised);
    }

    /// Reports a header block that a hole ran through, if one was being collected.
    fn flush_holed_block(&mut self, records: &mut Vec<Record>) {
        if self.block_holed > 0 {
            records.push(Record::HeadersLost {
                stream: self.block_stream,
                missing: self.block_holed,
            });
            self.block_holed = 0;
            self.block.clear();
        }
    }

    /// Turns one complete frame into whatever it is worth reporting.
    fn record(&mut self, header: &FrameHeader, payload: &[u8], records: &mut Vec<Record>) {
        match header.kind {
            FRAME_HEADERS | FRAME_CONTINUATION => {
                if header.kind == FRAME_HEADERS {
                    self.block_stream = header.stream;
                    self.block_end_stream = header.flags & FLAG_END_STREAM != 0;
                }
                if let Some(fragment) = header_block(header, payload) {
                    self.block.extend_from_slice(fragment);
                } else {
                    // A payload too short for its own padding or priority fields. Feeding the decoder
                    // anything from it would leave its table wrong for the rest of the connection.
                    self.block_holed += 1;
                }
                if header.flags & FLAG_END_HEADERS != 0 {
                    if self.block_holed > 0 {
                        self.flush_holed_block(records);
                    } else {
                        records.push(Record::Headers {
                            stream: self.block_stream,
                            block: core::mem::take(&mut self.block),
                            end_stream: self.block_end_stream,
                        });
                    }
                }
            }
            FRAME_DATA => records.push(Record::Data {
                stream: header.stream,
                length: header.length,
                end_stream: header.flags & FLAG_END_STREAM != 0,
            }),
            FRAME_GOAWAY => {
                if let (Some(last), Some(code)) = (payload.get(..4), payload.get(4..8)) {
                    records.push(Record::GoAway {
                        last_stream: be32(last) & 0x7fff_ffff,
                        code: be32(code),
                    });
                }
            }
            FRAME_RST_STREAM => {
                if let Some(code) = payload.get(..4) {
                    records.push(Record::Reset {
                        stream: header.stream,
                        code: be32(code),
                    });
                }
            }
            // SETTINGS, PING, WINDOW_UPDATE, PRIORITY and anything an extension adds. Read past, because
            // their lengths are what keeps the frame boundaries right, and otherwise ignored.
            _ => {}
        }
    }
}

/// A big-endian `u32` from exactly four bytes.
fn be32(bytes: &[u8]) -> u32 {
    match bytes {
        [a, b, c, d] => u32::from_be_bytes([*a, *b, *c, *d]),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

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

    #[test]
    fn a_frame_header_is_read_whole() {
        let bytes = frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, b"abc");
        let header = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(header.length, 3);
        assert_eq!(header.kind, FRAME_HEADERS);
        assert_eq!(header.stream, 1);
        assert_eq!(header.total(), 12);
    }

    /// The top bit of the stream identifier is reserved. A reader that trusts senders to leave it clear
    /// reports stream 2147483649 the one time somebody does not.
    #[test]
    fn the_reserved_bit_of_a_stream_identifier_is_ignored() {
        let mut bytes = frame(FRAME_DATA, 0, 1, b"");
        bytes[5] |= 0x80;
        assert_eq!(FrameHeader::parse(&bytes).unwrap().stream, 1);
    }

    /// Padding and priority are not part of the compressed block. Feeding them to a decoder corrupts its
    /// table, and a corrupt table means every later request decodes to nonsense rather than failing.
    #[test]
    fn padding_and_priority_are_stripped_from_a_header_block() {
        // pad length 2, priority (5 bytes), block, 2 bytes of padding
        let mut payload = vec![2, 0, 0, 0, 1, 7];
        payload.extend_from_slice(b"BLOCK");
        payload.extend_from_slice(&[0, 0]);
        let bytes = frame(FRAME_HEADERS, FLAG_PADDED | FLAG_PRIORITY, 1, &payload);
        let header = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(header_block(&header, &payload), Some(b"BLOCK".as_slice()));
    }

    #[test]
    fn a_payload_too_short_for_its_own_padding_yields_nothing() {
        let payload = [200_u8, 1, 2];
        let header = FrameHeader::parse(&frame(FRAME_HEADERS, FLAG_PADDED, 1, &payload)).unwrap();
        assert_eq!(header_block(&header, &payload), None);
    }

    #[test]
    fn a_whole_request_arrives_as_one_header_block() {
        let mut stream = Stream::new();
        let mut bytes = PREFACE.to_vec();
        bytes.extend(frame(
            FRAME_HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1,
            b"HPACK",
        ));
        let records = stream.feed(&bytes, 0);
        assert_eq!(
            records,
            vec![Record::Headers {
                stream: 1,
                block: b"HPACK".to_vec(),
                end_stream: true
            }]
        );
    }

    /// A block too big for one frame continues in `CONTINUATION` frames, and the decoder needs all of it at
    /// once because HPACK is a single compressed run.
    #[test]
    fn a_block_split_across_continuation_frames_is_rejoined() {
        let mut stream = Stream::new();
        let mut bytes = frame(FRAME_HEADERS, 0, 3, b"HP");
        bytes.extend(frame(FRAME_CONTINUATION, 0, 3, b"AC"));
        bytes.extend(frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 3, b"K"));
        let records = stream.feed(&bytes, 0);
        assert_eq!(
            records,
            vec![Record::Headers {
                stream: 3,
                block: b"HPACK".to_vec(),
                end_stream: false
            }]
        );
    }

    /// Frames do not line up with the four-kilobyte capture, so a frame split across two calls is the
    /// normal case rather than the exception.
    #[test]
    fn a_frame_split_across_two_calls_is_rejoined() {
        let mut stream = Stream::new();
        let bytes = frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, b"HPACK");
        assert!(stream.feed(bytes.get(..7).unwrap(), 0).is_empty());
        assert!(stream.feed(bytes.get(7..11).unwrap(), 0).is_empty());
        let records = stream.feed(bytes.get(11..).unwrap(), 0);
        assert_eq!(records.len(), 1);
    }

    /// The point of the whole exercise. A 60KB body is not captured, but its frame says how long it is, so
    /// the hole can be stepped over exactly and the request after it is still read.
    #[test]
    fn a_hole_in_a_body_costs_the_body_and_nothing_else() {
        let mut stream = Stream::new();
        let mut first = frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, b"REQUEST");
        // A DATA frame of 5000 bytes, of which only 100 were captured.
        first.extend(frame(FRAME_DATA, FLAG_END_STREAM, 1, &[0; 5000]));
        let captured = first.get(..first.len() - 4900).unwrap();

        let mut records = stream.feed(captured, 4900);
        assert_eq!(
            records.first(),
            Some(&Record::Headers {
                stream: 1,
                block: b"REQUEST".to_vec(),
                end_stream: false
            })
        );
        assert!(!stream.is_desynchronised());

        // The next request on the same connection is still found.
        records = stream.feed(&frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, b"SECOND"), 0);
        assert_eq!(
            records,
            vec![Record::Headers {
                stream: 3,
                block: b"SECOND".to_vec(),
                end_stream: false
            }]
        );
    }

    /// A hole that runs past the end of a frame lands in the next frame's header, where there is nothing to
    /// work from. Guessing would mean reading arbitrary bytes as a length.
    #[test]
    fn a_hole_across_a_frame_boundary_is_reported_rather_than_guessed_at() {
        let mut stream = Stream::new();
        let mut bytes = frame(FRAME_DATA, 0, 1, &[0; 100]);
        bytes.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 3, b"LOST"));
        let captured = bytes.get(..50).unwrap();
        let records = stream.feed(captured, bytes.len() - 50);
        assert!(records.contains(&Record::Desynchronised));
        assert!(stream.is_desynchronised());
    }

    /// Implementations write whole frames, so the start of the next call is the likeliest place for one to
    /// begin. Taking it back up is worth doing, and worth saying.
    #[test]
    fn a_lost_stream_is_picked_up_again_at_the_next_call() {
        let mut stream = Stream::new();
        stream.feed(frame(FRAME_DATA, 0, 1, &[0; 100]).get(..50).unwrap(), 4000);
        assert!(stream.is_desynchronised());

        let records = stream.feed(&frame(FRAME_HEADERS, FLAG_END_HEADERS, 5, b"AGAIN"), 0);
        assert_eq!(records.first(), Some(&Record::Resynchronised));
        assert!(records.contains(&Record::Headers {
            stream: 5,
            block: b"AGAIN".to_vec(),
            end_stream: false
        }));
    }

    /// Bytes that are not a frame are not treated as one, or recovery would produce a stream of invented
    /// frames rather than nothing.
    #[test]
    fn recovery_does_not_accept_bytes_that_are_not_a_frame() {
        let mut stream = Stream::new();
        stream.feed(frame(FRAME_DATA, 0, 1, &[0; 100]).get(..50).unwrap(), 4000);
        assert!(
            stream
                .feed(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff", 0)
                .is_empty()
        );
        assert!(stream.is_desynchronised());
    }

    /// A block that a hole ran through must not reach the decoder: HPACK's table advances with every block,
    /// so a skipped one leaves the decoder describing a table the sender does not have.
    #[test]
    fn a_header_block_with_a_hole_in_it_is_reported_as_lost_rather_than_decoded() {
        let mut stream = Stream::new();
        let bytes = frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, &[7; 200]);
        // Sixty bytes captured, the rest of the frame missing, and the hole ends on its boundary.
        let records = stream.feed(bytes.get(..60).unwrap(), bytes.len() - 60);
        assert_eq!(
            records,
            vec![Record::HeadersLost {
                stream: 1,
                missing: 149
            }]
        );
    }

    #[test]
    fn a_goaway_is_read_with_its_code() {
        let mut stream = Stream::new();
        let mut payload = 7_u32.to_be_bytes().to_vec();
        payload.extend_from_slice(&11_u32.to_be_bytes());
        let records = stream.feed(&frame(FRAME_GOAWAY, 0, 0, &payload), 0);
        assert_eq!(
            records,
            vec![Record::GoAway {
                last_stream: 7,
                code: 11
            }]
        );
    }

    /// Frames nothing here acts on still have to be read past, because their lengths are what keeps every
    /// later frame boundary right.
    #[test]
    fn frames_that_are_ignored_are_still_stepped_over() {
        let mut stream = Stream::new();
        let mut bytes = frame(0x4, 0, 0, &[0; 18]); // SETTINGS
        bytes.extend(frame(0x8, 0, 0, &[0; 4])); // WINDOW_UPDATE
        bytes.extend(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, b"AFTER"));
        let records = stream.feed(&bytes, 0);
        assert_eq!(
            records,
            vec![Record::Headers {
                stream: 1,
                block: b"AFTER".to_vec(),
                end_stream: false
            }]
        );
    }

    /// Nothing here may panic on bytes chosen by whoever is on the other end of the connection.
    #[test]
    fn nothing_in_a_hostile_stream_causes_a_panic() {
        for bytes in [
            b"".as_slice(),
            b"\x00".as_slice(),
            b"\xff\xff\xff\x01\xff\xff\xff\xff\xff".as_slice(),
            &[0xff; 64],
            PREFACE,
        ] {
            let mut stream = Stream::new();
            let _ = stream.feed(bytes, 0);
            let _ = stream.feed(bytes, 9999);
            let _ = stream.feed(bytes, 0);
        }
    }
}
