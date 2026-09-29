//! Recognising what a lump of plaintext is, without pretending to more than that.
//!
//! What comes out of a uprobe is one buffer from one `SSL_write`. It may be a whole request, the first
//! fragment of one, the middle of a response body, or sixteen bytes of an HTTP/2 frame header. There is no
//! framing to rely on and no stream to reassemble yet, so this looks at a buffer and answers one question:
//! does this *begin* something recognisable?
//!
//! Returning `None` is the common and correct answer, and it matters that it stays correct. A summariser
//! that guesses turns the middle of a JPEG into a request for `/þÿ` and prints it with a straight face.

/// The HTTP/2 connection preface, which every HTTP/2 client sends before anything else.
const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The methods worth recognising. Anything else at the start of a buffer is not a request as far as this is
/// concerned, which is the right bias: a false negative is a missing line and a false positive is a lie.
const METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT",
];

/// What a buffer turned out to begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Summary<'a> {
    /// An HTTP/1.x request line, and the `Host` header if it was in the same buffer.
    Request {
        /// `GET`, `POST`, and so on.
        method: &'a str,
        /// The request target, as sent.
        target: &'a str,
        /// The `Host` header, when this buffer reached it.
        host: Option<&'a str>,
    },
    /// An HTTP/1.x status line.
    Response {
        /// The status code.
        status: u16,
        /// The reason phrase, which servers are free to make up.
        reason: &'a str,
    },
    /// The HTTP/2 connection preface.
    ///
    /// Everything after it is binary frames with HPACK-compressed headers, which means the method and path
    /// of an HTTP/2 request are *not* readable from a single buffer the way an HTTP/1.1 request line is.
    /// Recognising the preface is how the interface can say that plainly instead of showing nothing.
    Http2Preface,
}

/// What a buffer begins, if it begins anything.
pub fn summarise(bytes: &[u8]) -> Option<Summary<'_>> {
    if bytes.starts_with(HTTP2_PREFACE) {
        return Some(Summary::Http2Preface);
    }
    let first_line = line(bytes)?;
    if let Some(rest) = first_line.strip_prefix("HTTP/1.") {
        return status_line(rest);
    }
    request_line(first_line, bytes)
}

/// The first CRLF-terminated line, as text, or `None` if there is not one in what we have.
///
/// LF alone is accepted because some clients send it; a line with no terminator at all is not accepted,
/// because a truncated buffer would otherwise produce a request for half a path.
fn line(bytes: &[u8]) -> Option<&str> {
    let end = bytes.iter().position(|&b| b == b'\n')?;
    let line = bytes.get(..end)?;
    let line = match line.split_last() {
        Some((b'\r', head)) => head,
        _ => line,
    };
    core::str::from_utf8(line).ok()
}

/// `1 200 OK` — everything after `HTTP/1.`
fn status_line(rest: &str) -> Option<Summary<'_>> {
    let mut parts = rest.splitn(3, ' ');
    // The minor version, which nothing here does anything with.
    let _ = parts.next()?;
    let status = parts.next()?.parse().ok()?;
    Some(Summary::Response {
        status,
        reason: parts.next().unwrap_or("").trim(),
    })
}

/// `GET /path HTTP/1.1`, plus a look through the headers for `Host`.
fn request_line<'a>(first_line: &'a str, bytes: &'a [u8]) -> Option<Summary<'a>> {
    let mut parts = first_line.split(' ');
    let method = parts.next()?;
    if !METHODS.contains(&method) {
        return None;
    }
    let target = parts.next()?;
    // Insisting on the version keeps this from matching a line of prose that happens to start with `PATCH`.
    let version = parts.next()?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return None;
    }
    Some(Summary::Request {
        method,
        target,
        host: host_header(bytes),
    })
}

/// The value of the `Host` header, if the buffer reached it.
///
/// Stops at the blank line that ends the headers, so a body containing something that looks like a header
/// cannot contribute one.
fn host_header(bytes: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(bytes).ok()?;
    for line in text.split('\n').skip(1) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            return Some(value.trim());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_read_with_its_host() {
        let bytes = b"GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(
            summarise(bytes),
            Some(Summary::Request {
                method: "GET",
                target: "/v1/messages",
                host: Some("api.anthropic.com")
            })
        );
    }

    /// Header names are case-insensitive and real clients disagree about which case to use.
    #[test]
    fn the_host_header_is_found_whatever_case_it_arrives_in() {
        let bytes = b"POST / HTTP/1.1\r\nhost: example.com\r\n\r\n";
        assert!(matches!(
            summarise(bytes),
            Some(Summary::Request {
                host: Some("example.com"),
                ..
            })
        ));
    }

    /// A request split across two `SSL_write` calls arrives without its headers. The request line is still
    /// the truth; the host simply is not in this buffer.
    #[test]
    fn a_request_without_its_headers_yet_has_no_host_rather_than_a_wrong_one() {
        assert_eq!(
            summarise(b"GET / HTTP/1.1\r\n"),
            Some(Summary::Request {
                method: "GET",
                target: "/",
                host: None
            })
        );
    }

    /// A `Host:` line inside a body is not a header. Stopping at the blank line is what makes that true.
    #[test]
    fn a_host_line_in_the_body_is_not_a_header() {
        let bytes = b"POST / HTTP/1.1\r\nContent-Length: 20\r\n\r\nHost: evil.example\r\n";
        assert!(matches!(
            summarise(bytes),
            Some(Summary::Request { host: None, .. })
        ));
    }

    #[test]
    fn a_response_is_read_with_its_status() {
        assert_eq!(
            summarise(b"HTTP/1.1 429 Too Many Requests\r\nRetry-After: 5\r\n\r\n"),
            Some(Summary::Response {
                status: 429,
                reason: "Too Many Requests"
            })
        );
    }

    /// The reason phrase is whatever the server felt like sending, including nothing.
    #[test]
    fn a_response_with_no_reason_phrase_is_still_a_response() {
        assert_eq!(
            summarise(b"HTTP/1.1 204\r\n\r\n"),
            Some(Summary::Response {
                status: 204,
                reason: ""
            })
        );
    }

    /// The traffic that matters most here is HTTP/2: every current agent API is. Its headers are HPACK, so
    /// the preface is the only thing readable from a single buffer, and the interface should say so rather
    /// than show an empty line.
    #[test]
    fn the_http2_preface_is_recognised_for_what_it_is() {
        assert_eq!(
            summarise(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x12\x04\x00"),
            Some(Summary::Http2Preface)
        );
    }

    /// The whole point of the exercise. A summariser that guesses turns the middle of a response body into a
    /// request for a path made of mojibake and prints it as fact.
    #[test]
    fn a_buffer_that_begins_nothing_is_reported_as_nothing() {
        assert_eq!(summarise(&[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), None);
        assert_eq!(summarise(b"\x00\x00\x12\x04\x00\x00\x00\x00\x00"), None);
        assert_eq!(summarise(b""), None);
        assert_eq!(summarise(b"{\"model\":\"claude\"}\n"), None);
    }

    /// `GET` at the start of a sentence in a body is not a request line. Insisting on the version is what
    /// separates the two.
    #[test]
    fn prose_that_starts_with_a_method_is_not_a_request() {
        assert_eq!(summarise(b"GET the thing from the shelf\r\n"), None);
        assert_eq!(summarise(b"POST /path\r\n"), None);
    }

    /// A buffer cut off before its first newline could be half a path. Half a path printed as a whole one is
    /// worse than nothing at all.
    #[test]
    fn a_line_with_no_terminator_is_not_a_line() {
        assert_eq!(summarise(b"GET /very-long-pa"), None);
    }

    /// Nothing here may panic on a buffer chosen by whoever is on the other end of the connection.
    #[test]
    fn nothing_in_a_hostile_buffer_causes_a_panic() {
        for bytes in [
            b"GET".as_slice(),
            b"HTTP/1.".as_slice(),
            b"HTTP/1.1\r\n".as_slice(),
            b"HTTP/1.1 not-a-number OK\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost\r\n".as_slice(),
            b"GET / HTTP/1.1\n\xff\xfe: x\n".as_slice(),
            &[b'\n'; 64],
        ] {
            let _ = summarise(bytes);
        }
    }
}
