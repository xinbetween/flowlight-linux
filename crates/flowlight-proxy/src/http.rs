//! Reading just enough HTTP/1.1 to decide about a request, and passing the rest through untouched.
//!
//! The proxy exists to *decide*, not to observe: everything Flowlight knows about what a process said it
//! learnt from the TLS library before encryption, and it still does while interception is on. So nothing here
//! buffers a body or looks inside one. A head is read, a decision is made, and the body is copied through byte
//! for byte with the framing the sender chose.
//!
//! # Why the framing is worked out rather than guessed
//!
//! Because getting it wrong is a hang. A response with no `Content-Length` and no chunking ends at the close of
//! the connection; a `HEAD` has no body however much its headers promise; a 304 has none either. Each of those,
//! read the wrong way, leaves the proxy waiting for bytes that are never coming while the client waits for it.

use anyhow::{Context as _, Result, bail};
use flowlight_rules::Mock;
use std::io::{BufRead, Read, Write};

/// The most a head may be. Larger than any real one and small enough that a sender which never sends `\r\n\r\n`
/// cannot make this grow without limit.
const MOST_HEAD: usize = 64 * 1024;

/// The most of a request body that is drained before answering with a mock.
///
/// A client that is uploading when its request is refused has to be read to the end or it sees the connection
/// break rather than the answer. Past this it is read no further and the connection is closed, which is the
/// honest outcome for an upload nobody upstream is going to receive.
const MOST_DRAIN: u64 = 16 * 1024 * 1024;

/// A request's first line and its headers. Never its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// `GET`, uppercased as it is on the wire.
    pub method: String,
    /// The request target, as written.
    pub target: String,
    /// `HTTP/1.1`, or whatever was claimed.
    pub version: String,
    /// The headers, in the order they arrived, with their names as they were written.
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// One header, by name, case-insensitively.
    pub fn header(&self, wanted: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.as_str())
    }

    /// The host this request is for.
    ///
    /// The `Host` header, with its port taken off. An absolute-form target — which a client only sends to a
    /// proxy it knows about — is read too, because a redirected client does not know it is talking to one and
    /// something else on the machine might.
    pub fn host(&self) -> Option<String> {
        if let Some(rest) = self
            .target
            .strip_prefix("http://")
            .or_else(|| self.target.strip_prefix("https://"))
            && let Some(authority) = rest.split(['/', '?', '#']).next()
            && !authority.is_empty()
        {
            return Some(without_port(authority));
        }
        self.header("host")
            .map(without_port)
            .filter(|host| !host.is_empty())
    }

    /// The path, which is the target with any absolute form taken off.
    pub fn path(&self) -> String {
        for scheme in ["http://", "https://"] {
            if let Some(rest) = self.target.strip_prefix(scheme) {
                return match rest.find('/') {
                    Some(at) => rest.get(at..).unwrap_or("/").to_owned(),
                    None => "/".to_owned(),
                };
            }
        }
        self.target.clone()
    }

    /// The head as it goes back on the wire.
    ///
    /// Written out again rather than copied, because a header removed here — `Proxy-Connection`, say — must not
    /// survive in a copy of the original bytes.
    pub fn bytes(&self) -> Vec<u8> {
        let mut text = format!("{} {} {}\r\n", self.method, self.target, self.version);
        for (name, value) in &self.headers {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        text.push_str("\r\n");
        text.into_bytes()
    }
}

/// A response's status line and headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// `HTTP/1.1`.
    pub version: String,
    /// The code.
    pub code: u16,
    /// The reason, as sent, which may be empty.
    pub reason: String,
    /// The headers.
    pub headers: Vec<(String, String)>,
}

impl Status {
    /// One header, by name, case-insensitively.
    pub fn header(&self, wanted: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(wanted))
            .map(|(_, value)| value.as_str())
    }

    /// The status line and headers, back on the wire.
    pub fn bytes(&self) -> Vec<u8> {
        let mut text = if self.reason.is_empty() {
            format!("{} {}\r\n", self.version, self.code)
        } else {
            format!("{} {} {}\r\n", self.version, self.code, self.reason)
        };
        for (name, value) in &self.headers {
            text.push_str(&format!("{name}: {value}\r\n"));
        }
        text.push_str("\r\n");
        text.into_bytes()
    }
}

/// How the body after a head is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// There is no body at all.
    Nothing,
    /// This many bytes.
    Length(u64),
    /// Chunks, until a zero-length one.
    Chunked,
    /// Until the connection closes, which also means this connection cannot be reused.
    UntilClose,
}

/// Reads a request's head, or nothing when the connection ended cleanly first.
pub fn read_head<R: BufRead>(from: &mut R) -> Result<Option<Head>> {
    let Some(lines) = read_lines(from)? else {
        return Ok(None);
    };
    let mut lines = lines.into_iter();
    let first = lines.next().unwrap_or_default();
    let mut words = first.split_whitespace();
    let method = words.next().unwrap_or_default().to_owned();
    let target = words.next().unwrap_or_default().to_owned();
    let version = words.next().unwrap_or("HTTP/1.1").to_owned();
    if method.is_empty() || target.is_empty() {
        bail!("a request began with `{first}`, which is not a request line");
    }
    Ok(Some(Head {
        method,
        target,
        version,
        headers: headers_of(lines),
    }))
}

/// Reads a response's status line and headers.
pub fn read_status<R: BufRead>(from: &mut R) -> Result<Option<Status>> {
    let Some(lines) = read_lines(from)? else {
        return Ok(None);
    };
    let mut lines = lines.into_iter();
    let first = lines.next().unwrap_or_default();
    let mut words = first.splitn(3, ' ');
    let version = words.next().unwrap_or_default().to_owned();
    let code: u16 =
        words.next().unwrap_or_default().parse().with_context(|| {
            format!("a response began with `{first}`, which has no status in it")
        })?;
    let reason = words.next().unwrap_or_default().to_owned();
    Ok(Some(Status {
        version,
        code,
        reason,
        headers: headers_of(lines),
    }))
}

/// How a request's body is delimited.
pub fn framing_of_request(head: &Head) -> Framing {
    if head
        .header("transfer-encoding")
        .is_some_and(|value| value.to_lowercase().contains("chunked"))
    {
        return Framing::Chunked;
    }
    match head
        .header("content-length")
        .and_then(|value| value.trim().parse().ok())
    {
        Some(0) | None => Framing::Nothing,
        Some(length) => Framing::Length(length),
    }
}

/// How a response's body is delimited, which depends on the request it answers.
pub fn framing_of_response(request: &Head, status: &Status) -> Framing {
    // A HEAD is answered with the headers of a GET and none of its body, however much Content-Length says.
    // Reading the promised bytes here waits for a body that is never sent.
    if request.method.eq_ignore_ascii_case("head")
        || status.code == 204
        || status.code == 304
        || (100..200).contains(&status.code)
    {
        return Framing::Nothing;
    }
    if status
        .header("transfer-encoding")
        .is_some_and(|value| value.to_lowercase().contains("chunked"))
    {
        return Framing::Chunked;
    }
    match status
        .header("content-length")
        .and_then(|value| value.trim().parse().ok())
    {
        Some(0) => Framing::Nothing,
        Some(length) => Framing::Length(length),
        // No length and no chunking: the body is whatever arrives before the close.
        None => Framing::UntilClose,
    }
}

/// Copies a body from one side to the other, byte for byte.
///
/// Nothing is buffered whole and nothing is looked at. A chunked body is copied chunk by chunk with its sizes
/// intact rather than being decoded and re-encoded, because re-encoding it would change bytes that the sender
/// chose and that something downstream may be counting.
pub fn relay_body<R: BufRead, W: Write>(from: &mut R, to: &mut W, framing: Framing) -> Result<()> {
    match framing {
        Framing::Nothing => Ok(()),
        Framing::Length(length) => {
            let copied = std::io::copy(&mut from.take(length), to)?;
            if copied < length {
                bail!("the body ended after {copied} of {length} byte(s)");
            }
            Ok(())
        }
        Framing::UntilClose => {
            std::io::copy(from, to)?;
            Ok(())
        }
        Framing::Chunked => {
            loop {
                let mut line = String::new();
                if read_line(from, &mut line)? == 0 {
                    bail!("a chunked body ended in the middle of a chunk header");
                }
                to.write_all(line.as_bytes())?;
                let size = usize::from_str_radix(
                    line.trim_end().split(';').next().unwrap_or_default().trim(),
                    16,
                )
                .with_context(|| format!("`{}` is not a chunk size", line.trim_end()))?;
                if size == 0 {
                    // The trailers and the blank line that ends them.
                    loop {
                        let mut trailer = String::new();
                        if read_line(from, &mut trailer)? == 0 {
                            break;
                        }
                        to.write_all(trailer.as_bytes())?;
                        if trailer.trim().is_empty() {
                            break;
                        }
                    }
                    return Ok(());
                }
                // The chunk and the carriage return and newline after it.
                std::io::copy(&mut from.take(size as u64 + 2), to)?;
            }
        }
    }
}

/// Reads and throws away a request's body, so that a client which was uploading sees its answer rather than a
/// broken connection.
pub fn drain_body<R: BufRead>(from: &mut R, framing: Framing) -> Result<()> {
    let mut nowhere = std::io::sink();
    match framing {
        // Reading until close would mean waiting for a client that is waiting for us.
        Framing::UntilClose => Ok(()),
        Framing::Length(length) if length > MOST_DRAIN => Ok(()),
        other => relay_body(from, &mut nowhere, other),
    }
}

/// The canned answer as it goes on the wire.
///
/// Flowlight writes the framing headers itself: a mock whose `Content-Length` disagreed with its body would
/// hang the client rather than test it. The connection is closed afterwards because nothing was sent upstream,
/// so there is no real response behind this one to keep a reused connection in step with.
pub fn mock_bytes(mock: &Mock) -> Vec<u8> {
    let allowed = mock.status != 204 && mock.status != 304 && !(100..200).contains(&mock.status);
    let body = if allowed {
        mock.body.as_bytes()
    } else {
        &[][..]
    };
    let mut text = format!("HTTP/1.1 {} {}\r\n", mock.status, reason(mock.status));
    let written = ["content-length", "connection", "transfer-encoding"];
    let mut said_type = false;
    for (name, value) in &mock.headers {
        let name = header_safe(name);
        if name.is_empty() || written.iter().any(|taken| name.eq_ignore_ascii_case(taken)) {
            continue;
        }
        if name.eq_ignore_ascii_case("content-type") {
            said_type = true;
        }
        text.push_str(&format!("{name}: {}\r\n", header_safe(value)));
    }
    if allowed && !said_type {
        let guessed =
            if mock.body.trim_start().starts_with('{') || mock.body.trim_start().starts_with('[') {
                "application/json"
            } else {
                "text/plain; charset=utf-8"
            };
        text.push_str(&format!("Content-Type: {guessed}\r\n"));
    }
    if allowed {
        text.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    // Named in the response as well as in Flowlight, so that a log kept somewhere else on this machine can
    // also tell that this answer did not come from the server.
    text.push_str(&format!(
        "{}: {}\r\n",
        if mock.refusal {
            "X-Flowlight-Refused"
        } else {
            "X-Flowlight-Mock"
        },
        header_safe(&mock.title())
    ));
    text.push_str("Connection: close\r\n\r\n");
    let mut bytes = text.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

/// Strips anything that would end a header line.
///
/// A header value comes from a text field somebody typed into. A newline in one would let a mock forge extra
/// headers, or a whole second response.
pub fn header_safe(text: &str) -> String {
    text.chars()
        .filter(|character| !matches!(character, '\r' | '\n' | '\0'))
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The reason phrase for a status, for the ones anybody mocks.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        408 => "Request Timeout",
        409 => "Conflict",
        418 => "I'm a teapot",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Mocked",
    }
}

/// Everything Flowlight sends when it could not reach the server at all.
pub fn unreachable_bytes(host: &str, why: &str) -> Vec<u8> {
    let body = format!("Flowlight could not reach {host}: {why}\n");
    let mut text = format!(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\
         X-Flowlight-Error: upstream\r\nConnection: close\r\n\r\n",
        body.len()
    );
    text.push_str(&body);
    text.into_bytes()
}

/// A host with its port taken off, lowercased.
fn without_port(authority: &str) -> String {
    let authority = authority.trim();
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && port.chars().all(|c| c.is_ascii_digit()) => {
            host
        }
        _ => authority,
    };
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .to_lowercase()
}

/// Reads a head's lines, or nothing when the connection ended before one started.
fn read_lines<R: BufRead>(from: &mut R) -> Result<Option<Vec<String>>> {
    let mut lines = Vec::new();
    let mut read = 0;
    loop {
        let mut line = String::new();
        let got = read_line(from, &mut line)?;
        if got == 0 {
            // A connection that closed with nothing on it is not an error; a connection that closed halfway
            // through a head is.
            return if lines.is_empty() {
                Ok(None)
            } else {
                bail!("a head ended before its blank line")
            };
        }
        read += got;
        if read > MOST_HEAD {
            bail!("a head is longer than {MOST_HEAD} bytes, which no real one is");
        }
        if line.trim().is_empty() {
            // The blank line before a head's first line is tolerated: some clients send a stray newline after
            // a previous request.
            if lines.is_empty() {
                continue;
            }
            return Ok(Some(lines));
        }
        lines.push(line.trim_end().to_owned());
    }
}

/// One line, as bytes, so that a body Flowlight never decodes cannot fail to be valid text.
fn read_line<R: BufRead>(from: &mut R, into: &mut String) -> Result<usize> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        match from.read(&mut byte)? {
            0 => break,
            _ => {
                bytes.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
        }
        if bytes.len() > MOST_HEAD {
            bail!("a line is longer than {MOST_HEAD} bytes");
        }
    }
    into.push_str(&String::from_utf8_lossy(&bytes));
    Ok(bytes.len())
}

/// Header lines as names and values. A line without a colon is not a header and is dropped.
fn headers_of<I: Iterator<Item = String>>(lines: I) -> Vec<(String, String)> {
    lines
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.trim().to_owned();
            if name.is_empty() {
                return None;
            }
            Some((name, value.trim().to_owned()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn head(text: &str) -> Head {
        let mut reader = Cursor::new(text.as_bytes().to_vec());
        read_head(&mut reader).unwrap().expect("a head")
    }

    #[test]
    fn a_request_line_and_its_headers_are_read() {
        let read = head("POST /v1/messages HTTP/1.1\r\nHost: api.example.com\r\nX-A: 1\r\n\r\n");
        assert_eq!(read.method, "POST");
        assert_eq!(read.target, "/v1/messages");
        assert_eq!(read.version, "HTTP/1.1");
        assert_eq!(read.host().as_deref(), Some("api.example.com"));
        assert_eq!(read.path(), "/v1/messages");
        assert_eq!(read.header("x-a"), Some("1"));
        // Case does not matter on the way in, and the name is kept as it was written on the way out.
        assert_eq!(read.header("HOST"), Some("api.example.com"));
        assert!(String::from_utf8_lossy(&read.bytes()).contains("Host: api.example.com\r\n"));
    }

    /// A redirected client does not know it is talking to a proxy, but something else on the machine might.
    #[test]
    fn an_absolute_target_still_yields_a_host_and_a_path() {
        let read = head(
            "GET http://api.example.com:8080/v1/x?a=1 HTTP/1.1\r\nHost: wrong.example\r\n\r\n",
        );
        assert_eq!(read.host().as_deref(), Some("api.example.com"));
        assert_eq!(read.path(), "/v1/x?a=1");
        // And an absolute target with no path at all is the root.
        let bare = head("GET http://api.example.com HTTP/1.1\r\n\r\n");
        assert_eq!(bare.path(), "/");
    }

    #[test]
    fn a_host_header_loses_its_port_and_its_case() {
        let read = head("GET / HTTP/1.1\r\nHost: API.Example.COM:443\r\n\r\n");
        assert_eq!(read.host().as_deref(), Some("api.example.com"));
        // IPv6, whose colons are inside brackets.
        let six = head("GET / HTTP/1.1\r\nHost: [::1]:8080\r\n\r\n");
        assert_eq!(six.host().as_deref(), Some("::1"));
    }

    #[test]
    fn a_connection_that_closed_with_nothing_on_it_is_not_an_error() {
        let mut empty = Cursor::new(Vec::new());
        assert_eq!(read_head(&mut empty).unwrap(), None);
    }

    /// And one that closed halfway through a head is, because continuing would mean guessing at the rest.
    #[test]
    fn a_head_that_never_ended_is_an_error() {
        let mut half = Cursor::new(b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec());
        assert!(read_head(&mut half).is_err());
    }

    #[test]
    fn a_head_longer_than_any_real_one_is_refused() {
        let mut enormous = String::from("GET / HTTP/1.1\r\n");
        for i in 0..5_000 {
            enormous.push_str(&format!("X-Padding-{i}: {}\r\n", "x".repeat(40)));
        }
        enormous.push_str("\r\n");
        let mut reader = Cursor::new(enormous.into_bytes());
        assert!(read_head(&mut reader).is_err());
    }

    #[test]
    fn a_status_line_is_read() {
        let mut reader =
            Cursor::new(b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 30\r\n\r\n".to_vec());
        let status = read_status(&mut reader).unwrap().unwrap();
        assert_eq!(status.code, 503);
        assert_eq!(status.reason, "Service Unavailable");
        assert_eq!(status.header("retry-after"), Some("30"));
        assert!(
            String::from_utf8_lossy(&status.bytes())
                .starts_with("HTTP/1.1 503 Service Unavailable")
        );
    }

    /// Each of these, read the wrong way, leaves the proxy waiting for bytes that are never coming while the
    /// client waits for the proxy.
    #[test]
    fn framing_is_worked_out_rather_than_guessed() {
        let get = head("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(framing_of_request(&get), Framing::Nothing);

        let post = head("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 12\r\n\r\n");
        assert_eq!(framing_of_request(&post), Framing::Length(12));

        let streamed = head("POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(framing_of_request(&streamed), Framing::Chunked);

        let status = |text: &str| {
            let mut reader = Cursor::new(text.as_bytes().to_vec());
            read_status(&mut reader).unwrap().unwrap()
        };
        // A HEAD is answered with a GET's headers and none of its body.
        let head_request = head("HEAD / HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(
            framing_of_response(
                &head_request,
                &status("HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n")
            ),
            Framing::Nothing
        );
        assert_eq!(
            framing_of_response(&get, &status("HTTP/1.1 204 No Content\r\n\r\n")),
            Framing::Nothing
        );
        assert_eq!(
            framing_of_response(
                &get,
                &status("HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n")
            ),
            Framing::Nothing
        );
        // No length and no chunking: the body ends when the connection does.
        assert_eq!(
            framing_of_response(&get, &status("HTTP/1.1 200 OK\r\n\r\n")),
            Framing::UntilClose
        );
    }

    /// Copied chunk by chunk with its sizes intact, rather than decoded and re-encoded: the bytes are the
    /// sender's and something downstream may be counting them.
    #[test]
    fn a_chunked_body_is_copied_exactly() {
        let body = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut reader = Cursor::new(body.as_bytes().to_vec());
        let mut written = Vec::new();
        relay_body(&mut reader, &mut written, Framing::Chunked).unwrap();
        assert_eq!(String::from_utf8_lossy(&written), body);
    }

    #[test]
    fn a_chunked_body_with_trailers_is_copied_too() {
        let body = "3\r\nabc\r\n0\r\nX-Checksum: 1\r\n\r\n";
        let mut reader = Cursor::new(body.as_bytes().to_vec());
        let mut written = Vec::new();
        relay_body(&mut reader, &mut written, Framing::Chunked).unwrap();
        assert_eq!(String::from_utf8_lossy(&written), body);
    }

    #[test]
    fn a_body_of_a_known_length_is_copied_exactly_that_far() {
        let mut reader = Cursor::new(b"hello, worldAND THE NEXT REQUEST".to_vec());
        let mut written = Vec::new();
        relay_body(&mut reader, &mut written, Framing::Length(12)).unwrap();
        assert_eq!(String::from_utf8_lossy(&written), "hello, world");
        // And the rest is still there to be read as the next request, which is what keep-alive is.
        let mut rest = String::new();
        reader.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "AND THE NEXT REQUEST");
    }

    /// A body that stops short is an error rather than a short write, because the far end is counting.
    #[test]
    fn a_body_that_ends_early_is_an_error() {
        let mut reader = Cursor::new(b"hello".to_vec());
        let mut written = Vec::new();
        assert!(relay_body(&mut reader, &mut written, Framing::Length(12)).is_err());
    }

    fn mock(status: u16, body: &str) -> Mock {
        Mock {
            id: 1,
            enabled: true,
            subject: flowlight_rules::Subject::parse("api.example.com"),
            path: "*".to_owned(),
            method: String::new(),
            status,
            headers: Vec::new(),
            body: body.to_owned(),
            delay: 0,
            refusal: false,
            note: None,
        }
    }

    /// A mock whose Content-Length disagreed with its body would hang the client rather than test it.
    #[test]
    fn a_mock_is_framed_by_flowlight_and_not_by_whoever_wrote_it() {
        let mut rule = mock(503, r#"{"error":"mocked"}"#);
        rule.headers = vec![
            ("Content-Length".to_owned(), "99999".to_owned()),
            ("Retry-After".to_owned(), "30".to_owned()),
        ];
        let text = String::from_utf8_lossy(&mock_bytes(&rule)).into_owned();
        assert!(text.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(text.contains("Content-Length: 18\r\n"), "{text}");
        assert!(!text.contains("99999"));
        assert!(text.contains("Retry-After: 30\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("X-Flowlight-Mock: "));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.ends_with(r#"{"error":"mocked"}"#));
    }

    /// A status that cannot carry a body does not get one, however much the rule says.
    #[test]
    fn a_status_with_no_body_gets_no_body() {
        for status in [204_u16, 304, 100] {
            let text = String::from_utf8_lossy(&mock_bytes(&mock(status, "ignored"))).into_owned();
            assert!(!text.contains("ignored"), "{status}: {text}");
            assert!(!text.contains("Content-Length"), "{status}: {text}");
        }
    }

    /// A newline in a header value would let a rule forge extra headers, or a whole second response.
    #[test]
    fn a_header_cannot_forge_another_one() {
        let mut rule = mock(200, "");
        rule.headers = vec![(
            "X-A".to_owned(),
            "1\r\nX-Forged: yes\r\n\r\nHTTP/1.1 200 OK".to_owned(),
        )];
        let text = String::from_utf8_lossy(&mock_bytes(&rule)).into_owned();
        // Asserted line by line, because what must not happen is another header *line* or another status
        // line. The forged text surviving inside one value is harmless and is the sanitiser working.
        let lines: Vec<&str> = text.split("\r\n").collect();
        assert_eq!(
            lines
                .iter()
                .filter(|line| line.starts_with("HTTP/"))
                .count(),
            1,
            "{text}"
        );
        assert!(
            !lines.iter().any(|line| line.starts_with("X-Forged")),
            "{text}"
        );
        assert!(lines.iter().any(|line| line.starts_with("X-A: ")), "{text}");
    }

    /// A refusal and a stand-in are given by the same machinery and are not the same thing to read in a log.
    #[test]
    fn a_refusal_says_that_it_is_one() {
        let mut rule = mock(403, "no");
        rule.refusal = true;
        let text = String::from_utf8_lossy(&mock_bytes(&rule)).into_owned();
        assert!(text.contains("X-Flowlight-Refused: "));
        assert!(!text.contains("X-Flowlight-Mock"));
    }

    #[test]
    fn an_unreachable_server_is_a_bad_gateway_that_says_why() {
        let text =
            String::from_utf8_lossy(&unreachable_bytes("api.example.com", "connection refused"))
                .into_owned();
        assert!(text.starts_with("HTTP/1.1 502 Bad Gateway\r\n"));
        assert!(text.contains("api.example.com"));
        assert!(text.contains("connection refused"));
    }
}

// MARK: Guardrails

/// How much of a request body is looked at before it is forwarded.
///
/// The same four kilobytes the payload probes capture, and for the same reason: a JSON-RPC envelope puts its
/// method and its parameters at the front, and everything after that is the argument — which nothing here
/// reads.
pub const PEEK: usize = 4096;

/// The most of a body that is held in memory in order to look at its beginning.
///
/// A body larger than this is forwarded without being looked at at all. That is a deliberate hole and it is
/// the safe direction: the alternative is holding an arbitrary upload in the proxy's memory, and a guardrail
/// that can be evaded by a sixteen-megabyte request is better than a proxy that can be stopped by one.
pub const MOST_HELD: u64 = 16 * 1024 * 1024;

/// Whether a request could be an MCP call worth looking at.
///
/// Asked before anything is held in memory. A GET has no body, and a body that is not JSON is not JSON-RPC,
/// so neither is worth the copy.
pub fn could_be_mcp(head: &Head) -> bool {
    if !matches!(
        head.method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "PATCH"
    ) {
        return false;
    }
    head.header("content-type").is_none_or(|kind| {
        let kind = kind.to_ascii_lowercase();
        kind.contains("json") || kind.contains("event-stream")
    })
}

/// Reads a body into memory so that its beginning can be looked at, or says it was too big to hold.
///
/// The bytes come back untouched, to be forwarded exactly as they arrived. Nothing here decodes, reframes or
/// keeps them.
pub fn hold_body<R: BufRead>(from: &mut R, framing: Framing) -> Result<Option<Vec<u8>>> {
    match framing {
        Framing::Nothing => Ok(Some(Vec::new())),
        Framing::Length(length) if length > MOST_HELD => Ok(None),
        Framing::Length(length) => {
            let mut held = Vec::with_capacity(length.min(64 * 1024) as usize);
            let copied = std::io::copy(&mut from.take(length), &mut held)?;
            if copied < length {
                bail!("the body ended after {copied} of {length} byte(s)");
            }
            Ok(Some(held))
        }
        // A chunked body has no length to check in advance, so it is held up to the same ceiling and
        // abandoned past it. Re-framed on the way out as one piece, which is why the length is written.
        Framing::Chunked => {
            let mut held = Vec::new();
            let mut sink = std::io::Cursor::new(&mut held);
            relay_body(from, &mut sink, Framing::Chunked)?;
            if held.len() as u64 > MOST_HELD {
                return Ok(None);
            }
            Ok(Some(held))
        }
        // Reading until close would mean waiting for a client that is waiting for us.
        Framing::UntilClose => Ok(None),
    }
}

/// A JSON-RPC error, as the answer to a call a guardrail refused.
///
/// An error the agent understands, not a dropped connection it will retry. A refusal that looks like a network
/// failure teaches an agent to try again; one that looks like an answer teaches it that the tool is not
/// available, which is what is true.
///
/// `-32000` is the JSON-RPC range reserved for an implementation's own errors, which this is.
pub fn refusal_bytes(id: &str, said: &str) -> Vec<u8> {
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32000,"message":{},"data":{{"refusedBy":"flowlight"}}}}}}"#,
        serde_json::to_string(said).unwrap_or_else(|_| "\"refused\"".to_owned())
    );
    let mut text = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         X-Flowlight-Guardrail: refused\r\nConnection: close\r\n\r\n",
        body.len()
    );
    text.push_str(&body);
    text.into_bytes()
}

/// The `id` of the first JSON-RPC envelope in a body, as JSON, so a refusal can answer the call it refuses.
///
/// A JSON-RPC client matches the answer to the question by this. Getting it wrong means the agent waits for an
/// answer that never comes, which is the same as a dropped connection and worse than an error.
///
/// Read as a raw token rather than parsed, because an id may be a number or a string and it is written back
/// exactly as it arrived either way.
pub fn envelope_id(body: &[u8]) -> String {
    let window = body.get(..body.len().min(PEEK)).unwrap_or(body);
    let Ok(text) = core::str::from_utf8(window) else {
        return "null".to_owned();
    };
    let Some(at) = text.find("\"id\"") else {
        return "null".to_owned();
    };
    let rest = text.get(at + 4..).unwrap_or_default();
    let Some(colon) = rest.find(':') else {
        return "null".to_owned();
    };
    let value = rest.get(colon + 1..).unwrap_or_default().trim_start();
    if let Some(quoted) = value.strip_prefix('"') {
        let end = quoted.find('"').unwrap_or(0);
        let inner = quoted.get(..end).unwrap_or_default();
        return serde_json::to_string(inner).unwrap_or_else(|_| "null".to_owned());
    }
    let end = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    match value.get(..end) {
        Some(digits) if !digits.is_empty() => digits.to_owned(),
        _ => "null".to_owned(),
    }
}

#[cfg(test)]
mod guardrail_tests {
    use super::*;
    use std::io::Cursor;

    fn head(text: &str) -> Head {
        let mut reader = Cursor::new(text.as_bytes().to_vec());
        read_head(&mut reader).unwrap().expect("a head")
    }

    /// Asked before anything is held in memory, so that a request nobody could have a guardrail about does
    /// not pay for the feature.
    #[test]
    fn only_something_that_could_be_a_call_is_looked_at() {
        assert!(could_be_mcp(&head(
            "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n"
        )));
        // A content type nobody stated: worth looking at, because plenty of clients do not send one.
        assert!(could_be_mcp(&head("POST /mcp HTTP/1.1\r\nHost: x\r\n\r\n")));
        // Streaming responses to a POST are how MCP works over HTTP.
        assert!(could_be_mcp(&head(
            "POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Type: text/event-stream\r\n\r\n"
        )));
        assert!(!could_be_mcp(&head("GET /mcp HTTP/1.1\r\nHost: x\r\n\r\n")));
        assert!(!could_be_mcp(&head(
            "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: image/png\r\n\r\n"
        )));
    }

    #[test]
    fn a_body_is_held_exactly_as_it_arrived() {
        let mut reader = Cursor::new(b"{\"jsonrpc\":\"2.0\"}rest".to_vec());
        let held = hold_body(&mut reader, Framing::Length(17))
            .unwrap()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&held), r#"{"jsonrpc":"2.0"}"#);
    }

    /// A guardrail that can be evaded by a sixteen-megabyte request is better than a proxy that can be
    /// stopped by one.
    #[test]
    fn a_body_too_large_to_hold_is_not_held() {
        let mut reader = Cursor::new(Vec::new());
        assert_eq!(
            hold_body(&mut reader, Framing::Length(MOST_HELD + 1)).unwrap(),
            None
        );
        assert_eq!(hold_body(&mut reader, Framing::UntilClose).unwrap(), None);
    }

    /// A JSON-RPC client matches an answer to its question by the id. Getting it wrong means the agent waits
    /// for an answer that never comes.
    #[test]
    fn the_id_of_a_call_is_read_back_exactly() {
        assert_eq!(
            envelope_id(br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#),
            "7"
        );
        assert_eq!(
            envelope_id(br#"{"jsonrpc":"2.0","id":"abc","method":"tools/call"}"#),
            "\"abc\""
        );
        assert_eq!(envelope_id(br#"{"id" : 42 }"#), "42");
        // Nothing recognisable is a null id, which is what JSON-RPC says to answer when the id is unknown.
        assert_eq!(envelope_id(b"not json at all"), "null");
        assert_eq!(envelope_id(br#"{"method":"tools/call"}"#), "null");
        assert_eq!(envelope_id(&[0xff, 0xfe]), "null");
    }

    /// An id that is a string has to come back as a string, quoted and escaped, or the answer is not JSON.
    #[test]
    fn a_string_id_comes_back_as_valid_json() {
        let bytes = refusal_bytes(&envelope_id(br#"{"id":"a\"b"}"#), "no");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let body = text.split("\r\n\r\n").nth(1).unwrap_or_default();
        let parsed: serde_json::Value =
            serde_json::from_str(body).expect("the refusal should be JSON");
        assert_eq!(parsed["jsonrpc"], "2.0");
    }

    /// An error the agent understands, not a dropped connection it will retry.
    #[test]
    fn a_refusal_is_an_answer_and_not_a_failure() {
        let bytes = refusal_bytes("7", "claude: no write_file");
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("X-Flowlight-Guardrail: refused"));
        let body = text.split("\r\n\r\n").nth(1).unwrap_or_default();
        let parsed: serde_json::Value =
            serde_json::from_str(body).expect("the refusal should be JSON");
        assert_eq!(parsed["id"], 7);
        assert_eq!(parsed["error"]["code"], -32000);
        assert_eq!(parsed["error"]["message"], "claude: no write_file");
        assert_eq!(parsed["error"]["data"]["refusedBy"], "flowlight");
        // And the length is Flowlight's arithmetic, not anybody's claim.
        assert!(text.contains(&format!("Content-Length: {}\r\n", body.len())));
    }
}
