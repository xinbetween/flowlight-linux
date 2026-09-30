//! The sockets, the TLS on both sides, and the decision in the middle.
//!
//! A thread per connection, and blocking reads. There is one proxy on a machine and the connections through it
//! are an agent's, not a web server's; a runtime would be a dependency and an indirection for a workload that
//! is measured in tens.
//!
//! # How a connection arrives, and how its destination is known
//!
//! The kernel redirects it. A `cgroup/connect4` program rewrites the destination to this port and remembers
//! what it was, keyed by the socket's cookie; this asks the kernel for the cookie of the connection it just
//! accepted and looks the original up. Nothing is read from the client to find out where it was going, which
//! matters because the alternative — trusting the `Host` header — would let anything on the machine send
//! itself anywhere by lying about it.
//!
//! # Why a host nobody mocks is not terminated
//!
//! Because terminating it would present a certificate for no reason, and the first thing a certificate somebody
//! did not expect does is break. A connection to a host no mock covers is relayed as ciphertext: the bytes are
//! copied both ways and Flowlight never sees inside, exactly as if interception were off.

use crate::authority::{Authority, Signed};
use crate::http::{self, Framing};
use anyhow::{Context as _, Result};
use flowlight_rules::Mock;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use rustls_pki_types::ServerName;
use std::io::{BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;

/// How long to wait on a socket that has said nothing.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(120);

/// Where a redirected connection was actually going.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reached {
    /// The address the application asked for.
    pub address: IpAddr,
    /// The port it asked for.
    pub port: u16,
}

/// What happened to one connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decided {
    /// Relayed as ciphertext. Nothing was terminated and nothing was seen.
    Passed {
        /// The host, when the client's handshake named one.
        host: Option<String>,
    },
    /// Terminated, and every request on it was forwarded upstream untouched.
    Forwarded {
        /// The host.
        host: String,
        /// How many requests went through.
        requests: usize,
    },
    /// Terminated, and at least one request was answered by a rule.
    Answered {
        /// The host.
        host: String,
        /// The rules that answered, by identifier.
        rules: Vec<i64>,
        /// Whether the answer called itself a refusal.
        refusal: bool,
    },
    /// Nothing could be done with it, and why.
    Failed {
        /// The host, if one was known by the time it went wrong.
        host: Option<String>,
        /// What went wrong.
        why: String,
    },
}

/// Everything a connection needs to be decided about.
pub struct Proxy {
    authority: Arc<Authority>,
    upstream: Arc<ClientConfig>,
    /// The canned answers in force, newest read wins. Held behind a lock so that writing a mock takes effect
    /// on the next connection rather than on the next restart.
    mocks: std::sync::RwLock<Vec<Mock>>,
    /// Hosts never terminated, whatever else says so.
    spared: std::sync::RwLock<Vec<String>>,
}

impl Proxy {
    /// Builds one from an authority.
    pub fn new(authority: Authority) -> Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut upstream = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // Only HTTP/1.1 upstream, because only HTTP/1.1 is understood here. Offering h2 and then speaking
        // HTTP/1.1 to what came back would be a hang.
        upstream.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            authority: Arc::new(authority),
            upstream: Arc::new(upstream),
            mocks: std::sync::RwLock::new(Vec::new()),
            spared: std::sync::RwLock::new(Vec::new()),
        })
    }

    /// Replaces the canned answers.
    pub fn set_mocks(&self, mocks: Vec<Mock>) {
        if let Ok(mut held) = self.mocks.write() {
            *held = mocks;
        }
    }

    /// Replaces the list of hosts never terminated.
    pub fn set_spared(&self, spared: Vec<String>) {
        if let Ok(mut held) = self.spared.write() {
            *held = spared;
        }
    }

    /// The authority, for whatever has to write its certificate somewhere.
    pub fn authority(&self) -> &Authority {
        &self.authority
    }

    /// Whether this host is one to leave alone.
    fn is_spared(&self, host: &str) -> bool {
        self.spared.read().is_ok_and(|spared| {
            spared
                .iter()
                .any(|pattern| flowlight_rules::Subject::parse(pattern).covers_host(host))
        })
    }

    /// Whether any rule could answer for this host.
    fn mocks_anything(&self, host: &str) -> bool {
        self.mocks
            .read()
            .is_ok_and(|mocks| flowlight_rules::mocks_anything(&mocks, host))
    }

    /// Handles one accepted connection.
    ///
    /// Takes the original destination rather than working it out, because the only trustworthy source for it is
    /// the kernel and the only place that can ask is the caller.
    pub fn handle(&self, client: TcpStream, reached: Reached) -> Decided {
        let _ = client.set_read_timeout(Some(PATIENCE));
        let _ = client.set_write_timeout(Some(PATIENCE));
        match self.decide(client, reached) {
            Ok(decided) => decided,
            Err(err) => Decided::Failed {
                host: None,
                why: format!("{err:#}"),
            },
        }
    }

    /// The whole of it, with the failures in one place.
    fn decide(&self, mut client: TcpStream, reached: Reached) -> Result<Decided> {
        // The name is taken from the handshake, not from a header: a header is written by whoever is
        // connecting, and the certificate presented has to be for the name they asked for.
        let (named, first) = peek_server_name(&mut client)?;

        // A host nobody mocks is never terminated. No certificate is presented, nothing is decrypted, and the
        // connection is what it would have been if interception were off.
        let terminate = named
            .as_deref()
            .is_some_and(|host| !self.is_spared(host) && self.mocks_anything(host));
        if !terminate {
            let upstream = TcpStream::connect(SocketAddr::new(reached.address, reached.port))
                .with_context(|| {
                    format!("connecting onwards to {}:{}", reached.address, reached.port)
                })?;
            relay_ciphertext(client, upstream, &first)?;
            return Ok(Decided::Passed { host: named });
        }
        let host = named.unwrap_or_default();

        let signed = self
            .authority
            .signed_for(&host)
            .with_context(|| format!("signing a certificate for {host}"))?;
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(OneHost::new(signed)?));
        let mut server = server;
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connection =
            ServerConnection::new(Arc::new(server)).context("starting TLS with the client")?;
        let inside = StreamOwned::new(connection, Prefixed::new(client, first));

        self.exchange(inside, &host, reached)
    }

    /// Reads requests off a terminated connection, and decides about each.
    fn exchange(
        &self,
        inside: StreamOwned<ServerConnection, Prefixed>,
        host: &str,
        reached: Reached,
    ) -> Result<Decided> {
        let mut client = BufReader::new(inside);
        let mut upstream: Option<StreamOwned<ClientConnection, TcpStream>> = None;
        let mut forwarded = 0;
        let mut answered = Vec::new();
        let mut refusal = false;

        loop {
            let Some(head) = http::read_head(&mut client)? else {
                break;
            };
            let framing = http::framing_of_request(&head);
            let path = head.path();

            if let Some(mock) = self.answer_for(host, &head.method, &path) {
                // Drained before answering, so a client that was uploading sees the answer rather than a
                // connection that broke.
                let _ = http::drain_body(&mut client, framing);
                if mock.delay > 0 {
                    std::thread::sleep(std::time::Duration::from_secs(u64::from(
                        mock.delay.min(600),
                    )));
                }
                answered.push(mock.id);
                refusal = refusal || mock.refusal;
                client.get_mut().write_all(&http::mock_bytes(&mock))?;
                let _ = client.get_mut().flush();
                // The answer says `Connection: close`, because nothing went upstream and there is no real
                // response behind it to keep a reused connection in step with.
                break;
            }

            let onwards = match upstream.take() {
                Some(ready) => ready,
                None => match self.connect(host, reached) {
                    Ok(ready) => ready,
                    Err(err) => {
                        let _ = http::drain_body(&mut client, framing);
                        let _ = client
                            .get_mut()
                            .write_all(&http::unreachable_bytes(host, &format!("{err:#}")));
                        finish(client.get_mut());
                        return Ok(Decided::Failed {
                            host: Some(host.to_owned()),
                            why: format!("{err:#}"),
                        });
                    }
                },
            };
            let mut onwards = BufReader::new(onwards);
            onwards.get_mut().write_all(&head.bytes())?;
            http::relay_body(&mut client, onwards.get_mut(), framing)?;
            onwards.get_mut().flush()?;
            forwarded += 1;

            let Some(status) = http::read_status(&mut onwards)? else {
                break;
            };
            let answer = http::framing_of_response(&head, &status);
            client.get_mut().write_all(&status.bytes())?;
            http::relay_body(&mut onwards, client.get_mut(), answer)?;
            let _ = client.get_mut().flush();

            let closing = answer == Framing::UntilClose
                || status
                    .header("connection")
                    .is_some_and(|value| value.to_lowercase().contains("close"))
                || head
                    .header("connection")
                    .is_some_and(|value| value.to_lowercase().contains("close"));
            if closing {
                break;
            }
            upstream = Some(onwards.into_inner());
        }

        // A TLS connection that stops without a close_notify is an error at the far end, not a close: rustls
        // says so outright and curl prints it. Sent here, once, on every way out of the loop.
        finish(client.get_mut());

        Ok(if answered.is_empty() {
            Decided::Forwarded {
                host: host.to_owned(),
                requests: forwarded,
            }
        } else {
            Decided::Answered {
                host: host.to_owned(),
                rules: answered,
                refusal,
            }
        })
    }

    /// The rule that answers a request, if one does.
    fn answer_for(&self, host: &str, method: &str, path: &str) -> Option<Mock> {
        let mocks = self.mocks.read().ok()?;
        flowlight_rules::mocked(&mocks, host, method, path).cloned()
    }

    /// Opens the real connection, verifying the real certificate.
    ///
    /// Verified properly, against the machine's roots, and with the name the client asked for. A proxy that
    /// did not check upstream would turn "Flowlight is watching" into "Flowlight is a hole", and the client
    /// cannot tell because it is checking Flowlight's certificate rather than the server's.
    fn connect(
        &self,
        host: &str,
        reached: Reached,
    ) -> Result<StreamOwned<ClientConnection, TcpStream>> {
        let name = ServerName::try_from(host.to_owned()).with_context(|| {
            format!("{host} is not a name a certificate can be checked against")
        })?;
        let socket = TcpStream::connect(SocketAddr::new(reached.address, reached.port))
            .with_context(|| format!("connecting to {}:{}", reached.address, reached.port))?;
        let _ = socket.set_read_timeout(Some(PATIENCE));
        let _ = socket.set_write_timeout(Some(PATIENCE));
        let connection = ClientConnection::new(Arc::clone(&self.upstream), name)
            .with_context(|| format!("starting TLS with {host}"))?;
        Ok(StreamOwned::new(connection, socket))
    }
}

/// Ends a terminated connection properly.
fn finish(stream: &mut StreamOwned<ServerConnection, Prefixed>) {
    stream.conn.send_close_notify();
    let _ = stream.flush();
    let _ = stream.sock.socket.shutdown(std::net::Shutdown::Write);
}

/// A resolver that has one certificate, for the host this connection is about.
struct OneHost {
    key: Arc<CertifiedKey>,
}

impl OneHost {
    fn new(signed: Signed) -> Result<Self> {
        let provider = rustls::crypto::ring::default_provider();
        let key = provider
            .key_provider
            .load_private_key(signed.key()?)
            .context("loading the leaf key into rustls")?;
        Ok(Self {
            key: Arc::new(CertifiedKey::new(signed.chain, key)),
        })
    }
}

impl std::fmt::Debug for OneHost {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("OneHost")
    }
}

impl ResolvesServerCert for OneHost {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }
}

/// Reads the server name out of a client's first bytes without consuming them.
///
/// The bytes are kept and replayed, because the handshake still has to happen afterwards — and because a
/// connection Flowlight decides not to terminate must arrive upstream byte for byte as it was sent.
fn peek_server_name(client: &mut TcpStream) -> Result<(Option<String>, Vec<u8>)> {
    use std::io::Read as _;
    let mut first = Vec::new();
    let mut buffer = [0_u8; 4096];
    // Enough for a ClientHello. One read is usually the whole of it; a few more cover a client that wrote it
    // in pieces.
    for _ in 0..8 {
        let read = client.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        first.extend_from_slice(buffer.get(..read).unwrap_or_default());
        match sni_of(&first) {
            Some(name) => return Ok((Some(name), first)),
            None if first.len() > 16 * 1024 => break,
            None => {}
        }
    }
    Ok((None, first))
}

/// The server name in a TLS ClientHello, if there is a whole one here.
///
/// Parsed by hand rather than by handing the bytes to a TLS library, because the library would want to own the
/// connection and this has to decide whether to terminate it at all. Every length is checked against what is
/// actually present: these are the first bytes of a connection from something that may be lying.
pub fn sni_of(bytes: &[u8]) -> Option<String> {
    // A handshake record carrying a ClientHello.
    if bytes.first() != Some(&0x16) {
        return None;
    }
    let record = read_bytes(bytes, 5, be16(bytes, 3)? as usize)?;
    if record.first() != Some(&0x01) {
        return None;
    }
    // Handshake length, then the client version and the random.
    let mut at = 4 + 2 + 32;
    let session = *record.get(at)? as usize;
    at += 1 + session;
    let suites = be16(record, at)? as usize;
    at += 2 + suites;
    let compression = *record.get(at)? as usize;
    at += 1 + compression;
    let extensions_length = be16(record, at)? as usize;
    at += 2;
    let extensions = read_bytes(record, at, extensions_length)?;

    let mut at = 0;
    while at + 4 <= extensions.len() {
        let kind = be16(extensions, at)?;
        let length = be16(extensions, at + 2)? as usize;
        let body = read_bytes(extensions, at + 4, length)?;
        if kind == 0x0000 {
            // server_name: a list, whose first entry of type 0 is the host.
            let list = read_bytes(body, 2, be16(body, 0)? as usize)?;
            let mut inner = 0;
            while inner + 3 <= list.len() {
                let name_length = be16(list, inner + 1)? as usize;
                let name = read_bytes(list, inner + 3, name_length)?;
                if list.get(inner) == Some(&0) {
                    return String::from_utf8(name.to_vec())
                        .ok()
                        .map(|name| name.trim_end_matches('.').to_lowercase())
                        .filter(|name| !name.is_empty());
                }
                inner += 3 + name_length;
            }
            return None;
        }
        at += 4 + length;
    }
    None
}

/// A big-endian sixteen-bit number at an offset, if it is there.
fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let high = u16::from(*bytes.get(at)?);
    let low = u16::from(*bytes.get(at + 1)?);
    Some((high << 8) | low)
}

/// A slice, if the whole of it is present.
fn read_bytes(bytes: &[u8], at: usize, length: usize) -> Option<&[u8]> {
    bytes.get(at..at.checked_add(length)?)
}

/// Copies bytes both ways until either side closes.
///
/// For a connection Flowlight decided not to terminate: the bytes already read are written first, and after
/// that nothing here knows or cares what they are.
fn relay_ciphertext(client: TcpStream, upstream: TcpStream, first: &[u8]) -> Result<()> {
    use std::io::Read as _;
    let _ = upstream.set_read_timeout(Some(PATIENCE));
    let _ = upstream.set_write_timeout(Some(PATIENCE));
    let mut to_upstream = upstream
        .try_clone()
        .context("copying the upstream socket")?;
    to_upstream.write_all(first)?;

    let mut from_client = client.try_clone().context("copying the client socket")?;
    let outward = std::thread::Builder::new()
        .name("flowlight-relay-out".to_owned())
        .spawn(move || {
            let mut buffer = [0_u8; 32 * 1024];
            loop {
                match from_client.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        if to_upstream
                            .write_all(buffer.get(..read).unwrap_or_default())
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            // Half-closed rather than dropped, so a server that is still answering can finish.
            let _ = to_upstream.shutdown(std::net::Shutdown::Write);
        })
        .context("starting the outward relay")?;

    let mut from_upstream = upstream;
    let mut to_client = client;
    let mut buffer = [0_u8; 32 * 1024];
    loop {
        match from_upstream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if to_client
                    .write_all(buffer.get(..read).unwrap_or_default())
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    let _ = to_client.shutdown(std::net::Shutdown::Write);
    let _ = outward.join();
    Ok(())
}

/// A stream whose first bytes were already read.
///
/// The ClientHello had to be read to find out where the connection was going; the TLS library then has to see
/// it as though nothing had.
pub struct Prefixed {
    socket: TcpStream,
    first: Vec<u8>,
    at: usize,
}

impl Prefixed {
    fn new(socket: TcpStream, first: Vec<u8>) -> Self {
        Self {
            socket,
            first,
            at: 0,
        }
    }
}

impl std::io::Read for Prefixed {
    fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
        if let Some(rest) = self.first.get(self.at..)
            && !rest.is_empty()
        {
            let taking = rest.len().min(into.len());
            into.get_mut(..taking)
                .ok_or_else(|| std::io::Error::other("a buffer shrank"))?
                .copy_from_slice(rest.get(..taking).unwrap_or_default());
            self.at += taking;
            return Ok(taking);
        }
        self.socket.read(into)
    }
}

impl Write for Prefixed {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.socket.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

/// A connection that could not be accepted at all.
pub fn refuse(mut client: TcpStream, why: &str) {
    let _ = client.write_all(&http::unreachable_bytes("the intended host", why));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ClientHello built by hand, so the parser is tested against bytes rather than against itself.
    pub(super) fn client_hello(name: Option<&str>) -> Vec<u8> {
        let mut extensions = Vec::new();
        if let Some(name) = name {
            let mut entry = vec![0x00];
            entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
            entry.extend_from_slice(name.as_bytes());
            let mut list = (entry.len() as u16).to_be_bytes().to_vec();
            list.extend_from_slice(&entry);
            extensions.extend_from_slice(&0x0000_u16.to_be_bytes());
            extensions.extend_from_slice(&(list.len() as u16).to_be_bytes());
            extensions.extend_from_slice(&list);
        }
        // An extension before it, so the walk is exercised rather than the first entry.
        let mut all = Vec::new();
        all.extend_from_slice(&0x002b_u16.to_be_bytes());
        all.extend_from_slice(&2_u16.to_be_bytes());
        all.extend_from_slice(&[0x03, 0x04]);
        all.extend_from_slice(&extensions);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0); // no session
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1); // one compression method
        body.push(0);
        body.extend_from_slice(&(all.len() as u16).to_be_bytes());
        body.extend_from_slice(&all);

        let mut handshake = vec![0x01];
        let length = (body.len() as u32).to_be_bytes();
        handshake.extend_from_slice(length.get(1..).unwrap_or_default());
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn a_server_name_is_read_out_of_a_handshake() {
        assert_eq!(
            sni_of(&client_hello(Some("api.example.com"))).as_deref(),
            Some("api.example.com")
        );
        // Lowercased and with a trailing dot taken off, so it matches a rule the way everything else does.
        assert_eq!(
            sni_of(&client_hello(Some("API.Example.COM."))).as_deref(),
            Some("api.example.com")
        );
    }

    #[test]
    fn a_handshake_with_no_server_name_yields_none() {
        assert_eq!(sni_of(&client_hello(None)), None);
    }

    /// These are the first bytes of a connection from something that may be lying. Every length is checked
    /// against what is present, so a truncated or overlong one is nothing rather than a panic.
    #[test]
    fn a_truncated_or_lying_handshake_is_nothing_rather_than_a_panic() {
        let whole = client_hello(Some("api.example.com"));
        for upto in 0..whole.len() {
            // Not asserted to be None — a prefix may legitimately still contain the name — only that it
            // cannot panic or read past the end.
            let _ = sni_of(whole.get(..upto).unwrap_or_default());
        }
        // A record that claims to be far longer than it is.
        let mut lying = whole.clone();
        if let Some(slot) = lying.get_mut(3..5) {
            slot.copy_from_slice(&u16::MAX.to_be_bytes());
        }
        assert_eq!(sni_of(&lying), None);
        assert_eq!(sni_of(&[]), None);
        assert_eq!(sni_of(&[0x16]), None);
        // Not a handshake record at all.
        assert_eq!(sni_of(&[0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5]), None);
    }

    /// The bytes read to find the name have to reach the TLS library as though nothing had read them.
    #[test]
    fn a_prefixed_stream_replays_what_was_already_read() {
        use std::io::Read as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let mut socket = TcpStream::connect(address).unwrap();
            socket.write_all(b"THE REST").unwrap();
        });
        let (accepted, _) = listener.accept().unwrap();
        let mut stream = Prefixed::new(accepted, b"THE FIRST ".to_vec());
        let mut read = String::new();
        stream.read_to_string(&mut read).unwrap();
        assert_eq!(read, "THE FIRST THE REST");
        writer.join().unwrap();
    }
}

#[cfg(test)]
mod end_to_end {
    use super::*;
    use std::io::Read as _;
    use std::net::TcpListener;
    use std::path::PathBuf;

    /// A directory of its own for one test, removed afterwards.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("flowlight-proxy-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        /// The directories Flowlight itself creates, inside the scratch one. Not the scratch directory: what
        /// is asserted about their modes is what Flowlight does, not what a test's `mkdir` did.
        fn keys(&self) -> PathBuf {
            self.0.join("intercept")
        }

        /// And where the certificate is published, which is a different audience.
        fn published(&self) -> PathBuf {
            self.0.join("share")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn mock(subject: &str, status: u16) -> Mock {
        Mock {
            id: 7,
            enabled: true,
            subject: flowlight_rules::Subject::parse(subject),
            path: "*".to_owned(),
            method: String::new(),
            status,
            headers: vec![("Retry-After".to_owned(), "30".to_owned())],
            body: r#"{"error":"mocked by flowlight"}"#.to_owned(),
            delay: 0,
            refusal: false,
            note: None,
        }
    }

    /// A client that trusts only Flowlight's authority, which is the situation `trust` puts a machine in.
    fn trusting(authority: &Authority) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots.add(authority.certificate().clone()).unwrap();
        let mut configuration = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        configuration.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(configuration)
    }

    /// The whole terminating path, with no network: a real TLS handshake against a certificate Flowlight made
    /// a moment earlier, and a request answered by a rule instead of by a server.
    ///
    /// A mocked request never goes upstream, which is what makes this testable without one — and is also the
    /// property worth asserting.
    #[test]
    fn a_mocked_request_is_answered_over_real_tls_and_nothing_goes_upstream() {
        let scratch = Scratch::new("mocked");
        let authority = Authority::open(&scratch.keys(), &scratch.published(), "a-test").unwrap();
        let client_side = trusting(&authority);

        let proxy = Proxy::new(authority).unwrap();
        proxy.set_mocks(vec![mock("api.example.com", 503)]);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let client = std::thread::spawn(move || {
            let socket = TcpStream::connect(address).unwrap();
            let name = ServerName::try_from("api.example.com").unwrap();
            let connection = ClientConnection::new(client_side, name).unwrap();
            let mut inside = StreamOwned::new(connection, socket);
            inside
                .write_all(
                    b"GET /v1/x HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n",
                )
                .unwrap();
            let mut answer = String::new();
            let mut reader = BufReader::new(inside);
            reader.read_to_string(&mut answer).unwrap();
            answer
        });

        let (accepted, _) = listener.accept().unwrap();
        // Port 1, which nothing is listening on: if this tried to go upstream it would fail rather than pass.
        let decided = proxy.handle(
            accepted,
            Reached {
                address: "127.0.0.1".parse().unwrap(),
                port: 1,
            },
        );
        let answer = client.join().unwrap();

        assert!(
            answer.starts_with("HTTP/1.1 503 Service Unavailable"),
            "{answer}"
        );
        assert!(answer.contains("X-Flowlight-Mock: "), "{answer}");
        assert!(answer.contains("Retry-After: 30"), "{answer}");
        assert!(
            answer.ends_with(r#"{"error":"mocked by flowlight"}"#),
            "{answer}"
        );
        assert_eq!(
            decided,
            Decided::Answered {
                host: "api.example.com".to_owned(),
                rules: vec![7],
                refusal: false,
            }
        );
    }

    /// A host nobody mocks is not terminated at all: no certificate is presented, and the bytes reach the far
    /// end exactly as they were sent — including the ones Flowlight had to read to find out the name.
    #[test]
    fn a_host_nobody_mocks_is_relayed_as_ciphertext() {
        let scratch = Scratch::new("passed");
        let authority = Authority::open(&scratch.keys(), &scratch.published(), "a-test").unwrap();
        let proxy = Proxy::new(authority).unwrap();
        proxy.set_mocks(vec![mock("somewhere.else.example", 503)]);

        // The "server": whatever it receives, it sends back.
        let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
        let reached = upstream.local_addr().unwrap();
        let echo = std::thread::spawn(move || {
            let (mut socket, _) = upstream.accept().unwrap();
            let mut seen = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                match socket.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => {
                        seen.extend_from_slice(&buffer[..read]);
                        socket.write_all(&buffer[..read]).unwrap();
                        if seen.len() >= 5 {
                            break;
                        }
                    }
                }
            }
            seen
        });

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let hello = super::tests::client_hello(Some("api.example.com"));
        let sent = hello.clone();
        let client = std::thread::spawn(move || {
            let mut socket = TcpStream::connect(address).unwrap();
            socket.write_all(&sent).unwrap();
            let mut back = vec![0_u8; sent.len()];
            socket.read_exact(&mut back).unwrap();
            back
        });

        let (accepted, _) = listener.accept().unwrap();
        let decided = proxy.handle(
            accepted,
            Reached {
                address: reached.ip(),
                port: reached.port(),
            },
        );
        let back = client.join().unwrap();
        let seen = echo.join().unwrap();

        assert_eq!(
            decided,
            Decided::Passed {
                host: Some("api.example.com".to_owned())
            }
        );
        // The handshake Flowlight read in order to decide reached the far end unchanged.
        assert_eq!(seen, hello);
        assert_eq!(back, hello);
    }

    /// Opening an authority that exists does not make a new one. A second certificate would mean everything
    /// that was told to trust the first stops working.
    #[test]
    fn an_authority_is_created_once_and_then_read() {
        let scratch = Scratch::new("once");
        let first = Authority::open(&scratch.keys(), &scratch.published(), "a-test").unwrap();
        let bytes = first.certificate().clone();
        drop(first);
        let second = Authority::open(&scratch.keys(), &scratch.published(), "a-test").unwrap();
        assert_eq!(second.certificate(), &bytes);
    }

    /// Anybody who can read the authority's key can impersonate every site on the internet to anything that
    /// trusts its certificate.
    #[test]
    #[cfg(unix)]
    fn the_keys_are_readable_by_nobody_else() {
        use std::os::unix::fs::MetadataExt as _;
        let scratch = Scratch::new("modes");
        let _ = Authority::open(&scratch.keys(), &scratch.published(), "a-test").unwrap();
        let mode = |directory: PathBuf, name: &str| {
            std::fs::metadata(directory.join(name)).unwrap().mode() & 0o777
        };
        assert_eq!(mode(scratch.keys(), "flowlight-ca.key"), 0o600);
        assert_eq!(mode(scratch.keys(), "leaf.key"), 0o600);
        // And the certificate is public by definition: anything that must trust it has to read it, which
        // includes an agent running as somebody who is not root.
        assert_eq!(mode(scratch.published(), "flowlight-ca.pem"), 0o644);
        assert_eq!(mode(scratch.published(), "ca-bundle.pem"), 0o644);
        assert_eq!(
            std::fs::metadata(scratch.keys()).unwrap().mode() & 0o777,
            0o700
        );
        // The published directory is the other way round on purpose: a certificate nobody can read is a
        // certificate nothing can be told to trust.
        assert_eq!(
            std::fs::metadata(scratch.published()).unwrap().mode() & 0o777,
            0o755
        );
    }

    /// The bundle is this machine's roots plus Flowlight's, not Flowlight's alone: a bundle holding only one
    /// authority would break every host that is not being intercepted.
    #[test]
    fn the_bundle_holds_more_than_flowlights_own_certificate() {
        let scratch = Scratch::new("bundle");
        let authority = Authority::open(&scratch.keys(), &scratch.published(), "a-test").unwrap();
        let bundle = std::fs::read_to_string(authority.bundle()).unwrap();
        let ours = std::fs::read_to_string(authority.path()).unwrap();
        assert!(bundle.ends_with(&ours), "the authority should be last");
        if crate::authority::system_bundle().is_some() {
            assert!(
                bundle.matches("BEGIN CERTIFICATE").count() > 1,
                "the machine has a bundle, so ours is not the only certificate in it"
            );
        }
    }
}
