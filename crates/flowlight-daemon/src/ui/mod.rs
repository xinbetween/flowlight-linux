//! A page on loopback showing what the machine is doing.
//!
//! The macOS build has an application window. This has a page served on `127.0.0.1`, because a daemon with
//! no window is a daemon nobody looks at, and `flowlightd history --since 6h | less` is not an interface.
//!
//! # The awkward part, stated rather than hidden
//!
//! This daemon runs as root, and what it knows is every host every process on the machine reached. Serving
//! that on loopback makes it available to **every local user**, not only the one who started it — loopback
//! is not a permission boundary. On a single-user laptop that is nothing; on a shared machine it is a
//! disclosure.
//!
//! So: bound to `127.0.0.1` and never to anything else, read-only in every route, and behind a token
//! generated at startup and printed once. The token lives in memory, never on disk, and dies with the
//! process. `--no-ui` turns the whole thing off.
//!
//! # Why it reads the database rather than sharing memory
//!
//! The watcher holds the only writable handle and is busy draining a perf buffer. A page that took a lock on
//! that would be a page that can stall the kernel's reader, which is the one thing in this program that
//! must not be stalled. A second, read-only connection to the same file costs nothing — SQLite's
//! write-ahead log exists for this — and cannot write even by mistake.

use anyhow::{Context as _, Result};
use flowlight_store::Store;
use serde::Serialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Response, Server};

/// The page itself, compiled in. No content delivery network, no fonts fetched from anywhere: a root daemon
/// that asks a browser to run somebody else's script has misunderstood its job.
const PAGE: &str = include_str!("page.html");

/// Starts the server on a thread and returns the address it is on.
pub fn serve(address: SocketAddr, database: PathBuf, token: String) -> Result<SocketAddr> {
    // Refuse anything that is not loopback rather than trusting the caller to have typed it correctly. There
    // is no legitimate reason to serve this on a routable address, and a typo that did so would publish the
    // machine's entire network history.
    if !address.ip().is_loopback() {
        anyhow::bail!(
            "the interface may only be served on loopback; {address} is not. What this knows is every host \
             every process on the machine reached, and there is no version of publishing that which is a \
             good idea."
        );
    }
    let server = Server::http(address)
        .map_err(|err| anyhow::anyhow!("{err}"))
        .with_context(|| format!("listening on {address}"))?;
    let bound = server.server_addr().to_ip().ok_or_else(|| {
        anyhow::anyhow!("the server bound to something that is not an IP address")
    })?;

    std::thread::Builder::new()
        .name("flowlight-ui".to_owned())
        .spawn(move || run(&server, &database, &token))
        .context("starting the interface thread")?;
    Ok(bound)
}

/// Answers requests until the process ends.
fn run(server: &Server, database: &Path, token: &str) {
    for request in server.incoming_requests() {
        let url = request.url().to_owned();
        let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
        let response = if !authorised(query, token) {
            // The same answer for a wrong token and an unknown path, so that guessing tokens tells nobody
            // whether the route exists.
            text(404, "not found")
        } else {
            match path {
                "/" => html(PAGE),
                "/api/requests" => json_or_error(|| requests(database, query)),
                "/api/processes" => json_or_error(|| processes(database, query)),
                "/api/hosts" => json_or_error(|| hosts(database, query)),
                "/api/agents" => json_or_error(|| agents(database, query)),
                "/api/coverage" => json_or_error(|| coverage(database, query)),
                _ => text(404, "not found"),
            }
        };
        // A browser that went away mid-answer is not an error worth a line.
        let _ = request.respond(response);
    }
}

/// Whether the request carried the token.
fn authorised(query: &str, token: &str) -> bool {
    parameter(query, "token")
        .is_some_and(|given| constant_time_eq(given.as_bytes(), token.as_bytes()))
}

/// Compares without returning early, so that the time taken says nothing about how much matched.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    difference == 0
}

/// One query parameter, percent-decoded.
fn parameter(query: &str, name: &str) -> Option<String> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .map(|(_, value)| percent_decode(value))
}

/// Turns `%20` back into a space, and `+` too.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes.get(index) {
            Some(b'%') => {
                let hex = value
                    .get(index + 1..index + 3)
                    .and_then(|hex| u8::from_str_radix(hex, 16).ok());
                match hex {
                    Some(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    // A stray `%` is a stray `%`, not a reason to lose the rest of the string.
                    None => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            Some(b'+') => {
                out.push(b' ');
                index += 1;
            }
            Some(byte) => {
                out.push(*byte);
                index += 1;
            }
            None => break,
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A window in seconds, from `since`, defaulting to an hour and capped at a year.
fn window(query: &str) -> i64 {
    let seconds = parameter(query, "since")
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(3_600)
        .clamp(0, 365 * 86_400);
    now() - seconds
}

/// Now, in seconds since the epoch.
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
}

/// What the page shows for one request.
#[derive(Serialize)]
struct RequestView {
    at: i64,
    process: String,
    agent: Option<String>,
    confidence: String,
    pid: u32,
    direction: String,
    protocol: Option<String>,
    method: Option<String>,
    target: Option<String>,
    host: Option<String>,
    status: Option<u16>,
    bytes: u32,
    truncated: bool,
    unreadable: Option<String>,
}

/// What the page shows for one process.
#[derive(Serialize)]
struct ProcessView {
    process: String,
    confidence: String,
    requests: i64,
    hosts: i64,
    bytes: i64,
    last_seen: i64,
}

/// What the page shows for one host.
#[derive(Serialize)]
struct HostView {
    host: String,
    requests: i64,
    last_seen: i64,
}

/// What the page shows for one agent, with the comparison already made.
#[derive(Serialize)]
struct AgentView {
    agent: String,
    requests: i64,
    hosts: i64,
    processes: i64,
    bytes: i64,
    last_seen: i64,
    /// Configured servers that never touch the network, which nothing here can ever see.
    local: Vec<String>,
    domains: Vec<DomainView>,
}

#[derive(Serialize)]
struct DomainView {
    host: String,
    standing: String,
    requests: i64,
    servers: Vec<String>,
}

/// What the page shows on the Coverage tab.
#[derive(Serialize)]
struct CoverageView {
    requests: i64,
    processes_read: i64,
    connections: i64,
    truncated: i64,
    undecodable: i64,
    named_by_comm: i64,
    named_by_pid: i64,
    refused: i64,
    dropped: i64,
    unread: Vec<UnreadView>,
    unprobed: Vec<UnprobedView>,
}

#[derive(Serialize)]
struct UnreadView {
    process: String,
    connections: i64,
}

#[derive(Serialize)]
struct UnprobedView {
    path: String,
    reason: String,
}

fn requests(database: &Path, query: &str) -> Result<String> {
    let mut store = Store::open_read_only(database)?;
    let limit = parameter(query, "limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(200)
        .clamp(1, 2_000);
    let rows: Vec<RequestView> = store
        .requests_since(window(query), limit)?
        .into_iter()
        .map(|row| RequestView {
            at: row.at,
            process: row.process,
            agent: row.agent,
            confidence: row.confidence,
            pid: row.pid,
            direction: row.direction,
            protocol: row.protocol,
            method: row.method,
            target: row.target,
            host: row.host,
            status: row.status,
            bytes: row.bytes,
            truncated: row.truncated,
            unreadable: row.unreadable,
        })
        .collect();
    Ok(serde_json::to_string(&rows)?)
}

fn processes(database: &Path, query: &str) -> Result<String> {
    let mut store = Store::open_read_only(database)?;
    let rows: Vec<ProcessView> = store
        .processes(window(query))?
        .into_iter()
        .map(|row| ProcessView {
            process: row.process,
            confidence: row.confidence,
            requests: row.requests,
            hosts: row.hosts,
            bytes: row.bytes,
            last_seen: row.last_seen,
        })
        .collect();
    Ok(serde_json::to_string(&rows)?)
}

fn hosts(database: &Path, query: &str) -> Result<String> {
    let mut store = Store::open_read_only(database)?;
    let process = parameter(query, "process").unwrap_or_default();
    let rows: Vec<HostView> = store
        .hosts_for(&process, window(query), 100)?
        .into_iter()
        .map(|row| HostView {
            host: row.host,
            requests: row.requests,
            last_seen: row.last_seen,
        })
        .collect();
    Ok(serde_json::to_string(&rows)?)
}

fn agents(database: &Path, query: &str) -> Result<String> {
    let mut store = Store::open_read_only(database)?;
    let since = window(query);
    // Read per request rather than cached: they are a handful of small files, and a configuration edited
    // while the page is open should show up on the next poll rather than the next restart.
    let configured = crate::history::configured_servers();
    let mut views = Vec::new();
    for row in store.agents(since)? {
        let contacted: Vec<(String, i64)> = store
            .hosts_for_agent(&row.agent, since, 200)?
            .into_iter()
            .map(|host| (host.host, host.requests))
            .collect();
        let mine: Vec<flowlight_agents::mcp::Server> = configured
            .iter()
            .filter(|server| server.agent == row.agent)
            .cloned()
            .collect();
        let domains = flowlight_agents::mcp::merge(
            &mine,
            &contacted,
            flowlight_agents::mcp::endpoints_for(&row.agent),
        );
        views.push(AgentView {
            agent: row.agent,
            requests: row.requests,
            hosts: row.hosts,
            processes: row.processes,
            bytes: row.bytes,
            last_seen: row.last_seen,
            local: mine
                .iter()
                .filter(|server| !server.transport.crosses_the_network())
                .map(|server| server.name.clone())
                .collect(),
            domains: domains
                .into_iter()
                .map(|domain| DomainView {
                    host: domain.host,
                    standing: domain.standing.as_str().to_owned(),
                    requests: domain.requests,
                    servers: domain.servers,
                })
                .collect(),
        });
    }
    Ok(serde_json::to_string(&views)?)
}

fn coverage(database: &Path, query: &str) -> Result<String> {
    let mut store = Store::open_read_only(database)?;
    let coverage = store.coverage(window(query))?;
    let view = CoverageView {
        requests: coverage.requests,
        processes_read: coverage.processes_read,
        connections: coverage.connections,
        truncated: coverage.truncated,
        undecodable: coverage.undecodable,
        named_by_comm: coverage.named_by_comm,
        named_by_pid: coverage.named_by_pid,
        refused: coverage.refused,
        dropped: coverage.dropped,
        unread: coverage
            .unread
            .into_iter()
            .map(|unread| UnreadView {
                process: unread.process,
                connections: unread.connections,
            })
            .collect(),
        unprobed: coverage
            .unprobed
            .into_iter()
            .map(|note| UnprobedView {
                path: note.subject,
                reason: note.detail,
            })
            .collect(),
    };
    Ok(serde_json::to_string(&view)?)
}

/// Runs a handler and turns a failure into a response rather than a panic.
fn json_or_error<F>(handler: F) -> Response<std::io::Cursor<Vec<u8>>>
where
    F: FnOnce() -> Result<String>,
{
    match handler() {
        Ok(body) => json(&body),
        // The message goes to the page, because the page is the only thing looking. It is this machine's
        // own error about this machine's own database, shown to somebody who already holds the token.
        Err(err) => text(500, &format!("{err:#}")),
    }
}

/// A response with headers added, skipping any that will not parse — which none of the constants below can.
fn with(
    mut response: Response<std::io::Cursor<Vec<u8>>>,
    headers: &[(&str, &str)],
) -> Response<std::io::Cursor<Vec<u8>>> {
    for (name, value) in headers {
        if let Ok(header) = Header::from_bytes(name.as_bytes(), value.as_bytes()) {
            response = response.with_header(header);
        }
    }
    response
}

fn json(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    with(
        Response::from_string(body),
        &[("Content-Type", "application/json; charset=utf-8")],
    )
}

fn html(body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    with(
        Response::from_string(body),
        &[
            ("Content-Type", "text/html; charset=utf-8"),
            // Nothing on this page loads from anywhere, and nothing should be able to.
            (
                "Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; \
                 connect-src 'self'",
            ),
            ("Referrer-Policy", "no-referrer"),
        ],
    )
}

fn text(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    with(
        Response::from_string(body).with_status_code(status),
        &[("Content-Type", "text/plain; charset=utf-8")],
    )
}

/// A token for the address bar.
///
/// Sixteen bytes from the kernel, as hex. It never touches the disk and dies with the process, so there is
/// nothing to rotate and nothing to leak afterwards.
pub fn token() -> Result<String> {
    use std::io::Read as _;
    // `read_exact` on an open handle, never `fs::read`: `/dev/urandom` has no end, and reading it whole is
    // a program that never returns.
    let mut file = std::fs::File::open("/dev/urandom").context("reading /dev/urandom")?;
    let mut bytes = [0_u8; 16];
    file.read_exact(&mut bytes)
        .context("reading /dev/urandom")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parameter_is_read_out_of_a_query() {
        assert_eq!(parameter("a=1&b=2", "b").as_deref(), Some("2"));
        assert_eq!(parameter("a=1", "b"), None);
        assert_eq!(parameter("", "b"), None);
    }

    /// Process names contain slashes, dots and spaces, and the page asks about them by name.
    #[test]
    fn a_parameter_is_percent_decoded() {
        assert_eq!(
            parameter("process=git%2Dremote%2Dhttp", "process").as_deref(),
            Some("git-remote-http")
        );
        assert_eq!(parameter("process=a+b", "process").as_deref(), Some("a b"));
    }

    /// A malformed escape is a malformed escape, not a reason to lose the rest of the name.
    #[test]
    fn a_stray_percent_does_not_swallow_the_rest() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("a%zzb"), "a%zzb");
    }

    #[test]
    fn a_request_without_the_token_is_not_answered() {
        assert!(!authorised("", "abc"));
        assert!(!authorised("token=", "abc"));
        assert!(!authorised("token=ab", "abc"));
        assert!(!authorised("token=abcd", "abc"));
        assert!(authorised("token=abc", "abc"));
    }

    #[test]
    fn the_comparison_does_not_stop_at_the_first_difference() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    /// There is no legitimate reason to serve this on a routable address, and a typo that did so would
    /// publish the machine's entire network history.
    #[test]
    fn the_interface_refuses_to_leave_loopback() {
        let err = serve(
            "0.0.0.0:0".parse().unwrap(),
            PathBuf::from("/nonexistent"),
            "t".to_owned(),
        )
        .unwrap_err();
        assert!(format!("{err}").contains("loopback"), "{err}");
    }

    #[test]
    fn a_window_defaults_to_an_hour_and_cannot_be_absurd() {
        let now = now();
        assert!((now - window("")) == 3_600);
        assert!((now - window("since=60")) == 60);
        assert!((now - window("since=-5")) == 0);
        assert!((now - window("since=999999999")) == 365 * 86_400);
    }

    #[test]
    fn a_token_is_long_enough_to_be_one() {
        let token = token().unwrap();
        assert_eq!(token.len(), 32);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        // Two in a row being equal would mean it is not random, which is the only property that matters.
        assert_ne!(token, super::token().unwrap());
    }
}
