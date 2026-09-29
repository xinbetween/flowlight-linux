//! What Flowlight keeps, for how long, and what survives when the detail expires.
//!
//! Up to 0.1.4 this daemon printed to standard output and kept nothing, which is defensible for a thing you
//! watch and useless for a thing you ask questions of. "Which host did that agent reach at three in the
//! morning" is the question people actually have, and it cannot be answered by a terminal that has scrolled.
//!
//! # Retention is a decision, so it is written down
//!
//! Two tiers, both with a number attached:
//!
//! - **Detail** — every connection and every request, for seven days by default. Hosts, paths, methods,
//!   statuses, byte counts. This is the tier that answers "what happened".
//! - **Summary** — one row per day per process per host, for ninety days. Counts and totals, no paths. This
//!   is the tier that answers "is this normal", and it is what the detail is folded into rather than what
//!   replaces it after the fact.
//!
//! Nothing is kept forever, and the defaults are printed at startup rather than left in a manual. A tool
//! that reads every HTTPS request on a machine and quietly accumulates them is a liability however good its
//! intentions.
//!
//! # Folding, not overwriting
//!
//! The rollup sums into existing rows rather than replacing them. That is a lesson from the macOS build,
//! where a repair that used `INSERT … ON CONFLICT DO UPDATE SET count = excluded.count` silently discarded
//! the history it was supposed to be repairing. Here it is `count + excluded.count`, and there is a test
//! whose only job is that distinction.
//!
//! # Why a crate of its own
//!
//! It has no Linux-only dependency, so it builds and its tests run on any machine — including the ones the
//! daemon around it cannot be compiled on. The same reason [`flowlight_common`] is a crate of its own.

use anyhow::{Context as _, Result};
use rusqlite::{Connection, OptionalExtension as _, params};
use std::path::Path;

/// How long individual requests are kept, unless told otherwise.
pub const DEFAULT_RETENTION_DAYS: u32 = 7;

/// How long the daily summary is kept.
pub const DEFAULT_SUMMARY_DAYS: u32 = 90;

/// How many rows to hold before writing, so that a busy machine is not one transaction per request.
const BATCH: usize = 256;

/// A connection, as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRow {
    /// When, in seconds since the epoch.
    pub at: i64,
    /// What the process is called.
    pub process: String,
    /// Where that name came from.
    pub confidence: String,
    /// The process.
    pub pid: u32,
    /// The address, if the family was one we read.
    pub destination: Option<String>,
    /// The port.
    pub port: u16,
}

/// A request or response, as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestRow {
    /// When, in seconds since the epoch.
    pub at: i64,
    /// What the process is called.
    pub process: String,
    /// Where that name came from.
    pub confidence: String,
    /// The process.
    pub pid: u32,
    /// `out` or `in`.
    pub direction: String,
    /// `http/2` when the connection was one.
    pub protocol: Option<String>,
    /// The method, for a request.
    pub method: Option<String>,
    /// The target, already redacted of credentials before it reaches here.
    pub target: Option<String>,
    /// The host or `:authority`.
    pub host: Option<String>,
    /// The status, for a response.
    pub status: Option<u16>,
    /// How many bytes the call carried.
    pub bytes: u32,
    /// Whether more was carried than captured.
    pub truncated: bool,
    /// Why this connection could not be read, when it could not.
    pub unreadable: Option<String>,
}

/// One day's traffic between one process and one host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyRow {
    /// `YYYY-MM-DD`, in UTC.
    pub day: String,
    /// The process.
    pub process: String,
    /// The host, or empty when the request had none.
    pub host: String,
    /// How many requests.
    pub requests: i64,
    /// How many bytes they carried.
    pub bytes: i64,
}

/// What a sweep did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Swept {
    /// Requests folded into the daily summary and then removed.
    pub requests_rolled: usize,
    /// Connections removed.
    pub connections_removed: usize,
    /// Summary rows removed for being older than the summary period.
    pub summary_removed: usize,
}

/// How long things are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retention {
    /// Days of individual requests and connections.
    pub detail_days: u32,
    /// Days of the daily summary.
    pub summary_days: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            detail_days: DEFAULT_RETENTION_DAYS,
            summary_days: DEFAULT_SUMMARY_DAYS,
        }
    }
}

impl Retention {
    /// A sentence for the startup banner.
    ///
    /// Printed rather than documented, because a retention period nobody is told about is a retention period
    /// nobody agreed to.
    pub fn describe(&self) -> String {
        format!(
            "keeping individual requests for {} day{}, and a daily summary for {} day{}",
            self.detail_days,
            plural(self.detail_days),
            self.summary_days,
            plural(self.summary_days)
        )
    }
}

/// `s`, unless there is one of the thing.
fn plural(count: u32) -> &'static str {
    if count == 1 { "" } else { "s" }
}

/// The database.
pub struct Store {
    connection: Connection,
    pending_connections: Vec<ConnectionRow>,
    pending_requests: Vec<RequestRow>,
}

impl Store {
    /// Opens or creates the database at a path, readable only by its owner.
    ///
    /// The mode matters. This file holds every host every process on the machine reached, and on a shared
    /// machine that is a list of what everyone was doing. It is created `0600` and the directory `0700`.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
            restrict(parent, 0o700)?;
        }
        let connection = Connection::open(path)
            .with_context(|| format!("opening the database at {}", path.display()))?;
        restrict(path, 0o600)?;
        Self::from_connection(connection)
    }

    /// An in-memory database, for tests.
    pub fn in_memory() -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(connection: Connection) -> Result<Self> {
        // WAL so that a reader — the interface, eventually — does not block the writer. `synchronous =
        // NORMAL` because losing the last few requests to a power cut is not worth an fsync per batch.
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "NORMAL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self {
            connection,
            pending_connections: Vec::new(),
            pending_requests: Vec::new(),
        };
        store.migrate()?;
        Ok(store)
    }

    /// Creates the schema, or leaves it alone if it is already the one we want.
    fn migrate(&self) -> Result<()> {
        self.connection.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS connections (
                id          INTEGER PRIMARY KEY,
                at          INTEGER NOT NULL,
                process     TEXT    NOT NULL,
                confidence  TEXT    NOT NULL,
                pid         INTEGER NOT NULL,
                destination TEXT,
                port        INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS connections_at ON connections(at);
            CREATE TABLE IF NOT EXISTS requests (
                id         INTEGER PRIMARY KEY,
                at         INTEGER NOT NULL,
                process    TEXT    NOT NULL,
                confidence TEXT    NOT NULL,
                pid        INTEGER NOT NULL,
                direction  TEXT    NOT NULL,
                protocol   TEXT,
                method     TEXT,
                target     TEXT,
                host       TEXT,
                status     INTEGER,
                bytes      INTEGER NOT NULL,
                truncated  INTEGER NOT NULL,
                unreadable TEXT
            );
            CREATE INDEX IF NOT EXISTS requests_at ON requests(at);
            CREATE INDEX IF NOT EXISTS requests_process ON requests(process, at);
            CREATE TABLE IF NOT EXISTS daily_requests (
                day      TEXT    NOT NULL,
                process  TEXT    NOT NULL,
                host     TEXT    NOT NULL,
                requests INTEGER NOT NULL,
                bytes    INTEGER NOT NULL,
                PRIMARY KEY (day, process, host)
            );
            CREATE TABLE IF NOT EXISTS daily_connections (
                day         TEXT    NOT NULL,
                process     TEXT    NOT NULL,
                port        INTEGER NOT NULL,
                connections INTEGER NOT NULL,
                PRIMARY KEY (day, process, port)
            );
            ",
        )?;
        self.connection.execute(
            "INSERT INTO meta(key, value) VALUES('schema', '1') ON CONFLICT(key) DO NOTHING",
            [],
        )?;
        Ok(())
    }

    /// Queues a connection.
    pub fn record_connection(&mut self, row: ConnectionRow) -> Result<()> {
        self.pending_connections.push(row);
        self.flush_if_full()
    }

    /// Queues a request.
    pub fn record_request(&mut self, row: RequestRow) -> Result<()> {
        self.pending_requests.push(row);
        self.flush_if_full()
    }

    fn flush_if_full(&mut self) -> Result<()> {
        if self.pending_connections.len() + self.pending_requests.len() >= BATCH {
            self.flush()?;
        }
        Ok(())
    }

    /// Writes everything queued, in one transaction.
    pub fn flush(&mut self) -> Result<()> {
        if self.pending_connections.is_empty() && self.pending_requests.is_empty() {
            return Ok(());
        }
        let transaction = self.connection.transaction()?;
        {
            let mut insert = transaction.prepare_cached(
                "INSERT INTO connections(at, process, confidence, pid, destination, port)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for row in &self.pending_connections {
                insert.execute(params![
                    row.at,
                    row.process,
                    row.confidence,
                    row.pid,
                    row.destination,
                    row.port
                ])?;
            }
            let mut insert = transaction.prepare_cached(
                "INSERT INTO requests(at, process, confidence, pid, direction, protocol, method,
                                      target, host, status, bytes, truncated, unreadable)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )?;
            for row in &self.pending_requests {
                insert.execute(params![
                    row.at,
                    row.process,
                    row.confidence,
                    row.pid,
                    row.direction,
                    row.protocol,
                    row.method,
                    row.target,
                    row.host,
                    row.status,
                    row.bytes,
                    row.truncated,
                    row.unreadable
                ])?;
            }
        }
        transaction.commit()?;
        self.pending_connections.clear();
        self.pending_requests.clear();
        Ok(())
    }

    /// Folds expired detail into the daily summary and removes it.
    ///
    /// `now` is passed in rather than read from the clock so that the behaviour at a boundary is something a
    /// test can state rather than something that happens once a week at midnight.
    pub fn sweep(&mut self, now: i64, retention: Retention) -> Result<Swept> {
        self.flush()?;
        let detail_cutoff = now - i64::from(retention.detail_days) * 86_400;
        let summary_cutoff = now - i64::from(retention.summary_days) * 86_400;
        let transaction = self.connection.transaction()?;
        let mut swept = Swept::default();

        // `requests + excluded.requests`, not `excluded.requests`. A sweep that runs twice over overlapping
        // windows, or one that folds a second day into a row that already exists, must add to what is there.
        // The macOS build lost history to exactly this line written the other way.
        transaction.execute(
            "INSERT INTO daily_requests(day, process, host, requests, bytes)
             SELECT date(at, 'unixepoch'), process, coalesce(host, ''), count(*), coalesce(sum(bytes), 0)
             FROM requests WHERE at < ?1
             GROUP BY 1, 2, 3
             ON CONFLICT(day, process, host) DO UPDATE
               SET requests = requests + excluded.requests,
                   bytes    = bytes + excluded.bytes",
            params![detail_cutoff],
        )?;
        swept.requests_rolled =
            transaction.execute("DELETE FROM requests WHERE at < ?1", params![detail_cutoff])?;

        transaction.execute(
            "INSERT INTO daily_connections(day, process, port, connections)
             SELECT date(at, 'unixepoch'), process, port, count(*)
             FROM connections WHERE at < ?1
             GROUP BY 1, 2, 3
             ON CONFLICT(day, process, port) DO UPDATE
               SET connections = connections + excluded.connections",
            params![detail_cutoff],
        )?;
        swept.connections_removed = transaction.execute(
            "DELETE FROM connections WHERE at < ?1",
            params![detail_cutoff],
        )?;

        let cutoff_day: String = transaction.query_row(
            "SELECT date(?1, 'unixepoch')",
            params![summary_cutoff],
            |row| row.get(0),
        )?;
        swept.summary_removed = transaction.execute(
            "DELETE FROM daily_requests WHERE day < ?1",
            params![&cutoff_day],
        )?;
        swept.summary_removed += transaction.execute(
            "DELETE FROM daily_connections WHERE day < ?1",
            params![&cutoff_day],
        )?;

        transaction.commit()?;
        Ok(swept)
    }

    /// Requests since a moment, newest first.
    pub fn requests_since(&mut self, since: i64, limit: usize) -> Result<Vec<RequestRow>> {
        self.flush()?;
        let mut statement = self.connection.prepare(
            "SELECT at, process, confidence, pid, direction, protocol, method, target, host,
                    status, bytes, truncated, unreadable
             FROM requests WHERE at >= ?1 ORDER BY at DESC, id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(params![since, limit as i64], |row| {
            Ok(RequestRow {
                at: row.get(0)?,
                process: row.get(1)?,
                confidence: row.get(2)?,
                pid: row.get(3)?,
                direction: row.get(4)?,
                protocol: row.get(5)?,
                method: row.get(6)?,
                target: row.get(7)?,
                host: row.get(8)?,
                status: row.get(9)?,
                bytes: row.get(10)?,
                truncated: row.get(11)?,
                unreadable: row.get(12)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The daily summary, newest first.
    pub fn summary(&mut self, limit: usize) -> Result<Vec<DailyRow>> {
        self.flush()?;
        let mut statement = self.connection.prepare(
            "SELECT day, process, host, requests, bytes FROM daily_requests
             ORDER BY day DESC, requests DESC LIMIT ?1",
        )?;
        let rows = statement.query_map(params![limit as i64], |row| {
            Ok(DailyRow {
                day: row.get(0)?,
                process: row.get(1)?,
                host: row.get(2)?,
                requests: row.get(3)?,
                bytes: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The oldest request still held, for the interface to be able to say how far back it can see.
    pub fn earliest_request(&mut self) -> Result<Option<i64>> {
        self.flush()?;
        Ok(self
            .connection
            .query_row("SELECT min(at) FROM requests", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .optional()?
            .flatten())
    }
}

/// Sets a file or directory's mode, on the only platform this runs on.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("restricting {} to {mode:o}", path.display()))
}

/// Everywhere else, which is only ever a developer machine running the tests.
#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 86_400;

    fn request(at: i64, process: &str, host: &str, bytes: u32) -> RequestRow {
        RequestRow {
            at,
            process: process.to_owned(),
            confidence: "path".to_owned(),
            pid: 4711,
            direction: "out".to_owned(),
            protocol: Some("http/2".to_owned()),
            method: Some("POST".to_owned()),
            target: Some("/v1/messages".to_owned()),
            host: Some(host.to_owned()),
            status: None,
            bytes,
            truncated: false,
            unreadable: None,
        }
    }

    #[test]
    fn a_request_written_is_a_request_read_back() {
        let mut store = Store::in_memory().unwrap();
        let row = request(1_000, "claude", "api.anthropic.com", 3_800);
        store.record_request(row.clone()).unwrap();
        assert_eq!(store.requests_since(0, 10).unwrap(), vec![row]);
    }

    #[test]
    fn requests_come_back_newest_first() {
        let mut store = Store::in_memory().unwrap();
        for at in [100, 300, 200] {
            store
                .record_request(request(at, "curl", "example.com", 10))
                .unwrap();
        }
        let times: Vec<_> = store
            .requests_since(0, 10)
            .unwrap()
            .iter()
            .map(|row| row.at)
            .collect();
        assert_eq!(times, [300, 200, 100]);
    }

    #[test]
    fn nothing_older_than_the_window_is_returned() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(request(100, "curl", "example.com", 10))
            .unwrap();
        store
            .record_request(request(900, "curl", "example.com", 10))
            .unwrap();
        assert_eq!(store.requests_since(500, 10).unwrap().len(), 1);
    }

    /// Detail expires; the shape of what happened does not. A month later the question is "was this normal",
    /// and that is answerable from counts without keeping every path anyone requested.
    #[test]
    fn expired_detail_becomes_a_summary_rather_than_nothing() {
        let mut store = Store::in_memory().unwrap();
        let now = 30 * DAY;
        store
            .record_request(request(
                now - 10 * DAY,
                "claude",
                "api.anthropic.com",
                1_000,
            ))
            .unwrap();
        store
            .record_request(request(now - 10 * DAY, "claude", "api.anthropic.com", 500))
            .unwrap();
        store
            .record_request(request(now - DAY, "claude", "api.anthropic.com", 7))
            .unwrap();

        let swept = store.sweep(now, Retention::default()).unwrap();
        assert_eq!(swept.requests_rolled, 2);

        // The recent one is untouched.
        assert_eq!(store.requests_since(0, 10).unwrap().len(), 1);

        let summary = store.summary(10).unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].process, "claude");
        assert_eq!(summary[0].host, "api.anthropic.com");
        assert_eq!(summary[0].requests, 2);
        assert_eq!(summary[0].bytes, 1_500);
    }

    /// The line this whole module is careful about. A second fold into a day that already has a row must
    /// add to it. Written the other way — `SET requests = excluded.requests` — it silently replaces, and the
    /// history it was supposed to be preserving is gone. The macOS build lost data to exactly that.
    #[test]
    fn folding_twice_adds_rather_than_replaces() {
        let mut store = Store::in_memory().unwrap();
        let now = 30 * DAY;
        let old = now - 10 * DAY;

        store
            .record_request(request(old, "claude", "api.anthropic.com", 100))
            .unwrap();
        store.sweep(now, Retention::default()).unwrap();
        store
            .record_request(request(old, "claude", "api.anthropic.com", 400))
            .unwrap();
        store.sweep(now, Retention::default()).unwrap();

        let summary = store.summary(10).unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(
            summary[0].requests, 2,
            "the first fold was replaced, not added to"
        );
        assert_eq!(summary[0].bytes, 500);
    }

    /// A sweep with nothing to sweep must be a no-op, because it runs on a timer and most times there is
    /// nothing old enough.
    #[test]
    fn a_sweep_with_nothing_expired_changes_nothing() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(request(30 * DAY, "curl", "example.com", 10))
            .unwrap();
        let swept = store.sweep(30 * DAY, Retention::default()).unwrap();
        assert_eq!(swept, Swept::default());
        assert_eq!(store.requests_since(0, 10).unwrap().len(), 1);
    }

    /// Nothing is kept forever, including the summary.
    #[test]
    fn the_summary_expires_too() {
        let mut store = Store::in_memory().unwrap();
        let now = 200 * DAY;
        store
            .record_request(request(now - 150 * DAY, "curl", "example.com", 10))
            .unwrap();
        store.sweep(now, Retention::default()).unwrap();
        assert!(
            store.summary(10).unwrap().is_empty(),
            "a summary older than the summary period is still a record nobody agreed to keep"
        );
    }

    /// A request with no host is still a request, and grouping must not lose it.
    #[test]
    fn a_request_without_a_host_still_appears_in_the_summary() {
        let mut store = Store::in_memory().unwrap();
        let now = 30 * DAY;
        let mut row = request(now - 10 * DAY, "node", "", 10);
        row.host = None;
        store.record_request(row).unwrap();
        store.sweep(now, Retention::default()).unwrap();
        let summary = store.summary(10).unwrap();
        assert_eq!(summary.len(), 1);
        assert_eq!(summary[0].host, "");
    }

    #[test]
    fn connections_are_kept_and_swept_on_the_same_schedule() {
        let mut store = Store::in_memory().unwrap();
        let now = 30 * DAY;
        store
            .record_connection(ConnectionRow {
                at: now - 10 * DAY,
                process: "curl".to_owned(),
                confidence: "path".to_owned(),
                pid: 1,
                destination: Some("93.184.216.34".to_owned()),
                port: 443,
            })
            .unwrap();
        let swept = store.sweep(now, Retention::default()).unwrap();
        assert_eq!(swept.connections_removed, 1);
    }

    /// The banner has to be able to say what the numbers are, because a retention period nobody is told
    /// about is a retention period nobody agreed to.
    #[test]
    fn the_retention_period_can_be_said_out_loud() {
        let described = Retention::default().describe();
        assert!(described.contains("7 days"), "{described}");
        assert!(described.contains("90 days"), "{described}");
        let one = Retention {
            detail_days: 1,
            summary_days: 1,
        }
        .describe();
        assert!(one.contains("1 day,"), "{one}");
    }

    /// This file holds every host every process on the machine reached. On a shared machine that is a list
    /// of what everyone was doing.
    #[cfg(unix)]
    #[test]
    fn the_database_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = std::env::temp_dir().join("flowlight-store-mode");
        let _ = std::fs::remove_dir_all(&directory);
        let path = directory.join("flowlight.db");
        let store = Store::open(&path).unwrap();
        drop(store);

        let file = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(file, 0o600, "the database is {file:o}");
        let parent = std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
        assert_eq!(parent, 0o700, "the directory is {parent:o}");
    }

    /// Opening a database that already exists must not lose what is in it.
    #[test]
    fn reopening_keeps_what_was_there() {
        let directory = std::env::temp_dir().join("flowlight-store-reopen");
        let _ = std::fs::remove_dir_all(&directory);
        let path = directory.join("flowlight.db");

        let mut store = Store::open(&path).unwrap();
        store
            .record_request(request(1_000, "claude", "api.anthropic.com", 1))
            .unwrap();
        store.flush().unwrap();
        drop(store);

        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.requests_since(0, 10).unwrap().len(), 1);
        assert_eq!(store.earliest_request().unwrap(), Some(1_000));
    }

    /// Writes are batched, so a reader that does not flush first sees a database that is behind.
    #[test]
    fn a_read_flushes_what_is_queued() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(request(1, "curl", "example.com", 1))
            .unwrap();
        // No explicit flush.
        assert_eq!(store.requests_since(0, 10).unwrap().len(), 1);
    }
}
