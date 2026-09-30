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
    /// The agent this process is working for, if it is working for one.
    pub agent: Option<String>,
    /// The address, if the family was one we read.
    pub destination: Option<String>,
    /// The port.
    pub port: u16,
    /// Whether this connection was refused before the SYN rather than opened.
    pub blocked: bool,
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
    /// The agent this process is working for, if it is working for one.
    ///
    /// `claude` does not make requests; it spawns `node`, which spawns `git`, which makes one. This is the
    /// answer to "who caused this", which is the question people ask and `process` does not answer.
    pub agent: Option<String>,
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

/// A process that opened HTTPS connections and had none of its traffic read.
///
/// The single most useful thing Coverage says, because it is the failure that otherwise looks exactly like
/// success: an empty screen means "this agent made no requests" and "this agent made four hundred requests
/// Flowlight could not read" equally well, and only one of those is worth knowing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unread {
    /// The process.
    pub process: String,
    /// How many connections it opened that nothing was read from.
    pub connections: i64,
}

/// One process, and what it has been doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessRow {
    /// What it is called.
    pub process: String,
    /// Where that name came from, at its best over the window.
    pub confidence: String,
    /// Requests read from it.
    pub requests: i64,
    /// Distinct hosts it reached.
    pub hosts: i64,
    /// Bytes those requests carried.
    pub bytes: i64,
    /// The most recent one, in seconds since the epoch.
    pub last_seen: i64,
}

/// Traffic that happened, grouped so that a rule can be tried against it.
///
/// Two sources, and they know different things. A stored request knows the host and not the port, because
/// a probe on a TLS library never sees one. A stored connection knows the address and the port and not the
/// host, because at `connect()` the name has already been resolved and thrown away. Both are real traffic
/// and a rule has to be judged against both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficRow {
    /// The agent that caused it, if any.
    pub agent: Option<String>,
    /// The host, for a row that came from a request.
    pub host: Option<String>,
    /// The address, for a row that came from a connection.
    pub address: Option<String>,
    /// The port, for a row that came from a connection.
    pub port: Option<u16>,
    /// How many times.
    pub occurrences: i64,
}

/// A rule: what to do about something a process tries to reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRow {
    /// Its identifier, so a verdict can name the rule that produced it and `forget` can take it away.
    pub id: i64,
    /// When it was written.
    pub created: i64,
    /// `allow`, `ask` or `block`.
    pub action: String,
    /// A hostname, a pattern, a literal address, or `*`.
    pub subject: String,
    /// The port, or zero for every port.
    pub port: u16,
    /// `everyone`, or `agent:<name>`.
    pub scope: String,
    /// Why, if whoever wrote it said.
    pub note: Option<String>,
}

/// What writing a rule did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrote {
    /// There was no such rule.
    Added,
    /// There was one, saying something else.
    Changed,
    /// There was one, saying exactly this.
    Unchanged,
}

/// One agent, and what it has been doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRow {
    /// The agent.
    pub agent: String,
    /// Requests read from it or anything it started.
    pub requests: i64,
    /// Distinct hosts reached.
    pub hosts: i64,
    /// Distinct processes doing the work.
    pub processes: i64,
    /// Bytes those requests carried.
    pub bytes: i64,
    /// The most recent one.
    pub last_seen: i64,
}

/// One host a process reached, and how often.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRow {
    /// The host.
    pub host: String,
    /// Requests to it.
    pub requests: i64,
    /// The most recent one.
    pub last_seen: i64,
}

/// Something worth remembering that is not a request: a library that could not be probed, records the
/// kernel dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// When.
    pub at: i64,
    /// What sort of thing: `unprobed-library`, `dropped`.
    pub kind: String,
    /// What it was about — a path, usually.
    pub subject: String,
    /// The explanation, as a sentence.
    pub detail: String,
}

/// What was seen, and what was not.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Coverage {
    /// How far back this covers.
    pub window: i64,
    /// Requests read.
    pub requests: i64,
    /// Distinct processes something was read from.
    pub processes_read: i64,
    /// Connections opened.
    pub connections: i64,
    /// Processes that opened HTTPS connections and had nothing read.
    pub unread: Vec<Unread>,
    /// Calls that carried more than was captured.
    pub truncated: i64,
    /// Connections whose HTTP/2 could not be decoded.
    pub undecodable: i64,
    /// Records naming a process by its `comm`, which the kernel cuts at fifteen characters.
    pub named_by_comm: i64,
    /// Records naming a process by its pid, which is not a name.
    pub named_by_pid: i64,
    /// Records the kernel had nowhere to put.
    pub dropped: i64,
    /// Connections refused before the handshake, because a rule said so.
    pub refused: i64,
    /// Libraries found and not probed.
    pub unprobed: Vec<Note>,
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

    /// Opens an existing database without being able to write to it.
    ///
    /// What the interface uses. It runs in the same process as the watcher and has no business writing, and
    /// a second connection rather than a shared lock means a slow page cannot hold up the kernel's reader.
    /// SQLite's write-ahead log is what makes concurrent reading safe here.
    pub fn open_read_only(path: &Path) -> Result<Self> {
        use rusqlite::OpenFlags;
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening {} for reading", path.display()))?;
        Ok(Self {
            connection,
            pending_connections: Vec::new(),
            pending_requests: Vec::new(),
        })
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

    /// The schema this version of the code expects.
    pub const SCHEMA: i64 = 4;

    /// Creates the schema, or brings an older one up to it.
    ///
    /// `CREATE TABLE IF NOT EXISTS` alone is not a migration: it does nothing to a table that already
    /// exists, so a column added in a later version never appears in a database created by an earlier one.
    /// A database written by 0.1.7 is a database somebody has a week of history in, and silently failing to
    /// read it — or silently failing to *write* half of what it is told — is worse than refusing to open it.
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
                port        INTEGER NOT NULL,
                agent       TEXT,
                blocked     INTEGER NOT NULL DEFAULT 0
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
                unreadable TEXT,
                agent      TEXT
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
            CREATE TABLE IF NOT EXISTS rules (
                id      INTEGER PRIMARY KEY,
                created INTEGER NOT NULL,
                subject TEXT    NOT NULL,
                port    INTEGER NOT NULL,
                scope   TEXT    NOT NULL,
                note    TEXT,
                action  TEXT    NOT NULL DEFAULT 'block',
                UNIQUE (subject, port, scope)
            );
            CREATE TABLE IF NOT EXISTS notes (
                id      INTEGER PRIMARY KEY,
                at      INTEGER NOT NULL,
                kind    TEXT    NOT NULL,
                subject TEXT    NOT NULL,
                detail  TEXT    NOT NULL,
                UNIQUE (kind, subject)
            );
            CREATE INDEX IF NOT EXISTS notes_at ON notes(at);
            CREATE TABLE IF NOT EXISTS daily_connections (
                day         TEXT    NOT NULL,
                process     TEXT    NOT NULL,
                port        INTEGER NOT NULL,
                connections INTEGER NOT NULL,
                PRIMARY KEY (day, process, port)
            );
            ",
        )?;
        // Schema 1 is 0.1.5 through 0.1.7: everything above, without `agent`. Schema 2 is 0.1.8, without
        // `blocked`. Each column is added if it is missing rather than if the recorded version says so,
        // because a database interrupted halfway through an upgrade is a database that has to open again.
        for (table, column, kind) in [
            ("requests", "agent", "TEXT"),
            ("connections", "agent", "TEXT"),
            ("connections", "blocked", "INTEGER NOT NULL DEFAULT 0"),
            // Schema 3 is 0.2.0, where every rule was a block and every scope was global.
            ("rules", "action", "TEXT NOT NULL DEFAULT 'block'"),
        ] {
            if !self.has_column(table, column)? {
                self.connection
                    .execute(
                        &format!("ALTER TABLE {table} ADD COLUMN {column} {kind}"),
                        [],
                    )
                    .with_context(|| format!("adding {table}.{column} to an existing database"))?;
            }
        }
        // After the columns exist, not before. An index names a column, so creating it in the same batch
        // as the tables works on a fresh database and fails on every upgraded one — which is the half
        // nobody runs until it is in somebody's hands.
        self.connection
            .execute_batch("CREATE INDEX IF NOT EXISTS requests_agent ON requests(agent, at);")?;

        self.connection.execute(
            "INSERT INTO meta(key, value) VALUES('schema', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![Self::SCHEMA.to_string()],
        )?;
        Ok(())
    }

    /// Whether a table already has a column.
    fn has_column(&self, table: &str, column: &str) -> Result<bool> {
        let mut statement = self
            .connection
            .prepare(&format!("PRAGMA table_info({table})"))?;
        let mut names = statement.query_map([], |row| row.get::<_, String>(1))?;
        Ok(names.any(|name| name.is_ok_and(|name| name == column)))
    }

    /// What schema version the database is at.
    pub fn schema_version(&self) -> Result<i64> {
        Ok(self
            .connection
            .query_row("SELECT value FROM meta WHERE key = 'schema'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .and_then(|value| value.parse().ok())
            .unwrap_or(0))
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
                "INSERT INTO connections(at, process, confidence, pid, destination, port, agent, blocked)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for row in &self.pending_connections {
                insert.execute(params![
                    row.at,
                    row.process,
                    row.confidence,
                    row.pid,
                    row.destination,
                    row.port,
                    row.agent,
                    row.blocked
                ])?;
            }
            let mut insert = transaction.prepare_cached(
                "INSERT INTO requests(at, process, confidence, pid, direction, protocol, method,
                                      target, host, status, bytes, truncated, unreadable, agent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
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
                    row.unreadable,
                    row.agent
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
                    status, bytes, truncated, unreadable, agent
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
                agent: row.get(13)?,
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

    /// Records something that is not a request.
    ///
    /// Written immediately rather than batched, and deduplicated on `(kind, subject)`: a library that cannot
    /// be probed cannot be probed every five seconds for the rest of the week, and a row per rescan would
    /// bury the one fact in ten thousand copies of it.
    pub fn record_note(&mut self, kind: &str, subject: &str, detail: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO notes(at, kind, subject, detail) VALUES (unixepoch(), ?1, ?2, ?3)
             ON CONFLICT(kind, subject) DO UPDATE SET at = excluded.at, detail = excluded.detail",
            params![kind, subject, detail],
        )?;
        Ok(())
    }

    /// Counts a record the kernel dropped before it could be read.
    pub fn record_drop(&mut self, count: u64) -> Result<()> {
        self.connection.execute(
            "INSERT INTO notes(at, kind, subject, detail)
             VALUES (unixepoch(), 'dropped', 'kernel', ?1)
             ON CONFLICT(kind, subject) DO UPDATE
               SET at = excluded.at,
                   detail = CAST(CAST(detail AS INTEGER) + CAST(excluded.detail AS INTEGER) AS TEXT)",
            params![count.to_string()],
        )?;
        Ok(())
    }

    /// What was seen in a window, and what was not.
    pub fn coverage(&mut self, since: i64) -> Result<Coverage> {
        self.flush()?;
        let mut coverage = Coverage {
            window: since,
            ..Coverage::default()
        };

        coverage.requests = self.connection.query_row(
            "SELECT count(*) FROM requests WHERE at >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        coverage.processes_read = self.connection.query_row(
            "SELECT count(DISTINCT process) FROM requests WHERE at >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        coverage.connections = self.connection.query_row(
            "SELECT count(*) FROM connections WHERE at >= ?1",
            params![since],
            |row| row.get(0),
        )?;
        coverage.truncated = self.connection.query_row(
            "SELECT count(*) FROM requests WHERE at >= ?1 AND truncated = 1",
            params![since],
            |row| row.get(0),
        )?;
        coverage.undecodable = self.connection.query_row(
            "SELECT count(*) FROM requests WHERE at >= ?1 AND unreadable IS NOT NULL",
            params![since],
            |row| row.get(0),
        )?;
        coverage.named_by_comm = self.connection.query_row(
            "SELECT count(*) FROM requests WHERE at >= ?1 AND confidence = 'comm'",
            params![since],
            |row| row.get(0),
        )?;
        coverage.named_by_pid = self.connection.query_row(
            "SELECT count(*) FROM requests WHERE at >= ?1 AND confidence = 'pid'",
            params![since],
            |row| row.get(0),
        )?;
        coverage.refused = self.connection.query_row(
            "SELECT count(*) FROM connections WHERE at >= ?1 AND blocked = 1",
            params![since],
            |row| row.get(0),
        )?;
        coverage.dropped = self
            .connection
            .query_row(
                "SELECT CAST(detail AS INTEGER) FROM notes WHERE kind = 'dropped'",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);

        // The question the whole screen exists for. A process that opened an HTTPS connection and had
        // nothing read from it is using a TLS implementation there is no probe for — Go's, or one linked
        // into its own binary — and from the outside that is indistinguishable from a quiet process.
        let mut statement = self.connection.prepare(
            "SELECT c.process, count(*) FROM connections c
             WHERE c.at >= ?1 AND c.port IN (443, 8443)
               AND NOT EXISTS (
                 SELECT 1 FROM requests r WHERE r.process = c.process AND r.at >= ?1
               )
             GROUP BY c.process
             ORDER BY count(*) DESC",
        )?;
        coverage.unread = statement
            .query_map(params![since], |row| {
                Ok(Unread {
                    process: row.get(0)?,
                    connections: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let mut statement = self.connection.prepare(
            "SELECT at, kind, subject, detail FROM notes WHERE kind = 'unprobed-library' ORDER BY subject",
        )?;
        coverage.unprobed = statement
            .query_map([], |row| {
                Ok(Note {
                    at: row.get(0)?,
                    kind: row.get(1)?,
                    subject: row.get(2)?,
                    detail: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        Ok(coverage)
    }

    /// Every process something was read from, busiest first.
    ///
    /// The interface's front page. `min(confidence)` rather than `max` because `comm` sorts before `path`
    /// and the *worst* name a process was given over the window is the one worth showing — a process named
    /// from its path nine times out of ten and from a truncated `comm` once is a process whose rules might
    /// not match.
    pub fn processes(&mut self, since: i64) -> Result<Vec<ProcessRow>> {
        self.flush()?;
        let mut statement = self.connection.prepare(
            "SELECT process, min(confidence), count(*), count(DISTINCT host),
                    coalesce(sum(bytes), 0), max(at)
             FROM requests WHERE at >= ?1
             GROUP BY process
             ORDER BY count(*) DESC",
        )?;
        let rows = statement.query_map(params![since], |row| {
            Ok(ProcessRow {
                process: row.get(0)?,
                confidence: row.get(1)?,
                requests: row.get(2)?,
                hosts: row.get(3)?,
                bytes: row.get(4)?,
                last_seen: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Every distinct piece of traffic in a window, with how often it happened.
    ///
    /// Grouped in the database rather than replayed row by row: a day is thousands of rows and a handful of
    /// distinct answers, and a simulation only needs the answers.
    pub fn traffic_since(&mut self, since: i64) -> Result<Vec<TrafficRow>> {
        self.flush()?;
        let mut statement = self.connection.prepare(
            "SELECT agent, host, NULL, NULL, count(*) FROM requests
             WHERE at >= ?1 AND host IS NOT NULL AND host != ''
             GROUP BY agent, host
             UNION ALL
             SELECT agent, NULL, destination, port, count(*) FROM connections
             WHERE at >= ?1 AND destination IS NOT NULL
             GROUP BY agent, destination, port
             ORDER BY 5 DESC",
        )?;
        let rows = statement.query_map(params![since], |row| {
            Ok(TrafficRow {
                agent: row.get(0)?,
                host: row.get(1)?,
                address: row.get(2)?,
                port: row.get(3)?,
                occurrences: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Writes a rule, replacing whatever was said about the same subject, port and scope.
    ///
    /// Replacing rather than adding, because `allow x` after `block x` is somebody changing their mind
    /// about `x` — and leaving both would make it a contradiction, resolved conservatively, which is the
    /// opposite of what they just asked for.
    pub fn put_rule(
        &mut self,
        action: &str,
        subject: &str,
        port: u16,
        scope: &str,
        note: Option<&str>,
    ) -> Result<Wrote> {
        let existing: Option<String> = self
            .connection
            .query_row(
                "SELECT action FROM rules WHERE subject = ?1 AND port = ?2 AND scope = ?3",
                params![subject, port, scope],
                |row| row.get(0),
            )
            .optional()?;
        self.connection.execute(
            "INSERT INTO rules(created, action, subject, port, scope, note)
             VALUES (unixepoch(), ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(subject, port, scope) DO UPDATE
               SET action = excluded.action, note = excluded.note, created = excluded.created",
            params![action, subject, port, scope, note],
        )?;
        Ok(match existing {
            None => Wrote::Added,
            Some(previous) if previous == action => Wrote::Unchanged,
            Some(_) => Wrote::Changed,
        })
    }

    /// Removes one rule by its identifier. Returns whether there was one.
    pub fn forget_rule(&mut self, id: i64) -> Result<bool> {
        Ok(self
            .connection
            .execute("DELETE FROM rules WHERE id = ?1", params![id])?
            > 0)
    }

    /// Every rule, oldest first.
    pub fn rules(&mut self) -> Result<Vec<RuleRow>> {
        let mut statement = self.connection.prepare(
            "SELECT id, created, action, subject, port, scope, note FROM rules
             ORDER BY created, subject",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(RuleRow {
                id: row.get(0)?,
                created: row.get(1)?,
                action: row.get(2)?,
                subject: row.get(3)?,
                port: row.get(4)?,
                scope: row.get(5)?,
                note: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// How many connections were refused in a window.
    pub fn blocked_since(&mut self, since: i64) -> Result<i64> {
        self.flush()?;
        Ok(self.connection.query_row(
            "SELECT count(*) FROM connections WHERE at >= ?1 AND blocked = 1",
            params![since],
            |row| row.get(0),
        )?)
    }

    /// Every agent something was read from, busiest first.
    pub fn agents(&mut self, since: i64) -> Result<Vec<AgentRow>> {
        self.flush()?;
        let mut statement = self.connection.prepare(
            "SELECT agent, count(*), count(DISTINCT host), count(DISTINCT process),
                    coalesce(sum(bytes), 0), max(at)
             FROM requests WHERE at >= ?1 AND agent IS NOT NULL
             GROUP BY agent
             ORDER BY count(*) DESC",
        )?;
        let rows = statement.query_map(params![since], |row| {
            Ok(AgentRow {
                agent: row.get(0)?,
                requests: row.get(1)?,
                hosts: row.get(2)?,
                processes: row.get(3)?,
                bytes: row.get(4)?,
                last_seen: row.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The hosts one agent reached, busiest first.
    ///
    /// What the MCP comparison is made against: these are the hosts that were actually contacted, and the
    /// configuration files say which ones were meant to be.
    pub fn hosts_for_agent(
        &mut self,
        agent: &str,
        since: i64,
        limit: usize,
    ) -> Result<Vec<HostRow>> {
        self.flush()?;
        let mut statement = self.connection.prepare(
            "SELECT host, count(*), max(at) FROM requests
             WHERE at >= ?1 AND agent = ?2 AND host IS NOT NULL
             GROUP BY host ORDER BY count(*) DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(params![since, agent, limit as i64], |row| {
            Ok(HostRow {
                host: row.get(0)?,
                requests: row.get(1)?,
                last_seen: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The hosts one process reached, busiest first.
    pub fn hosts_for(&mut self, process: &str, since: i64, limit: usize) -> Result<Vec<HostRow>> {
        self.flush()?;
        let mut statement = self.connection.prepare(
            "SELECT host, count(*), max(at) FROM requests
             WHERE at >= ?1 AND process = ?2 AND host IS NOT NULL
             GROUP BY host ORDER BY count(*) DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(params![since, process, limit as i64], |row| {
            Ok(HostRow {
                host: row.get(0)?,
                requests: row.get(1)?,
                last_seen: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Whether anything is waiting to be written.
    ///
    /// The interface reads the database rather than sharing memory with the watcher, so a batch still in
    /// hand is a batch the screen cannot see. The watcher uses this to flush on a timer.
    pub fn has_pending(&self) -> bool {
        !self.pending_connections.is_empty() || !self.pending_requests.is_empty()
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
            agent: None,
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
                agent: None,
                destination: Some("93.184.216.34".to_owned()),
                port: 443,
                blocked: false,
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

    // Coverage

    /// The failure that otherwise looks exactly like success. An empty screen means "this agent made no
    /// requests" and "this agent made four hundred requests nothing could read" equally well.
    #[test]
    fn a_process_that_connected_and_was_never_read_is_named() {
        let mut store = Store::in_memory().unwrap();
        // A Go program: it opened HTTPS connections, and its TLS is linked into its own binary.
        for _ in 0..3 {
            store
                .record_connection(ConnectionRow {
                    at: 1_000,
                    process: "gh".to_owned(),
                    confidence: "path".to_owned(),
                    pid: 1,
                    agent: None,
                    destination: Some("140.82.121.6".to_owned()),
                    port: 443,
                    blocked: false,
                })
                .unwrap();
        }
        // And one whose traffic was read, which must not appear.
        store
            .record_connection(ConnectionRow {
                at: 1_000,
                process: "curl".to_owned(),
                confidence: "path".to_owned(),
                pid: 2,
                agent: None,
                destination: Some("93.184.216.34".to_owned()),
                port: 443,
                blocked: false,
            })
            .unwrap();
        store
            .record_request(request(1_000, "curl", "example.com", 10))
            .unwrap();

        let coverage = store.coverage(0).unwrap();
        assert_eq!(
            coverage.unread,
            vec![Unread {
                process: "gh".to_owned(),
                connections: 3
            }]
        );
        assert_eq!(coverage.requests, 1);
        assert_eq!(coverage.processes_read, 1);
        assert_eq!(coverage.connections, 4);
    }

    /// A connection to something that is not HTTPS is not evidence of anything unread. SSH, DNS over TCP and
    /// a database connection are all traffic this deliberately does not try to read.
    #[test]
    fn a_connection_that_is_not_https_is_not_counted_as_unread() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_connection(ConnectionRow {
                at: 1_000,
                process: "ssh".to_owned(),
                confidence: "path".to_owned(),
                pid: 1,
                agent: None,
                destination: Some("10.0.0.1".to_owned()),
                port: 22,
                blocked: false,
            })
            .unwrap();
        assert!(store.coverage(0).unwrap().unread.is_empty());
    }

    /// Coverage is about a window. A process read from last week and silent today is unread today.
    #[test]
    fn the_window_decides_what_counts_as_unread() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(request(1_000, "gh", "api.github.com", 10))
            .unwrap();
        store
            .record_connection(ConnectionRow {
                at: 50_000,
                process: "gh".to_owned(),
                confidence: "path".to_owned(),
                pid: 1,
                agent: None,
                destination: None,
                port: 443,
                blocked: false,
            })
            .unwrap();
        assert!(store.coverage(0).unwrap().unread.is_empty());
        assert_eq!(store.coverage(40_000).unwrap().unread.len(), 1);
    }

    #[test]
    fn the_things_that_were_read_imperfectly_are_counted() {
        let mut store = Store::in_memory().unwrap();
        let mut truncated = request(1_000, "claude", "api.anthropic.com", 61_440);
        truncated.truncated = true;
        store.record_request(truncated).unwrap();

        let mut undecodable = request(1_000, "node", "", 40);
        undecodable.unreadable = Some("joined late".to_owned());
        store.record_request(undecodable).unwrap();

        let mut weak = request(1_000, "git-remote-http", "github.com", 40);
        weak.confidence = "comm".to_owned();
        store.record_request(weak).unwrap();

        let mut nameless = request(1_000, "pid 91", "", 40);
        nameless.confidence = "pid".to_owned();
        store.record_request(nameless).unwrap();

        let coverage = store.coverage(0).unwrap();
        assert_eq!(coverage.truncated, 1);
        assert_eq!(coverage.undecodable, 1);
        assert_eq!(coverage.named_by_comm, 1);
        assert_eq!(coverage.named_by_pid, 1);
    }

    /// A library that cannot be probed cannot be probed every five seconds for the rest of the week. One
    /// row, updated, not ten thousand copies of one fact.
    #[test]
    fn a_note_about_the_same_thing_twice_is_one_note() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_note("unprobed-library", "/usr/lib/libssl.so.3", "no symbols")
            .unwrap();
        store
            .record_note(
                "unprobed-library",
                "/usr/lib/libssl.so.3",
                "still no symbols",
            )
            .unwrap();
        let coverage = store.coverage(0).unwrap();
        assert_eq!(coverage.unprobed.len(), 1);
        assert_eq!(coverage.unprobed[0].detail, "still no symbols");
    }

    /// Drops accumulate. Each report is a count since the last one, not a total.
    #[test]
    fn dropped_records_add_up() {
        let mut store = Store::in_memory().unwrap();
        store.record_drop(12).unwrap();
        store.record_drop(30).unwrap();
        assert_eq!(store.coverage(0).unwrap().dropped, 42);
    }

    #[test]
    fn coverage_of_an_empty_database_is_zero_rather_than_an_error() {
        let mut store = Store::in_memory().unwrap();
        let coverage = store.coverage(0).unwrap();
        assert_eq!(coverage.requests, 0);
        assert_eq!(coverage.dropped, 0);
        assert!(coverage.unread.is_empty());
        assert!(coverage.unprobed.is_empty());
    }

    // The interface's queries

    #[test]
    fn processes_come_back_busiest_first_with_their_hosts_counted() {
        let mut store = Store::in_memory().unwrap();
        for _ in 0..3 {
            store
                .record_request(request(1_000, "claude", "api.anthropic.com", 100))
                .unwrap();
        }
        store
            .record_request(request(1_100, "claude", "statsig.anthropic.com", 50))
            .unwrap();
        store
            .record_request(request(1_050, "curl", "example.com", 10))
            .unwrap();

        let processes = store.processes(0).unwrap();
        assert_eq!(processes.len(), 2);
        assert_eq!(processes[0].process, "claude");
        assert_eq!(processes[0].requests, 4);
        assert_eq!(processes[0].hosts, 2);
        assert_eq!(processes[0].bytes, 350);
        assert_eq!(processes[0].last_seen, 1_100);
        assert_eq!(processes[1].process, "curl");
    }

    /// The worst name a process was given over the window is the one worth showing. A process named from
    /// its path nine times and from a truncated `comm` once is a process whose rules might not match.
    #[test]
    fn a_process_is_shown_at_its_least_certain_name() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(request(1_000, "claude", "api.anthropic.com", 1))
            .unwrap();
        let mut weak = request(1_001, "claude", "api.anthropic.com", 1);
        weak.confidence = "comm".to_owned();
        store.record_request(weak).unwrap();
        assert_eq!(store.processes(0).unwrap()[0].confidence, "comm");
    }

    #[test]
    fn the_hosts_one_process_reached_come_back_busiest_first() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(request(1_000, "claude", "statsig.anthropic.com", 1))
            .unwrap();
        for _ in 0..2 {
            store
                .record_request(request(1_000, "claude", "api.anthropic.com", 1))
                .unwrap();
        }
        store
            .record_request(request(1_000, "curl", "example.com", 1))
            .unwrap();

        let hosts = store.hosts_for("claude", 0, 10).unwrap();
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].host, "api.anthropic.com");
        assert_eq!(hosts[0].requests, 2);
        // Another process's hosts are another process's.
        assert!(hosts.iter().all(|host| host.host != "example.com"));
    }

    /// The interface reads the database rather than sharing memory with the watcher, so a batch still in
    /// hand is a batch the screen cannot see.
    #[test]
    fn pending_writes_are_visible_as_pending() {
        let mut store = Store::in_memory().unwrap();
        assert!(!store.has_pending());
        store
            .record_request(request(1, "curl", "example.com", 1))
            .unwrap();
        assert!(store.has_pending());
        store.flush().unwrap();
        assert!(!store.has_pending());
    }

    /// The interface must not be able to write, and must be able to read what the watcher wrote.
    #[test]
    fn a_read_only_handle_reads_and_does_not_write() {
        let directory = std::env::temp_dir().join("flowlight-store-readonly");
        let _ = std::fs::remove_dir_all(&directory);
        let path = directory.join("flowlight.db");

        let mut writer = Store::open(&path).unwrap();
        writer
            .record_request(request(1_000, "claude", "api.anthropic.com", 1))
            .unwrap();
        writer.flush().unwrap();

        let mut reader = Store::open_read_only(&path).unwrap();
        assert_eq!(reader.requests_since(0, 10).unwrap().len(), 1);
        assert!(
            reader.record_note("unprobed-library", "/x", "y").is_err(),
            "the interface has no business writing"
        );
    }

    // Agents

    /// `claude` does not make requests; it spawns `node`, which spawns `git`. The agent column is the
    /// answer to "who caused this", which is the question people ask.
    #[test]
    fn requests_are_grouped_by_the_agent_that_caused_them() {
        let mut store = Store::in_memory().unwrap();
        for (process, host) in [
            ("node", "api.anthropic.com"),
            ("git-remote-https", "github.com"),
            ("curl", "mcp.sentry.dev"),
        ] {
            let mut row = request(1_000, process, host, 100);
            row.agent = Some("claude".to_owned());
            store.record_request(row).unwrap();
        }
        // And one belonging to nobody.
        store
            .record_request(request(1_000, "apt", "archive.ubuntu.com", 10))
            .unwrap();

        let agents = store.agents(0).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent, "claude");
        assert_eq!(agents[0].requests, 3);
        assert_eq!(agents[0].hosts, 3);
        assert_eq!(agents[0].processes, 3);
    }

    #[test]
    fn the_hosts_one_agent_reached_are_its_own() {
        let mut store = Store::in_memory().unwrap();
        let mut mine = request(1_000, "node", "mcp.sentry.dev", 1);
        mine.agent = Some("claude".to_owned());
        store.record_request(mine).unwrap();
        let mut theirs = request(1_000, "node", "other.example", 1);
        theirs.agent = Some("codex".to_owned());
        store.record_request(theirs).unwrap();

        let hosts = store.hosts_for_agent("claude", 0, 10).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].host, "mcp.sentry.dev");
    }

    /// A database written by 0.1.7 is a database somebody has a week of history in. `CREATE TABLE IF NOT
    /// EXISTS` does nothing to a table that already exists, so without a real migration the new column
    /// would never appear and every write would fail against it.
    #[test]
    fn a_database_from_the_previous_version_is_brought_forward_without_losing_anything() {
        let directory = std::env::temp_dir().join("flowlight-store-migrate");
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("flowlight.db");

        // Schema 1, exactly as 0.1.5 through 0.1.7 wrote it.
        let old = rusqlite::Connection::open(&path).unwrap();
        old.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE connections (id INTEGER PRIMARY KEY, at INTEGER NOT NULL,
               process TEXT NOT NULL, confidence TEXT NOT NULL, pid INTEGER NOT NULL,
               destination TEXT, port INTEGER NOT NULL);
             CREATE TABLE requests (id INTEGER PRIMARY KEY, at INTEGER NOT NULL,
               process TEXT NOT NULL, confidence TEXT NOT NULL, pid INTEGER NOT NULL,
               direction TEXT NOT NULL, protocol TEXT, method TEXT, target TEXT, host TEXT,
               status INTEGER, bytes INTEGER NOT NULL, truncated INTEGER NOT NULL, unreadable TEXT);
             INSERT INTO meta(key, value) VALUES('schema', '1');
             INSERT INTO requests(at, process, confidence, pid, direction, bytes, truncated)
               VALUES (1000, 'claude', 'path', 7, 'out', 42, 0);",
        )
        .unwrap();
        drop(old);

        let mut store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), Store::SCHEMA);

        // The old row is still there, and reads back with no agent rather than failing.
        let rows = store.requests_since(0, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].process, "claude");
        assert_eq!(rows[0].agent, None);

        // And a new row with an agent can be written into the same table.
        let mut fresh = request(2_000, "node", "api.anthropic.com", 1);
        fresh.agent = Some("claude".to_owned());
        store.record_request(fresh).unwrap();
        store.flush().unwrap();
        assert_eq!(
            store.requests_since(1_500, 10).unwrap()[0].agent.as_deref(),
            Some("claude")
        );
    }

    /// Opening twice must not try to migrate twice.
    #[test]
    fn migrating_an_already_current_database_changes_nothing() {
        let directory = std::env::temp_dir().join("flowlight-store-migrate-twice");
        let _ = std::fs::remove_dir_all(&directory);
        let path = directory.join("flowlight.db");
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), Store::SCHEMA);
        drop(store);
        let store = Store::open(&path).unwrap();
        assert_eq!(store.schema_version().unwrap(), Store::SCHEMA);
    }

    // Traffic, for trying a rule against

    /// Two sources that know different things, both of which a rule has to be judged against.
    #[test]
    fn traffic_comes_from_both_what_was_read_and_what_was_connected_to() {
        let mut store = Store::in_memory().unwrap();
        let mut request = request(1_000, "node", "api.anthropic.com", 100);
        request.agent = Some("claude".to_owned());
        store.record_request(request.clone()).unwrap();
        store.record_request(request).unwrap();
        store
            .record_connection(ConnectionRow {
                at: 1_000,
                process: "node".to_owned(),
                confidence: "path".to_owned(),
                pid: 1,
                agent: Some("claude".to_owned()),
                destination: Some("160.79.104.10".to_owned()),
                port: 443,
                blocked: false,
            })
            .unwrap();

        let traffic = store.traffic_since(0).unwrap();
        assert_eq!(traffic.len(), 2);

        let by_request = traffic.iter().find(|row| row.host.is_some()).unwrap();
        assert_eq!(by_request.host.as_deref(), Some("api.anthropic.com"));
        assert_eq!(by_request.occurrences, 2);
        // A request knows no port, and saying it did would let a rule claim changes it cannot make.
        assert_eq!(by_request.port, None);

        let by_connection = traffic.iter().find(|row| row.address.is_some()).unwrap();
        assert_eq!(by_connection.address.as_deref(), Some("160.79.104.10"));
        assert_eq!(by_connection.port, Some(443));
        assert_eq!(by_connection.agent.as_deref(), Some("claude"));
    }

    #[test]
    fn traffic_outside_the_window_is_not_traffic() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(request(100, "curl", "example.com", 1))
            .unwrap();
        assert!(store.traffic_since(500).unwrap().is_empty());
    }

    /// A request with no host cannot be judged by name and would group into a row describing nothing.
    #[test]
    fn a_request_with_no_host_is_not_offered_as_traffic() {
        let mut store = Store::in_memory().unwrap();
        let mut row = request(1_000, "node", "", 1);
        row.host = None;
        store.record_request(row).unwrap();
        assert!(store.traffic_since(0).unwrap().is_empty());
    }

    // Rules

    #[test]
    fn a_rule_written_is_a_rule_read_back() {
        let mut store = Store::in_memory().unwrap();
        assert_eq!(
            store
                .put_rule("block", "example.com", 443, "everyone", Some("noisy"))
                .unwrap(),
            Wrote::Added
        );
        let rules = store.rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, "block");
        assert_eq!(rules[0].subject, "example.com");
        assert_eq!(rules[0].port, 443);
        assert_eq!(rules[0].note.as_deref(), Some("noisy"));
    }

    /// `allow x` after `block x` is somebody changing their mind about `x`. Keeping both would make it a
    /// contradiction, resolved conservatively, which is the opposite of what they just asked for.
    #[test]
    fn writing_a_different_answer_for_the_same_thing_replaces_it() {
        let mut store = Store::in_memory().unwrap();
        store
            .put_rule("block", "example.com", 0, "everyone", None)
            .unwrap();
        assert_eq!(
            store
                .put_rule("allow", "example.com", 0, "everyone", None)
                .unwrap(),
            Wrote::Changed
        );
        let rules = store.rules().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].action, "allow");
    }

    /// Writing the same thing twice has done nothing, and saying otherwise teaches somebody that the
    /// command's output means nothing.
    #[test]
    fn writing_the_same_rule_twice_changes_nothing_and_says_so() {
        let mut store = Store::in_memory().unwrap();
        store
            .put_rule("block", "example.com", 443, "everyone", None)
            .unwrap();
        assert_eq!(
            store
                .put_rule("block", "example.com", 443, "everyone", None)
                .unwrap(),
            Wrote::Unchanged
        );
        assert_eq!(store.rules().unwrap().len(), 1);
    }

    /// A rule for one port, a rule for every port, and a rule for one agent are three different rules
    /// about the same host.
    #[test]
    fn scope_and_port_make_rules_distinct() {
        let mut store = Store::in_memory().unwrap();
        store
            .put_rule("block", "example.com", 443, "everyone", None)
            .unwrap();
        store
            .put_rule("block", "example.com", 0, "everyone", None)
            .unwrap();
        store
            .put_rule("allow", "example.com", 0, "agent:claude", None)
            .unwrap();
        assert_eq!(store.rules().unwrap().len(), 3);
    }

    #[test]
    fn a_rule_can_be_taken_away_by_its_identifier() {
        let mut store = Store::in_memory().unwrap();
        store
            .put_rule("block", "example.com", 443, "everyone", None)
            .unwrap();
        let id = store.rules().unwrap()[0].id;
        assert!(store.forget_rule(id).unwrap());
        assert!(!store.forget_rule(id).unwrap());
        assert!(store.rules().unwrap().is_empty());
    }

    /// A refusal is a connection that did not happen, and the record of it is the only evidence there is.
    #[test]
    fn a_refused_connection_is_recorded_as_one() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_connection(ConnectionRow {
                at: 1_000,
                process: "curl".to_owned(),
                confidence: "path".to_owned(),
                pid: 1,
                agent: None,
                destination: Some("93.184.216.34".to_owned()),
                port: 443,
                blocked: true,
            })
            .unwrap();
        assert_eq!(store.blocked_since(0).unwrap(), 1);
        assert_eq!(store.blocked_since(2_000).unwrap(), 0);
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
