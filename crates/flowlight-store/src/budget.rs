//! How much Flowlight is allowed to read, and for how long.
//!
//! Up to here the answer was "everything, forever". That is defensible for a tool somebody has just started
//! and indefensible for one that has been running since March: a daemon reading every HTTPS request on a
//! machine should have limits it can state, and they should be limits somebody agreed to rather than ones
//! nobody was told about.
//!
//! Four of them, and each is a number rather than a principle:
//!
//! - **A session.** Payload capture stops after eight hours unless it is renewed. You turned this on to
//!   look at something; it should not still be reading your traffic next week.
//! - **A daily ceiling per process.** After sixty-four megabytes in a day, payloads from that process stop
//!   being captured until tomorrow. One chatty program should not be able to fill a disk, and nothing needs
//!   a gigabyte of somebody's traffic to be useful.
//! - **What of a request target is kept.** All of it, the host only, or nothing. Credentials are already
//!   removed; a path can still say more about what somebody was doing than they would choose to write down.
//! - **Retention.** Seven days of detail, ninety of summary. This one existed before the others and now
//!   sits with them, because a reader asking "what does this keep" should find one answer and not four.
//!
//! # Whole sentences
//!
//! [`Budget::describe`] is built from complete sentences rather than a template with numbers dropped into
//! it. That is a habit from the macOS build, where the same summary is translated into nine languages and a
//! sentence assembled from fragments is a sentence that reads like one in at least three of them. It is now
//! translated here too, which is what the habit was for: each sentence is one entry in the catalogue, with
//! the numbers and the units passed in, so a translator is given prose to translate rather than fragments to
//! reassemble.

use anyhow::Result;
use flowlight_text::Language;
use rusqlite::{Connection, OptionalExtension as _, params};

/// How long payload capture lasts before it has to be renewed.
pub const DEFAULT_SESSION_MINUTES: u32 = 480;

/// How many bytes of payload one process may contribute in a day.
pub const DEFAULT_DAILY_BYTES: i64 = 64 * 1024 * 1024;

/// How much of a request target is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Paths {
    /// The whole target, with credentials already removed. The default, and what makes a request legible.
    #[default]
    Full,
    /// The host and nothing after it. Enough to say who was talked to, not what was asked for.
    HostOnly,
    /// Neither. The host is still recorded — it is how anything is grouped — but no path is.
    None,
}

impl Paths {
    /// How this reads in the database and on the screen.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::HostOnly => "host-only",
            Self::None => "none",
        }
    }

    /// Reads one back, or nothing if it is not one.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "full" => Some(Self::Full),
            "host-only" => Some(Self::HostOnly),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// Whether a tool's name may be kept.
    ///
    /// `None` means keep as little as possible, and a tool's name says what was asked for in the same way a
    /// path does. The *method* is kept either way: `tools/call` is a fact about the shape of the traffic and
    /// says nothing about the work.
    pub fn keeps_tool_names(self) -> bool {
        self != Self::None
    }

    /// Applies the policy to a target.
    ///
    /// `Full` keeps it, `HostOnly` keeps the fact that there was one, `None` keeps nothing. The middle one
    /// is `/…` rather than an empty string on purpose: "there was a path and it is not shown" and "there
    /// was no path" are different things, and a reader should be able to tell which they are looking at.
    pub fn apply(self, target: Option<String>) -> Option<String> {
        match self {
            Self::Full => target,
            Self::HostOnly => target.map(|_| "/…".to_owned()),
            Self::None => None,
        }
    }
}

/// What Flowlight is allowed to read, and for how long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Whether payloads are read at all.
    pub payloads: bool,
    /// How long payload capture lasts before it has to be renewed, in minutes. Zero means indefinitely,
    /// which is a thing somebody can choose and not a thing they get by default.
    pub session_minutes: u32,
    /// When the current session began, in seconds since the epoch.
    pub session_began: i64,
    /// How many bytes of payload one process may contribute in a day. Zero means no ceiling.
    pub daily_bytes: i64,
    /// How much of a request target is kept.
    pub paths: Paths,
    /// Days of individual requests and connections.
    pub detail_days: u32,
    /// Days of the daily summary.
    pub summary_days: u32,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            payloads: true,
            session_minutes: DEFAULT_SESSION_MINUTES,
            session_began: 0,
            daily_bytes: DEFAULT_DAILY_BYTES,
            paths: Paths::default(),
            detail_days: crate::DEFAULT_RETENTION_DAYS,
            summary_days: crate::DEFAULT_SUMMARY_DAYS,
        }
    }
}

impl Budget {
    /// Whether payloads should be read at this moment.
    ///
    /// Two questions in one: whether they were ever wanted, and whether the session that wanted them has
    /// run out.
    pub fn reading_payloads(&self, now: i64) -> bool {
        self.payloads && !self.session_expired(now)
    }

    /// Whether the session has run out.
    pub fn session_expired(&self, now: i64) -> bool {
        if self.session_minutes == 0 {
            return false;
        }
        let ends = self.session_began + i64::from(self.session_minutes) * 60;
        now >= ends
    }

    /// How long the session has left, in seconds, or `None` if it does not end.
    pub fn session_remaining(&self, now: i64) -> Option<i64> {
        (self.session_minutes != 0)
            .then(|| (self.session_began + i64::from(self.session_minutes) * 60 - now).max(0))
    }

    /// Whether a process that has contributed this many bytes today may contribute more.
    pub fn within_daily(&self, bytes: i64) -> bool {
        self.daily_bytes == 0 || bytes < self.daily_bytes
    }

    /// Retention, in the shape the sweeper wants it.
    pub fn retention(&self) -> crate::Retention {
        crate::Retention {
            detail_days: self.detail_days,
            summary_days: self.summary_days,
        }
    }

    /// What this budget is, in sentences.
    ///
    /// Printed at startup and shown in the interface. Assembled from whole sentences rather than one
    /// template with numbers dropped into it, so that it reads like something a person wrote.
    pub fn describe(&self, now: i64, language: Language) -> Vec<String> {
        let mut said = Vec::new();

        if !self.payloads {
            said.push(language.say("budget.payloads.off").to_owned());
        } else if self.session_expired(now) {
            said.push(language.say("budget.session.expired").to_owned());
        } else {
            match self.session_remaining(now) {
                Some(remaining) => said.push(language.fill(
                    "budget.session.remaining",
                    &[("remaining", &duration(remaining, language))],
                )),
                None => said.push(language.say("budget.session.unlimited").to_owned()),
            }
        }

        if self.daily_bytes == 0 {
            said.push(language.say("budget.daily.none").to_owned());
        } else {
            said.push(language.fill(
                "budget.daily",
                &[("size", &bytes(self.daily_bytes, language))],
            ));
        }

        said.push(
            language
                .say(match self.paths {
                    Paths::Full => "budget.paths.full",
                    Paths::HostOnly => "budget.paths.host",
                    Paths::None => "budget.paths.none",
                })
                .to_owned(),
        );

        said.push(language.fill(
            "budget.retention",
            &[
                ("detail", &language.days(self.detail_days)),
                ("summary", &language.days(self.summary_days)),
            ],
        ));
        said
    }
}

/// A length of time, in the largest unit that does not lie about the precision.
fn duration(seconds: i64, language: Language) -> String {
    let counted = |key: &'static str, plural: &'static str, count: i64| {
        language.fill(
            if count == 1 { key } else { plural },
            &[("count", &count.to_string())],
        )
    };
    if seconds < 60 {
        counted("time.seconds.one", "time.seconds.many", seconds)
    } else if seconds < 3_600 {
        counted("time.minutes.one", "time.minutes.many", seconds / 60)
    } else {
        let hour = counted("time.hours.one", "time.hours.many", seconds / 3_600);
        match (seconds % 3_600) / 60 {
            0 => hour,
            minutes => language.fill(
                "time.joined",
                &[
                    ("hours", &hour),
                    (
                        "minutes",
                        &counted("time.minutes.one", "time.minutes.many", minutes),
                    ),
                ],
            ),
        }
    }
}

/// A size, in the unit somebody would say out loud.
fn bytes(count: i64, language: Language) -> String {
    if count >= 1024 * 1024 * 1024 {
        format!("{:.1} GB", count as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if count >= 1024 * 1024 {
        format!("{} MB", count / (1024 * 1024))
    } else if count >= 1024 {
        format!("{} kB", count / 1024)
    } else {
        // The one unit that is a word rather than a symbol, and therefore the one that translates.
        language.fill("size.bytes", &[("count", &count.to_string())])
    }
}

/// Reads the budget, filling in the defaults for anything never written.
pub(crate) fn read(connection: &Connection) -> Result<Budget> {
    let mut budget = Budget::default();
    let get = |key: &str| -> Result<Option<String>> {
        Ok(connection
            .query_row(
                "SELECT value FROM budget WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?)
    };
    if let Some(value) = get("payloads")? {
        budget.payloads = value == "true";
    }
    if let Some(value) = get("session_minutes")?.and_then(|v| v.parse().ok()) {
        budget.session_minutes = value;
    }
    if let Some(value) = get("session_began")?.and_then(|v| v.parse().ok()) {
        budget.session_began = value;
    }
    if let Some(value) = get("daily_bytes")?.and_then(|v| v.parse().ok()) {
        budget.daily_bytes = value;
    }
    if let Some(value) = get("paths")?.as_deref().and_then(Paths::parse) {
        budget.paths = value;
    }
    if let Some(value) = get("detail_days")?.and_then(|v| v.parse().ok()) {
        budget.detail_days = value;
    }
    if let Some(value) = get("summary_days")?.and_then(|v| v.parse().ok()) {
        budget.summary_days = value;
    }
    Ok(budget)
}

/// Writes the budget, every field of it.
pub(crate) fn write(connection: &Connection, budget: &Budget) -> Result<()> {
    for (key, value) in [
        ("payloads", budget.payloads.to_string()),
        ("session_minutes", budget.session_minutes.to_string()),
        ("session_began", budget.session_began.to_string()),
        ("daily_bytes", budget.daily_bytes.to_string()),
        ("paths", budget.paths.as_str().to_owned()),
        ("detail_days", budget.detail_days.to_string()),
        ("summary_days", budget.summary_days.to_string()),
    ] {
        connection.execute(
            "INSERT INTO budget(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reason a session exists: you turned this on to look at something, and it should not still be
    /// reading your traffic next week.
    #[test]
    fn a_session_runs_out() {
        let budget = Budget {
            session_minutes: 60,
            session_began: 1_000,
            ..Budget::default()
        };
        assert!(budget.reading_payloads(1_000));
        assert!(budget.reading_payloads(4_599));
        assert!(!budget.reading_payloads(4_600));
        assert!(budget.session_expired(4_600));
    }

    /// No limit is a thing somebody can choose, and not a thing they get by default.
    #[test]
    fn a_session_of_zero_minutes_does_not_run_out() {
        let budget = Budget {
            session_minutes: 0,
            session_began: 0,
            ..Budget::default()
        };
        assert!(budget.reading_payloads(i64::MAX / 2));
        assert_eq!(budget.session_remaining(0), None);
        assert!(
            budget
                .describe(0, Language::English)
                .iter()
                .any(|line| line.contains("which was asked for, not assumed"))
        );
    }

    #[test]
    fn payloads_can_be_off_altogether() {
        let budget = Budget {
            payloads: false,
            ..Budget::default()
        };
        assert!(!budget.reading_payloads(0));
        assert!(
            budget
                .describe(0, Language::English)
                .iter()
                .any(|line| line.contains("Connections are still attributed"))
        );
    }

    #[test]
    fn a_daily_ceiling_is_a_ceiling() {
        let budget = Budget {
            daily_bytes: 100,
            ..Budget::default()
        };
        assert!(budget.within_daily(99));
        assert!(!budget.within_daily(100));
        assert!(!budget.within_daily(1_000));

        let unlimited = Budget {
            daily_bytes: 0,
            ..Budget::default()
        };
        assert!(unlimited.within_daily(i64::MAX));
    }

    /// "There was a path and it is not shown" and "there was no path" are different things, and a reader
    /// should be able to tell which they are looking at.
    #[test]
    fn a_hidden_path_is_not_the_same_as_no_path() {
        let target = Some("/v1/messages?model=x".to_owned());
        assert_eq!(Paths::Full.apply(target.clone()), target);
        assert_eq!(Paths::HostOnly.apply(target.clone()).as_deref(), Some("/…"));
        assert_eq!(Paths::None.apply(target), None);
        // And a request that had no path still has none.
        assert_eq!(Paths::HostOnly.apply(None), None);
    }

    /// `none` means keep as little as possible, and a tool's name says what was asked for. The method is
    /// kept either way: it is a fact about the shape of the traffic.
    #[test]
    fn keeping_nothing_keeps_no_tool_names_either() {
        assert!(Paths::Full.keeps_tool_names());
        assert!(Paths::HostOnly.keeps_tool_names());
        assert!(!Paths::None.keeps_tool_names());
    }

    #[test]
    fn a_path_policy_survives_being_written_down_and_read_back() {
        for policy in [Paths::Full, Paths::HostOnly, Paths::None] {
            assert_eq!(Paths::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(Paths::parse("some"), None);
    }

    /// A summary is prose, and prose survives being read aloud. Every line is a sentence.
    #[test]
    fn every_line_of_the_summary_is_a_sentence() {
        let budget = Budget {
            session_began: 0,
            ..Budget::default()
        };
        let said = budget.describe(0, Language::English);
        assert_eq!(said.len(), 4);
        for line in &said {
            assert!(line.ends_with('.'), "not a sentence: {line}");
            assert!(
                line.chars().next().is_some_and(char::is_uppercase),
                "does not start a sentence: {line}"
            );
        }
        assert!(said[0].contains("8 hours"), "{}", said[0]);
        assert!(said[1].contains("64 MB"), "{}", said[1]);
        assert!(said[3].contains("7 days"), "{}", said[3]);
        assert!(said[3].contains("90 days"), "{}", said[3]);
    }

    /// One day, not one days. The macOS build got this wrong in three languages before anybody noticed.
    #[test]
    fn one_of_a_thing_is_not_plural() {
        let budget = Budget {
            detail_days: 1,
            summary_days: 1,
            session_minutes: 1,
            session_began: 0,
            ..Budget::default()
        };
        let said = budget.describe(0, Language::English);
        assert!(
            said[3].contains("1 day, and a daily summary for 1 day."),
            "{}",
            said[3]
        );
        assert!(said[0].contains("1 minute"), "{}", said[0]);
    }

    #[test]
    fn a_length_of_time_reads_the_way_somebody_would_say_it() {
        assert_eq!(duration(30, Language::English), "30 seconds");
        assert_eq!(duration(60, Language::English), "1 minute");
        assert_eq!(duration(120, Language::English), "2 minutes");
        assert_eq!(duration(3_600, Language::English), "1 hour");
        assert_eq!(duration(7_200, Language::English), "2 hours");
        assert_eq!(duration(3_660, Language::English), "1 hour and 1 minute");
        assert_eq!(duration(7_380, Language::English), "2 hours and 3 minutes");
        assert_eq!(duration(28_800, Language::English), "8 hours");
    }

    #[test]
    fn a_size_reads_the_way_somebody_would_say_it() {
        assert_eq!(bytes(512, Language::English), "512 bytes");
        assert_eq!(bytes(2_048, Language::English), "2 kB");
        assert_eq!(bytes(64 * 1024 * 1024, Language::English), "64 MB");
        assert_eq!(bytes(2 * 1024 * 1024 * 1024, Language::English), "2.0 GB");
    }
}
