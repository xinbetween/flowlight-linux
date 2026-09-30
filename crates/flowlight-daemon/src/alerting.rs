//! Noticing things, and saying what the numbers were.
//!
//! Two halves, because the signals divide cleanly in two. Some are about a *rate* and can only be judged when a
//! window has closed — how much a process moved this hour against what it usually moves. Others are about a
//! single event and are judged as it happens: a host nothing had reached before, a port nothing usually
//! reaches, a connection a rule refused.
//!
//! # Why the first contact set is held in memory
//!
//! Because the alternative is a query per connection against every host ever recorded, and this runs on the
//! event path. It is read once at startup and added to as things are seen, which means a restart re-reads it —
//! and a host recorded before the restart is not new afterwards, which is the point.

use flowlight_alerts::{Alert, Kind, Settings};
use flowlight_store::Store;
use std::collections::BTreeSet;

/// The metric a process's hourly bytes are recorded under.
const BYTES_HOUR: &str = "bytes_hour";

/// The metric a process's daily host count is recorded under.
const HOSTS_DAY: &str = "hosts_day";

/// What has been seen before, so that "new" means something.
pub struct Seen {
    /// Every host ever recorded.
    hosts: BTreeSet<String>,
    /// Every process ever recorded.
    processes: BTreeSet<String>,
    /// How strict to be.
    settings: Settings,
    /// The hour last judged, so one is not judged twice.
    last_hour: i64,
    /// The day last judged.
    last_day: i64,
}

impl Seen {
    /// Reads what has been seen before.
    ///
    /// Read once, at startup. A host recorded before a restart is not new after one, which is what makes the
    /// signal worth anything.
    pub fn new(store: &mut Store, now: i64) -> Self {
        Self {
            hosts: store.every_host().unwrap_or_default(),
            processes: store.every_process().unwrap_or_default(),
            settings: Settings::default(),
            // The hour and day in progress are not judged: they are not finished.
            last_hour: now.div_euclid(3_600),
            last_day: now.div_euclid(86_400),
        }
    }

    /// How many hosts and processes are being remembered, for a line at startup.
    pub fn counts(&self) -> (usize, usize) {
        (self.hosts.len(), self.processes.len())
    }

    /// What to say about one connection, as it happens.
    ///
    /// Three signals, and each is cheap: two set lookups and a comparison against a list of ports.
    pub fn about_connection(
        &mut self,
        process: &str,
        address: &str,
        port: u16,
        agent: Option<&str>,
    ) -> Vec<Alert> {
        let mut said = Vec::new();
        if let Some(alert) = flowlight_alerts::new_process(process, &self.processes) {
            self.processes.insert(process.to_owned());
            said.push(alert);
        }
        if let Some(alert) = flowlight_alerts::non_standard_port(process, address, port) {
            said.push(alert);
        }
        // An agent is configured with names. An address is what is left when a name was never involved.
        if let Some(agent) = agent
            && let Some(alert) = flowlight_alerts::agent_unnamed_host(agent, address, port)
        {
            said.push(alert);
        }
        said
    }

    /// What to say about one request, as it happens.
    pub fn about_request(&mut self, process: &str, host: Option<&str>) -> Vec<Alert> {
        let Some(host) = host.map(str::trim).filter(|host| !host.is_empty()) else {
            return Vec::new();
        };
        let mut said = Vec::new();
        if let Some(alert) = flowlight_alerts::first_contact(host, process, &self.hosts) {
            self.hosts.insert(host.to_lowercase());
            said.push(alert);
        }
        said
    }

    /// What to say about a connection a rule refused.
    ///
    /// Always said, because the person it happens to is usually the person who wrote the rule, and an hour
    /// spent on a network that appears to be broken is an hour nobody gets back.
    pub fn about_refusal(
        &self,
        process: &str,
        address: &str,
        port: u16,
        agent: Option<&str>,
    ) -> Alert {
        flowlight_alerts::refused(process, address, port, agent)
    }

    /// Judges the hours and days that have closed since this was last asked.
    ///
    /// Returns what is worth saying. Nothing is judged twice, and the window in progress is never judged: it is
    /// not finished, and half an hour of traffic compared against whole ones is a spike every time.
    pub fn about_windows(&mut self, store: &mut Store, now: i64) -> Vec<Alert> {
        let mut said = Vec::new();
        let hour = now.div_euclid(3_600);
        let day = now.div_euclid(86_400);

        // At most a day's worth in one pass, so a daemon started after a week away does not spend a minute
        // catching up on hours nobody will read about.
        let from = self.last_hour.max(hour - 24);
        for closed in from..hour {
            said.extend(self.judge_hour(store, closed));
        }
        self.last_hour = hour;

        if day > self.last_day {
            for closed in self.last_day.max(day - 7)..day {
                said.extend(self.judge_day(store, closed));
            }
            self.last_day = day;
        }
        said
    }

    /// One closed hour.
    fn judge_hour(&self, store: &mut Store, hour: i64) -> Vec<Alert> {
        let (from, until) = (hour * 3_600, (hour + 1) * 3_600);
        let Ok(moved) = store.bytes_by_process(from, until) else {
            return Vec::new();
        };
        let mut said = Vec::new();
        for (process, bytes) in moved {
            let baseline = store.baseline(BYTES_HOUR, &process).ok().flatten();
            // Judged against what was normal *before* this hour, then the hour folded in. The other order
            // compares an hour against itself and finds nothing.
            if let Some(alert) = flowlight_alerts::volume_spike(
                &process,
                bytes,
                &clock_hour(hour),
                baseline,
                &self.settings,
            ) {
                said.push(alert);
            }
            let updated = flowlight_alerts::update(baseline, bytes as f64);
            let _ = store.set_baseline(BYTES_HOUR, &process, updated);
        }
        said
    }

    /// One closed day.
    fn judge_day(&self, store: &mut Store, day: i64) -> Vec<Alert> {
        let (from, until) = (day * 86_400, (day + 1) * 86_400);
        let Ok(reached) = store.hosts_by_process(from, until) else {
            return Vec::new();
        };
        let mut said = Vec::new();
        for (process, hosts) in reached {
            let baseline = store.baseline(HOSTS_DAY, &process).ok().flatten();
            if let Some(alert) =
                flowlight_alerts::destination_spike(&process, hosts, baseline, &self.settings)
            {
                said.push(alert);
            }
            let updated = flowlight_alerts::update(baseline, hosts as f64);
            let _ = store.set_baseline(HOSTS_DAY, &process, updated);
        }
        said
    }
}

/// An hour as a person reads it, in UTC.
///
/// UTC because the daily summary's days are UTC days, and two definitions of when a day starts in one tool is
/// worse than one that is occasionally surprising.
fn clock_hour(hour: i64) -> String {
    // `clock` already says UTC, which is why nothing is appended here.
    flowlight_ask::window::clock(hour * 3_600)
}

/// Records what was noticed, and says how much of it was new.
pub fn keep(store: &mut Store, said: &[Alert], now: i64) -> usize {
    let mut kept = 0;
    for alert in said {
        if store.record_alert(alert, now).unwrap_or(false) {
            kept += 1;
        }
    }
    kept
}

/// How an alert reads on one line.
pub fn line(alert: &Alert) -> String {
    format!(
        "{} {}",
        match alert.severity {
            3 => "!!",
            2 => "! ",
            _ => "  ",
        },
        alert.detail
    )
}

/// Whether this kind is about an agent, for a view that separates them.
pub fn about_an_agent(kind: &str) -> bool {
    Kind::parse(kind).is_some_and(Kind::is_about_an_agent)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stocked() -> Store {
        Store::in_memory().expect("a database")
    }

    /// A restart must not make every host new again.
    #[test]
    fn what_was_seen_before_is_read_at_startup() {
        let mut store = stocked();
        store
            .record_request(flowlight_store::RequestRow {
                at: 1_000,
                process: "curl".to_owned(),
                confidence: "path".to_owned(),
                pid: 1,
                agent: None,
                direction: "out".to_owned(),
                protocol: None,
                method: Some("GET".to_owned()),
                target: None,
                host: Some("known.example".to_owned()),
                status: Some(200),
                bytes: 10,
                truncated: false,
                unreadable: None,
                rpc_method: None,
                rpc_tool: None,
            })
            .unwrap();
        store.flush().unwrap();

        let mut seen = Seen::new(&mut store, 10_000);
        let (hosts, processes) = seen.counts();
        assert_eq!(hosts, 1);
        assert_eq!(processes, 1);
        // Already known, so not new.
        assert!(seen.about_request("curl", Some("known.example")).is_empty());
        // And this one is.
        let said = seen.about_request("curl", Some("fresh.example"));
        assert_eq!(said.len(), 1);
        assert_eq!(said[0].kind, Kind::FirstContact);
        // Only once.
        assert!(seen.about_request("curl", Some("fresh.example")).is_empty());
    }

    #[test]
    fn a_connection_can_say_three_things_at_once() {
        let mut store = stocked();
        let mut seen = Seen::new(&mut store, 10_000);
        let said = seen.about_connection("mystery", "1.2.3.4", 4444, Some("claude"));
        let kinds: Vec<Kind> = said.iter().map(|alert| alert.kind).collect();
        assert!(kinds.contains(&Kind::NewProcess));
        assert!(kinds.contains(&Kind::NonStandardPort));
        assert!(kinds.contains(&Kind::AgentUnnamedHost));
        // And the process is not new a second time.
        let again = seen.about_connection("mystery", "1.2.3.4", 4444, Some("claude"));
        assert!(!again.iter().any(|alert| alert.kind == Kind::NewProcess));
    }

    #[test]
    fn a_connection_on_a_usual_port_with_no_agent_says_nothing_after_the_first_time() {
        let mut store = stocked();
        let mut seen = Seen::new(&mut store, 10_000);
        let _ = seen.about_connection("curl", "1.2.3.4", 443, None);
        assert!(
            seen.about_connection("curl", "1.2.3.4", 443, None)
                .is_empty()
        );
    }

    /// The hour in progress is not judged: half an hour of traffic against whole ones is a spike every time.
    #[test]
    fn the_window_in_progress_is_never_judged() {
        let mut store = stocked();
        // Midway through hour 10.
        let now = 10 * 3_600 + 1_800;
        let mut seen = Seen::new(&mut store, now);
        assert!(seen.about_windows(&mut store, now).is_empty());
        // And nothing was folded into a baseline either, because nothing was judged.
        assert_eq!(store.baseline(BYTES_HOUR, "curl").unwrap(), None);
    }

    /// A closed hour is judged once, and folded into the baseline whether or not it was worth saying.
    #[test]
    fn a_closed_hour_is_judged_once_and_remembered() {
        let mut store = stocked();
        let mut seen = Seen::new(&mut store, 10 * 3_600);
        for at in [10 * 3_600, 10 * 3_600 + 60] {
            store
                .record_request(flowlight_store::RequestRow {
                    at,
                    process: "node".to_owned(),
                    confidence: "path".to_owned(),
                    pid: 1,
                    agent: None,
                    direction: "out".to_owned(),
                    protocol: None,
                    method: Some("POST".to_owned()),
                    target: None,
                    host: Some("api.example".to_owned()),
                    status: Some(200),
                    bytes: 1_000,
                    truncated: false,
                    unreadable: None,
                    rpc_method: None,
                    rpc_tool: None,
                })
                .unwrap();
        }
        store.flush().unwrap();

        // An hour later, hour 10 has closed.
        let _ = seen.about_windows(&mut store, 11 * 3_600);
        let baseline = store
            .baseline(BYTES_HOUR, "node")
            .unwrap()
            .expect("a baseline");
        assert_eq!(baseline.samples, 1);
        assert!((baseline.mean - 2_000.0).abs() < 0.001, "{}", baseline.mean);

        // Asked again at the same moment, nothing is judged twice.
        let before = baseline.samples;
        let _ = seen.about_windows(&mut store, 11 * 3_600);
        assert_eq!(
            store.baseline(BYTES_HOUR, "node").unwrap().unwrap().samples,
            before
        );
    }

    /// A daemon started after a week away must not spend a minute catching up on hours nobody will read about.
    #[test]
    fn catching_up_is_bounded() {
        let mut store = stocked();
        let mut seen = Seen::new(&mut store, 0);
        // A year later.
        let said = seen.about_windows(&mut store, 365 * 86_400);
        assert!(said.len() < 100, "{} alerts", said.len());
    }

    #[test]
    fn a_refusal_is_always_worth_saying() {
        let mut store = stocked();
        let seen = Seen::new(&mut store, 0);
        let alert = seen.about_refusal("curl", "1.1.1.1", 443, Some("claude"));
        assert_eq!(alert.kind, Kind::Refused);
        assert!(alert.detail.contains("claude"));
    }

    #[test]
    fn severity_shows_in_a_line() {
        let alert = Alert {
            kind: Kind::VolumeSpike,
            subject: "node".to_owned(),
            detail: "moved a lot".to_owned(),
            severity: 3,
        };
        assert!(line(&alert).starts_with("!!"));
    }

    #[test]
    fn an_agent_kind_is_recognised_from_what_was_stored() {
        assert!(about_an_agent("an agent reached an unnamed host"));
        assert!(!about_an_agent("traffic spike"));
        // One a later version wrote is not claimed either way.
        assert!(!about_an_agent("something new"));
    }
}
