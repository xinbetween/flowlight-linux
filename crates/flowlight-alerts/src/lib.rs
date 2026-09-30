//! Anomalies, each carrying the arithmetic that produced it.
//!
//! A ranked list with no numbers behind it is a horoscope. So every alert here names what it compared against
//! and what it found — "moved 412 MB in the hour from 14:00, 4.2σ above its baseline of 31 MB/h" rather than
//! "unusual activity". Somebody who disagrees can go and check.
//!
//! # What is here and what is in the daemon
//!
//! The deciding is here, over numbers, so that every judgement can be tested without a database or a kernel.
//! Producing the numbers is the daemon's job, because that is a set of queries.
//!
//! # What does not port from the macOS build
//!
//! Two signals: "traffic while nobody was at the keyboard" and "an agent was active while you were away". Both
//! rest on there being a keyboard and a session to be away from, and this runs on servers. They are absent
//! rather than approximated, because a signal that fires because a machine has no display is not a signal.

pub mod baseline;

pub use baseline::{Baseline, update};

use std::collections::BTreeSet;

/// Ports that are somebody's service rather than somebody's idea.
///
/// Not a security judgement — plenty of harmless things listen elsewhere. It is the list that makes "a process
/// reached a port nothing usually reaches" mean something, and it is deliberately generous so that the signal
/// is rare enough to read.
pub const USUAL_PORTS: &[u16] = &[
    20, 21, 22, 25, 53, 67, 68, 80, 110, 123, 137, 138, 143, 389, 443, 465, 587, 636, 853, 990,
    993, 995, 1900, 3478, 3479, 3480, 3481, 5223, 5228, 5353, 8000, 8080, 8443, 9418,
];

/// What sort of thing was noticed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// A process moved much more than it usually does in an hour.
    VolumeSpike,
    /// A process reached many more distinct hosts than it usually does in a day.
    DestinationSpike,
    /// A host nothing on this machine had ever reached before.
    FirstContact,
    /// A process that had never been on the network before.
    NewProcess,
    /// A port nothing usually reaches.
    NonStandardPort,
    /// An agent reached a host with no name — an address, which nothing configured it to use.
    AgentUnnamedHost,
    /// An agent sent far more than it received, which is the shape of a copy leaving.
    AgentExfiltration,
    /// A connection a rule refused.
    Refused,
}

impl Kind {
    /// The name this is stored and shown under.
    ///
    /// The stored name is English and is what a later version reads back, so an alert written by an older
    /// build still says what it was about.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VolumeSpike => "traffic spike",
            Self::DestinationSpike => "unusual number of destinations",
            Self::FirstContact => "first contact with a host",
            Self::NewProcess => "a process new to the network",
            Self::NonStandardPort => "a port nothing usually reaches",
            Self::AgentUnnamedHost => "an agent reached an unnamed host",
            Self::AgentExfiltration => "an agent sent much more than it received",
            Self::Refused => "a connection was refused",
        }
    }

    /// Reads one back, or nothing if this version does not know it.
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::VolumeSpike,
            Self::DestinationSpike,
            Self::FirstContact,
            Self::NewProcess,
            Self::NonStandardPort,
            Self::AgentUnnamedHost,
            Self::AgentExfiltration,
            Self::Refused,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == text.trim())
    }

    /// Whether this is about an agent rather than about any process.
    pub fn is_about_an_agent(self) -> bool {
        matches!(self, Self::AgentUnnamedHost | Self::AgentExfiltration)
    }
}

/// One thing worth saying, with the numbers that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// What sort of thing.
    pub kind: Kind,
    /// What it is about: a process, an agent, a host.
    pub subject: String,
    /// One sentence, containing the arithmetic. A person who disagrees can go and check.
    pub detail: String,
    /// One to three. Three is "go and look now"; one is "worth knowing".
    pub severity: u8,
}

/// How strict to be.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Settings {
    /// How many deviations above normal is worth saying.
    pub sigma: f64,
    /// How many samples a baseline needs before it is trusted.
    pub least_samples: u32,
    /// How few bytes are never worth an alert, however unusual.
    pub least_bytes: i64,
    /// How many times more an agent may send than it receives before that is worth saying.
    pub upload_ratio: f64,
    /// How few bytes an agent may send before the ratio is worth applying.
    pub least_upload: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            // Three deviations, which is the conventional line and is where the macOS build draws it.
            sigma: 3.0,
            // A day of hourly samples. Less than that and "usually" is not a word anybody should use.
            least_samples: 24,
            // A megabyte. Below it, a spike is arithmetic rather than news.
            least_bytes: 1_024 * 1_024,
            upload_ratio: 10.0,
            least_upload: 5 * 1_024 * 1_024,
        }
    }
}

/// Whether an hour's traffic from a process is worth saying something about.
///
/// Three things have to be true: there is enough history to call anything usual, the amount is large enough to
/// matter, and it is far enough above normal. The order matters only for the message.
pub fn volume_spike(
    process: &str,
    bytes: i64,
    hour: &str,
    baseline: Option<Baseline>,
    settings: &Settings,
) -> Option<Alert> {
    let baseline = baseline?;
    if baseline.samples < settings.least_samples || bytes < settings.least_bytes {
        return None;
    }
    // A tenth of the mean, or sixty-four kilobytes, whichever is larger: a floor proportional to the thing
    // being measured, so a busy process is not judged by a quiet one's standards.
    let floor = (baseline.mean * 0.1).max(64_000.0);
    let score = baseline.z_score(bytes as f64, floor);
    if score < settings.sigma {
        return None;
    }
    Some(Alert {
        kind: Kind::VolumeSpike,
        subject: process.to_owned(),
        detail: format!(
            "{process} moved {} in the hour from {hour} — {score:.1} deviations above its baseline of {} an hour, over {} hours of history",
            bytes_said(bytes),
            bytes_said(baseline.mean as i64),
            baseline.samples
        ),
        severity: if score >= settings.sigma * 2.0 { 3 } else { 2 },
    })
}

/// Whether a day's worth of distinct hosts from a process is worth saying something about.
pub fn destination_spike(
    process: &str,
    hosts: i64,
    baseline: Option<Baseline>,
    settings: &Settings,
) -> Option<Alert> {
    let baseline = baseline?;
    // Days, not hours, so there is less history and less is asked of it.
    if baseline.samples < 3 || hosts < 5 {
        return None;
    }
    let score = baseline.z_score(hosts as f64, (baseline.mean * 0.2).max(2.0));
    if score < settings.sigma {
        return None;
    }
    Some(Alert {
        kind: Kind::DestinationSpike,
        subject: process.to_owned(),
        detail: format!(
            "{process} reached {hosts} distinct host(s) today — {score:.1} deviations above its baseline of {:.0}, over {} days of history",
            baseline.mean, baseline.samples
        ),
        severity: 2,
    })
}

/// A host nothing on this machine had reached before.
///
/// Worth one line and no more: on a developer's machine this happens all day. It is here because the *first*
/// time a machine reaches somewhere is the only time that fact is cheap to notice, and because it is the signal
/// somebody goes looking for after the fact.
pub fn first_contact(host: &str, by: &str, known: &BTreeSet<String>) -> Option<Alert> {
    let host = host.trim().to_lowercase();
    if host.is_empty() || known.contains(&host) {
        return None;
    }
    Some(Alert {
        kind: Kind::FirstContact,
        subject: host.clone(),
        detail: format!("{by} reached {host}, which nothing on this machine had reached before"),
        severity: 1,
    })
}

/// A process that had never been on the network before.
pub fn new_process(process: &str, known: &BTreeSet<String>) -> Option<Alert> {
    let process = process.trim();
    if process.is_empty() || known.contains(process) {
        return None;
    }
    Some(Alert {
        kind: Kind::NewProcess,
        subject: process.to_owned(),
        detail: format!("{process} opened a connection, and had never been on the network before"),
        severity: 1,
    })
}

/// A port nothing usually reaches.
pub fn non_standard_port(process: &str, address: &str, port: u16) -> Option<Alert> {
    if port == 0 || USUAL_PORTS.contains(&port) {
        return None;
    }
    Some(Alert {
        kind: Kind::NonStandardPort,
        subject: process.to_owned(),
        detail: format!(
            "{process} reached {address} on port {port}, which is not one of the {} ports anything usually reaches",
            USUAL_PORTS.len()
        ),
        severity: 1,
    })
}

/// An agent that reached an address with no name.
///
/// An agent is configured with names. An address is what is left when a name was never involved — which is
/// either something clever or something that does not want to be looked up.
pub fn agent_unnamed_host(agent: &str, address: &str, port: u16) -> Option<Alert> {
    let address = address.trim();
    if address.is_empty() {
        return None;
    }
    Some(Alert {
        kind: Kind::AgentUnnamedHost,
        subject: agent.to_owned(),
        detail: format!(
            "{agent} reached {address}:{port} — an address rather than a name, which nothing configured it to use"
        ),
        severity: 2,
    })
}

/// An agent that sent far more than it received.
///
/// The shape of a copy leaving rather than a question being asked. Deliberately crude: it is a ratio and a
/// floor, and it says so, because the alternative is a number nobody can argue with.
pub fn agent_exfiltration(
    agent: &str,
    host: &str,
    sent: i64,
    received: i64,
    settings: &Settings,
) -> Option<Alert> {
    if sent < settings.least_upload {
        return None;
    }
    let ratio = sent as f64 / (received.max(1)) as f64;
    if ratio < settings.upload_ratio {
        return None;
    }
    Some(Alert {
        kind: Kind::AgentExfiltration,
        subject: agent.to_owned(),
        detail: format!(
            "{agent} sent {} to {host} and received {} back — {ratio:.0} times as much out as in",
            bytes_said(sent),
            bytes_said(received)
        ),
        severity: 3,
    })
}

/// A connection a rule refused.
///
/// Not an anomaly: it is Flowlight doing what it was told. It is here because the person it happens to is
/// usually the person who wrote the rule, and an hour spent on a network that appears to be broken is an hour
/// nobody gets back.
pub fn refused(process: &str, address: &str, port: u16, agent: Option<&str>) -> Alert {
    Alert {
        kind: Kind::Refused,
        subject: process.to_owned(),
        detail: match agent {
            Some(agent) => {
                format!("{process}, working for {agent}, was refused {address}:{port} by a rule")
            }
            None => format!("{process} was refused {address}:{port} by a rule"),
        },
        severity: 1,
    }
}

/// Bytes, as a person would say them.
pub fn bytes_said(bytes: i64) -> String {
    const KB: f64 = 1024.0;
    let amount = bytes as f64;
    if amount < KB {
        return format!("{bytes} bytes");
    }
    for (limit, unit) in [
        (KB * KB, "KB"),
        (KB * KB * KB, "MB"),
        (KB * KB * KB * KB, "GB"),
    ] {
        if amount < limit {
            return format!("{:.1} {unit}", amount / (limit / KB));
        }
    }
    format!("{:.1} TB", amount / (KB * KB * KB * KB))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steady(samples: u32, value: f64) -> Baseline {
        let mut baseline = None;
        for _ in 0..samples {
            baseline = Some(update(baseline, value));
        }
        baseline.expect("at least one sample")
    }

    /// Every alert carries the arithmetic, because a ranked list with no numbers behind it is a horoscope.
    #[test]
    fn a_spike_says_what_it_compared_against() {
        let alert = volume_spike(
            "node",
            400 * 1_024 * 1_024,
            "14:00",
            Some(steady(48, 30.0 * 1_024.0 * 1_024.0)),
            &Settings::default(),
        )
        .expect("a spike");
        assert_eq!(alert.kind, Kind::VolumeSpike);
        assert_eq!(alert.subject, "node");
        assert!(alert.detail.contains("400.0 MB"), "{}", alert.detail);
        assert!(
            alert.detail.contains("deviations above"),
            "{}",
            alert.detail
        );
        assert!(alert.detail.contains("30.0 MB an hour"), "{}", alert.detail);
        assert!(
            alert.detail.contains("48 hours of history"),
            "{}",
            alert.detail
        );
    }

    /// Less than a day of history, and "usually" is not a word anybody should use.
    #[test]
    fn a_baseline_with_too_little_history_says_nothing() {
        let settings = Settings::default();
        assert!(
            volume_spike(
                "node",
                400 * 1_024 * 1_024,
                "14:00",
                Some(steady(4, 1.0)),
                &settings
            )
            .is_none()
        );
        assert!(volume_spike("node", 400 * 1_024 * 1_024, "14:00", None, &settings).is_none());
    }

    /// Below a megabyte a spike is arithmetic rather than news.
    #[test]
    fn a_small_amount_is_never_a_spike_however_unusual() {
        let alert = volume_spike(
            "node",
            2_000,
            "14:00",
            Some(steady(48, 1.0)),
            &Settings::default(),
        );
        assert!(alert.is_none());
    }

    /// A busy process must not be judged by a quiet one's standards, which is what a proportional floor is
    /// for.
    #[test]
    fn a_busy_process_is_judged_against_its_own_size() {
        let settings = Settings::default();
        // A process that normally moves a gigabyte an hour, moving 1.1 gigabytes.
        let busy = steady(48, 1_024.0 * 1_024.0 * 1_024.0);
        let gigabyte = 1_024 * 1_024 * 1_024;
        assert!(
            volume_spike(
                "backup",
                gigabyte + gigabyte / 10,
                "14:00",
                Some(busy),
                &settings
            )
            .is_none(),
            "a tenth more than usual is not a spike for something that big"
        );
        // And ten times as much is.
        assert!(volume_spike("backup", gigabyte * 10, "14:00", Some(busy), &settings).is_some());
    }

    #[test]
    fn a_severe_spike_is_severity_three() {
        let alert = volume_spike(
            "node",
            10_000 * 1_024 * 1_024,
            "14:00",
            Some(steady(48, 1_024.0 * 1_024.0)),
            &Settings::default(),
        )
        .expect("a spike");
        assert_eq!(alert.severity, 3);
    }

    #[test]
    fn a_host_is_only_new_once() {
        let mut known = BTreeSet::new();
        let alert = first_contact("Api.Example.COM", "node", &known).expect("new");
        // Lowercased, so the same host by another spelling is not new again.
        assert_eq!(alert.subject, "api.example.com");
        known.insert("api.example.com".to_owned());
        assert!(first_contact("api.example.com", "node", &known).is_none());
        assert!(first_contact("API.EXAMPLE.COM", "node", &known).is_none());
        assert!(first_contact("", "node", &known).is_none());
    }

    #[test]
    fn a_process_is_only_new_once() {
        let mut known = BTreeSet::new();
        assert!(new_process("curl", &known).is_some());
        known.insert("curl".to_owned());
        assert!(new_process("curl", &known).is_none());
        assert!(new_process("  ", &known).is_none());
    }

    #[test]
    fn a_usual_port_is_not_worth_saying_anything_about() {
        for port in [22, 80, 443, 853, 8443] {
            assert!(
                non_standard_port("curl", "1.2.3.4", port).is_none(),
                "{port}"
            );
        }
        let alert = non_standard_port("curl", "1.2.3.4", 4444).expect("unusual");
        assert!(alert.detail.contains("port 4444"), "{}", alert.detail);
        // Zero is not a port.
        assert!(non_standard_port("curl", "1.2.3.4", 0).is_none());
    }

    /// The shape of a copy leaving rather than a question being asked.
    #[test]
    fn an_agent_that_sends_far_more_than_it_receives_is_worth_saying() {
        let settings = Settings::default();
        let alert = agent_exfiltration(
            "claude",
            "somewhere.example",
            200 * 1_024 * 1_024,
            1_024 * 1_024,
            &settings,
        )
        .expect("a ratio worth saying");
        assert_eq!(alert.severity, 3);
        assert!(alert.detail.contains("200.0 MB"), "{}", alert.detail);
        assert!(
            alert.detail.contains("times as much out as in"),
            "{}",
            alert.detail
        );

        // A small upload is not worth the ratio, however lopsided.
        assert!(
            agent_exfiltration("claude", "x", 1_000, 1, &settings).is_none(),
            "a kilobyte out is not an exfiltration"
        );
        // And a normal conversation is not either.
        assert!(
            agent_exfiltration(
                "claude",
                "x",
                10 * 1_024 * 1_024,
                9 * 1_024 * 1_024,
                &settings
            )
            .is_none()
        );
    }

    /// A refusal is not an anomaly — it is Flowlight doing what it was told. It is recorded because the person
    /// it happens to is usually the person who wrote the rule.
    #[test]
    fn a_refusal_names_the_agent_when_there_is_one() {
        let with = refused("curl", "1.1.1.1", 443, Some("claude"));
        assert!(
            with.detail.contains("working for claude"),
            "{}",
            with.detail
        );
        let without = refused("curl", "1.1.1.1", 443, None);
        assert!(
            !without.detail.contains("working for"),
            "{}",
            without.detail
        );
        assert_eq!(without.kind, Kind::Refused);
    }

    #[test]
    fn every_kind_reads_back_from_what_it_is_stored_as() {
        for kind in [
            Kind::VolumeSpike,
            Kind::DestinationSpike,
            Kind::FirstContact,
            Kind::NewProcess,
            Kind::NonStandardPort,
            Kind::AgentUnnamedHost,
            Kind::AgentExfiltration,
            Kind::Refused,
        ] {
            assert_eq!(Kind::parse(kind.as_str()), Some(kind));
        }
        // One a later version wrote is not one this version invents an answer for.
        assert_eq!(Kind::parse("something new"), None);
    }

    #[test]
    fn bytes_are_said_the_way_a_person_says_them() {
        assert_eq!(bytes_said(512), "512 bytes");
        assert_eq!(bytes_said(2_048), "2.0 KB");
        assert_eq!(bytes_said(5 * 1_024 * 1_024), "5.0 MB");
        assert_eq!(bytes_said(3 * 1_024 * 1_024 * 1_024), "3.0 GB");
    }
}
