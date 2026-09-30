//! What a question about the database answers with.
//!
//! One set of shapes, used by every way of asking: the native interface over its socket, the web page over
//! its loopback port, and the subcommands on the terminal. They were three sets once, and the `agent`
//! column reached two of them — a column added to a row should be a column that appears, not one somebody
//! has to remember to add in three places.
//!
//! Everything here takes a [`Store`] and returns plain data. Nothing knows what a socket is.

use anyhow::Result;
use flowlight_agents::mcp;
use flowlight_store::Store;
use serde::Serialize;
use std::path::PathBuf;

/// The largest window anybody may ask for, so that a question cannot be made expensive by asking it badly.
const LONGEST_WINDOW: i64 = 365 * 86_400;

/// The most rows any one answer carries.
const MOST_ROWS: usize = 2_000;

/// One request or response, as an interface shows it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RequestView {
    /// When, in seconds since the epoch.
    pub at: i64,
    /// What the process is called.
    pub process: String,
    /// Where that name came from.
    pub confidence: String,
    /// The process.
    pub pid: u32,
    /// The agent that caused it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// `out` or `in`.
    pub direction: String,
    /// `http/2` when the connection was one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// The method, for a request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// The target, already redacted of credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// The host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    /// The status, for a response.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// How many bytes the call carried.
    pub bytes: u32,
    /// Whether more was carried than captured.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// Why this connection could not be read, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unreadable: Option<String>,
}

/// One process, and what it has been doing.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ProcessView {
    /// What it is called.
    pub process: String,
    /// Where that name came from, at its least certain over the window.
    pub confidence: String,
    /// Requests read from it.
    pub requests: i64,
    /// Distinct hosts reached.
    pub hosts: i64,
    /// Bytes those requests carried.
    pub bytes: i64,
    /// The most recent one.
    pub last_seen: i64,
}

/// One host something reached.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HostView {
    /// The host.
    pub host: String,
    /// Requests to it.
    pub requests: i64,
    /// The most recent one.
    pub last_seen: i64,
}

/// One agent, with what it reached compared against what it was configured to reach.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AgentView {
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
    /// Configured servers that never touch the network, which nothing here can ever see.
    pub local: Vec<String>,
    /// Hosts, and how each one stands.
    pub domains: Vec<DomainView>,
}

/// One host an agent reached or was configured to reach.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DomainView {
    /// The host.
    pub host: String,
    /// `used`, `unused`, `unexpected` or `endpoint`.
    pub standing: String,
    /// Requests to it.
    pub requests: i64,
    /// The configured servers that name it.
    pub servers: Vec<String>,
}

/// One rule.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleView {
    /// Its identifier, which `forget` takes.
    pub id: i64,
    /// `allow`, `ask` or `block`.
    pub action: String,
    /// A host, a pattern, an address or `*`.
    pub subject: String,
    /// The port, or zero for any.
    pub port: u16,
    /// `everyone` or `agent:<name>`.
    pub scope: String,
    /// Why, if whoever wrote it said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When it was written.
    pub created: i64,
}

/// What Flowlight is allowed to read, and for how long.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BudgetView {
    /// Whether payloads are read at all.
    pub payloads: bool,
    /// Whether they are being read *now*, which the session can decide otherwise.
    pub reading: bool,
    /// Minutes before capture has to be renewed. Zero for no limit.
    pub session_minutes: u32,
    /// Seconds of the session left, or `None` if it does not end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_remaining: Option<i64>,
    /// Bytes one process may contribute in a day. Zero for no ceiling.
    pub daily_bytes: i64,
    /// `full`, `host-only` or `none`.
    pub paths: String,
    /// Days of individual requests.
    pub detail_days: u32,
    /// Days of the daily summary.
    pub summary_days: u32,
    /// The whole thing in sentences, which is what an interface should show rather than seven numbers.
    pub described: Vec<String>,
}

/// One thing a candidate rule would change.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ChangeView {
    /// The host or address this is about.
    pub subject: String,
    /// The agent, if the traffic belonged to one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// The port, when the history recorded one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// What happens today.
    pub before: String,
    /// What would happen with the rule in place.
    pub after: String,
    /// How many times this traffic occurred in the window.
    pub occurrences: i64,
}

/// What was seen, and what was not.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct CoverageView {
    /// Requests read.
    pub requests: i64,
    /// Distinct processes something was read from.
    pub processes_read: i64,
    /// Connections opened.
    pub connections: i64,
    /// Calls that carried more than was captured.
    pub truncated: i64,
    /// Connections whose HTTP/2 could not be decoded.
    pub undecodable: i64,
    /// Records naming a process by its `comm`.
    pub named_by_comm: i64,
    /// Records naming a process by its pid.
    pub named_by_pid: i64,
    /// Connections refused because a rule said so.
    pub refused: i64,
    /// Records the kernel had nowhere to put.
    pub dropped: i64,
    /// Processes that opened HTTPS connections and had nothing read.
    pub unread: Vec<UnreadView>,
    /// Libraries found and not probed.
    pub unprobed: Vec<UnprobedView>,
}

/// One process nothing was read from.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnreadView {
    /// The process.
    pub process: String,
    /// Connections it opened.
    pub connections: i64,
}

/// One library that could not be probed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnprobedView {
    /// Where it is.
    pub path: String,
    /// Why not.
    pub reason: String,
}

/// Now, in seconds since the epoch.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64)
}

/// A window, clamped so that a question cannot be made expensive by asking it badly.
pub fn window(now: i64, seconds: i64) -> i64 {
    now - seconds.clamp(0, LONGEST_WINDOW)
}

/// A row count, clamped for the same reason.
pub fn rows(limit: usize) -> usize {
    limit.clamp(1, MOST_ROWS)
}

/// Requests since a moment, newest first.
pub fn requests(store: &mut Store, since: i64, limit: usize) -> Result<Vec<RequestView>> {
    Ok(store
        .requests_since(since, rows(limit))?
        .into_iter()
        .map(|row| RequestView {
            at: row.at,
            process: row.process,
            confidence: row.confidence,
            pid: row.pid,
            agent: row.agent,
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
        .collect())
}

/// Processes, busiest first.
pub fn processes(store: &mut Store, since: i64) -> Result<Vec<ProcessView>> {
    Ok(store
        .processes(since)?
        .into_iter()
        .map(|row| ProcessView {
            process: row.process,
            confidence: row.confidence,
            requests: row.requests,
            hosts: row.hosts,
            bytes: row.bytes,
            last_seen: row.last_seen,
        })
        .collect())
}

/// The hosts one process reached.
pub fn hosts(store: &mut Store, process: &str, since: i64) -> Result<Vec<HostView>> {
    Ok(store
        .hosts_for(process, since, 100)?
        .into_iter()
        .map(|row| HostView {
            host: row.host,
            requests: row.requests,
            last_seen: row.last_seen,
        })
        .collect())
}

/// Agents, with the comparison against their configuration already made.
pub fn agents(store: &mut Store, since: i64, homes: &[PathBuf]) -> Result<Vec<AgentView>> {
    let configured: Vec<mcp::Server> = mcp::configuration_files(homes)
        .iter()
        .flat_map(|(agent, path)| mcp::read(agent, path))
        .collect();
    let mut views = Vec::new();
    for row in store.agents(since)? {
        let contacted: Vec<(String, i64)> = store
            .hosts_for_agent(&row.agent, since, 200)?
            .into_iter()
            .map(|host| (host.host, host.requests))
            .collect();
        let mine: Vec<mcp::Server> = configured
            .iter()
            .filter(|server| server.agent == row.agent)
            .cloned()
            .collect();
        let domains = mcp::merge(&mine, &contacted, mcp::endpoints_for(&row.agent));
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
    Ok(views)
}

/// Every rule, oldest first.
pub fn rules(store: &mut Store) -> Result<Vec<RuleView>> {
    Ok(store
        .rules()?
        .into_iter()
        .map(|row| RuleView {
            id: row.id,
            action: row.action,
            subject: row.subject,
            port: row.port,
            scope: row.scope,
            note: row.note,
            created: row.created,
        })
        .collect())
}

/// What Flowlight is allowed to read, described.
pub fn budget(store: &mut Store, now: i64) -> Result<BudgetView> {
    Ok(describe(&store.budget()?, now))
}

/// Turns a budget into what an interface shows.
fn describe(budget: &flowlight_store::Budget, now: i64) -> BudgetView {
    BudgetView {
        payloads: budget.payloads,
        reading: budget.reading_payloads(now),
        session_minutes: budget.session_minutes,
        session_remaining: budget.session_remaining(now),
        daily_bytes: budget.daily_bytes,
        paths: budget.paths.as_str().to_owned(),
        detail_days: budget.detail_days,
        summary_days: budget.summary_days,
        described: budget.describe(now),
    }
}

/// What one request may change about the budget.
///
/// Every field optional, because changing one thing should not mean restating the other six — and a caller
/// that had to restate them would silently overwrite whatever somebody else had changed in between.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct BudgetChange {
    /// Read payloads, or stop.
    pub payloads: Option<bool>,
    /// Minutes before capture has to be renewed.
    pub session_minutes: Option<u32>,
    /// Start the session again from now.
    #[serde(default)]
    pub renew: bool,
    /// Bytes one process may contribute in a day.
    pub daily_bytes: Option<i64>,
    /// `full`, `host-only` or `none`.
    pub paths: Option<String>,
    /// Days of individual requests.
    pub detail_days: Option<u32>,
    /// Days of the daily summary.
    pub summary_days: Option<u32>,
}

/// Changes the budget, and says what it now is.
pub fn set_budget(store: &mut Store, change: &BudgetChange, now: i64) -> Result<BudgetView> {
    use anyhow::Context as _;
    let mut budget = store.budget()?;
    if let Some(payloads) = change.payloads {
        // Turning capture back on starts the session again, because the session is how long *this* decision
        // lasts, and the old one belonged to a decision somebody has just replaced.
        if payloads && !budget.payloads {
            budget.session_began = now;
        }
        budget.payloads = payloads;
    }
    if let Some(minutes) = change.session_minutes {
        budget.session_minutes = minutes;
        budget.session_began = now;
    }
    if change.renew {
        budget.session_began = now;
    }
    if let Some(bytes) = change.daily_bytes {
        budget.daily_bytes = bytes.max(0);
    }
    if let Some(paths) = &change.paths {
        budget.paths = flowlight_store::Paths::parse(paths)
            .with_context(|| format!("`{paths}` is not full, host-only or none"))?;
    }
    if let Some(days) = change.detail_days {
        budget.detail_days = days;
    }
    if let Some(days) = change.summary_days {
        budget.summary_days = days;
    }
    store.set_budget(&budget)?;
    Ok(describe(&budget, now))
}

/// What adding a rule would change, judged against traffic that actually happened.
///
/// A claim about the past, not a promise about the future: a host that was not reached in the window does
/// not appear, and a name that resolves elsewhere tomorrow will behave differently. Reporting only what is
/// derivable from evidence is the point.
pub fn simulate(
    store: &mut Store,
    action: &str,
    subject: &str,
    port: u16,
    agent: Option<&str>,
    since: i64,
) -> Result<Vec<ChangeView>> {
    use anyhow::Context as _;
    let action = flowlight_rules::Action::parse(action)
        .with_context(|| format!("`{action}` is not allow, ask or block"))?;
    let scope = agent.map_or(flowlight_rules::Scope::Everyone, |agent| {
        flowlight_rules::Scope::Agent(agent.to_owned())
    });

    let existing: Vec<flowlight_rules::Rule> = store
        .rules()?
        .into_iter()
        .filter_map(|row| {
            Some(flowlight_rules::Rule {
                id: row.id,
                action: flowlight_rules::Action::parse(&row.action)?,
                scope: flowlight_rules::Scope::parse(&row.scope)?,
                subject: flowlight_rules::Subject::parse(&row.subject),
                port: (row.port != 0).then_some(row.port),
            })
        })
        .collect();
    // An identifier no rule has, so that the verdict can never be attributed to it by accident.
    let candidate = flowlight_rules::Rule {
        id: existing.iter().map(|rule| rule.id).max().unwrap_or(0) + 1,
        action,
        scope,
        subject: flowlight_rules::Subject::parse(subject),
        port: (port != 0).then_some(port),
    };

    let history: Vec<(flowlight_rules::Facts, i64)> = store
        .traffic_since(since)?
        .into_iter()
        .map(|row| {
            (
                flowlight_rules::Facts {
                    agent: row.agent,
                    host: row.host,
                    address: row.address,
                    port: row.port,
                },
                row.occurrences,
            )
        })
        .collect();

    Ok(flowlight_rules::simulate(&existing, &candidate, &history)
        .into_iter()
        .map(|change| ChangeView {
            subject: change.subject,
            agent: change.agent,
            port: change.port,
            before: change.before.as_str().to_owned(),
            after: change.after.as_str().to_owned(),
            occurrences: change.occurrences,
        })
        .collect())
}

/// What was seen, and what was not.
pub fn coverage(store: &mut Store, since: i64) -> Result<CoverageView> {
    let coverage = store.coverage(since)?;
    Ok(CoverageView {
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
    })
}

/// Every home directory on the machine, which is where agents keep their configuration.
///
/// This daemon runs as root and watches the whole machine, so the agents on it belong to users. Reading
/// only root's configuration would find nothing on every machine anyone actually uses.
pub fn homes() -> Vec<PathBuf> {
    let mut homes = vec![PathBuf::from("/root")];
    if let Ok(entries) = std::fs::read_dir("/home") {
        homes.extend(entries.flatten().map(|entry| entry.path()));
    }
    homes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A question cannot be made expensive by asking it badly, and a window into the future is not a
    /// window.
    #[test]
    fn a_window_is_clamped_at_both_ends() {
        assert_eq!(window(1_000, 60), 940);
        assert_eq!(window(1_000, -5), 1_000);
        assert_eq!(window(1_000, i64::MAX), 1_000 - LONGEST_WINDOW);
    }

    #[test]
    fn a_row_count_is_clamped_too() {
        assert_eq!(rows(10), 10);
        assert_eq!(rows(0), 1);
        assert_eq!(rows(usize::MAX), MOST_ROWS);
    }

    /// The bug that caused these shapes to be shared rather than written out three times: a column added
    /// to a row reached two of the three places that serialise it.
    #[test]
    fn every_column_of_a_stored_request_reaches_the_view() {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(flowlight_store::RequestRow {
                at: 1_000,
                process: "node".to_owned(),
                confidence: "path".to_owned(),
                pid: 4711,
                agent: Some("claude".to_owned()),
                direction: "out".to_owned(),
                protocol: Some("http/2".to_owned()),
                method: Some("POST".to_owned()),
                target: Some("/v1/messages".to_owned()),
                host: Some("api.anthropic.com".to_owned()),
                status: None,
                bytes: 3_800,
                truncated: true,
                unreadable: None,
            })
            .unwrap();
        let view = requests(&mut store, 0, 10).unwrap();
        assert_eq!(view.len(), 1);
        let json = serde_json::to_string(&view[0]).unwrap();
        for expected in [
            r#""agent":"claude""#,
            r#""process":"node""#,
            r#""method":"POST""#,
            r#""host":"api.anthropic.com""#,
            r#""truncated":true"#,
        ] {
            assert!(json.contains(expected), "{expected} missing from {json}");
        }
        assert!(!json.contains("status"), "{json}");
    }

    /// An interface should show sentences, not seven numbers.
    #[test]
    fn a_budget_comes_with_its_own_description() {
        let mut store = Store::in_memory().unwrap();
        let view = budget(&mut store, 0).unwrap();
        assert!(view.payloads);
        assert_eq!(view.paths, "full");
        assert_eq!(view.described.len(), 4);
        assert!(view.described[1].contains("64 MB"), "{:?}", view.described);
    }

    /// Changing one thing must not mean restating the other six: a caller that had to would silently
    /// overwrite whatever somebody else had changed in between.
    #[test]
    fn changing_one_thing_leaves_the_rest_alone() {
        let mut store = Store::in_memory().unwrap();
        let view = set_budget(
            &mut store,
            &BudgetChange {
                paths: Some("host-only".to_owned()),
                ..BudgetChange::default()
            },
            1_000,
        )
        .unwrap();
        assert_eq!(view.paths, "host-only");
        assert_eq!(
            view.daily_bytes,
            flowlight_store::budget::DEFAULT_DAILY_BYTES
        );
        assert_eq!(
            view.session_minutes,
            flowlight_store::budget::DEFAULT_SESSION_MINUTES
        );
    }

    /// The session is how long *this* decision lasts. Turning capture back on is a new decision.
    #[test]
    fn turning_payloads_back_on_starts_the_session_again() {
        let mut store = Store::in_memory().unwrap();
        set_budget(
            &mut store,
            &BudgetChange {
                payloads: Some(false),
                ..BudgetChange::default()
            },
            1_000,
        )
        .unwrap();
        let view = set_budget(
            &mut store,
            &BudgetChange {
                payloads: Some(true),
                ..BudgetChange::default()
            },
            100_000,
        )
        .unwrap();
        assert!(view.reading);
        assert_eq!(
            view.session_remaining,
            Some(i64::from(flowlight_store::budget::DEFAULT_SESSION_MINUTES) * 60)
        );
    }

    #[test]
    fn a_path_policy_that_is_not_one_is_refused() {
        let mut store = Store::in_memory().unwrap();
        assert!(
            set_budget(
                &mut store,
                &BudgetChange {
                    paths: Some("some".to_owned()),
                    ..BudgetChange::default()
                },
                0
            )
            .is_err()
        );
    }

    /// The sentence somebody can act on before the rule is real.
    #[test]
    fn a_simulation_says_what_a_rule_would_have_changed() {
        let mut store = Store::in_memory().unwrap();
        let mut row = flowlight_store::RequestRow {
            at: 1_000,
            process: "node".to_owned(),
            confidence: "path".to_owned(),
            pid: 1,
            agent: Some("claude".to_owned()),
            direction: "out".to_owned(),
            protocol: None,
            method: Some("POST".to_owned()),
            target: Some("/x".to_owned()),
            host: Some("telemetry.example".to_owned()),
            status: None,
            bytes: 10,
            truncated: false,
            unreadable: None,
        };
        store.record_request(row.clone()).unwrap();
        store.record_request(row.clone()).unwrap();
        row.host = Some("api.anthropic.com".to_owned());
        store.record_request(row).unwrap();

        let changes = simulate(&mut store, "block", "telemetry.example", 0, None, 0).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].subject, "telemetry.example");
        assert_eq!(changes[0].before, "allow");
        assert_eq!(changes[0].after, "block");
        assert_eq!(changes[0].occurrences, 2);
    }

    /// The commonest thing anybody types, and saying "nothing" is the whole value of asking first.
    #[test]
    fn a_rule_that_would_change_nothing_says_nothing() {
        let mut store = Store::in_memory().unwrap();
        assert!(
            simulate(&mut store, "block", "somewhere.else", 0, None, 0)
                .unwrap()
                .is_empty()
        );
    }

    /// An action this version does not understand must be refused before anything is simulated, or the
    /// answer describes a rule nobody could write.
    #[test]
    fn an_action_that_is_not_one_is_refused() {
        let mut store = Store::in_memory().unwrap();
        assert!(simulate(&mut store, "maybe", "example.com", 0, None, 0).is_err());
    }

    #[test]
    fn coverage_of_an_empty_database_is_zero_rather_than_an_error() {
        let mut store = Store::in_memory().unwrap();
        let view = coverage(&mut store, 0).unwrap();
        assert_eq!(view, CoverageView::default());
    }

    #[test]
    fn an_agent_with_no_configuration_still_appears_with_what_it_reached() {
        let mut store = Store::in_memory().unwrap();
        let mut row = flowlight_store::RequestRow {
            at: 1_000,
            process: "node".to_owned(),
            confidence: "path".to_owned(),
            pid: 1,
            agent: Some("claude".to_owned()),
            direction: "out".to_owned(),
            protocol: None,
            method: Some("GET".to_owned()),
            target: Some("/".to_owned()),
            host: Some("api.anthropic.com".to_owned()),
            status: None,
            bytes: 10,
            truncated: false,
            unreadable: None,
        };
        store.record_request(row.clone()).unwrap();
        row.host = Some("telemetry.example".to_owned());
        store.record_request(row).unwrap();

        let agents = agents(&mut store, 0, &[]).unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].agent, "claude");
        // Its own service is not a surprise; the other host is.
        let standings: Vec<(&str, &str)> = agents[0]
            .domains
            .iter()
            .map(|domain| (domain.host.as_str(), domain.standing.as_str()))
            .collect();
        assert!(
            standings.contains(&("api.anthropic.com", "endpoint")),
            "{standings:?}"
        );
        assert!(
            standings.contains(&("telemetry.example", "unexpected")),
            "{standings:?}"
        );
    }
}
