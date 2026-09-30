//! Running the queries against the local history, and turning the results into the compact JSON a model is
//! handed back.
//!
//! Every function here ends in a `SELECT` on [`flowlight_store`], and every one of them returns counts,
//! totals and names. Nothing returns a request target, a header, a tool's arguments or a timestamp to the
//! second, because none of those are needed to answer a question and all of them are somebody's work.
//!
//! # Why a bad argument is an error and not an empty result
//!
//! A model that wrote `from: "last Tuesday"` and got back `{}` reports that nothing happened. Handed a
//! sentence saying the window could not be read, it writes a window it can. The error text is part of the
//! feature, not a diagnostic.

use crate::guide;
use crate::query::{Call, Query};
use crate::window::{self, Window};
use anyhow::{Result, bail};
use flowlight_store::Store;
use serde_json::{Map, Value, json};

/// What one query produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Produced {
    /// What the model is handed.
    pub json: String,
    /// A sentence for the transcript, so somebody reading it does not have to parse JSON to see what came
    /// back.
    pub summary: String,
}

/// Runs one call.
pub fn run(call: &Call, store: &mut Store, now: i64) -> Result<Produced> {
    // The questions about Flowlight itself need no window: they are about how it is set up, not about when.
    match call.query {
        Query::Settings => return settings(store),
        Query::Rules => return rules(store),
        Query::HowTo => return how_to(call),
        _ => {}
    }

    let Some(from) = call.argument("from") else {
        bail!(
            "That query needs a window. Give `from` as '30m', '24h', '7d', 'today', 'yesterday' or a date."
        );
    };
    let Some(window) = window::resolve(from, call.argument("to"), now) else {
        bail!(
            "I could not read that time window: from '{from}'{}. Use something like '24h', '7d', \
             'yesterday', or a date as YYYY-MM-DD.",
            call.argument("to")
                .map(|to| format!(" to '{to}'"))
                .unwrap_or_default()
        );
    };
    let limit = call.limit();
    let process = call.argument("process");

    match call.query {
        Query::Totals => totals(store, window, process),
        Query::TopProcesses => top_processes(store, window, limit),
        Query::TopHosts => top_hosts(store, window, process, limit, false),
        Query::NewHosts => top_hosts(store, window, process, limit, true),
        Query::Agents => agents(store, window, limit),
        Query::AgentHosts => agent_hosts(store, call, window, limit),
        Query::AgentTools => agent_tools(store, call, window, limit),
        Query::Coverage => coverage(store, window),
        Query::OverTime => over_time(store, call, window, process),
        // Answered above, where they do not need a window.
        Query::Rules | Query::Settings | Query::HowTo => {
            bail!("That query does not take a window")
        }
    }
}

/// Wraps a result with the window it was about, so an answer can say which window it is describing.
fn produced(
    window: Option<Window>,
    mut body: Map<String, Value>,
    summary: String,
) -> Result<Produced> {
    if let Some(window) = window {
        body.insert("window".to_owned(), json!(window.described()));
    }
    Ok(Produced {
        json: serde_json::to_string(&Value::Object(body))?,
        summary,
    })
}

/// How much moved.
fn totals(store: &mut Store, window: Window, process: Option<&str>) -> Result<Produced> {
    // Never narrowed by a focus. A focus is a setting about what somebody is looking at; a model asked what
    // this machine did would otherwise answer with a subset and say it was the machine.
    let rows = store.processes(window.from, None)?;
    let counted: Vec<_> = rows
        .iter()
        .filter(|row| process.is_none_or(|name| row.process == name))
        .collect();
    let requests: i64 = counted.iter().map(|row| row.requests).sum();
    let bytes: i64 = counted.iter().map(|row| row.bytes).sum();
    let coverage = store.coverage(window.from)?;
    let mut body = Map::new();
    body.insert("requests".to_owned(), json!(requests));
    body.insert("bytes".to_owned(), json!(bytes));
    body.insert("processes".to_owned(), json!(counted.len()));
    if process.is_none() {
        // Connections are not attributed per process in this total, so naming one would be a number about
        // something else.
        body.insert("connections".to_owned(), json!(coverage.connections));
    }
    if let Some(name) = process {
        body.insert("process".to_owned(), json!(name));
    }
    let summary = format!(
        "{requests} request(s), {bytes} byte(s){}",
        process
            .map(|name| format!(" from {name}"))
            .unwrap_or_default()
    );
    produced(Some(window), body, summary)
}

/// The busiest processes.
fn top_processes(store: &mut Store, window: Window, limit: usize) -> Result<Produced> {
    let rows = store.processes(window.from, None)?;
    let listed: Vec<Value> = rows
        .iter()
        .take(limit)
        .map(|row| {
            json!({
                "process": row.process,
                "requests": row.requests,
                "hosts": row.hosts,
                "bytes": row.bytes,
                "naming": row.confidence,
            })
        })
        .collect();
    let summary = format!("{} process(es)", listed.len());
    let mut body = Map::new();
    body.insert("processes".to_owned(), Value::Array(listed));
    produced(Some(window), body, summary)
}

/// The busiest hosts, or the ones that are new.
fn top_hosts(
    store: &mut Store,
    window: Window,
    process: Option<&str>,
    limit: usize,
    only_new: bool,
) -> Result<Produced> {
    let rows = if only_new {
        store.new_hosts(process, window.from, limit)?
    } else {
        store.hosts(process, window.from, limit)?
    };
    let listed: Vec<Value> = rows
        .iter()
        .map(|row| json!({ "host": row.host, "requests": row.requests }))
        .collect();
    let summary = format!(
        "{} {}host(s)",
        listed.len(),
        if only_new { "new " } else { "" }
    );
    let mut body = Map::new();
    body.insert("hosts".to_owned(), Value::Array(listed));
    if only_new {
        body.insert(
            "meaning".to_owned(),
            json!("hosts reached in this window and never before it"),
        );
    }
    produced(Some(window), body, summary)
}

/// The agents that were active.
fn agents(store: &mut Store, window: Window, limit: usize) -> Result<Produced> {
    let rows = store.agents(window.from)?;
    let listed: Vec<Value> = rows
        .iter()
        .take(limit)
        .map(|row| {
            json!({
                "agent": row.agent,
                "requests": row.requests,
                "hosts": row.hosts,
                "processes": row.processes,
                "bytes": row.bytes,
            })
        })
        .collect();
    let summary = if listed.is_empty() {
        "no agents".to_owned()
    } else {
        format!("{} agent(s)", listed.len())
    };
    let mut body = Map::new();
    body.insert("agents".to_owned(), Value::Array(listed));
    produced(Some(window), body, summary)
}

/// Which agent a call is about, or a sentence saying it did not name one.
fn named_agent(call: &Call) -> Result<&str> {
    match call.argument("agent") {
        Some(agent) => Ok(agent),
        None => bail!(
            "That query needs an agent. Call the agents query first to see which ones Flowlight has \
             recorded, then name one."
        ),
    }
}

/// The hosts one agent reached.
fn agent_hosts(store: &mut Store, call: &Call, window: Window, limit: usize) -> Result<Produced> {
    let agent = named_agent(call)?;
    let rows = store.hosts_for_agent(agent, window.from, limit)?;
    let listed: Vec<Value> = rows
        .iter()
        .map(|row| json!({ "host": row.host, "requests": row.requests }))
        .collect();
    let summary = format!("{} host(s) for {agent}", listed.len());
    let mut body = Map::new();
    body.insert("agent".to_owned(), json!(agent));
    body.insert("hosts".to_owned(), Value::Array(listed));
    produced(Some(window), body, summary)
}

/// What one agent said to MCP servers.
fn agent_tools(store: &mut Store, call: &Call, window: Window, limit: usize) -> Result<Produced> {
    let agent = named_agent(call)?;
    let rows = store.tools_for_agent(agent, window.from, limit)?;
    let listed: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "method": row.method,
                "tool": row.tool,
                "host": row.host,
                "calls": row.calls,
            })
        })
        .collect();
    let summary = format!("{} MCP call(s) by {agent}", listed.len());
    let mut body = Map::new();
    body.insert("agent".to_owned(), json!(agent));
    body.insert("calls".to_owned(), Value::Array(listed));
    // Said in the result rather than only in the instructions, because this is the one place a model is
    // likeliest to fill a gap with an invention.
    body.insert(
        "note".to_owned(),
        json!("Flowlight records the method and the tool's name. A tool's arguments are never recorded."),
    );
    produced(Some(window), body, summary)
}

/// What was not read.
fn coverage(store: &mut Store, window: Window) -> Result<Produced> {
    let seen = store.coverage(window.from)?;
    let unread: Vec<Value> = seen
        .unread
        .iter()
        .map(|row| json!({ "process": row.process, "connections": row.connections }))
        .collect();
    let mut body = Map::new();
    body.insert("requests_read".to_owned(), json!(seen.requests));
    body.insert("processes_read".to_owned(), json!(seen.processes_read));
    body.insert("connections".to_owned(), json!(seen.connections));
    body.insert("nothing_read_from".to_owned(), Value::Array(unread));
    body.insert("truncated".to_owned(), json!(seen.truncated));
    body.insert("undecodable_http2".to_owned(), json!(seen.undecodable));
    body.insert("named_by_comm".to_owned(), json!(seen.named_by_comm));
    body.insert("named_by_pid".to_owned(), json!(seen.named_by_pid));
    body.insert("dropped_by_kernel".to_owned(), json!(seen.dropped));
    body.insert("refused_by_a_rule".to_owned(), json!(seen.refused));
    body.insert(
        "meaning".to_owned(),
        json!(
            "A process under nothing_read_from opened connections Flowlight could not read — Go programs \
             and Chrome link their own TLS. Its traffic happened and is not in any other answer."
        ),
    );
    let summary = format!(
        "{} request(s) read, {} process(es) with nothing read",
        seen.requests,
        seen.unread.len()
    );
    produced(Some(window), body, summary)
}

/// A series over time.
fn over_time(
    store: &mut Store,
    call: &Call,
    window: Window,
    process: Option<&str>,
) -> Result<Produced> {
    let bucket = window::bucket(window, call.argument("granularity"));
    let rows = store.series(process, window.from, window.to, bucket)?;
    // Bounded like everything else: a minute bucket over a year is not a series, it is the database.
    let listed: Vec<Value> = rows
        .iter()
        .take(crate::query::MOST_ROWS * 4)
        .map(|row| json!({ "at": row.at, "requests": row.requests, "bytes": row.bytes }))
        .collect();
    let busiest = rows.iter().max_by_key(|row| row.requests);
    let summary = match busiest {
        Some(row) => format!(
            "{} bucket(s), busiest had {} request(s)",
            listed.len(),
            row.requests
        ),
        None => "nothing in that window".to_owned(),
    };
    let mut body = Map::new();
    body.insert("bucket_seconds".to_owned(), json!(bucket));
    body.insert("series".to_owned(), Value::Array(listed));
    produced(Some(window), body, summary)
}

/// The rules.
fn rules(store: &mut Store) -> Result<Produced> {
    let rows = store.rules()?;
    let listed: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "id": row.id,
                "action": row.action,
                "subject": row.subject,
                "port": row.port,
                "scope": row.scope,
                "note": row.note,
            })
        })
        .collect();
    let summary = if listed.is_empty() {
        "no rules".to_owned()
    } else {
        format!("{} rule(s)", listed.len())
    };
    let mut body = Map::new();
    body.insert("rules".to_owned(), Value::Array(listed));
    body.insert(
        "precedence".to_owned(),
        json!("The most specific rule wins: subject, then port, then scope. Nothing is refused unless a rule says so."),
    );
    produced(None, body, summary)
}

/// How Flowlight is set up.
///
/// The endpoint of the model that is answering is in here, and its key is not: a key is not configuration.
fn settings(store: &mut Store) -> Result<Produced> {
    let budget = store.budget()?;
    let export = store.export()?;
    let ask = store.ask()?;
    let mut body = Map::new();
    body.insert("reading_payloads".to_owned(), json!(budget.payloads));
    body.insert("session_minutes".to_owned(), json!(budget.session_minutes));
    body.insert(
        "daily_bytes_per_process".to_owned(),
        json!(budget.daily_bytes),
    );
    body.insert(
        "keeps_of_each_target".to_owned(),
        json!(budget.paths.as_str()),
    );
    body.insert("detail_days".to_owned(), json!(budget.detail_days));
    body.insert("summary_days".to_owned(), json!(budget.summary_days));
    let sending = export.may_send();
    body.insert("exporting".to_owned(), json!(sending));
    body.insert(
        "export_destination".to_owned(),
        json!(export.destination.filter(|_| sending)),
    );
    body.insert("answering_model".to_owned(), json!(ask.model));
    body.insert("answering_provider".to_owned(), json!(ask.kind.as_str()));
    body.insert("schema_version".to_owned(), json!(store.schema_version()?));
    body.insert(
        "flowlight_version".to_owned(),
        json!(env!("CARGO_PKG_VERSION")),
    );
    let summary = format!(
        "payloads {}, keeping {} day(s) of detail",
        if budget.payloads { "on" } else { "off" },
        budget.detail_days
    );
    produced(None, body, summary)
}

/// What a feature is and how to use it.
fn how_to(call: &Call) -> Result<Produced> {
    let asked = call.argument("topic").unwrap_or_default();
    let mut body = Map::new();
    match guide::look_up(asked) {
        Some(topic) => {
            body.insert("topic".to_owned(), json!(topic.title));
            body.insert("answer".to_owned(), json!(topic.detail));
            let summary = topic.title.to_owned();
            produced(None, body, summary)
        }
        None => {
            // The list rather than nothing, so the model can name a topic that exists instead of inventing
            // an answer about one that does not.
            body.insert(
                "answer".to_owned(),
                json!(
                    "Flowlight's guide has nothing written down about that. Say so rather than answering \
                     from memory."
                ),
            );
            body.insert(
                "topics_that_exist".to_owned(),
                json!(
                    guide::TOPICS
                        .iter()
                        .map(|topic| topic.title)
                        .collect::<Vec<_>>()
                ),
            );
            produced(None, body, "no matching topic".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowlight_store::RequestRow;
    use std::collections::BTreeMap;

    fn call(query: Query, arguments: &[(&str, &str)]) -> Call {
        Call {
            query,
            arguments: arguments
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    fn request(at: i64, process: &str, host: &str, agent: Option<&str>) -> RequestRow {
        RequestRow {
            at,
            process: process.to_owned(),
            confidence: "path".to_owned(),
            pid: 1,
            agent: agent.map(str::to_owned),
            direction: "out".to_owned(),
            protocol: None,
            method: Some("GET".to_owned()),
            target: Some("/secret-path".to_owned()),
            host: Some(host.to_owned()),
            status: Some(200),
            bytes: 100,
            truncated: false,
            unreadable: None,
            rpc_method: None,
            rpc_tool: None,
        }
    }

    fn stocked() -> Store {
        let mut store = Store::in_memory().unwrap();
        store
            .record_request(request(1_000, "curl", "example.com", None))
            .unwrap();
        store
            .record_request(request(1_100, "node", "api.anthropic.com", Some("claude")))
            .unwrap();
        store.flush().unwrap();
        store
    }

    /// The property that matters most: a result is counts and names, and a request target is in none of
    /// them. Asserted over every query rather than per query, because the one that leaks will be the one
    /// added later.
    #[test]
    fn no_query_returns_a_request_target() {
        let mut store = stocked();
        for query in crate::query::EVERY_QUERY {
            let produced = run(
                &call(
                    *query,
                    &[("from", "7d"), ("agent", "claude"), ("topic", "block")],
                ),
                &mut store,
                2_000,
            )
            .unwrap();
            assert!(
                !produced.json.contains("secret-path"),
                "{} leaked a request target: {}",
                query.as_str(),
                produced.json
            );
        }
    }

    #[test]
    fn totals_counts_what_was_read() {
        let mut store = stocked();
        let produced = run(&call(Query::Totals, &[("from", "7d")]), &mut store, 2_000).unwrap();
        let value: Value = serde_json::from_str(&produced.json).unwrap();
        assert_eq!(value.get("requests").and_then(Value::as_i64), Some(2));
        assert_eq!(value.get("bytes").and_then(Value::as_i64), Some(200));
        assert_eq!(value.get("processes").and_then(Value::as_i64), Some(2));

        let one = run(
            &call(Query::Totals, &[("from", "7d"), ("process", "curl")]),
            &mut store,
            2_000,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&one.json).unwrap();
        assert_eq!(value.get("requests").and_then(Value::as_i64), Some(1));
    }

    /// A window that cannot be read is a sentence the model can correct, not an empty result it will report
    /// as "nothing happened".
    #[test]
    fn an_unreadable_window_is_an_error_with_words_in_it() {
        let mut store = stocked();
        let failed = run(
            &call(Query::Totals, &[("from", "last Tuesday")]),
            &mut store,
            2_000,
        );
        let message = format!("{:#}", failed.unwrap_err());
        assert!(message.contains("could not read"), "{message}");
        assert!(message.contains("24h"), "{message}");
    }

    #[test]
    fn a_query_that_needs_a_window_and_has_none_says_so() {
        let mut store = stocked();
        let message = format!(
            "{:#}",
            run(&call(Query::TopHosts, &[]), &mut store, 2_000).unwrap_err()
        );
        assert!(message.contains("needs a window"), "{message}");
    }

    /// And an agent query with no agent points at the query that lists them, rather than failing in a way
    /// that leaves the model guessing at names.
    #[test]
    fn an_agent_query_without_an_agent_points_at_the_agents_query() {
        let mut store = stocked();
        let message = format!(
            "{:#}",
            run(
                &call(Query::AgentHosts, &[("from", "7d")]),
                &mut store,
                2_000
            )
            .unwrap_err()
        );
        assert!(message.contains("agents query"), "{message}");
    }

    #[test]
    fn an_agents_answer_names_the_agent_and_not_the_process() {
        let mut store = stocked();
        let produced = run(&call(Query::Agents, &[("from", "7d")]), &mut store, 2_000).unwrap();
        assert!(produced.json.contains("claude"));
        let hosts = run(
            &call(Query::AgentHosts, &[("from", "7d"), ("agent", "claude")]),
            &mut store,
            2_000,
        )
        .unwrap();
        assert!(hosts.json.contains("api.anthropic.com"));
        assert!(!hosts.json.contains("example.com"));
    }

    /// Coverage carries the sentence explaining what an unread process means, because the number alone is
    /// the one a model will read as zero.
    #[test]
    fn coverage_explains_itself() {
        let mut store = stocked();
        let produced = run(&call(Query::Coverage, &[("from", "7d")]), &mut store, 2_000).unwrap();
        assert!(produced.json.contains("nothing_read_from"));
        assert!(produced.json.contains("Go programs"));
    }

    /// The guide answers from what is written down, and says nothing when nothing is written down.
    #[test]
    fn how_to_answers_from_the_guide_or_not_at_all() {
        let mut store = stocked();
        let produced = run(
            &call(Query::HowTo, &[("topic", "how do I block a host")]),
            &mut store,
            2_000,
        )
        .unwrap();
        assert!(produced.json.contains("flowlightd block"));

        let unknown = run(
            &call(Query::HowTo, &[("topic", "the capital of France")]),
            &mut store,
            2_000,
        )
        .unwrap();
        assert!(unknown.json.contains("nothing written down"));
        assert!(unknown.json.contains("topics_that_exist"));
    }

    /// Settings says which model answers and never its key, because a key is not configuration.
    #[test]
    fn settings_never_carries_a_key() {
        let mut store = stocked();
        let produced = run(&call(Query::Settings, &[]), &mut store, 2_000).unwrap();
        assert!(produced.json.contains("reading_payloads"));
        assert!(!produced.json.to_lowercase().contains("key"));
    }

    /// A result says which window it is about, so an answer cannot quote a window nobody asked for.
    #[test]
    fn a_result_names_its_own_window() {
        let mut store = stocked();
        let produced = run(
            &call(Query::Totals, &[("from", "6h")]),
            &mut store,
            1_000_000,
        )
        .unwrap();
        assert!(produced.json.contains("\"window\""));
        assert!(produced.json.contains("6 hour(s)"), "{}", produced.json);
        let day = run(
            &call(Query::Totals, &[("from", "24h")]),
            &mut store,
            1_000_000,
        )
        .unwrap();
        assert!(day.json.contains("1 day(s)"), "{}", day.json);
    }

    #[test]
    fn a_series_buckets_the_window() {
        let mut store = stocked();
        let produced = run(
            &call(Query::OverTime, &[("from", "7d"), ("granularity", "hour")]),
            &mut store,
            2_000,
        )
        .unwrap();
        let value: Value = serde_json::from_str(&produced.json).unwrap();
        assert_eq!(
            value.get("bucket_seconds").and_then(Value::as_i64),
            Some(3_600)
        );
    }

    #[test]
    fn a_call_with_no_arguments_at_all_still_works_for_the_queries_that_take_none() {
        let mut store = stocked();
        for query in [Query::Rules, Query::Settings] {
            assert!(
                run(
                    &Call {
                        query,
                        arguments: BTreeMap::new()
                    },
                    &mut store,
                    2_000
                )
                .is_ok()
            );
        }
    }
}
