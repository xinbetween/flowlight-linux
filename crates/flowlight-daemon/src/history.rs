//! Asking the database what happened, rather than watching it happen.
//!
//! The reason storage exists. "Which host did that agent reach at three in the morning" is the question
//! people actually have, and a terminal that has scrolled cannot answer it.

use crate::Command;
use anyhow::{Context as _, bail};
use flowlight_agents::mcp;
use flowlight_store::{RequestRow, Store};
use serde::Serialize;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Answers one question and exits.
pub fn run(command: &Command, database: &Path, json: bool) -> anyhow::Result<()> {
    // A rule can be written before anything has been watched — that is a reasonable order to do things in,
    // and refusing would mean telling somebody to start a daemon in order to configure it. Every other
    // command is a question about history, and a missing database is the answer to it.
    let writes = matches!(
        command,
        Command::Block(_)
            | Command::Allow(_)
            | Command::Ask(_)
            | Command::Forget { .. }
            | Command::Budget { .. }
            | Command::Export { .. }
            | Command::Model { .. }
    );
    if !writes && !database.exists() {
        bail!(
            "there is no database at {}. Nothing has been recorded yet, or it was recorded somewhere else \
             — `flowlightd --database PATH` names it.",
            database.display()
        );
    }
    let mut store = Store::open(database)?;
    let mut out = std::io::stdout().lock();

    match command {
        Command::History { since, limit } => {
            let window = parse_window(since)
                .with_context(|| format!("reading `{since}` as a length of time"))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64);
            let rows = store.requests_since(now - window, *limit)?;
            if rows.is_empty() {
                // A count of zero and an empty screen look the same and mean different things. One of them
                // is "nothing happened" and the other is "you are looking in the wrong place".
                let earliest = store.earliest_request()?;
                match earliest {
                    Some(at) => eprintln!(
                        "Nothing in the last {since}. The oldest request held is from {} seconds ago.",
                        now - at
                    ),
                    None => eprintln!("Nothing has been recorded yet."),
                }
                return Ok(());
            }
            for row in rows {
                if json {
                    writeln!(out, "{}", line(&RequestView::from(&row)))?;
                } else {
                    writeln!(out, "{}", request_line(&row))?;
                }
            }
        }
        Command::Block(rule) => write_rule(&mut store, "block", rule)?,
        Command::Allow(rule) => write_rule(&mut store, "allow", rule)?,
        Command::Ask(rule) => write_rule(&mut store, "ask", rule)?,
        Command::Budget {
            payloads,
            session,
            renew,
            daily,
            paths,
            detail_days,
            summary_days,
        } => {
            let asked = payloads.is_some()
                || session.is_some()
                || *renew
                || daily.is_some()
                || paths.is_some()
                || detail_days.is_some()
                || summary_days.is_some();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64);

            let view = if asked {
                let payloads = match payloads.as_deref() {
                    None => None,
                    Some("yes" | "true" | "on") => Some(true),
                    Some("no" | "false" | "off") => Some(false),
                    Some(other) => bail!("`{other}` is not yes or no"),
                };
                crate::views::set_budget(
                    &mut store,
                    &crate::views::BudgetChange {
                        payloads,
                        session_minutes: *session,
                        renew: *renew,
                        // Megabytes on the way in, bytes inside: nobody types a byte count.
                        daily_bytes: daily.map(|megabytes| megabytes.max(0) * 1024 * 1024),
                        paths: paths.clone(),
                        detail_days: *detail_days,
                        summary_days: *summary_days,
                    },
                    now,
                )?
            } else {
                crate::views::budget(&mut store, now)?
            };

            if json {
                writeln!(out, "{}", line(&view))?;
            } else {
                for sentence in &view.described {
                    writeln!(out, "{sentence}")?;
                }
                if asked {
                    eprintln!("\nA running flowlightd picks this up within a couple of seconds.");
                }
            }
        }
        Command::Export {
            to,
            fields,
            headers,
            consent,
            off,
        } => {
            let mut set = std::collections::BTreeMap::new();
            for header in headers {
                let (name, value) = header
                    .split_once('=')
                    .with_context(|| format!("reading `{header}` as Name=value"))?;
                set.insert(name.to_owned(), value.to_owned());
            }
            let asked = to.is_some() || fields.is_some() || !set.is_empty() || *consent || *off;

            let view = if asked {
                crate::views::set_export(
                    &mut store,
                    &crate::views::ExportChange {
                        destination: to.clone(),
                        fields: fields.clone(),
                        headers: (!set.is_empty()).then_some(set),
                        consent: *consent,
                        off: *off,
                    },
                )?
            } else {
                crate::views::export(&mut store)?
            };

            if json {
                writeln!(out, "{}", line(&view))?;
            } else {
                for sentence in &view.disclosure {
                    writeln!(out, "{sentence}")?;
                }
                if view.revoked {
                    writeln!(
                        out,
                        "\nThe agreement on record was to something else, so it has been taken away."
                    )?;
                }
                match (view.sending, &view.why_not) {
                    (true, _) => writeln!(
                        out,
                        "\nThis is in force. Records already stored and not yet sent go in the first batch."
                    )?,
                    (false, Some(reason)) => writeln!(out, "\nNothing is being sent: {reason}")?,
                    (false, None) => {}
                }
                writeln!(out, "\nFields available: {}", view.every_field.join(", "))?;
                if asked {
                    eprintln!("\nA running flowlightd picks this up within a few seconds.");
                }
            }
        }
        Command::Model {
            kind,
            endpoint,
            model,
            key_file,
            forget_key,
            off,
        } => {
            // The key first, so that what is reported afterwards is the state including it. Reported the
            // other way round, `--key-file` and `--kind anthropic` in one command would print "no key on
            // file" about a command that had just put one there.
            if *forget_key {
                crate::asking::set_key(database, "")?;
            }
            if let Some(path) = key_file {
                let key = crate::asking::key_from(path)?;
                crate::asking::set_key(database, &key)?;
            }
            let key_on_file = crate::asking::have_key(database);
            let asked = kind.is_some() || endpoint.is_some() || model.is_some() || *off;

            let view = if asked {
                crate::views::set_ask(
                    &mut store,
                    &crate::views::AskChange {
                        kind: kind.clone(),
                        endpoint: endpoint.clone(),
                        model: model.clone(),
                        off: *off,
                    },
                    key_on_file,
                )?
            } else {
                crate::views::ask(&mut store, key_on_file)?
            };

            if json {
                writeln!(out, "{}", line(&view))?;
            } else {
                for sentence in &view.disclosure {
                    writeln!(out, "{sentence}")?;
                }
                match &view.why_not {
                    Some(reason) => writeln!(out, "\nNot ready: {reason}")?,
                    None => writeln!(
                        out,
                        "\nReady. `flowlightd query \"…\"` asks {} a question.",
                        view.model.as_deref().unwrap_or("it")
                    )?,
                }
                if view.needs_key && !view.key_on_file {
                    writeln!(
                        out,
                        "A key goes in a file: `flowlightd model --key-file PATH`. Not on a command line, \
                         where it would be in the shell's history and in every process listing on the \
                         machine."
                    )?;
                }
            }
        }
        Command::Query {
            question,
            show_work,
        } => {
            let asked = question.join(" ");
            if asked.trim().is_empty() {
                bail!("nothing was asked. `flowlightd query \"what did claude reach today?\"`");
            }
            let configuration = store.ask()?;
            let key_on_file = crate::asking::have_key(database);
            if let Some(reason) = configuration.why_not(key_on_file) {
                bail!("{reason}");
            }
            let key = crate::asking::key(database)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64);

            // Printed as it goes, not afterwards, and only when asked for: a body containing a question
            // about somebody's machine is not something to put on a terminal they did not ask to see it on.
            let mut sent = Vec::new();
            let answered = flowlight_ask::provider::ask(
                &configuration,
                &key,
                &flowlight_ask::Question {
                    question: asked.clone(),
                    instructions: flowlight_ask::query::instructions(
                        &flowlight_ask::window::clock(now),
                    ),
                },
                &mut |call| {
                    flowlight_ask::runner::run(call, &mut store, now).map(|produced| produced.json)
                },
                &mut |body| sent.push(body.to_owned()),
            )?;

            if json {
                writeln!(out, "{}", line(&crate::views::answered(&asked, &answered)))?;
            } else {
                if *show_work {
                    for body in &sent {
                        writeln!(out, "--- sent to {}:", configuration.kind.described())?;
                        writeln!(out, "{body}")?;
                    }
                    for ran in &answered.calls {
                        writeln!(
                            out,
                            "--- {} {:?}{}",
                            ran.query,
                            ran.arguments,
                            if ran.failed { " (refused)" } else { "" }
                        )?;
                        if !ran.summary.is_empty() {
                            writeln!(out, "    {}", ran.summary)?;
                        }
                    }
                }
                writeln!(out, "{}", answered.answer)?;
                // Always, and after the answer: which queries produced it is the only way to tell an answer
                // from a plausible sentence.
                if !answered.calls.is_empty() && !*show_work {
                    let names: Vec<&str> = answered
                        .calls
                        .iter()
                        .map(|ran| ran.query.as_str())
                        .collect();
                    writeln!(out, "\n(from {})", names.join(", "))?;
                }
            }
        }
        Command::Simulate {
            action,
            rule,
            since,
        } => {
            let window = parse_window(since)
                .with_context(|| format!("reading `{since}` as a length of time"))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64);
            let changes = crate::views::simulate(
                &mut store,
                action,
                &rule.subject,
                rule.port,
                rule.agent.as_deref(),
                now - window,
            )?;
            if changes.is_empty() {
                // The commonest answer, and the whole value of asking first.
                eprintln!(
                    "Nothing in the last {since} would have been decided differently. That is not \
                     nothing: it means the rule is either already covered by one you have, or about \
                     traffic this machine has not seen."
                );
                return Ok(());
            }
            let total: i64 = changes.iter().map(|change| change.occurrences).sum();
            eprintln!(
                "{total} request(s) or connection(s) in the last {since} would have been decided \
                 differently:\n"
            );
            for change in changes {
                if json {
                    writeln!(out, "{}", line(&change))?;
                } else {
                    let who = change
                        .agent
                        .as_deref()
                        .map_or_else(String::new, |agent| format!("  ({agent})"));
                    let port = change
                        .port
                        .map_or_else(String::new, |port| format!(":{port}"));
                    writeln!(
                        out,
                        "  {:>8} → {:<8} {:<44} {:>7}{who}",
                        change.before,
                        change.after,
                        format!("{}{port}", change.subject),
                        change.occurrences
                    )?;
                }
            }
            eprintln!(
                "\nThis is a claim about the past, not a promise about the future. A host that was not \
                 reached in this window does not appear here."
            );
        }
        Command::Forget { id } => {
            if store.forget_rule(*id)? {
                eprintln!("Rule {id} is gone.");
            } else {
                eprintln!("There is no rule {id}. `flowlightd rules` lists the ones there are.");
            }
        }
        Command::Rules => {
            let rules = store.rules()?;
            if rules.is_empty() {
                eprintln!("No rules. Nothing is being refused.");
                return Ok(());
            }
            for rule in rules {
                if json {
                    writeln!(
                        out,
                        "{}",
                        line(&RuleView {
                            id: rule.id,
                            action: &rule.action,
                            subject: &rule.subject,
                            port: rule.port,
                            scope: &rule.scope,
                            note: rule.note.as_deref(),
                            created: rule.created,
                        })
                    )?;
                } else {
                    let port = if rule.port == 0 {
                        "any".to_owned()
                    } else {
                        rule.port.to_string()
                    };
                    writeln!(
                        out,
                        "{:<4} {:<6} {:<40} port {:<6} {}{}",
                        rule.id,
                        rule.action,
                        rule.subject,
                        port,
                        rule.scope,
                        rule.note
                            .map_or(String::new(), |note| format!("  — {note}"))
                    )?;
                }
            }
        }
        Command::Agents { since } => {
            let window = parse_window(since)
                .with_context(|| format!("reading `{since}` as a length of time"))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64);
            let agents = store.agents(now - window)?;
            if agents.is_empty() {
                eprintln!(
                    "No agent has been seen in the last {since}. Flowlight recognises an agent by the name \
                     of its executable and attributes anything it starts to it; a tool it does not \
                     recognise appears under its own name instead."
                );
                return Ok(());
            }
            let configured = configured_servers();
            for agent in agents {
                let contacted: Vec<(String, i64)> = store
                    .hosts_for_agent(&agent.agent, now - window, 200)?
                    .into_iter()
                    .map(|host| (host.host, host.requests))
                    .collect();
                let mine: Vec<mcp::Server> = configured
                    .iter()
                    .filter(|server| server.agent == agent.agent)
                    .cloned()
                    .collect();
                let domains = mcp::merge(&mine, &contacted, mcp::endpoints_for(&agent.agent));
                if json {
                    writeln!(out, "{}", line(&agent_view(&agent, &mine, &domains)))?;
                } else {
                    write!(out, "{}", agent_report(&agent, &mine, &domains))?;
                }
            }
        }
        Command::Coverage { since } => {
            let window = parse_window(since)
                .with_context(|| format!("reading `{since}` as a length of time"))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64);
            let coverage = store.coverage(now - window)?;
            if json {
                writeln!(out, "{}", line(&coverage_view(&coverage)))?;
            } else {
                write!(out, "{}", coverage_report(&coverage, since))?;
            }
        }
        Command::Summary { limit } => {
            let rows = store.summary(*limit)?;
            if rows.is_empty() {
                eprintln!(
                    "The summary is empty. It is what expired detail is folded into, so it stays empty \
                     until some detail has expired."
                );
                return Ok(());
            }
            for row in rows {
                if json {
                    writeln!(
                        out,
                        "{}",
                        line(&DailyView {
                            day: &row.day,
                            process: &row.process,
                            host: &row.host,
                            requests: row.requests,
                            bytes: row.bytes,
                        })
                    )?;
                } else {
                    writeln!(
                        out,
                        "{}  {:<24} {:<40} {:>6} requests  {:>10} bytes",
                        row.day, row.process, row.host, row.requests, row.bytes
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Writes one rule and says what it did.
///
/// The scope is stated plainly, because `block example.com` and `block example.com --agent claude` are
/// different enough that somebody who meant the second and typed the first should notice immediately.
fn write_rule(store: &mut Store, action: &str, rule: &crate::RuleArgs) -> anyhow::Result<()> {
    let scope = rule
        .agent
        .as_ref()
        .map_or_else(|| "everyone".to_owned(), |agent| format!("agent:{agent}"));
    let wrote = store.put_rule(
        action,
        &rule.subject,
        rule.port,
        &scope,
        rule.note.as_deref(),
    )?;

    let ports = if rule.port == 0 {
        "any port".to_owned()
    } else {
        format!("port {}", rule.port)
    };
    let who = rule
        .agent
        .as_ref()
        .map_or_else(|| "everyone".to_owned(), |agent| format!("{agent} only"));
    match wrote {
        flowlight_store::Wrote::Unchanged => {
            eprintln!(
                "{} was already {action}ed for {who}. Nothing changed.",
                rule.subject
            );
        }
        flowlight_store::Wrote::Changed | flowlight_store::Wrote::Added => {
            eprintln!("{}: {action}, {ports}, {who}.", rule.subject);
            if rule.subject.starts_with("*.") {
                // Said now rather than discovered later. The rule is real and is reported when it is
                // reached; what it cannot do is refuse the connection before it happens.
                eprintln!(
                    "  A pattern cannot be refused before the handshake — the name is resolved and thrown \
                     away before connect() is called. It is still matched and reported when it is reached."
                );
            }
            // Said plainly, because the command returns before the rule is in force and somebody testing
            // it a second later deserves to know why it has not taken effect yet.
            eprintln!(
                "  A running flowlightd picks this up within a couple of seconds; if none is running, \
                 nothing is enforcing anything."
            );
        }
    }
    Ok(())
}

/// Every MCP server configured anywhere on the machine.
///
/// Home directories rather than one: this daemon runs as root and watches the whole machine, and the agents
/// on it belong to users. Reading only root's configuration would find nothing on every machine anyone
/// actually uses.
pub fn configured_servers() -> Vec<mcp::Server> {
    let mut homes = vec![PathBuf::from("/root")];
    if let Ok(entries) = std::fs::read_dir("/home") {
        homes.extend(entries.flatten().map(|entry| entry.path()));
    }
    mcp::configuration_files(&homes)
        .iter()
        .flat_map(|(agent, path)| mcp::read(agent, path))
        .collect()
}

/// One agent, as prose.
fn agent_report(
    agent: &flowlight_store::AgentRow,
    configured: &[mcp::Server],
    domains: &[mcp::Domain],
) -> String {
    let mut out = format!(
        "\n{}\n  {} request(s) from {} process(es), {} host(s), last {} seconds ago\n",
        agent.agent,
        agent.requests,
        agent.processes,
        agent.hosts,
        seconds_ago(agent.last_seen)
    );

    let local: Vec<&mcp::Server> = configured
        .iter()
        .filter(|server| !server.transport.crosses_the_network())
        .collect();
    if !local.is_empty() {
        // Said rather than omitted. A server that talks over a pipe is a server nothing here can ever see,
        // and leaving it off the screen invites the conclusion that Flowlight looked and found nothing.
        out.push_str(&format!(
            "\n  {} MCP server(s) run locally and never touch the network, so nothing here can see them: {}\n",
            local.len(),
            local
                .iter()
                .map(|server| server.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    if domains.is_empty() {
        out.push_str("\n  No hosts reached, and none configured.\n");
        return out;
    }

    out.push_str("\n  Hosts, against what this agent was configured to reach:\n\n");
    for domain in domains {
        let servers = if domain.servers.is_empty() {
            String::new()
        } else {
            format!("  ({})", domain.servers.join(", "))
        };
        out.push_str(&format!(
            "    {:<11} {:<44} {:>6} request(s){servers}\n",
            domain.standing.as_str(),
            domain.host,
            domain.requests
        ));
    }
    out.push_str(
        "\n    unexpected  reached, and in no configuration — the one worth a second look\n\
         \x20   unused      configured, and not reached\n\
         \x20   used        configured, and reached\n\
         \x20   endpoint    the agent's own service, which is neither MCP nor a surprise\n",
    );
    out
}

/// How long ago, in seconds, without pulling in a date library for one number.
fn seconds_ago(at: i64) -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() as i64);
    (now - at).max(0)
}

/// Coverage, as prose.
///
/// Zeroes are printed rather than omitted. The whole point of this screen is that it accounts for the gap
/// between what happened and what was recorded, and a line that disappears when it reads zero turns "nothing
/// was dropped" into "nobody checked".
fn coverage_report(coverage: &flowlight_store::Coverage, window: &str) -> String {
    let mut out = format!("Coverage for the last {window}\n\n");
    out.push_str(&format!(
        "  Read          {} request(s) from {} process(es), over {} connection(s)\n",
        coverage.requests, coverage.processes_read, coverage.connections
    ));

    if coverage.unread.is_empty() {
        out.push_str(
            "  Not read      nothing: every process that opened an HTTPS connection was read\n",
        );
    } else {
        out.push_str("  Not read\n");
        for unread in &coverage.unread {
            out.push_str(&format!(
                "                {:<24} {} connection(s), nothing read\n",
                unread.process, unread.connections
            ));
        }
        out.push_str(
            "\n                A process that opened HTTPS connections and had nothing read from them is\n\
             \x20               using a TLS implementation there is no probe for. Go links its own into the\n\
             \x20               binary, and so does Chrome. Both need symbols resolved per binary rather\n\
             \x20               than per library, which Flowlight does not do yet.\n\n",
        );
    }

    out.push_str(&format!(
        "  Truncated     {} call(s) carried more than four kilobytes; the rest was not captured\n",
        coverage.truncated
    ));
    out.push_str(&format!(
        "  Undecodable   {} HTTP/2 connection(s) could not be followed\n",
        coverage.undecodable
    ));
    out.push_str(&format!(
        "  Named weakly  {} record(s) name a process by its comm, which the kernel cuts at fifteen\n\
         \x20               characters; {} have no name at all\n",
        coverage.named_by_comm, coverage.named_by_pid
    ));
    out.push_str(&format!(
        "  Refused       {} connection(s) were refused before the handshake, because a rule said so\n",
        coverage.refused
    ));
    out.push_str(&format!(
        "  Dropped       {} record(s) were lost by the kernel before Flowlight read them\n",
        coverage.dropped
    ));

    if !coverage.unprobed.is_empty() {
        out.push_str("\n  Unprobed\n");
        for note in &coverage.unprobed {
            out.push_str(&format!("                {}\n", note.subject));
            out.push_str(&format!("                  {}\n", note.detail));
        }
    }

    out.push_str(
        "\n  Inbound connections are never attributed, and UDP and QUIC are not watched at all. Those are\n\
         \x20 design decisions rather than gaps, and they are in the README.\n",
    );
    out
}

/// One stored request, as a line.
fn request_line(row: &RequestRow) -> String {
    let arrow = if row.direction == "out" { "→" } else { "←" };
    let what = if let Some(method) = &row.method {
        format!(
            "{method} {}{}",
            row.host.as_deref().unwrap_or(""),
            row.target.as_deref().unwrap_or("")
        )
    } else if let Some(status) = row.status {
        format!("{status}  {} bytes", row.bytes)
    } else if let Some(reason) = &row.unreadable {
        format!("HTTP/2 — {reason}")
    } else {
        format!("{} bytes", row.bytes)
    };
    // The agent and the process, when they are not the same thing: `node` is true and answers nobody's
    // question.
    let who = match &row.agent {
        Some(agent) if *agent != row.process => format!("{agent}/{}", row.process),
        _ => row.process.clone(),
    };
    format!("{}  {:<28} pid {:<8} {arrow} {what}", row.at, who, row.pid)
}

/// Everything the JSON forms share: a field added to a row is a field that appears, rather than one
/// somebody has to remember to add in a second place.
///
/// This was hand-built once, and the `agent` column shipped without reaching it — the live stream had it
/// and `history --json` did not, because the two were written months apart and only one of them derived
/// anything. Deriving removes the class of mistake rather than the instance.
#[derive(Serialize)]
struct RequestView<'a> {
    at: i64,
    process: &'a str,
    confidence: &'a str,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<&'a str>,
    direction: &'a str,
    bytes: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unreadable: Option<&'a str>,
}

impl<'a> From<&'a RequestRow> for RequestView<'a> {
    fn from(row: &'a RequestRow) -> Self {
        Self {
            at: row.at,
            process: &row.process,
            confidence: &row.confidence,
            pid: row.pid,
            agent: row.agent.as_deref(),
            direction: &row.direction,
            bytes: row.bytes,
            protocol: row.protocol.as_deref(),
            method: row.method.as_deref(),
            target: row.target.as_deref(),
            host: row.host.as_deref(),
            status: row.status,
            truncated: row.truncated,
            unreadable: row.unreadable.as_deref(),
        }
    }
}

#[derive(Serialize)]
struct RuleView<'a> {
    id: i64,
    action: &'a str,
    subject: &'a str,
    port: u16,
    scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<&'a str>,
    created: i64,
}

#[derive(Serialize)]
struct DailyView<'a> {
    day: &'a str,
    process: &'a str,
    host: &'a str,
    requests: i64,
    bytes: i64,
}

#[derive(Serialize)]
struct CoverageView<'a> {
    requests: i64,
    processes_read: i64,
    connections: i64,
    truncated: i64,
    undecodable: i64,
    named_by_comm: i64,
    named_by_pid: i64,
    refused: i64,
    dropped: i64,
    unread: Vec<UnreadView<'a>>,
    unprobed: Vec<UnprobedView<'a>>,
}

#[derive(Serialize)]
struct UnreadView<'a> {
    process: &'a str,
    connections: i64,
}

#[derive(Serialize)]
struct UnprobedView<'a> {
    path: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
struct AgentView<'a> {
    agent: &'a str,
    requests: i64,
    processes: i64,
    hosts: i64,
    bytes: i64,
    last_seen: i64,
    configured: Vec<ServerView<'a>>,
    domains: Vec<DomainView<'a>>,
}

#[derive(Serialize)]
struct ServerView<'a> {
    name: &'a str,
    transport: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    source: &'a str,
}

#[derive(Serialize)]
struct DomainView<'a> {
    host: &'a str,
    standing: &'a str,
    requests: i64,
    servers: &'a [String],
}

/// One line of JSON, or a message if it somehow will not serialise.
fn line<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"))
}

fn coverage_view(coverage: &flowlight_store::Coverage) -> CoverageView<'_> {
    CoverageView {
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
            .iter()
            .map(|unread| UnreadView {
                process: &unread.process,
                connections: unread.connections,
            })
            .collect(),
        unprobed: coverage
            .unprobed
            .iter()
            .map(|note| UnprobedView {
                path: &note.subject,
                reason: &note.detail,
            })
            .collect(),
    }
}

fn agent_view<'a>(
    agent: &'a flowlight_store::AgentRow,
    configured: &'a [mcp::Server],
    domains: &'a [mcp::Domain],
) -> AgentView<'a> {
    AgentView {
        agent: &agent.agent,
        requests: agent.requests,
        processes: agent.processes,
        hosts: agent.hosts,
        bytes: agent.bytes,
        last_seen: agent.last_seen,
        configured: configured
            .iter()
            .map(|server| ServerView {
                name: &server.name,
                transport: server.transport.as_str(),
                host: server.host.as_deref(),
                source: &server.source,
            })
            .collect(),
        domains: domains
            .iter()
            .map(|domain| DomainView {
                host: &domain.host,
                standing: domain.standing.as_str(),
                requests: domain.requests,
                servers: &domain.servers,
            })
            .collect(),
    }
}

/// Reads `30m`, `6h`, `2d`, or a bare number of seconds.
///
/// Deliberately small. `humantime` would parse more forms than anyone types, and this is four lines whose
/// failure mode is a message naming what was not understood.
pub fn parse_window(text: &str) -> anyhow::Result<i64> {
    let text = text.trim();
    let (number, multiplier) = match text.chars().last() {
        Some('s') => (text.get(..text.len() - 1), 1),
        Some('m') => (text.get(..text.len() - 1), 60),
        Some('h') => (text.get(..text.len() - 1), 3_600),
        Some('d') => (text.get(..text.len() - 1), 86_400),
        Some(c) if c.is_ascii_digit() => (Some(text), 1),
        _ => bail!("expected something like `30m`, `6h`, `2d`, or a number of seconds"),
    };
    let number: i64 = number
        .unwrap_or("")
        .parse()
        .map_err(|_| anyhow::anyhow!("expected a number before the unit"))?;
    if number < 0 {
        bail!("a window into the future is not a window");
    }
    Ok(number * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_are_read_in_every_form_anyone_types() {
        assert_eq!(parse_window("90").unwrap(), 90);
        assert_eq!(parse_window("90s").unwrap(), 90);
        assert_eq!(parse_window("30m").unwrap(), 1_800);
        assert_eq!(parse_window("6h").unwrap(), 21_600);
        assert_eq!(parse_window("2d").unwrap(), 172_800);
        assert_eq!(parse_window("  1h  ").unwrap(), 3_600);
    }

    /// The message has to name the forms that work, because the one thing a person knows at that moment is
    /// that what they typed did not.
    #[test]
    fn something_that_is_not_a_window_says_what_one_looks_like() {
        let err = parse_window("yesterday").unwrap_err().to_string();
        assert!(err.contains("30m"), "{err}");
        assert!(parse_window("").is_err());
        assert!(parse_window("h").is_err());
        assert!(parse_window("-1h").is_err());
        assert!(parse_window("1 h").is_err());
    }

    /// The line that matters most on this screen is the one naming a process nothing was read from, and it
    /// has to name it rather than summarise it away.
    #[test]
    fn an_unread_process_is_named_in_the_report() {
        let coverage = flowlight_store::Coverage {
            requests: 12,
            processes_read: 2,
            connections: 30,
            unread: vec![flowlight_store::Unread {
                process: "gh".to_owned(),
                connections: 18,
            }],
            ..flowlight_store::Coverage::default()
        };
        let report = coverage_report(&coverage, "24h");
        assert!(report.contains("gh"), "{report}");
        assert!(
            report.contains("18 connection(s), nothing read"),
            "{report}"
        );
        assert!(report.contains("Go links its own"), "{report}");
    }

    /// A line that disappears when it reads zero turns "nothing was dropped" into "nobody checked".
    #[test]
    fn a_clean_window_still_says_so_rather_than_saying_nothing() {
        let report = coverage_report(&flowlight_store::Coverage::default(), "24h");
        assert!(
            report.contains("every process that opened an HTTPS connection was read"),
            "{report}"
        );
        assert!(report.contains("0 record(s) were lost"), "{report}");
        assert!(report.contains("0 call(s) carried more than"), "{report}");
    }

    /// `node` is true and answers nobody's question. The report leads with the agent.
    #[test]
    fn an_agents_report_names_what_it_reached_and_what_it_did_not() {
        let agent = flowlight_store::AgentRow {
            agent: "claude".to_owned(),
            requests: 42,
            hosts: 3,
            processes: 4,
            bytes: 1_000,
            last_seen: 0,
        };
        let configured = [mcp::Server {
            name: "sentry".to_owned(),
            agent: "claude".to_owned(),
            source: "~/.claude.json".to_owned(),
            transport: mcp::Transport::Http,
            host: Some("mcp.sentry.dev".to_owned()),
            command: None,
        }];
        let contacted = [
            ("mcp.sentry.dev".to_owned(), 12),
            ("telemetry.example".to_owned(), 3),
            ("api.anthropic.com".to_owned(), 27),
        ];
        let domains = mcp::merge(&configured, &contacted, mcp::endpoints_for("claude"));
        let report = agent_report(&agent, &configured, &domains);

        assert!(report.contains("claude"), "{report}");
        assert!(report.contains("unexpected  telemetry.example"), "{report}");
        assert!(report.contains("used        mcp.sentry.dev"), "{report}");
        assert!(report.contains("endpoint    api.anthropic.com"), "{report}");
    }

    /// A server that talks over a pipe is a server nothing here can ever see. Leaving it off the screen
    /// invites the conclusion that Flowlight looked and found nothing.
    #[test]
    fn a_local_mcp_server_is_said_to_be_invisible_rather_than_omitted() {
        let agent = flowlight_store::AgentRow {
            agent: "claude".to_owned(),
            requests: 0,
            hosts: 0,
            processes: 0,
            bytes: 0,
            last_seen: 0,
        };
        let configured = [mcp::Server {
            name: "filesystem".to_owned(),
            agent: "claude".to_owned(),
            source: "~/.claude.json".to_owned(),
            transport: mcp::Transport::Stdio,
            host: None,
            command: Some("npx".to_owned()),
        }];
        let report = agent_report(&agent, &configured, &[]);
        assert!(report.contains("never touch the network"), "{report}");
        assert!(report.contains("filesystem"), "{report}");
    }

    /// The bug that caused this to be derived rather than hand-written: the `agent` column reached the
    /// live stream and not this, because the two were written months apart and only one derived anything.
    #[test]
    fn every_column_of_a_stored_request_reaches_the_json() {
        let row = RequestRow {
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
            rpc_method: None,
            rpc_tool: None,
        };
        let json = line(&RequestView::from(&row));
        for expected in [
            r#""agent":"claude""#,
            r#""process":"node""#,
            r#""method":"POST""#,
            r#""host":"api.anthropic.com""#,
            r#""truncated":true"#,
        ] {
            assert!(json.contains(expected), "{expected} missing from {json}");
        }
        // And nothing that is not true.
        assert!(!json.contains("status"), "{json}");
        assert!(!json.contains("unreadable"), "{json}");
    }

    /// `node` is true and answers nobody's question.
    #[test]
    fn a_line_names_the_agent_and_the_process() {
        let row = RequestRow {
            at: 1_000,
            process: "node".to_owned(),
            confidence: "path".to_owned(),
            pid: 4711,
            agent: Some("claude".to_owned()),
            direction: "out".to_owned(),
            protocol: None,
            method: Some("GET".to_owned()),
            target: Some("/".to_owned()),
            host: Some("example.com".to_owned()),
            status: None,
            bytes: 10,
            truncated: false,
            unreadable: None,
            rpc_method: None,
            rpc_tool: None,
        };
        assert!(request_line(&row).contains("claude/node"));
    }
}
