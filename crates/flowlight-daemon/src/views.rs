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
use flowlight_store::{Mock, Store};
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
    /// The JSON-RPC method, for something said to an MCP server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_method: Option<String>,
    /// The tool, for an MCP `tools/call`. Never its arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_tool: Option<String>,
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
    /// What it actually said to them.
    pub tools: Vec<ToolView>,
    /// What it is set up to do, read out of its own configuration.
    ///
    /// Beside what it did, on purpose: a hook that runs a command and a request that command made are the
    /// same event seen from two ends, and only one of them is visible on the network.
    pub declares: Vec<CapabilityView>,
}

/// One thing an agent is set up to do.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CapabilityView {
    /// `skill`, `subagent`, `command`, `hook`, `permission`, `plugin` or `instructions`.
    pub kind: String,
    /// What it is called.
    pub name: String,
    /// One line about it: a hook's command, a permission's decision, a skill's description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Where it was found, without whose home it is in.
    pub source: String,
    /// Whether it can run a command or reach the network without being asked.
    pub sensitive: bool,
}

/// One thing an agent said to an MCP server.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ToolView {
    /// The JSON-RPC method.
    pub method: String,
    /// The tool, for a `tools/call`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// The host it was said to.
    pub host: String,
    /// How many times.
    pub calls: i64,
    /// The most recent one.
    pub last_seen: i64,
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

/// Where what was seen is sent, and what somebody agreed to.
///
/// Carries the disclosure as well as the settings, because an interface that showed the settings and not the
/// disclosure would be offering a yes to a question it had not asked.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExportView {
    /// Whether export is wanted.
    pub enabled: bool,
    /// Whether anything may actually be sent, which is the only one of these that decides anything.
    pub sending: bool,
    /// Where to, if anywhere.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// `file` or `otlp`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    /// What travels.
    pub fields: Vec<String>,
    /// Every field that could be chosen, so an interface can offer them without knowing the list.
    pub every_field: Vec<String>,
    /// The names of the headers sent. Never the values.
    pub headers: Vec<String>,
    /// Whether the configuration in force is the one somebody agreed to.
    pub consented: bool,
    /// Why nothing is being sent, when nothing is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why_not: Option<String>,
    /// The identifier of the last record sent.
    pub sent_through: i64,
    /// What somebody is being asked to agree to, in sentences.
    pub disclosure: Vec<String>,
    /// Whether this change took an existing agreement away.
    pub revoked: bool,
}

/// What one request may change about export.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ExportChange {
    /// A path or a URL.
    pub destination: Option<String>,
    /// The whole list, not an addition: a caller that meant to add one field and sent one field should get
    /// one field, and a disclosure somebody re-reads either way.
    pub fields: Option<Vec<String>>,
    /// Headers to set. An empty value removes one.
    pub headers: Option<std::collections::BTreeMap<String, String>>,
    /// Agree to the configuration as it stands.
    #[serde(default)]
    pub consent: bool,
    /// Stop sending, without forgetting where to or what was agreed.
    #[serde(default)]
    pub off: bool,
}

/// Where what was seen is sent, described.
pub fn export(store: &mut Store) -> Result<ExportView> {
    Ok(describe_export(&store.export()?, false))
}

/// Turns an export configuration into what an interface shows.
fn describe_export(export: &flowlight_store::Export, revoked: bool) -> ExportView {
    ExportView {
        enabled: export.enabled,
        sending: export.may_send(),
        destination: export.destination.clone(),
        transport: export
            .transport()
            .map(|transport| transport.as_str().to_owned()),
        fields: export
            .fields
            .iter()
            .map(|field| field.as_str().to_owned())
            .collect(),
        every_field: flowlight_store::export::EVERY_FIELD
            .iter()
            .map(|field| field.as_str().to_owned())
            .collect(),
        // Names only, here as everywhere. A view is the thing that ends up in a screenshot.
        headers: export.headers.keys().cloned().collect(),
        consented: export.consented.as_ref() == Some(&export.fingerprint()),
        why_not: export.why_not(),
        sent_through: export.sent_through,
        disclosure: export.disclose(),
        revoked,
    }
}

/// Changes the export configuration, and says what it now is.
///
/// Consent cannot be given in the same call that changes what consent would be to. That is the whole
/// mechanism: a yes belongs to a sentence somebody read, and a call that rewrote the sentence and said yes to
/// it in one breath would be a yes to nothing.
pub fn set_export(store: &mut Store, change: &ExportChange) -> Result<ExportView> {
    use anyhow::{Context as _, bail};
    let mut export = store.export()?;
    let reconfigured =
        change.destination.is_some() || change.fields.is_some() || change.headers.is_some();
    if change.consent && reconfigured {
        bail!(
            "consent is agreement to a particular disclosure, so it cannot be given in the same breath as              changing what the disclosure says. Make the change, read what it prints, then agree to it."
        );
    }

    if let Some(destination) = &change.destination {
        flowlight_store::export::Transport::of(destination).with_context(|| {
            format!(
                "`{destination}` is neither an absolute path nor an http(s) URL. A path means a file on                  this machine and nothing crosses the network; a URL means an OTLP collector and something                  does. Anything else is refused rather than guessed at."
            )
        })?;
        export.destination = Some(destination.clone());
        // Naming a destination is asking for export. It still sends nothing until somebody agrees.
        export.enabled = true;
    }
    if let Some(names) = &change.fields {
        let mut fields = std::collections::BTreeSet::new();
        for name in names {
            let field = flowlight_store::export::Field::parse(name)
                .with_context(|| format!("`{name}` is not a field this exports"))?;
            fields.insert(field);
        }
        if fields.is_empty() {
            bail!("a field list with nothing in it would send empty records");
        }
        export.fields = fields;
    }
    if let Some(headers) = &change.headers {
        for (name, value) in headers {
            if value.is_empty() {
                export.headers.remove(&name.to_lowercase());
            } else {
                export.headers.insert(name.to_lowercase(), value.clone());
            }
        }
    }
    if change.off {
        // The destination and the agreement are kept. Turning it off is not a change to what was agreed, so
        // turning it back on should not need agreeing again.
        export.enabled = false;
    }

    // Any change that moved the fingerprint takes the agreement with it. Not a warning: the agreement was to
    // something that is no longer what would happen.
    let revoked =
        export.consented.is_some() && export.consented.as_ref() != Some(&export.fingerprint());
    if revoked {
        export.consented = None;
    }
    if change.consent {
        export.consented = Some(export.fingerprint());
        export.enabled = true;
    }
    store.set_export(&export)?;
    Ok(describe_export(&export, revoked))
}

/// Which model answers questions, and what asking one would mean.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AskView {
    /// Whether the feature is on.
    pub enabled: bool,
    /// Whether a question could be asked right now, which is the only one of these that decides anything.
    pub ready: bool,
    /// `local`, `compatible`, `anthropic` or `gemini`.
    pub kind: String,
    /// Every kind there is, so an interface can offer them without carrying its own copy of the list.
    pub every_kind: Vec<String>,
    /// Where the model is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Which model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Whether this kind needs a key at all.
    pub needs_key: bool,
    /// Whether there is one on file. Never the key.
    pub key_on_file: bool,
    /// Whether asking sends anything off this machine.
    pub sends_off_the_machine: bool,
    /// Why a question cannot be asked, when it cannot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why_not: Option<String>,
    /// What asking would mean, in sentences.
    pub disclosure: Vec<String>,
}

/// What one request may change about which model answers.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct AskChange {
    /// `local`, `compatible`, `anthropic` or `gemini`.
    pub kind: Option<String>,
    /// Where the model is.
    pub endpoint: Option<String>,
    /// Which model to name in the request.
    pub model: Option<String>,
    /// Turn it off, keeping what is configured.
    #[serde(default)]
    pub off: bool,
}

/// Which model answers, described.
pub fn ask(store: &mut Store, key_on_file: bool) -> Result<AskView> {
    Ok(describe_ask(&store.ask()?, key_on_file))
}

/// Turns an Ask configuration into what an interface shows.
fn describe_ask(configuration: &flowlight_store::Ask, key_on_file: bool) -> AskView {
    AskView {
        enabled: configuration.enabled,
        ready: configuration.ready(key_on_file),
        kind: configuration.kind.as_str().to_owned(),
        every_kind: flowlight_store::ask::EVERY_KIND
            .iter()
            .map(|kind| kind.as_str().to_owned())
            .collect(),
        endpoint: configuration.endpoint.clone(),
        model: configuration.model.clone(),
        needs_key: configuration.kind.needs_key(),
        key_on_file,
        sends_off_the_machine: configuration.kind.sends_off_the_machine(),
        why_not: configuration.why_not(key_on_file),
        disclosure: configuration.disclose(),
    }
}

/// Changes which model answers, and says what is now configured.
///
/// The key is not here. It is a file, written by whoever called this, because a secret and a setting have
/// different lifetimes and different permissions and putting them in one struct loses that.
pub fn set_ask(store: &mut Store, change: &AskChange, key_on_file: bool) -> Result<AskView> {
    use anyhow::{Context as _, bail};
    let mut configuration = store.ask()?;
    if let Some(named) = &change.kind {
        let kind = flowlight_store::ask::Kind::parse(named).with_context(|| {
            format!(
                "`{named}` is not one of: {}",
                flowlight_store::ask::EVERY_KIND
                    .iter()
                    .map(|kind| kind.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        // A kind's suggested endpoint, when changing kind has left the old one pointing at the wrong
        // provider. Only when there is an obvious one, and never for a kind that means "somebody's own
        // server": guessing at its address would be guessing at whose.
        if kind != configuration.kind {
            configuration.endpoint = kind.suggested_endpoint().map(str::to_owned);
        }
        configuration.kind = kind;
    }
    if let Some(endpoint) = &change.endpoint {
        match flowlight_store::ask::Safety::of(endpoint, configuration.kind) {
            flowlight_store::ask::Safety::Fine => {}
            refused => bail!("{}", refused.describe(endpoint)),
        }
        configuration.endpoint = Some(endpoint.clone());
    }
    if let Some(model) = &change.model {
        configuration.model = Some(model.trim().to_owned()).filter(|model| !model.is_empty());
    }
    // Configuring a model is asking for the feature. Turning it off is a separate thing somebody says.
    configuration.enabled = !change.off;
    store.set_ask(&configuration)?;
    Ok(describe_ask(&configuration, key_on_file))
}

/// A question, its answer, and the work behind it.
///
/// The queries are part of the answer rather than a debugging aid. An answer with no queries under it is a
/// sentence a model made up, and the only way to tell the two apart is to show what ran.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AnsweredView {
    /// What was asked.
    pub question: String,
    /// What the model said.
    pub answer: String,
    /// Which queries ran.
    pub calls: Vec<RanView>,
    /// The exact bodies that left this machine, if any did. Empty for a model on this machine.
    pub sent: Vec<String>,
}

/// One query a model asked for.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RanView {
    /// Which query, as the model named it.
    pub query: String,
    /// What it filled in.
    pub arguments: std::collections::BTreeMap<String, String>,
    /// The sentence describing what came back, when there is one.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// Whether the call was refused, and the model told so.
    pub failed: bool,
}

/// Turns what a model said into what an interface shows.
pub fn answered(question: &str, answered: &flowlight_ask::Answered) -> AnsweredView {
    AnsweredView {
        question: question.to_owned(),
        answer: answered.answer.clone(),
        calls: answered
            .calls
            .iter()
            .map(|ran| RanView {
                query: ran.query.clone(),
                arguments: ran.arguments.clone(),
                summary: ran.summary.clone(),
                failed: ran.failed,
            })
            .collect(),
        sent: answered.sent.clone(),
    }
}

/// Whether connections are terminated, and whose.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InterceptView {
    /// Whether the feature is on.
    pub enabled: bool,
    /// Whether anything is actually being terminated.
    pub running: bool,
    /// Where the proxy listens.
    pub port: u16,
    /// The agents in scope. Empty means nobody.
    pub agents: Vec<String>,
    /// Hosts never terminated, whatever else says so.
    pub never: Vec<String>,
    /// Why nothing is being terminated, when nothing is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub why_not: Option<String>,
    /// What turning it on would mean, in sentences.
    pub disclosure: Vec<String>,
    /// Where the certificate anything must trust is, when there is one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    /// Where the bundle is, for anything that reads one rather than the machine's store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<String>,
}

/// What one request may change about interception.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct InterceptChange {
    /// Turn it on.
    #[serde(default)]
    pub on: bool,
    /// Turn it off, keeping the scope.
    #[serde(default)]
    pub off: bool,
    /// The whole scope, not an addition.
    pub agents: Option<Vec<String>>,
    /// The whole list of hosts never terminated.
    pub never: Option<Vec<String>>,
}

/// One canned answer.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MockView {
    /// Its identifier, which `forget-mock` takes.
    pub id: i64,
    /// Whether it answers.
    pub enabled: bool,
    /// The host or pattern.
    pub subject: String,
    /// The path glob.
    pub path: String,
    /// The method, or empty for any.
    pub method: String,
    /// The status it answers with.
    pub status: u16,
    /// How long it waits first.
    pub delay: u32,
    /// Whether it calls itself a refusal.
    pub refusal: bool,
    /// The header names it sends. Never their values, for the same reason export never shows one.
    pub headers: Vec<String>,
    /// How many bytes of body it answers with.
    pub body_bytes: usize,
    /// Why, if whoever wrote it said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Whether connections are terminated, described.
pub fn intercept(store: &mut Store, paths: Option<(String, String)>) -> Result<InterceptView> {
    Ok(describe_intercept(&store.intercept()?, paths))
}

/// Turns an interception configuration into what an interface shows.
fn describe_intercept(
    intercept: &flowlight_store::Intercept,
    paths: Option<(String, String)>,
) -> InterceptView {
    InterceptView {
        enabled: intercept.enabled,
        running: intercept.running(),
        port: intercept.port,
        agents: intercept.agents.clone(),
        never: intercept.never.clone(),
        why_not: intercept.why_not(),
        disclosure: intercept.disclose(),
        certificate: paths.as_ref().map(|(certificate, _)| certificate.clone()),
        bundle: paths.map(|(_, bundle)| bundle),
    }
}

/// Changes what is intercepted, and says what it now is.
pub fn set_intercept(
    store: &mut Store,
    change: &InterceptChange,
    paths: Option<(String, String)>,
) -> Result<InterceptView> {
    let mut intercept = store.intercept()?;
    if let Some(agents) = &change.agents {
        intercept.agents = agents
            .iter()
            .map(|agent| agent.trim().to_owned())
            .filter(|agent| !agent.is_empty())
            .collect();
    }
    if let Some(never) = &change.never {
        intercept.never = never
            .iter()
            .map(|host| host.trim().to_lowercase())
            .filter(|host| !host.is_empty())
            .collect();
    }
    // Both given, off wins. The one that changes what an application sees is the one to be careful with.
    if change.on {
        intercept.enabled = true;
    }
    if change.off {
        intercept.enabled = false;
    }
    store.set_intercept(&intercept)?;
    Ok(describe_intercept(&intercept, paths))
}

/// Every canned answer, in the order they are tried.
pub fn mocks(store: &mut Store) -> Result<Vec<MockView>> {
    Ok(store
        .mocks()?
        .into_iter()
        .map(|mock| MockView {
            id: mock.id,
            enabled: mock.enabled,
            subject: mock.subject.as_text(),
            path: mock.path,
            method: mock.method,
            status: mock.status,
            delay: mock.delay,
            refusal: mock.refusal,
            headers: mock.headers.into_iter().map(|(name, _)| name).collect(),
            body_bytes: mock.body.len(),
            note: mock.note,
        })
        .collect())
}

/// What one request may write as a canned answer.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct MockWrite {
    /// The host or pattern.
    pub subject: String,
    /// The path glob. `*` when left out.
    pub path: Option<String>,
    /// The method, or empty for any.
    pub method: Option<String>,
    /// The status. 503 when left out, because "the API is failing" is what anybody tries first.
    pub status: Option<u16>,
    /// Headers, as `Name: value` per line.
    pub headers: Option<String>,
    /// The body.
    pub body: Option<String>,
    /// Seconds to wait before answering.
    pub delay: Option<u32>,
    /// Whether this is a refusal rather than a stand-in.
    #[serde(default)]
    pub refusal: bool,
    /// Whether it answers at all.
    pub enabled: Option<bool>,
    /// Why.
    pub note: Option<String>,
}

/// Writes a canned answer.
pub fn write_mock(store: &mut Store, wanted: &MockWrite, now: i64) -> Result<&'static str> {
    use anyhow::bail;
    let subject = flowlight_rules::Subject::parse(&wanted.subject);
    if matches!(subject, flowlight_rules::Subject::Anything) {
        // Deliberately refused. A mock for `*` answers every request an agent makes with a canned reply,
        // which is not a test of anything and is very hard to notice.
        bail!(
            "a canned answer has to name a host. `*` would answer every request from every agent in scope,              which is not something anybody means to leave switched on."
        );
    }
    let status = wanted.status.unwrap_or(503);
    if !(100..600).contains(&status) {
        bail!("{status} is not an HTTP status");
    }
    let mock = Mock {
        id: 0,
        enabled: wanted.enabled.unwrap_or(true),
        subject,
        path: wanted
            .path
            .clone()
            .map(|path| path.trim().to_owned())
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| "*".to_owned()),
        method: wanted
            .method
            .clone()
            .unwrap_or_default()
            .trim()
            .to_uppercase(),
        status,
        headers: wanted
            .headers
            .as_deref()
            .map(parse_headers)
            .unwrap_or_default(),
        body: wanted.body.clone().unwrap_or_default(),
        delay: wanted.delay.unwrap_or(0).min(600),
        refusal: wanted.refusal,
        note: wanted.note.clone(),
    };
    Ok(match store.put_mock(&mock, now)? {
        flowlight_store::Wrote::Added => "added",
        flowlight_store::Wrote::Changed => "changed",
        flowlight_store::Wrote::Unchanged => "unchanged",
    })
}

/// Headers as they are typed: one `Name: value` per line.
fn parse_headers(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| {
            (
                flowlight_proxy::http::header_safe(name),
                flowlight_proxy::http::header_safe(value),
            )
        })
        .filter(|(name, _)| !name.is_empty())
        .collect()
}

/// One guardrail, and how often it has refused something.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct GuardrailView {
    /// Its identifier, which `forget-guardrail` takes.
    pub id: i64,
    /// Whether it refuses anything.
    pub enabled: bool,
    /// The agent, or empty for every agent.
    pub agent: String,
    /// The host the MCP server is at, or empty for every server.
    pub server: String,
    /// The tool or glob.
    pub tool: String,
    /// The resource URI or glob.
    pub resource: String,
    /// How it reads in a list.
    pub title: String,
    /// How many calls it has refused.
    pub hits: i64,
    /// When it last refused one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_hit: Option<i64>,
    /// Why, if whoever wrote it said.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// What one request may write as a guardrail.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct GuardrailWrite {
    /// The agent, or empty for every agent.
    #[serde(default)]
    pub agent: String,
    /// The host the MCP server is at, or empty for every server.
    #[serde(default)]
    pub server: String,
    /// The tool or glob.
    #[serde(default)]
    pub tool: String,
    /// The resource URI or glob.
    #[serde(default)]
    pub resource: String,
    /// Whether it refuses anything.
    pub enabled: Option<bool>,
    /// Why.
    pub note: Option<String>,
}

/// Every guardrail, in the order they are tried.
pub fn guardrails(store: &mut Store) -> Result<Vec<GuardrailView>> {
    let hits: std::collections::HashMap<i64, (i64, Option<i64>)> = store
        .guardrail_hits()?
        .into_iter()
        .map(|(id, hits, last)| (id, (hits, last)))
        .collect();
    Ok(store
        .guardrails()?
        .into_iter()
        .map(|guardrail| {
            let (hits, last_hit) = hits.get(&guardrail.id).copied().unwrap_or((0, None));
            GuardrailView {
                id: guardrail.id,
                enabled: guardrail.enabled,
                title: guardrail.title(),
                agent: guardrail.agent,
                server: guardrail.server,
                tool: guardrail.tool,
                resource: guardrail.resource,
                hits,
                last_hit,
                note: guardrail.note,
            }
        })
        .collect())
}

/// Writes a guardrail.
pub fn write_guardrail(
    store: &mut Store,
    wanted: &GuardrailWrite,
    now: i64,
) -> Result<&'static str> {
    use anyhow::bail;
    let guardrail = flowlight_store::Guardrail {
        id: 0,
        enabled: wanted.enabled.unwrap_or(true),
        agent: wanted.agent.trim().to_owned(),
        server: wanted.server.trim().to_owned(),
        tool: wanted.tool.trim().to_owned(),
        resource: wanted.resource.trim().to_owned(),
        note: wanted.note.clone(),
    };
    if !guardrail.is_complete() {
        // One that names nothing would refuse every tool of every agent, which is never one keystroke away
        // by accident.
        bail!(
            "a guardrail has to name a tool, a server or a resource. One that named none of them would \
             refuse every tool of every agent, which is not something anybody means to type."
        );
    }
    Ok(match store.put_guardrail(&guardrail, now)? {
        flowlight_store::Wrote::Added => "added",
        flowlight_store::Wrote::Changed => "changed",
        flowlight_store::Wrote::Unchanged => "unchanged",
    })
}

/// Who operates the addresses this machine has reached.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OwnersView {
    /// Whether Flowlight is asking.
    pub asking: bool,
    /// Where it would ask.
    pub resolver: String,
    /// What asking means, in sentences.
    pub disclosure: Vec<String>,
    /// Who was found, busiest first.
    pub owners: Vec<OwnerView>,
    /// How many addresses nobody has looked up yet.
    pub unknown: usize,
}

/// One operator.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct OwnerView {
    /// The autonomous system number.
    pub asn: u32,
    /// Who it belongs to.
    pub name: String,
    /// How many of their addresses were reached.
    pub addresses: i64,
    /// How many connections went to them.
    pub connections: i64,
}

/// Who operates what, described.
pub fn owners(store: &mut Store, since: i64) -> Result<OwnersView> {
    let resolver = flowlight_owners::lookup::resolver().map_or_else(
        || "a public resolver".to_owned(),
        |address| address.to_string(),
    );
    Ok(OwnersView {
        asking: store.owner_lookup()?,
        disclosure: crate::owning::disclose(&resolver),
        resolver,
        owners: store
            .owners(since)?
            .into_iter()
            .map(|row| OwnerView {
                asn: row.asn,
                name: row.name,
                addresses: row.addresses,
                connections: row.connections,
            })
            .collect(),
        unknown: store.addresses_without_owners(since, 1_000)?.len(),
    })
}

/// One thing that was noticed.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AlertView {
    /// Its identifier.
    pub id: i64,
    /// When, in seconds since the epoch.
    pub at: i64,
    /// What sort of thing.
    pub kind: String,
    /// What it was about.
    pub subject: String,
    /// The sentence, with the arithmetic in it.
    pub detail: String,
    /// One to three.
    pub severity: u8,
    /// Whether this is about an agent rather than about any process.
    pub about_an_agent: bool,
}

/// What was noticed recently, most recent first.
pub fn alerts(store: &mut Store, since: i64, limit: usize) -> Result<Vec<AlertView>> {
    Ok(store
        .alerts_since(since, rows(limit))?
        .into_iter()
        .map(|row| AlertView {
            about_an_agent: crate::alerting::about_an_agent(&row.kind),
            id: row.id,
            at: row.at,
            kind: row.kind,
            subject: row.subject,
            detail: row.detail,
            severity: row.severity,
        })
        .collect())
}

/// Traffic sliced one way, and the processes that do not look like the rest.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ReportView {
    /// What it is sliced by.
    pub by: String,
    /// Whether the bytes column means anything for this slice.
    pub counts_bytes: bool,
    /// The rows, busiest first.
    pub rows: Vec<ShareView>,
    /// Everything in the window, so a share can be a share of something.
    pub total_events: i64,
    /// Bytes in the window.
    pub total_bytes: i64,
    /// The processes worth a second look, and why.
    pub standing: Vec<StandingView>,
}

/// One row of a breakdown.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ShareView {
    /// What it is.
    pub name: String,
    /// How many requests or connections.
    pub events: i64,
    /// How many bytes.
    pub bytes: i64,
    /// What share of the window this is, as a percentage of events.
    pub share: f64,
}

/// One process that does not look like the rest, and why.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StandingView {
    /// What it is called.
    pub process: String,
    /// The reasons, strongest first, each with its arithmetic.
    pub reasons: Vec<String>,
    /// The sum of their weights — an ordering, and not a score of anything.
    pub weight: u32,
}

/// Traffic sliced one way, with the outliers named.
pub fn report(store: &mut Store, by: &str, since: i64, limit: usize) -> Result<ReportView> {
    use anyhow::Context as _;
    let slice = flowlight_store::Slice::parse(by)
        .with_context(|| format!("`{by}` is not one of: process, host, address, protocol"))?;
    let rows = store.breakdown(slice, since, rows(limit))?;
    let total_events: i64 = rows.iter().map(|row| row.events).sum();
    let total_bytes: i64 = rows.iter().map(|row| row.bytes).sum();

    // The outliers are always judged by process, whatever the slice: "this host is not like the others" is a
    // statement about a host's operator, which Flowlight has no business making.
    let mut counts: Vec<i64> = Vec::new();
    let processes = store.processes(since)?;
    for row in &processes {
        counts.push(row.hosts);
    }
    let usual = flowlight_alerts::profile::median(&mut counts);

    // Every process that made a request, and every process that opened connections nothing was read from.
    // The second list is the point: a process with no requests is invisible to `processes`, which is built
    // from requests — and "nothing could be read from this one" is precisely the thing worth saying about it.
    let mut candidates: Vec<String> = processes
        .iter()
        .take(20)
        .map(|row| row.process.clone())
        .collect();
    for unread in store.coverage(since)?.unread {
        if !candidates.contains(&unread.process) {
            candidates.push(unread.process);
        }
    }

    let mut standing = Vec::new();
    for process in &candidates {
        let traffic = store.traffic_of(process, since)?;
        let names = store.names_reached(process, since, 40)?;
        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
        let judged = flowlight_alerts::profile::standing(process, traffic, usual, &borrowed);
        if judged.reasons.is_empty() {
            continue;
        }
        standing.push(StandingView {
            process: judged.process,
            reasons: judged
                .reasons
                .into_iter()
                .map(|reason| reason.said)
                .collect(),
            weight: judged.weight,
        });
    }
    // Heaviest first, and stable, so two processes with the same reasons keep the order the store gave them
    // rather than swapping between two runs of the same question.
    standing.sort_by_key(|judged| std::cmp::Reverse(judged.weight));

    Ok(ReportView {
        by: slice.as_str().to_owned(),
        counts_bytes: slice.counts_bytes(),
        rows: rows
            .into_iter()
            .map(|row| ShareView {
                share: if total_events > 0 {
                    row.events as f64 * 100.0 / total_events as f64
                } else {
                    0.0
                },
                name: row.name,
                events: row.events,
                bytes: row.bytes,
            })
            .collect(),
        total_events,
        total_bytes,
        standing,
    })
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
            rpc_method: row.rpc_method,
            rpc_tool: row.rpc_tool,
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
    // Read once for every agent rather than once per agent: it is a walk of the same directories either way.
    let declared = flowlight_agents::workspace::scan(homes);
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
        let tools = store.tools_for_agent(&row.agent, since, 100)?;
        let domains = mcp::merge(&mine, &contacted, mcp::endpoints_for(&row.agent));
        let declares: Vec<CapabilityView> = declared
            .iter()
            // `.agents` holds things any agent can load, so they count for whichever agents are here.
            .filter(|capability| capability.agent == row.agent || capability.agent == "any agent")
            .map(|capability| CapabilityView {
                kind: capability.kind.as_str().to_owned(),
                name: capability.name.clone(),
                detail: capability.detail.clone(),
                source: capability.source.clone(),
                sensitive: capability.sensitive,
            })
            .collect();
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
            tools: tools
                .into_iter()
                .map(|row| ToolView {
                    method: row.method,
                    tool: row.tool,
                    host: row.host,
                    calls: row.calls,
                    last_seen: row.last_seen,
                })
                .collect(),
            declares,
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
                rpc_method: None,
                rpc_tool: None,
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
            rpc_method: None,
            rpc_tool: None,
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

    /// A destination that is neither a path nor a URL is refused rather than guessed at, because guessing
    /// wrong in the direction of the network is the worse mistake.
    #[test]
    fn a_destination_that_says_nothing_about_itself_is_refused() {
        let mut store = Store::in_memory().unwrap();
        assert!(
            set_export(
                &mut store,
                &ExportChange {
                    destination: Some("collector.example".to_owned()),
                    ..ExportChange::default()
                }
            )
            .is_err()
        );
    }

    /// Naming a destination is not agreeing to it.
    #[test]
    fn a_destination_alone_sends_nothing() {
        let mut store = Store::in_memory().unwrap();
        let view = set_export(
            &mut store,
            &ExportChange {
                destination: Some("/tmp/flowlight.jsonl".to_owned()),
                ..ExportChange::default()
            },
        )
        .unwrap();
        assert!(view.enabled);
        assert!(!view.sending);
        assert!(!view.consented);
        assert!(view.why_not.is_some());
        assert!(view.disclosure.len() > 3);
    }

    /// The mechanism, in one test: a yes belongs to a sentence somebody read, so a call that rewrote the
    /// sentence and said yes to it in the same breath is refused outright.
    #[test]
    fn consent_cannot_be_given_in_the_same_call_that_changes_what_it_is_consent_to() {
        let mut store = Store::in_memory().unwrap();
        let refused = set_export(
            &mut store,
            &ExportChange {
                destination: Some("/tmp/flowlight.jsonl".to_owned()),
                consent: true,
                ..ExportChange::default()
            },
        );
        assert!(refused.is_err());
        // And nothing was written on the way to refusing.
        assert!(!export(&mut store).unwrap().enabled);
    }

    #[test]
    fn agreeing_to_what_is_configured_puts_it_in_force() {
        let mut store = Store::in_memory().unwrap();
        set_export(
            &mut store,
            &ExportChange {
                destination: Some("/tmp/flowlight.jsonl".to_owned()),
                ..ExportChange::default()
            },
        )
        .unwrap();
        let view = set_export(
            &mut store,
            &ExportChange {
                consent: true,
                ..ExportChange::default()
            },
        )
        .unwrap();
        assert!(view.sending);
        assert!(view.consented);
        assert_eq!(view.why_not, None);
    }

    /// The failure the whole design exists to prevent, at the layer somebody's window talks to.
    #[test]
    fn changing_where_it_goes_takes_the_agreement_with_it() {
        let mut store = Store::in_memory().unwrap();
        for change in [
            ExportChange {
                destination: Some("/tmp/flowlight.jsonl".to_owned()),
                ..ExportChange::default()
            },
            ExportChange {
                consent: true,
                ..ExportChange::default()
            },
        ] {
            set_export(&mut store, &change).unwrap();
        }
        let view = set_export(
            &mut store,
            &ExportChange {
                destination: Some("https://somebody.else.example/v1/logs".to_owned()),
                ..ExportChange::default()
            },
        )
        .unwrap();
        assert!(view.revoked);
        assert!(!view.sending);
        assert!(!view.consented);
    }

    /// Turning it off is not a change to what was agreed, so turning it back on must not need agreeing
    /// again. The alternative trains people to click through the disclosure.
    #[test]
    fn turning_it_off_keeps_the_agreement() {
        let mut store = Store::in_memory().unwrap();
        for change in [
            ExportChange {
                destination: Some("/tmp/flowlight.jsonl".to_owned()),
                ..ExportChange::default()
            },
            ExportChange {
                consent: true,
                ..ExportChange::default()
            },
            ExportChange {
                off: true,
                ..ExportChange::default()
            },
        ] {
            set_export(&mut store, &change).unwrap();
        }
        let view = export(&mut store).unwrap();
        assert!(!view.enabled);
        assert!(!view.sending);
        // Still agreed to. Nothing about what would be sent has changed.
        assert!(view.consented);
        assert!(!view.revoked);
    }

    /// A field list with nothing in it would send empty records, and an interface that allowed it would be
    /// offering an export that does nothing and says it is working.
    #[test]
    fn an_empty_field_list_is_refused() {
        let mut store = Store::in_memory().unwrap();
        assert!(
            set_export(
                &mut store,
                &ExportChange {
                    fields: Some(Vec::new()),
                    ..ExportChange::default()
                }
            )
            .is_err()
        );
        assert!(
            set_export(
                &mut store,
                &ExportChange {
                    fields: Some(vec!["not-a-field".to_owned()]),
                    ..ExportChange::default()
                }
            )
            .is_err()
        );
    }

    /// Header values are not in a view, because a view is the thing that ends up in a screenshot.
    #[test]
    fn a_view_carries_header_names_and_never_their_values() {
        let mut store = Store::in_memory().unwrap();
        let view = set_export(
            &mut store,
            &ExportChange {
                destination: Some("https://collector.example/v1/logs".to_owned()),
                headers: Some(
                    [("Authorization".to_owned(), "Bearer sekrit".to_owned())]
                        .into_iter()
                        .collect(),
                ),
                ..ExportChange::default()
            },
        )
        .unwrap();
        assert_eq!(view.headers, vec!["authorization".to_owned()]);
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("sekrit"), "{json}");
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
            rpc_method: None,
            rpc_tool: None,
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
