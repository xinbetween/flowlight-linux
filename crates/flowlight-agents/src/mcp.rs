//! What an agent was told it could talk to, read out of its own configuration.
//!
//! Flowlight already knows what an agent *reached*. This is the other half: what it was *given*. Neither is
//! interesting alone and the comparison is the whole point — a server configured and never used is clutter,
//! and a host reached that appears in no configuration is the thing worth a second look.
//!
//! # The shapes, which nobody agreed on
//!
//! Every agent stores this differently, and all of them store the same two kinds of thing: a command to run
//! locally, or a URL to call. So the parsing here is deliberately loose — it looks for `mcpServers` or
//! `servers` or `mcp_servers`, takes whatever it finds, and ignores fields it does not understand. A
//! configuration file gaining a key must not cost anyone their MCP list.
//!
//! | Agent | File | Key |
//! | --- | --- | --- |
//! | Claude Code | `~/.claude.json`, `.mcp.json` | `mcpServers`, and per-project under `projects` |
//! | Codex | `~/.codex/config.toml` | `mcp_servers` |
//! | Cursor | `~/.cursor/mcp.json` | `mcpServers` |
//! | Gemini | `~/.gemini/settings.json` | `mcpServers` |
//! | VS Code | `.vscode/mcp.json` | `servers` |
//!
//! # What is not attempted
//!
//! Deciding whether a *reached* host is an MCP server. It cannot be told from the outside: an MCP server
//! over HTTP is an HTTP server. So a host is only ever called an MCP server because a configuration file
//! said so, and everything else is reported as what it is — a host an agent reached.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// How an agent reaches a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transport {
    /// A command run locally, talking over its standard input and output. Nothing crosses the network, so
    /// nothing here will ever see it — which is worth saying on the screen rather than leaving as a gap.
    Stdio,
    /// An HTTP endpoint.
    Http,
    /// Server-sent events, which is an HTTP endpoint held open.
    Sse,
}

impl Transport {
    /// A word for the interface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::Http => "http",
            Self::Sse => "sse",
        }
    }

    /// Whether traffic to this server is something Flowlight could ever see.
    pub fn crosses_the_network(self) -> bool {
        self != Self::Stdio
    }
}

/// One MCP server, as a configuration file describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// What the configuration calls it.
    pub name: String,
    /// Which agent's configuration it came from.
    pub agent: String,
    /// The file it was read from.
    pub source: String,
    /// How it is reached.
    pub transport: Transport,
    /// The host, for a server that is reached over the network.
    pub host: Option<String>,
    /// The command, for one that is not.
    pub command: Option<String>,
}

/// How a configuration file describes one server. Every field optional, because every agent leaves out a
/// different one and a missing field is not a broken file.
#[derive(Debug, Deserialize)]
struct RawServer {
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    command: Option<String>,
}

impl RawServer {
    /// Turns what was written into what it means.
    fn resolve(self, name: &str, agent: &str, source: &str) -> Option<Server> {
        let declared = self
            .r#type
            .or(self.transport)
            .map(|kind| kind.to_ascii_lowercase());
        let host = self.url.as_deref().and_then(host_of);
        // The declared type when there is one, and otherwise what the entry actually contains: a URL is a
        // network server whatever it calls itself, and something with only a command is not.
        let transport = match declared.as_deref() {
            Some("sse") => Transport::Sse,
            Some("http" | "streamable-http" | "streamable_http") => Transport::Http,
            Some("stdio") => Transport::Stdio,
            _ if self.url.is_some() => Transport::Http,
            _ => Transport::Stdio,
        };
        // An entry with neither a URL nor a command describes nothing, and inventing a server from it would
        // put a name on the screen that corresponds to nothing on the machine.
        if self.url.is_none() && self.command.is_none() {
            return None;
        }
        Some(Server {
            name: name.to_owned(),
            agent: agent.to_owned(),
            source: source.to_owned(),
            transport,
            host,
            command: self.command,
        })
    }
}

/// The host out of a URL, without a URL parser.
///
/// Deliberately small: what is wanted is the thing that would appear as a `Host` header, and everything
/// else in the URL is somebody else's problem. Returns `None` for anything that does not look like one,
/// rather than returning a fragment of it.
pub fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest)?;
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .filter(|authority| !authority.is_empty())?;
    // `user:password@host` — the credentials are not the host, and they are not something to print either.
    let host = authority.rsplit('@').next()?;
    // A bracketed IPv6 literal keeps its colons; everything else loses its port.
    let host = if host.starts_with('[') {
        host.split_once(']').map(|(head, _)| format!("{head}]"))?
    } else {
        host.split(':').next()?.to_owned()
    };
    (!host.is_empty()).then_some(host)
}

/// Every server a JSON configuration describes.
///
/// Tolerant by design. Unknown keys are ignored, an entry that describes nothing is skipped, and a file
/// that is not JSON at all yields nothing rather than an error — because the alternative is one malformed
/// file on a machine costing the whole MCP list.
pub fn from_json(text: &str, agent: &str, source: &str) -> Vec<Server> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut servers = Vec::new();
    collect_json(&value, agent, source, &mut servers, 0);
    servers.sort_by(|a, b| (&a.name, &a.source).cmp(&(&b.name, &b.source)));
    servers.dedup_by(|a, b| a.name == b.name && a.source == b.source);
    servers
}

/// Walks a JSON document looking for server maps.
///
/// Recursive because Claude Code keeps a copy per project under `projects`, keyed by directory, and the
/// same file holds the global set at the top level. Depth-capped so that a configuration file cannot be
/// made to exhaust the stack.
fn collect_json(
    value: &serde_json::Value,
    agent: &str,
    source: &str,
    out: &mut Vec<Server>,
    depth: usize,
) {
    if depth > 8 {
        return;
    }
    let Some(object) = value.as_object() else {
        return;
    };
    for key in ["mcpServers", "mcp_servers", "servers"] {
        if let Some(map) = object.get(key).and_then(serde_json::Value::as_object) {
            for (name, entry) in map {
                if let Ok(raw) = serde_json::from_value::<RawServer>(entry.clone())
                    && let Some(server) = raw.resolve(name, agent, source)
                {
                    out.push(server);
                }
            }
        }
    }
    // Only into containers, and only the ones that could hold a per-project copy. Descending into every
    // value would find the word `command` in somebody's prompt history.
    for key in ["projects", "mcp", "context_servers"] {
        if let Some(nested) = object.get(key) {
            if let Some(children) = nested.as_object() {
                for child in children.values() {
                    collect_json(child, agent, source, out, depth + 1);
                }
            }
            collect_json(nested, agent, source, out, depth + 1);
        }
    }
}

/// Every server a TOML configuration describes. Codex, mostly.
pub fn from_toml(text: &str, agent: &str, source: &str) -> Vec<Server> {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let Some(table) = value.as_table() else {
        return Vec::new();
    };
    let mut servers = Vec::new();
    for key in ["mcp_servers", "mcpServers", "servers"] {
        if let Some(map) = table.get(key).and_then(toml::Value::as_table) {
            for (name, entry) in map {
                if let Ok(raw) = entry.clone().try_into::<RawServer>()
                    && let Some(server) = raw.resolve(name, agent, source)
                {
                    servers.push(server);
                }
            }
        }
    }
    servers.sort_by(|a, b| a.name.cmp(&b.name));
    servers
}

/// Where each agent keeps its configuration, relative to a home directory.
const CONFIGURATIONS: &[(&str, &str)] = &[
    ("claude", ".claude.json"),
    ("claude", ".claude/settings.json"),
    ("claude", ".config/claude/mcp.json"),
    ("codex", ".codex/config.toml"),
    ("cursor", ".cursor/mcp.json"),
    ("gemini", ".gemini/settings.json"),
    ("goose", ".config/goose/config.yaml"),
    ("opencode", ".config/opencode/opencode.json"),
];

/// Every agent configuration file that exists under these home directories.
///
/// Home directories rather than one, because this daemon runs as root and watches the whole machine: the
/// agents on it belong to users, and reading only root's configuration would find nothing on every machine
/// anyone actually uses.
pub fn configuration_files(homes: &[PathBuf]) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    for home in homes {
        for (agent, relative) in CONFIGURATIONS {
            let path = home.join(relative);
            if path.is_file() {
                found.push(((*agent).to_owned(), path));
            }
        }
    }
    found
}

/// Reads one configuration file, choosing the parser by its extension.
pub fn read(agent: &str, path: &Path) -> Vec<Server> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let source = path.display().to_string();
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("toml") => from_toml(&text, agent, &source),
        // JSON for everything else, including the YAML files, which are not JSON and will simply yield
        // nothing until somebody needs them enough to add a parser.
        _ => from_json(&text, agent, &source),
    }
}

/// The hosts an agent talks to as a matter of course: its own model API, its telemetry, its updater.
///
/// Without this every agent's own service reads as an unexpected host, which is both wrong and the fastest
/// possible way to teach somebody to ignore this screen. The list is short, per agent, and errs towards
/// leaving things out: a host that is not on it is reported as unexpected, which is the safe direction.
pub const ENDPOINTS: &[(&str, &[&str])] = &[
    (
        "claude",
        &[
            "api.anthropic.com",
            "statsig.anthropic.com",
            "claude.ai",
            "console.anthropic.com",
        ],
    ),
    (
        "codex",
        &["api.openai.com", "chatgpt.com", "auth.openai.com"],
    ),
    (
        "gemini",
        &[
            "generativelanguage.googleapis.com",
            "cloudcode-pa.googleapis.com",
            "oauth2.googleapis.com",
        ],
    ),
    (
        "cursor",
        &["api2.cursor.sh", "api3.cursor.sh", "cursor.com"],
    ),
    ("aider", &["api.anthropic.com", "api.openai.com"]),
    ("opencode", &["api.opencode.ai"]),
];

/// The hosts this agent is expected to talk to on its own account.
pub fn endpoints_for(agent: &str) -> &'static [&'static str] {
    ENDPOINTS
        .iter()
        .find(|(name, _)| *name == agent)
        .map_or(&[], |(_, hosts)| *hosts)
}

/// How a host stands, once what was configured is compared with what was reached.
///
/// Ordered worst-first deliberately: this is what the interface sorts on, and the thing worth looking at
/// must not sit below forty rows of the thing that is fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Standing {
    /// The agent's own service — its model API, its telemetry. Expected, and not an MCP server.
    Endpoint,
    /// Configured, and reached in the window.
    Used,
    /// Configured, and not reached in the window. Clutter, or something that stopped working.
    Unused,
    /// Reached, and in no configuration. The one worth a second look.
    Unexpected,
}

impl Standing {
    /// A word for the interface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Used => "used",
            Self::Unused => "unused",
            Self::Unexpected => "unexpected",
        }
    }
}

/// One host, with everything known about it from both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain {
    /// The host.
    pub host: String,
    /// How it stands.
    pub standing: Standing,
    /// The configured servers that name it, if any.
    pub servers: Vec<String>,
    /// Requests to it in the window.
    pub requests: i64,
}

/// Compares what an agent was configured to reach with what it reached.
///
/// `contacted` is `(host, requests)` from the database, and `endpoints` the agent's own services, which are
/// neither MCP nor a surprise. Servers that never cross the network are left out entirely: a stdio server is
/// a program on this machine talking over a pipe, and listing it among hosts that were or were not reached
/// would invite the conclusion that Flowlight looked and found nothing.
pub fn merge(
    configured: &[Server],
    contacted: &[(String, i64)],
    endpoints: &[&str],
) -> Vec<Domain> {
    let counts: BTreeMap<&str, i64> = contacted
        .iter()
        .map(|(host, count)| (host.as_str(), *count))
        .collect();
    let mut domains: BTreeMap<String, Domain> = BTreeMap::new();

    for server in configured {
        if !server.transport.crosses_the_network() {
            continue;
        }
        let Some(host) = &server.host else {
            continue;
        };
        let requests = counts.get(host.as_str()).copied().unwrap_or(0);
        let domain = domains.entry(host.clone()).or_insert_with(|| Domain {
            host: host.clone(),
            standing: if requests > 0 {
                Standing::Used
            } else {
                Standing::Unused
            },
            servers: Vec::new(),
            requests,
        });
        if !domain.servers.contains(&server.name) {
            domain.servers.push(server.name.clone());
        }
    }

    for (host, requests) in contacted {
        domains.entry(host.clone()).or_insert_with(|| Domain {
            host: host.clone(),
            standing: if endpoints.contains(&host.as_str()) {
                Standing::Endpoint
            } else {
                Standing::Unexpected
            },
            servers: Vec::new(),
            requests: *requests,
        });
    }

    let mut domains: Vec<Domain> = domains.into_values().collect();
    // Unexpected first, then unused, then used; and within each, busiest first. The order is the point:
    // the thing worth looking at should not be below forty rows of the thing that is fine.
    domains.sort_by(|a, b| {
        b.standing
            .cmp(&a.standing)
            .then(b.requests.cmp(&a.requests))
            .then(a.host.cmp(&b.host))
    });
    domains
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_claude_configuration_is_read() {
        let text = r#"{
            "mcpServers": {
                "filesystem": { "command": "npx", "args": ["-y", "@mcp/server-filesystem"] },
                "sentry": { "type": "http", "url": "https://mcp.sentry.dev/mcp" }
            }
        }"#;
        let servers = from_json(text, "claude", "~/.claude.json");
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "filesystem");
        assert_eq!(servers[0].transport, Transport::Stdio);
        assert_eq!(servers[0].command.as_deref(), Some("npx"));
        assert_eq!(servers[1].name, "sentry");
        assert_eq!(servers[1].transport, Transport::Http);
        assert_eq!(servers[1].host.as_deref(), Some("mcp.sentry.dev"));
    }

    /// Claude Code keeps a copy per project, keyed by directory, in the same file as the global set.
    #[test]
    fn servers_configured_for_one_project_are_found_too() {
        let text = r#"{
            "mcpServers": { "global": { "url": "https://global.example" } },
            "projects": {
                "/home/x/work": { "mcpServers": { "local": { "url": "https://local.example" } } }
            }
        }"#;
        let servers = from_json(text, "claude", "f");
        let names: Vec<_> = servers.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["global", "local"]);
    }

    /// VS Code calls the key `servers`; Codex calls it `mcp_servers`. Nobody agreed on anything.
    #[test]
    fn the_other_spellings_of_the_same_key_are_read() {
        assert_eq!(
            from_json(
                r#"{"servers":{"a":{"url":"https://a.example"}}}"#,
                "vscode",
                "f"
            )
            .len(),
            1
        );
        assert_eq!(
            from_json(r#"{"mcp_servers":{"a":{"command":"x"}}}"#, "other", "f").len(),
            1
        );
    }

    #[test]
    fn a_codex_configuration_is_read() {
        let text = r#"
            [mcp_servers.everything]
            command = "npx"
            args = ["-y", "@modelcontextprotocol/server-everything"]

            [mcp_servers.remote]
            url = "https://mcp.example.com/sse"
            type = "sse"
        "#;
        let servers = from_toml(text, "codex", "~/.codex/config.toml");
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].name, "everything");
        assert_eq!(servers[0].transport, Transport::Stdio);
        assert_eq!(servers[1].transport, Transport::Sse);
        assert_eq!(servers[1].host.as_deref(), Some("mcp.example.com"));
    }

    /// A configuration that says nothing about its transport still says which kind it is, by what it
    /// contains: a URL is a network server whatever it calls itself.
    #[test]
    fn a_transport_is_inferred_when_it_is_not_declared() {
        let servers = from_json(
            r#"{"mcpServers":{"a":{"url":"https://a.example"}}}"#,
            "x",
            "f",
        );
        assert_eq!(servers[0].transport, Transport::Http);
        let servers = from_json(r#"{"mcpServers":{"a":{"command":"node"}}}"#, "x", "f");
        assert_eq!(servers[0].transport, Transport::Stdio);
    }

    /// An entry with neither a URL nor a command describes nothing, and inventing a server from it would
    /// put a name on the screen that corresponds to nothing on the machine.
    #[test]
    fn an_entry_that_describes_nothing_is_not_a_server() {
        assert!(from_json(r#"{"mcpServers":{"a":{"note":"todo"}}}"#, "x", "f").is_empty());
    }

    /// One malformed file on a machine must not cost the whole MCP list.
    #[test]
    fn a_file_that_is_not_a_configuration_yields_nothing_rather_than_failing() {
        assert!(from_json("", "x", "f").is_empty());
        assert!(from_json("not json", "x", "f").is_empty());
        assert!(from_json("[1,2,3]", "x", "f").is_empty());
        assert!(from_json(r#"{"mcpServers": "a string"}"#, "x", "f").is_empty());
        assert!(from_toml("not toml {{{", "x", "f").is_empty());
    }

    /// Nothing here may panic on a file chosen by whoever wrote it, including a deliberately deep one.
    #[test]
    fn a_deeply_nested_file_does_not_exhaust_the_stack() {
        let mut text = String::new();
        for _ in 0..2_000 {
            text.push_str(r#"{"projects":{"a":"#);
        }
        text.push_str("{}");
        for _ in 0..2_000 {
            text.push_str("}}");
        }
        let _ = from_json(&text, "x", "f");
    }

    // Hosts

    #[test]
    fn a_host_is_taken_out_of_a_url() {
        assert_eq!(
            host_of("https://mcp.example.com/sse").as_deref(),
            Some("mcp.example.com")
        );
        assert_eq!(
            host_of("http://localhost:3000/").as_deref(),
            Some("localhost")
        );
        assert_eq!(host_of("https://a.example").as_deref(), Some("a.example"));
        assert_eq!(
            host_of("https://a.example?x=1").as_deref(),
            Some("a.example")
        );
    }

    /// Credentials in a URL are not the host, and they are not something to print either.
    #[test]
    fn credentials_in_a_url_are_not_part_of_the_host() {
        assert_eq!(
            host_of("https://user:secret@mcp.example.com/sse").as_deref(),
            Some("mcp.example.com")
        );
    }

    #[test]
    fn an_ipv6_literal_keeps_its_colons_and_loses_its_port() {
        assert_eq!(host_of("http://[::1]:3000/x").as_deref(), Some("[::1]"));
    }

    #[test]
    fn something_that_is_not_a_url_has_no_host() {
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("npx -y server"), None);
        assert_eq!(host_of("https://"), None);
        assert_eq!(host_of("https:///path"), None);
    }

    // The comparison

    fn server(name: &str, url: &str) -> Server {
        Server {
            name: name.to_owned(),
            agent: "claude".to_owned(),
            source: "f".to_owned(),
            transport: Transport::Http,
            host: host_of(url),
            command: None,
        }
    }

    /// The whole point of reading configurations at all: the gap in either direction.
    #[test]
    fn configured_and_reached_are_compared_in_both_directions() {
        let configured = [
            server("sentry", "https://mcp.sentry.dev/mcp"),
            server("linear", "https://mcp.linear.app/sse"),
        ];
        let contacted = [
            ("mcp.sentry.dev".to_owned(), 12),
            ("api.anthropic.com".to_owned(), 340),
        ];
        let domains = merge(&configured, &contacted, &[]);

        let by_host: BTreeMap<_, _> = domains.iter().map(|d| (d.host.as_str(), d)).collect();
        assert_eq!(by_host["mcp.sentry.dev"].standing, Standing::Used);
        assert_eq!(by_host["mcp.sentry.dev"].servers, ["sentry"]);
        assert_eq!(by_host["mcp.linear.app"].standing, Standing::Unused);
        assert_eq!(by_host["api.anthropic.com"].standing, Standing::Unexpected);
    }

    /// Without this, every agent's own model API reads as an unexpected host — which is both wrong and the
    /// fastest possible way to teach somebody to ignore this screen.
    #[test]
    fn an_agents_own_service_is_not_a_surprise() {
        let contacted = [
            ("api.anthropic.com".to_owned(), 340),
            ("telemetry.example".to_owned(), 4),
        ];
        let domains = merge(&[], &contacted, endpoints_for("claude"));
        let by_host: BTreeMap<_, _> = domains.iter().map(|d| (d.host.as_str(), d)).collect();
        assert_eq!(by_host["api.anthropic.com"].standing, Standing::Endpoint);
        assert_eq!(by_host["telemetry.example"].standing, Standing::Unexpected);
    }

    /// An agent nobody listed endpoints for gets none, and everything it reaches is reported as reached.
    /// That is the safe direction: a host left off the list is shown, not hidden.
    #[test]
    fn an_unknown_agent_has_no_endpoints_rather_than_a_guess() {
        assert!(endpoints_for("something-new").is_empty());
        assert!(!endpoints_for("claude").is_empty());
    }

    /// The thing worth looking at must not be below forty rows of the thing that is fine.
    #[test]
    fn the_unexpected_is_listed_first() {
        let configured = [server("a", "https://a.example")];
        let contacted = [("a.example".to_owned(), 100), ("b.example".to_owned(), 1)];
        let domains = merge(&configured, &contacted, &[]);
        assert_eq!(domains[0].host, "b.example");
        assert_eq!(domains[0].standing, Standing::Unexpected);
    }

    /// A stdio server is a program on this machine talking over a pipe. Listing it among hosts that were or
    /// were not reached would invite the conclusion that Flowlight looked and found nothing.
    #[test]
    fn a_server_that_never_touches_the_network_is_not_listed_as_a_host() {
        let configured = [Server {
            name: "filesystem".to_owned(),
            agent: "claude".to_owned(),
            source: "f".to_owned(),
            transport: Transport::Stdio,
            host: None,
            command: Some("npx".to_owned()),
        }];
        assert!(merge(&configured, &[], &[]).is_empty());
    }

    #[test]
    fn two_servers_on_one_host_are_one_row_naming_both() {
        let configured = [
            server("one", "https://mcp.example.com/a"),
            server("two", "https://mcp.example.com/b"),
        ];
        let domains = merge(&configured, &[], &[]);
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].servers, ["one", "two"]);
    }

    #[test]
    fn configuration_files_are_found_where_agents_keep_them() {
        let home = std::env::temp_dir().join("flowlight-mcp-home");
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".codex")).unwrap();
        std::fs::write(home.join(".claude.json"), "{}").unwrap();
        std::fs::write(home.join(".codex/config.toml"), "").unwrap();

        let found = configuration_files(&[home.clone(), PathBuf::from("/nonexistent")]);
        let agents: Vec<_> = found.iter().map(|(agent, _)| agent.as_str()).collect();
        assert_eq!(agents, ["claude", "codex"]);
    }
}
