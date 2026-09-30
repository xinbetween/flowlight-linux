//! What an agent is set up to do, read out of its own configuration.
//!
//! [`crate::mcp`] reads one thing out of these files: the servers an agent was told it could talk to. The same
//! files say a great deal more, and two parts of it are worth anybody's attention before a single request has
//! been made.
//!
//! A **hook** is a program the agent runs on its own behalf, at a moment it chooses. A **permission** is a
//! decision somebody made once and has not looked at since. Both are things people set up in a hurry and then
//! forget, and neither is visible from any amount of watching the network — the traffic a hook causes looks
//! exactly like traffic the agent caused, because it is.
//!
//! # What is kept
//!
//! The name of the thing, and one line about it: a hook's command, a permission's rule, a skill's description.
//! Not the contents of a skill, which is somebody's writing, and not the body of an instruction file, which is
//! usually most of what they know about their own work.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The most files read from one directory, so a configuration directory somebody has filled with thousands of
/// things cannot make a scan take a noticeable amount of time.
const MOST_ENTRIES: usize = 200;

/// The most bytes read from one file. A description is a line; anything longer is a document.
const MOST_BYTES: usize = 64 * 1024;

/// What sort of thing an agent declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    /// Something the agent can load and follow.
    Skill,
    /// Another agent it can start.
    Subagent,
    /// A command somebody can type at it.
    Command,
    /// A program it runs on its own behalf.
    Hook,
    /// Something it was told it may or may not do without asking.
    Permission,
    /// An extension.
    Plugin,
    /// Standing instructions.
    Instructions,
}

impl Kind {
    /// The name this is written down and printed under.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skill => "skill",
            Self::Subagent => "subagent",
            Self::Command => "command",
            Self::Hook => "hook",
            Self::Permission => "permission",
            Self::Plugin => "plugin",
            Self::Instructions => "instructions",
        }
    }

    /// Whether this kind can run a command or reach the network without being asked.
    ///
    /// A hook always can: that is what it is. A permission can when it grants something rather than refusing
    /// it, which is decided per rule rather than per kind.
    pub fn is_sensitive(self) -> bool {
        matches!(self, Self::Hook)
    }
}

/// One thing an agent is set up to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Which agent's it is.
    pub agent: String,
    /// What sort of thing.
    pub kind: Kind,
    /// What it is called.
    pub name: String,
    /// One line about it: a hook's command, a permission's rule, a skill's description.
    pub detail: Option<String>,
    /// Where it was found.
    pub source: String,
    /// Whether it can run a command or reach the network without being asked.
    pub sensitive: bool,
}

/// Which directory belongs to which agent.
///
/// The same names [`crate::ancestry`] knows agents by, so that what an agent *declares* and what it *did* can be
/// put beside each other.
pub const DIRECTORIES: &[(&str, &str)] = &[
    (".claude", "claude"),
    (".codex", "codex"),
    (".cursor", "cursor"),
    (".gemini", "gemini"),
    (".windsurf", "windsurf"),
    (".continue", "continue"),
    (".aider", "aider"),
    (".opencode", "opencode"),
    (".goose", "goose"),
    // Not an agent's own directory: skills any agent can load. Counted for whichever agents are present.
    (".agents", ""),
];

/// Everything the agents under these home directories declare.
pub fn scan(homes: &[PathBuf]) -> Vec<Capability> {
    let mut found = Vec::new();
    for home in homes {
        for (directory, agent) in DIRECTORIES {
            let root = home.join(directory);
            if !root.is_dir() {
                continue;
            }
            let named = if agent.is_empty() { "any agent" } else { agent };
            found.extend(read_workspace(named, &root));
        }
    }
    found.sort_by(|left, right| {
        (left.agent.as_str(), left.kind, left.name.as_str()).cmp(&(
            right.agent.as_str(),
            right.kind,
            right.name.as_str(),
        ))
    });
    found.dedup();
    found
}

/// Everything one configuration directory declares.
pub fn read_workspace(agent: &str, root: &Path) -> Vec<Capability> {
    let mut found = Vec::new();
    // One Markdown file each, named after the thing.
    for (directory, kind) in [
        ("skills", Kind::Skill),
        ("agents", Kind::Subagent),
        ("commands", Kind::Command),
        ("rules", Kind::Instructions),
    ] {
        for (name, path) in entries(&root.join(directory)) {
            found.push(Capability {
                agent: agent.to_owned(),
                kind,
                detail: first_line(&path),
                name,
                source: shown(&path),
                sensitive: kind.is_sensitive(),
            });
        }
    }
    for name in ["settings.json", "settings.local.json"] {
        let path = root.join(name);
        let Ok(text) = read_some(&path) else { continue };
        found.extend(from_settings(agent, &text, &shown(&path)));
    }
    found
}

/// The hooks, permissions and plugins in a settings file.
pub fn from_settings(agent: &str, text: &str, source: &str) -> Vec<Capability> {
    let Ok(settings) = serde_json::from_str::<Settings>(text) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for (event, matchers) in settings.hooks {
        for matcher in matchers {
            for hook in matcher.hooks {
                let Some(command) = hook.command else {
                    continue;
                };
                found.push(Capability {
                    agent: agent.to_owned(),
                    kind: Kind::Hook,
                    name: match matcher.matcher.as_deref() {
                        Some(pattern) if !pattern.is_empty() => format!("{event} · {pattern}"),
                        _ => event.clone(),
                    },
                    detail: Some(command),
                    source: source.to_owned(),
                    // A hook runs a command the agent chose the moment for. That is the whole point of it and
                    // the reason it is worth listing.
                    sensitive: true,
                });
            }
        }
    }
    for (decision, rules) in [
        ("allow", settings.permissions.allow),
        ("ask", settings.permissions.ask),
        ("deny", settings.permissions.deny),
    ] {
        for rule in rules {
            found.push(Capability {
                agent: agent.to_owned(),
                kind: Kind::Permission,
                sensitive: decision == "allow" && grants_something(&rule),
                name: rule.clone(),
                detail: Some(decision.to_owned()),
                source: source.to_owned(),
            });
        }
    }
    for plugin in settings.enabled_plugins.into_keys() {
        found.push(Capability {
            agent: agent.to_owned(),
            kind: Kind::Plugin,
            name: plugin,
            detail: None,
            source: source.to_owned(),
            sensitive: false,
        });
    }
    found
}

/// Whether a permission rule lets an agent run a command or reach the network.
///
/// Matched on the tool it names rather than on its shape, because the shape is a moving target and the tools
/// that matter are few: running something, fetching something, and writing to a file.
pub fn grants_something(rule: &str) -> bool {
    let lowered = rule.to_lowercase();
    [
        "bash",
        "shell",
        "execute",
        "run(",
        "webfetch",
        "websearch",
        "write",
        "edit",
    ]
    .iter()
    .any(|tool| lowered.starts_with(tool) || lowered.contains(&format!("({tool}")))
}

/// What a settings file says, of the parts that are read.
///
/// Everything else is ignored by omission rather than read and dropped.
#[derive(Debug, Default, Deserialize)]
struct Settings {
    #[serde(default)]
    hooks: std::collections::BTreeMap<String, Vec<Matcher>>,
    #[serde(default)]
    permissions: Permissions,
    #[serde(default, rename = "enabledPlugins")]
    enabled_plugins: std::collections::BTreeMap<String, serde_json::Value>,
}

/// One matcher's hooks.
#[derive(Debug, Deserialize)]
struct Matcher {
    #[serde(default)]
    matcher: Option<String>,
    #[serde(default)]
    hooks: Vec<Hook>,
}

/// One hook.
#[derive(Debug, Deserialize)]
struct Hook {
    #[serde(default)]
    command: Option<String>,
}

/// What an agent may and may not do without asking.
#[derive(Debug, Default, Deserialize)]
struct Permissions {
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    ask: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

/// The things in a directory, as a name and a path.
///
/// A skill is usually a directory with a `SKILL.md` in it; a command or a subagent is usually one Markdown
/// file. Both shapes are read, and anything else in there is ignored.
fn entries(directory: &Path) -> Vec<(String, PathBuf)> {
    let Ok(listing) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for entry in listing.flatten().take(MOST_ENTRIES) {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if path.is_dir() {
            for inside in ["SKILL.md", "AGENT.md", "README.md"] {
                let described = path.join(inside);
                if described.is_file() {
                    found.push((name.to_owned(), described));
                    break;
                }
            }
            continue;
        }
        if let Some(stem) = name.strip_suffix(".md") {
            found.push((stem.to_owned(), path));
        }
    }
    found
}

/// The first line of a Markdown file that says something, without reading the whole of it.
///
/// A description, when the file has one. Not the body: a skill is somebody's writing and an instruction file is
/// usually most of what they know about their own work.
fn first_line(path: &Path) -> Option<String> {
    let text = read_some(path).ok()?;
    // A front-matter description is the intended answer where there is one.
    for line in text.lines().take(20) {
        if let Some(rest) = line.trim().strip_prefix("description:") {
            let described = rest.trim().trim_matches(['"', '\'']).trim();
            if !described.is_empty() {
                return Some(shortened(described));
            }
        }
    }
    text.lines()
        .map(str::trim)
        .find(|line| {
            !line.is_empty()
                && !line.starts_with("---")
                && !line.starts_with('#')
                && !line.contains(':')
        })
        .map(shortened)
}

/// At most one line's worth.
fn shortened(text: &str) -> String {
    let mut short: String = text.chars().take(200).collect();
    if text.chars().count() > 200 {
        short.push('…');
    }
    short
}

/// The beginning of a file, at most.
fn read_some(path: &Path) -> std::io::Result<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0_u8; MOST_BYTES];
    let read = file.read(&mut buffer)?;
    buffer.truncate(read);
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

/// A path as it is shown, with the home directory taken off.
fn shown(path: &Path) -> String {
    let text = path.display().to_string();
    // `/root/` is the whole of that home; `/home/` is followed by whose it is, and that component goes too.
    if let Some(rest) = text.strip_prefix("/root/") {
        return rest.to_owned();
    }
    if let Some(rest) = text.strip_prefix("/home/") {
        return rest
            .split_once('/')
            .map_or(rest, |(_, inside)| inside)
            .to_owned();
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A hook runs a command the agent chose the moment for, which is invisible to any amount of watching the
    /// network: the traffic it causes looks exactly like traffic the agent caused, because it is.
    #[test]
    fn a_hook_is_read_with_its_command_and_called_sensitive() {
        let text = r#"{
            "hooks": {
                "PreToolUse": [
                    { "matcher": "Bash", "hooks": [{ "type": "command", "command": "/usr/local/bin/audit.sh" }] }
                ]
            }
        }"#;
        let found = from_settings("claude", text, ".claude/settings.json");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, Kind::Hook);
        assert_eq!(found[0].name, "PreToolUse · Bash");
        assert_eq!(found[0].detail.as_deref(), Some("/usr/local/bin/audit.sh"));
        assert!(found[0].sensitive);
    }

    #[test]
    fn a_hook_with_no_matcher_is_named_after_its_event() {
        let text = r#"{"hooks":{"Stop":[{"hooks":[{"command":"say done"}]}]}}"#;
        let found = from_settings("claude", text, "x");
        assert_eq!(found[0].name, "Stop");
    }

    /// A permission is a decision somebody made once and has not looked at since. The ones worth flagging are
    /// the ones that grant rather than refuse.
    #[test]
    fn a_permission_that_grants_something_is_flagged_and_one_that_refuses_is_not() {
        let text = r#"{
            "permissions": {
                "allow": ["Bash(git push:*)", "Read(/etc/hosts)"],
                "deny": ["Bash(rm:*)"],
                "ask": ["WebFetch"]
            }
        }"#;
        let found = from_settings("claude", text, "x");
        let sensitive: Vec<&str> = found
            .iter()
            .filter(|capability| capability.sensitive)
            .map(|capability| capability.name.as_str())
            .collect();
        // Granted and dangerous.
        assert!(sensitive.contains(&"Bash(git push:*)"), "{sensitive:?}");
        // Granted and harmless.
        assert!(!sensitive.contains(&"Read(/etc/hosts)"));
        // Dangerous and refused, which is the opposite of a problem.
        assert!(!sensitive.contains(&"Bash(rm:*)"));
        // Dangerous and asked about, which is also not a problem.
        assert!(!sensitive.contains(&"WebFetch"));
        assert_eq!(
            found.iter().filter(|c| c.kind == Kind::Permission).count(),
            4
        );
    }

    #[test]
    fn what_a_rule_grants_is_judged_on_the_tool_it_names() {
        assert!(grants_something("Bash(anything)"));
        assert!(grants_something("bash"));
        assert!(grants_something("WebFetch(domain:example.com)"));
        assert!(grants_something("Write"));
        assert!(!grants_something("Read(/etc/hosts)"));
        assert!(!grants_something("Glob"));
    }

    #[test]
    fn plugins_are_listed_by_name() {
        let text = r#"{"enabledPlugins":{"some-plugin@1":{},"other":{}}}"#;
        let found = from_settings("claude", text, "x");
        let names: Vec<&str> = found.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"some-plugin@1"));
        assert!(names.contains(&"other"));
    }

    /// A settings file somebody is halfway through editing must not stop everything else being read.
    #[test]
    fn a_settings_file_that_is_not_json_yields_nothing_rather_than_failing() {
        assert!(from_settings("claude", "{not json", "x").is_empty());
        assert!(from_settings("claude", "", "x").is_empty());
        // Valid JSON of the wrong shape is not an error either.
        assert!(from_settings("claude", r#"{"hooks":"a string"}"#, "x").is_empty());
    }

    #[test]
    fn a_workspace_on_disk_is_read() {
        let home = std::env::temp_dir().join(format!("flowlight-workspace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        let root = home.join(".claude");
        std::fs::create_dir_all(root.join("skills/deploy")).unwrap();
        std::fs::create_dir_all(root.join("commands")).unwrap();
        std::fs::create_dir_all(root.join("agents")).unwrap();
        std::fs::write(
            root.join("skills/deploy/SKILL.md"),
            "---\nname: deploy\ndescription: Ships the thing\n---\n\nThe body, which is nobody's business.\n",
        )
        .unwrap();
        std::fs::write(root.join("commands/review.md"), "Reviews a change.\n").unwrap();
        std::fs::write(
            root.join("agents/tester.md"),
            "# Tester\n\nRuns the tests.\n",
        )
        .unwrap();
        std::fs::write(
            root.join("settings.json"),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"command":"audit"}]}]}}"#,
        )
        .unwrap();

        let found = scan(std::slice::from_ref(&home));
        let of =
            |kind: Kind| -> Vec<&Capability> { found.iter().filter(|c| c.kind == kind).collect() };
        assert_eq!(of(Kind::Skill).len(), 1);
        assert_eq!(of(Kind::Skill)[0].name, "deploy");
        // The description, not the body.
        assert_eq!(
            of(Kind::Skill)[0].detail.as_deref(),
            Some("Ships the thing")
        );
        assert!(!found.iter().any(|c| {
            c.detail
                .as_deref()
                .is_some_and(|detail| detail.contains("nobody's business"))
        }));
        assert_eq!(of(Kind::Command)[0].name, "review");
        assert_eq!(
            of(Kind::Command)[0].detail.as_deref(),
            Some("Reviews a change.")
        );
        assert_eq!(of(Kind::Subagent)[0].name, "tester");
        assert_eq!(of(Kind::Hook).len(), 1);
        assert!(found.iter().all(|c| c.agent == "claude"));

        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn a_home_with_no_agent_configuration_yields_nothing() {
        let home = std::env::temp_dir().join(format!("flowlight-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        assert!(scan(std::slice::from_ref(&home)).is_empty());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Paths are shown without whose home they are in, because that is said elsewhere and a path that spells
    /// out somebody's username is a path that ends up in a screenshot.
    #[test]
    fn a_path_is_shown_without_the_home_it_is_in() {
        assert_eq!(
            shown(Path::new("/home/somebody/.claude/settings.json")),
            ".claude/settings.json"
        );
        assert_eq!(
            shown(Path::new("/root/.claude/settings.json")),
            ".claude/settings.json"
        );
        assert_eq!(shown(Path::new("/etc/x")), "/etc/x");
    }
}
