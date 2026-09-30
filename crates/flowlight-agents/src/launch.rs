//! Starting an agent in an environment Flowlight already governs.
//!
//! Two things have to be true before an agent makes its first request, and neither can be arranged afterwards.
//!
//! The first is the mark. Which processes belong to an agent is written into a kernel map, and until now that
//! happened on a timer: a scan every second notices a new agent and marks it, and the kernel carries the mark
//! to everything it forks. That works and it has a gap — an agent that connects in its first second connects
//! unmarked, so a rule scoped to it does not apply to that connection. Starting the agent ourselves closes the
//! gap exactly: the process exists, stopped, before it has run a single instruction of its own program.
//!
//! The second is the environment. A certificate is trusted at launch by whatever started the process, and two
//! of the things that matter most read it from a variable and nowhere else — Node ignores the machine's trust
//! store outright. A variable cannot be put into a process that is already running, which is why `trust` can
//! only tell you about those two and this can do them.
//!
//! # Why this is pure
//!
//! Nothing here starts a process or talks to a kernel. What goes into the environment is a decision about
//! which variables mean what, and that is worth being able to test without forking anything.

use std::collections::BTreeMap;

/// What Flowlight puts into an agent's environment, and why each one is there.
///
/// Every entry is a variable something reads *only* at startup. Nothing here is Flowlight's own invention
/// except the last, which exists so that a process can tell it was started this way.
const TRUSTS: &[(&str, &str)] = &[
    ("SSL_CERT_FILE", "OpenSSL, and most things that link it"),
    ("CURL_CA_BUNDLE", "curl"),
    ("REQUESTS_CA_BUNDLE", "Python requests"),
    ("GIT_SSL_CAINFO", "git"),
    ("CARGO_HTTP_CAINFO", "cargo"),
    ("AWS_CA_BUNDLE", "the AWS command line"),
    (
        "NODE_EXTRA_CA_CERTS",
        "Node, which reads no trust store at all",
    ),
];

/// The variable that says an agent was started through Flowlight.
///
/// Not needed by anything. It is here because the first question anybody asks of a process that is behaving
/// oddly is what its environment was, and "nothing in it mentions Flowlight" is a misleading answer.
pub const MARKER: &str = "FLOWLIGHT_AGENT";

/// The environment an agent is started with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Environment {
    /// The variables to set, in the order they are explained.
    pub variables: BTreeMap<String, String>,
    /// A sentence per variable, so that what was done can be said rather than only done.
    pub because: Vec<String>,
}

impl Environment {
    /// What to set when launching this agent.
    ///
    /// The certificate variables go in only when they could matter: there is a bundle to point at, and this
    /// agent is one whose connections are being terminated. Setting them otherwise is harmless — the bundle is
    /// this machine's own roots plus Flowlight's — and it is still noise in somebody's environment, and noise
    /// in an environment is a thing people spend afternoons on.
    pub fn for_agent(agent: &str, bundle: Option<&str>, terminated: bool) -> Self {
        let mut variables = BTreeMap::new();
        let mut because = Vec::new();
        variables.insert(MARKER.to_string(), agent.to_string());

        match (bundle, terminated) {
            (Some(bundle), true) => {
                for (name, reads_it) in TRUSTS {
                    variables.insert((*name).to_string(), bundle.to_string());
                    because.push(format!("{name} — {reads_it}"));
                }
            }
            (_, false) => because.push(
                format!(
                    "Nothing about certificates: {agent}'s connections are not being terminated, so there is \
                     nothing for it to have to trust."
                ),
            ),
            (None, true) => because.push(
                "Nothing about certificates: there is no certificate authority yet, so there is nothing to \
                 point anything at."
                    .to_string(),
            ),
        }
        Self { variables, because }
    }

    /// The variables as lines something else can read: `NAME=value`, one per line.
    ///
    /// For a launcher or a supervisor that starts the agent itself. This is the part of the feature that works
    /// without a terminal, and without Flowlight being the parent.
    pub fn as_lines(&self) -> String {
        let mut text = String::new();
        for (name, value) in &self.variables {
            text.push_str(&format!("{name}={value}\n"));
        }
        text
    }
}

/// What to call the agent being started.
///
/// The name of the program, which is the identity everywhere else in Flowlight: a rule names `claude` because
/// that is what the executable is called. A path is reduced to its last component, and an interpreter is
/// stepped over — `node /usr/lib/claude/cli.js` is an agent called `claude` and not one called `node`, which
/// is the same judgement the process-tree attribution makes.
pub fn name_of(command: &[String], known: &[&str]) -> Option<String> {
    let mut words = command.iter().filter(|word| !word.is_empty());
    let program = basename(words.next()?);
    if !is_an_interpreter(&program) {
        return Some(program);
    }
    // An interpreter: the agent is whichever of its arguments names one. Only a known name, because the first
    // argument of an interpreter is a path to a script and a script is called all sorts of things.
    for word in words {
        if word.starts_with('-') {
            continue;
        }
        let candidate = basename(word);
        let stem = candidate
            .rsplit_once('.')
            .map_or(candidate.as_str(), |(stem, _)| stem)
            .to_string();
        for name in known {
            if stem.eq_ignore_ascii_case(name) || candidate.eq_ignore_ascii_case(name) {
                return Some((*name).to_string());
            }
        }
        // The path may name the agent in a directory rather than in the file: `/usr/lib/claude/cli.js`.
        for name in known {
            if word.split('/').any(|part| part.eq_ignore_ascii_case(name)) {
                return Some((*name).to_string());
            }
        }
    }
    Some(program)
}

/// Whether a program runs somebody else's code, in which case its own name is not the interesting one.
fn is_an_interpreter(program: &str) -> bool {
    let stem = program
        .trim_start_matches("-")
        .split('.')
        .next()
        .unwrap_or(program);
    matches!(
        stem,
        "node"
            | "nodejs"
            | "bun"
            | "deno"
            | "python"
            | "python2"
            | "python3"
            | "ruby"
            | "perl"
            | "env"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "dash"
            | "uv"
            | "uvx"
            | "npx"
            | "pnpm"
            | "yarn"
    )
}

/// The last component of a path.
fn basename(word: &str) -> String {
    word.rsplit('/')
        .next()
        .unwrap_or(word)
        .trim_start_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_string()).collect()
    }

    const KNOWN: &[&str] = &["claude", "cursor", "codex", "aider", "goose"];

    #[test]
    fn a_program_is_named_by_its_last_path_component() {
        assert_eq!(
            name_of(&command(&["/usr/local/bin/claude", "--help"]), KNOWN).as_deref(),
            Some("claude")
        );
        assert_eq!(
            name_of(&command(&["aider"]), KNOWN).as_deref(),
            Some("aider")
        );
    }

    /// The same judgement the process-tree attribution makes: `claude` does not make requests, it starts
    /// `node`, and a rule about the agent has to mean the agent.
    #[test]
    fn an_interpreter_is_stepped_over() {
        assert_eq!(
            name_of(&command(&["node", "/usr/lib/claude/cli.js"]), KNOWN).as_deref(),
            Some("claude")
        );
        assert_eq!(
            name_of(&command(&["/usr/bin/python3", "-m", "aider"]), KNOWN).as_deref(),
            Some("aider")
        );
        assert_eq!(
            name_of(&command(&["npx", "claude"]), KNOWN).as_deref(),
            Some("claude")
        );
        assert_eq!(
            name_of(&command(&["env", "FOO=1", "codex"]), KNOWN).as_deref(),
            Some("codex")
        );
    }

    /// An interpreter running something nobody recognises is still worth launching, and is called what it is
    /// called. Guessing a name from a script's filename would attach somebody's rules to the wrong thing.
    #[test]
    fn an_interpreter_running_something_unknown_keeps_its_own_name() {
        assert_eq!(
            name_of(&command(&["node", "/home/me/scratch.js"]), KNOWN).as_deref(),
            Some("node")
        );
    }

    #[test]
    fn nothing_at_all_is_not_a_command() {
        assert_eq!(name_of(&[], KNOWN), None);
        assert_eq!(name_of(&command(&[""]), KNOWN), None);
    }

    /// The marker is always there, because "nothing in its environment mentions Flowlight" is a misleading
    /// answer to the first question anybody asks about a process behaving oddly.
    #[test]
    fn the_marker_is_always_set() {
        for (bundle, terminated) in [
            (Some("/share/ca-bundle.pem"), true),
            (Some("/share/ca-bundle.pem"), false),
            (None, true),
            (None, false),
        ] {
            let environment = Environment::for_agent("claude", bundle, terminated);
            assert_eq!(
                environment.variables.get(MARKER).map(String::as_str),
                Some("claude")
            );
        }
    }

    /// Node reads no trust store at all, so this variable is the only way in and the whole reason the feature
    /// exists. Asserted by name.
    #[test]
    fn a_terminated_agent_is_told_where_the_bundle_is() {
        let environment = Environment::for_agent("claude", Some("/share/ca-bundle.pem"), true);
        for name in [
            "SSL_CERT_FILE",
            "CURL_CA_BUNDLE",
            "REQUESTS_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "NODE_EXTRA_CA_CERTS",
        ] {
            assert_eq!(
                environment.variables.get(name).map(String::as_str),
                Some("/share/ca-bundle.pem"),
                "{name}"
            );
        }
        // And every one of them is explained, because a variable set in somebody's environment without a
        // reason is a variable they will spend an afternoon on.
        assert_eq!(environment.because.len(), TRUSTS.len());
        assert!(environment.because.iter().any(|why| why.contains("Node")));
    }

    /// An agent nothing is terminating has nothing to trust, and pointing its tools at a bundle would be noise.
    #[test]
    fn an_agent_nobody_intercepts_gets_no_certificate_variables() {
        let environment = Environment::for_agent("claude", Some("/share/ca-bundle.pem"), false);
        assert_eq!(environment.variables.len(), 1);
        assert!(!environment.variables.contains_key("NODE_EXTRA_CA_CERTS"));
        assert!(
            environment
                .because
                .iter()
                .any(|why| why.contains("not being terminated"))
        );
    }

    /// And one that is terminated with no authority to point at is told so rather than pointed at nothing.
    #[test]
    fn a_missing_bundle_is_said_rather_than_set_to_nothing() {
        let environment = Environment::for_agent("claude", None, true);
        assert_eq!(environment.variables.len(), 1);
        assert!(
            environment
                .because
                .iter()
                .any(|why| why.contains("no certificate authority"))
        );
    }

    #[test]
    fn the_variables_come_out_as_lines_something_else_can_read() {
        let environment = Environment::for_agent("claude", Some("/b.pem"), true);
        let text = environment.as_lines();
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines.contains(&"NODE_EXTRA_CA_CERTS=/b.pem"));
        assert!(lines.contains(&"FLOWLIGHT_AGENT=claude"));
        // One per variable, and nothing else: this is read by a launcher, not by a person.
        assert_eq!(lines.len(), environment.variables.len());
        for line in lines {
            assert!(line.contains('='), "{line}");
        }
    }
}
