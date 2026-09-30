//! Flowlight's own written-down answer to "how do I…".
//!
//! Here rather than in the model, because the commands differ between versions and a model answering from
//! memory invents a flag that looks exactly like a real one. A made-up `--follow` is worse than "I don't
//! know": somebody types it, it fails, and the tool looks broken.
//!
//! Every entry names commands that exist in this build. When a flag changes, this file is part of the change.

/// One topic, as the model is handed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Topic {
    /// What it is about.
    pub title: &'static str,
    /// The words somebody might use for it, matched loosely.
    pub words: &'static [&'static str],
    /// The answer, in sentences and commands.
    pub detail: &'static str,
}

/// Everything Flowlight can explain about itself.
pub const TOPICS: &[Topic] = &[
    Topic {
        title: "Watching traffic",
        words: &[
            "watch",
            "start",
            "run",
            "monitor",
            "live",
            "daemon",
            "flowlightd",
        ],
        detail: "`sudo flowlightd` watches the machine and prints a line per request. It needs root because \
                 loading an eBPF program does. `--json` for one object per line, `--no-payloads` for \
                 connections only, `--seconds N` to stop by itself. The native window is `flowlight`, which \
                 runs as you and talks to the daemon over a socket.",
    },
    Topic {
        title: "Nothing is showing",
        words: &[
            "nothing",
            "empty",
            "no requests",
            "not working",
            "broken",
            "missing",
            "why",
        ],
        detail: "Three reasons, in the order they happen. Payload capture may be off or its session may have \
                 run out — `flowlightd budget` says, and `flowlightd budget --renew` starts it again. The \
                 process may use a TLS library Flowlight has no probe for: Go programs and Chrome link their \
                 own, and `flowlightd coverage` names every process whose connections could not be read. Or \
                 the daemon may not have been running when the connection was opened: HTTP/2 header \
                 compression cannot be rebuilt from the middle, and such a connection is reported as \
                 unreadable rather than guessed at.",
    },
    Topic {
        title: "Reading payloads",
        words: &[
            "payload",
            "https",
            "plaintext",
            "decrypt",
            "certificate",
            "read",
            "request body",
        ],
        detail: "Flowlight reads HTTPS by probing the TLS library as the application hands it plaintext, \
                 before encryption. No certificate is installed anywhere and certificate pinning is not \
                 involved. OpenSSL, GnuTLS and NSS are probed; only the first four kilobytes of any one call \
                 are captured. `--libssl PATH` adds a library the search did not find.",
    },
    Topic {
        title: "What is kept, and for how long",
        words: &[
            "budget",
            "retention",
            "keep",
            "how long",
            "session",
            "delete",
            "privacy",
            "paths",
        ],
        detail: "`flowlightd budget` says what Flowlight is allowed to read and for how long; with any \
                 option it changes it. `--payloads no` stops reading payloads, `--session MINUTES` makes \
                 capture expire, `--renew` starts it again, `--daily MB` caps what one process may \
                 contribute in a day, `--paths host-only|none` keeps less of each request target, and \
                 `--detail-days`/`--summary-days` set how long records live. The Budget page in the window \
                 does the same.",
    },
    Topic {
        title: "Blocking a host",
        words: &[
            "block", "rule", "refuse", "allow", "deny", "stop", "firewall",
        ],
        detail: "`sudo flowlightd block <host>` refuses connections to it before the handshake, in a \
                 cgroup/connect hook. `--port N` narrows it, `--agent NAME` scopes it to one agent and \
                 anything it starts. `allow` writes an exception to a broader rule and `ask` refuses while \
                 recording the question. `flowlightd rules` lists them with the identifiers `forget` takes. \
                 The most specific rule wins: subject, then port, then scope.",
    },
    Topic {
        title: "Trying a rule first",
        words: &["simulate", "preview", "what would", "dry run", "try"],
        detail: "`flowlightd simulate block <host> --since 24h` decides every piece of traffic in the window \
                 twice, once with the rules as they are and once with the candidate added, and reports only \
                 the verdicts that move. It is a claim about the past, not a promise about the future, and \
                 it writes nothing.",
    },
    Topic {
        title: "Agents and MCP",
        words: &[
            "agent", "claude", "cursor", "mcp", "tool", "server", "codex",
        ],
        detail: "`flowlightd agents --since 24h` lists the agents seen, what each reached, and the MCP \
                 servers it was configured for against the ones it actually used. An agent is recognised by \
                 the name of its executable, and its children inherit the attribution in the kernel at fork \
                 — so a request made by `git`, started by `node`, started by `claude`, is attributed to \
                 claude. Of an MCP call Flowlight records the JSON-RPC method and the tool's name. Never the \
                 arguments.",
    },
    Topic {
        title: "What was not seen",
        words: &[
            "coverage",
            "unread",
            "not seen",
            "gap",
            "trust",
            "truncated",
            "dropped",
        ],
        detail: "`flowlightd coverage --since 24h` is the screen that makes the rest worth trusting: \
                 processes that opened HTTPS connections and had nothing read, calls that carried more than \
                 was captured, HTTP/2 that could not be followed, processes named only by a truncated comm, \
                 and records the kernel dropped. Zeroes are printed rather than omitted, because a line that \
                 disappears turns \"nothing was dropped\" into \"nobody checked\".",
    },
    Topic {
        title: "Sending it somewhere else",
        words: &["export", "otlp", "collector", "send", "json", "log", "siem"],
        detail: "`sudo flowlightd export --to <path or URL>` discloses what would be sent and sends nothing. \
                 `--fields` chooses what travels, `--header NAME=VALUE` adds a header whose value is never \
                 shown back, and `--consent` agrees to the disclosure. Changing the destination, the fields \
                 or the headers takes the agreement away and nothing is sent until somebody agrees again.",
    },
    Topic {
        title: "Asking questions",
        words: &[
            "ask",
            "question",
            "model",
            "llm",
            "ai",
            "ollama",
            "anthropic",
            "gemini",
            "openai",
        ],
        detail: "Flowlight for Linux has no model of its own — no bundled weights and no default pointing at \
                 somebody's API — so one has to be configured. `sudo flowlightd model --kind local --model \
                 llama3.2` points at a server on this machine; `--kind anthropic --key-file PATH` or \
                 `--kind compatible --endpoint URL` points somewhere else. Then `flowlightd query \"what did \
                 claude reach today?\"`. The model never sees the database: it may name one of a fixed list \
                 of queries, which Flowlight runs.",
    },
    Topic {
        title: "The window and the socket",
        words: &[
            "window",
            "gui",
            "interface",
            "socket",
            "page",
            "browser",
            "web",
        ],
        detail: "`flowlight` is the native window. It runs as you and talks to the daemon over a Unix socket \
                 owned by whoever started it, mode 600 — a boundary the kernel enforces. `--web` also serves \
                 a page on loopback for a machine with no desktop session; it is off unless asked for, \
                 because loopback is reachable by every local user and a token is a secret that leaks into \
                 shell history.",
    },
];

/// The topic that best matches what somebody asked, or nothing when none does.
///
/// Scored by how many of a topic's words appear, rather than by the first match, because "why is nothing
/// showing in the live view" contains the word for three different topics and only one of them is the answer.
pub fn look_up(asked: &str) -> Option<&'static Topic> {
    let asked = asked.to_lowercase();
    let mut best: Option<(usize, &'static Topic)> = None;
    for topic in TOPICS {
        let score = topic
            .words
            .iter()
            .filter(|word| asked.contains(*word))
            .map(|word| word.len())
            .sum::<usize>()
            + usize::from(asked.contains(&topic.title.to_lowercase()));
        if score > 0 && best.is_none_or(|(previous, _)| score > previous) {
            best = Some((score, topic));
        }
    }
    best.map(|(_, topic)| topic)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_question_finds_the_topic_it_is_about() {
        assert_eq!(
            look_up("how do I block a host?").map(|topic| topic.title),
            Some("Blocking a host")
        );
        assert_eq!(
            look_up("why is nothing showing").map(|topic| topic.title),
            Some("Nothing is showing")
        );
        assert_eq!(
            look_up("can I send this to an OTLP collector").map(|topic| topic.title),
            Some("Sending it somewhere else")
        );
        assert_eq!(
            look_up("what model does ask use").map(|topic| topic.title),
            Some("Asking questions")
        );
    }

    /// Nothing rather than the first topic in the file, because a wrong confident answer about how to use a
    /// tool is the thing this module exists to prevent.
    #[test]
    fn a_question_about_something_else_finds_nothing() {
        assert_eq!(look_up("the capital of France"), None);
    }

    /// Every topic is reachable by at least one of its own words, which is the one way this file can be
    /// wrong without anybody noticing.
    #[test]
    fn every_topic_can_be_found() {
        for topic in TOPICS {
            let word = topic.words.first().copied().unwrap_or_default();
            assert!(look_up(word).is_some(), "{}", topic.title);
        }
    }

    /// Commands in the guide are commands that exist. Asserted loosely — that each entry names `flowlightd`
    /// or `flowlight` — because the real check is the smoke test running them.
    #[test]
    fn every_topic_names_a_command() {
        for topic in TOPICS {
            assert!(
                topic.detail.to_lowercase().contains("flowlight"),
                "{} explains nothing anybody can type",
                topic.title
            );
        }
    }
}
