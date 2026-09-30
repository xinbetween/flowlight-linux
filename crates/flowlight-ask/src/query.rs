//! The complete list of questions a model may ask of the local history.
//!
//! This is the privacy boundary of the whole feature. A model is never handed the database, a table, or a
//! query language — it is handed this list, and Flowlight runs whichever of these it names and gives back the
//! numbers. There is no `sql` case and there will not be one: a model that can write its own query can read
//! anything, and then "the model never sees your history" stops being true the first time somebody is clever.
//!
//! Two rules shape every one of them. **Aggregates, not rows**: nothing here returns a request, a target or a
//! timestamp to the second — only counts, totals and names, which is what answering a question needs. And
//! **bounded**: every result has a row limit and every window has an end, so a model cannot ask for the
//! database one page at a time.

use serde_json::{Value, json};
use std::collections::BTreeMap;

/// The most rows any one query returns.
pub const MOST_ROWS: usize = 50;

/// How many rows a query returns when the model does not say.
pub const SOME_ROWS: usize = 10;

/// One of the questions a model may ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Query {
    /// How much moved, in total.
    Totals,
    /// The busiest processes.
    TopProcesses,
    /// The busiest hosts.
    TopHosts,
    /// Hosts reached in this window that had never been reached before it.
    NewHosts,
    /// The agents that were active.
    Agents,
    /// The hosts one agent reached.
    AgentHosts,
    /// What one agent said to MCP servers: methods and tool names, never arguments.
    AgentTools,
    /// What was *not* read, which is the answer that stops every other answer being misleading.
    Coverage,
    /// A series over time, for "when did it happen" rather than "how much".
    OverTime,
    /// The rules that have been written.
    Rules,
    /// How Flowlight is set up right now.
    Settings,
    /// What a feature is and how to turn it on, from Flowlight's own written-down guide.
    HowTo,
}

/// Every query, in the order the model is shown them.
pub const EVERY_QUERY: &[Query] = &[
    Query::Totals,
    Query::TopProcesses,
    Query::TopHosts,
    Query::NewHosts,
    Query::Agents,
    Query::AgentHosts,
    Query::AgentTools,
    Query::Coverage,
    Query::OverTime,
    Query::Rules,
    Query::Settings,
    Query::HowTo,
];

/// What the model may fill in.
///
/// Kept deliberately small: a window, sometimes a process or an agent, sometimes a limit. Anything more
/// expressive is another way of saying "write your own query".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Parameter {
    /// What it is called in the arguments.
    pub name: &'static str,
    /// Whether the query cannot run without it.
    pub required: bool,
    /// What it means, as the model is told it.
    pub detail: &'static str,
}

/// The window every query about traffic takes.
const WINDOW: &[Parameter] = &[
    Parameter {
        name: "from",
        required: true,
        detail: "Start of the window: a shorthand like '30m', '24h', '7d', 'today' or 'yesterday', or a \
                 date as YYYY-MM-DD.",
    },
    Parameter {
        name: "to",
        required: false,
        detail: "End of the window; leave it out for now.",
    },
];

const PROCESS: Parameter = Parameter {
    name: "process",
    required: false,
    detail: "Restrict to one process by the name Flowlight shows, such as 'curl' or 'node'. Leave it out \
             for every process.",
};

const AGENT: Parameter = Parameter {
    name: "agent",
    required: true,
    detail: "The agent, by the name Flowlight shows: 'claude', 'cursor', 'codex'. Call the agents query \
             first if you do not know which ones there are.",
};

const LIMIT: Parameter = Parameter {
    name: "limit",
    required: false,
    detail: "How many rows to return, 1 to 50. Ten by default.",
};

impl Query {
    /// The name the model calls this by.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Totals => "totals",
            Self::TopProcesses => "topProcesses",
            Self::TopHosts => "topHosts",
            Self::NewHosts => "newHosts",
            Self::Agents => "agents",
            Self::AgentHosts => "agentHosts",
            Self::AgentTools => "agentTools",
            Self::Coverage => "coverage",
            Self::OverTime => "overTime",
            Self::Rules => "rules",
            Self::Settings => "settings",
            Self::HowTo => "howTo",
        }
    }

    /// Reads one back, or nothing if it is not one.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim();
        EVERY_QUERY
            .iter()
            .copied()
            .find(|query| query.as_str().eq_ignore_ascii_case(text))
    }

    /// What this query is for, as the model is told it.
    pub fn summary(self) -> &'static str {
        match self {
            Self::Totals => {
                "Requests read, connections opened, bytes carried and processes seen in a window — \
                 optionally for one process."
            }
            Self::TopProcesses => {
                "The processes that made the most requests in a window, with their hosts and bytes."
            }
            Self::TopHosts => "The hosts that were reached most, optionally for one process.",
            Self::NewHosts => {
                "Hosts reached in this window that had never been reached before it. Use this for \
                 \"anything new\" questions."
            }
            Self::Agents => {
                "The AI agents active in a window, with how many requests, hosts and processes each \
                 accounted for."
            }
            Self::AgentHosts => "The hosts one agent reached, busiest first.",
            Self::AgentTools => {
                "What one agent said to MCP servers: the JSON-RPC method, the tool's name and the host. \
                 Never a tool's arguments — Flowlight does not record them."
            }
            Self::Coverage => {
                "What was read and, more usefully, what was not: processes whose connections could not be \
                 read at all, truncated calls, undecodable HTTP/2, weakly named processes and records the \
                 kernel dropped. Call this before concluding that something did not happen."
            }
            Self::OverTime => {
                "Requests and bytes per bucket across a window, for spotting when something happened."
            }
            Self::Rules => {
                "The allow, ask and block rules that exist, what each names, and whether it is enforceable."
            }
            Self::Settings => {
                "How Flowlight is set up right now: what it is allowed to read, how long it keeps it, where \
                 it exports to, and which model answers these questions. Use this for questions about \
                 Flowlight rather than about traffic."
            }
            Self::HowTo => {
                "What a Flowlight feature does and the commands to use it, from Flowlight's own guide. Use \
                 this for \"how do I…\" and \"can Flowlight…\" questions, and never answer those from \
                 memory: the commands differ between versions, and a made-up flag is worse than no answer."
            }
        }
    }

    /// What this query takes.
    pub fn parameters(self) -> Vec<Parameter> {
        let window = WINDOW.to_vec();
        match self {
            Self::Totals => [window, vec![PROCESS]].concat(),
            Self::TopProcesses | Self::Agents => [window, vec![LIMIT]].concat(),
            Self::TopHosts | Self::NewHosts => [window, vec![PROCESS, LIMIT]].concat(),
            Self::AgentHosts | Self::AgentTools => [window, vec![AGENT, LIMIT]].concat(),
            Self::Coverage => window,
            Self::OverTime => [
                window,
                vec![
                    PROCESS,
                    Parameter {
                        name: "granularity",
                        required: false,
                        detail: "minute, hour or day. Left out, Flowlight picks one that fits the window.",
                    },
                ],
            ]
            .concat(),
            // About the tool, not about a window of traffic.
            Self::Rules | Self::Settings => Vec::new(),
            Self::HowTo => vec![Parameter {
                name: "topic",
                required: true,
                detail: "What the person asked about, in their own words: 'block a host', 'read payloads', \
                         'nothing is showing', 'export'.",
            }],
        }
    }
}

/// One call the model asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    /// Which query.
    pub query: Query,
    /// What it said to fill in.
    pub arguments: BTreeMap<String, String>,
}

impl Call {
    /// One argument, trimmed, or nothing when it is absent or empty.
    ///
    /// Empty counts as absent because a model that means "every process" writes `""` about as often as it
    /// leaves the field out, and reading that as a process named nothing returns an empty result that it
    /// will report as "nothing happened".
    pub fn argument(&self, name: &str) -> Option<&str> {
        self.arguments
            .get(name)
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            // The words a model writes when it means to leave a field blank. Read as values, each of these
            // is a process, an agent or a topic that does not exist.
            .filter(|value| {
                !matches!(
                    value.to_lowercase().as_str(),
                    "all" | "any" | "none" | "default" | "null"
                )
            })
    }

    /// The row limit it asked for, clamped.
    pub fn limit(&self) -> usize {
        self.argument("limit")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(SOME_ROWS)
            .clamp(1, MOST_ROWS)
    }
}

/// The single tool every provider is given, as the JSON Schema they all accept.
///
/// One tool with a `query` field rather than twelve tools, because every provider agrees on how one function
/// with an enum works and they disagree about almost everything else.
pub fn schema() -> Value {
    let names: Vec<&str> = EVERY_QUERY.iter().map(|query| query.as_str()).collect();
    json!({
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "enum": names,
                "description": "Which of Flowlight's queries to run.",
            },
            "from": { "type": "string", "description": "Start of the window: '30m', '24h', '7d', 'today', 'yesterday', or YYYY-MM-DD." },
            "to": { "type": "string", "description": "End of the window; omit for now." },
            "process": { "type": "string", "description": "One process by name; omit for every process." },
            "agent": { "type": "string", "description": "One agent by name, for the agent queries." },
            "limit": { "type": "string", "description": "How many rows, 1 to 50; omit for ten." },
            "granularity": { "type": "string", "description": "minute, hour or day, for overTime; omit to let Flowlight choose." },
            "topic": { "type": "string", "description": "What was asked about, for howTo." },
        },
        "required": ["query"],
    })
}

/// The name of the one tool.
pub const TOOL: &str = "runQuery";

/// What the tool is for, in the one sentence every provider shows the model.
pub const TOOL_SUMMARY: &str = "Run one of Flowlight's read-only queries against the network history recorded on this machine.";

/// The instructions every provider is given.
///
/// Written once, here, so that a local model and a hosted one are held to the same rules — including the one
/// about not inventing numbers, which is the rule that decides whether this feature is useful or a liability.
pub fn instructions(now: &str) -> String {
    let mut text = format!(
        "You answer questions about network activity recorded by Flowlight, a network monitor, on this \
         Linux machine.\n\nRight now it is {now}. Work out any window from that.\n\nYou cannot see the \
         database. You can call the queries listed below; Flowlight runs them locally and gives you back \
         totals and names. Call whatever you need, then answer in two or three sentences of plain \
         English.\n\nRules:\n\
         - Never invent a number. If a query returns nothing, say that nothing was recorded rather than \
         guessing.\n\
         - Flowlight attributes a request to the process that made it and, separately, to the agent that \
         caused it. `claude` does not make requests: it starts `node`, which starts `git`, which makes one. \
         Use the agent queries when the question is about an agent.\n\
         - Before concluding that something did not happen, call coverage. A process whose TLS could not be \
         read looks exactly like a process that did nothing, and saying \"it made no requests\" when \
         Flowlight simply could not read them is the one answer here that is worse than no answer.\n\
         - Prefer a relative window — '30m', '24h', '7d', 'today', 'yesterday' — and let Flowlight resolve \
         it. Write a date only when the question names one.\n\
         - Leave an argument out when you do not mean to narrow by it. Never write 'all', 'none' or \
         'default' into one: those are read as values, not as blanks.\n\
         - Bytes come back as whole numbers; convert them to human units in your answer.\n\
         - Prefer one precise query to several vague ones.\n\
         - Questions about Flowlight itself — how to do something, whether something is switched on, why \
         nothing is showing — are yours to answer too. Call howTo for how a feature works and settings for \
         how this machine is configured. Never answer those from memory.\n\
         - Flowlight does not record the arguments of an MCP tool call, the body of a request, or any \
         header. If you are asked what something said, say that only the method and the tool's name are \
         recorded.\n\
         - If the question is about neither this machine's activity nor Flowlight, say so plainly instead \
         of answering it.\n\nQueries you may call:\n\n"
    );
    for query in EVERY_QUERY {
        text.push_str(&format!("- {}: {}\n", query.as_str(), query.summary()));
        for parameter in query.parameters() {
            text.push_str(&format!(
                "    {}{}: {}\n",
                parameter.name,
                if parameter.required {
                    " (required)"
                } else {
                    ""
                },
                parameter.detail
            ));
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The boundary, asserted rather than trusted: there is no way to name a query that is not on the list.
    #[test]
    fn there_is_no_query_that_is_not_on_the_list() {
        assert_eq!(Query::parse("sql"), None);
        assert_eq!(Query::parse("SELECT * FROM requests"), None);
        assert_eq!(Query::parse("requests"), None);
        for query in EVERY_QUERY {
            assert_eq!(Query::parse(query.as_str()), Some(*query));
        }
    }

    /// A model that writes a name in a different case meant the query.
    #[test]
    fn a_name_is_read_whatever_case_it_is_written_in() {
        assert_eq!(Query::parse("  TopHosts "), Some(Query::TopHosts));
        assert_eq!(Query::parse("tophosts"), Some(Query::TopHosts));
    }

    /// The words a model writes when it means to leave a field blank. Read as values, each of them is a
    /// process that does not exist, and the empty result reads as "nothing happened".
    #[test]
    fn a_word_meaning_nothing_is_read_as_nothing() {
        for blank in ["", "  ", "all", "None", "DEFAULT", "any", "null"] {
            let call = Call {
                query: Query::TopHosts,
                arguments: [("process".to_owned(), blank.to_owned())]
                    .into_iter()
                    .collect(),
            };
            assert_eq!(call.argument("process"), None, "{blank}");
        }
        let call = Call {
            query: Query::TopHosts,
            arguments: [("process".to_owned(), " curl ".to_owned())]
                .into_iter()
                .collect(),
        };
        assert_eq!(call.argument("process"), Some("curl"));
    }

    /// A model cannot ask for the database one page at a time.
    #[test]
    fn a_limit_is_clamped_at_both_ends() {
        let limit = |value: &str| {
            Call {
                query: Query::TopHosts,
                arguments: [("limit".to_owned(), value.to_owned())]
                    .into_iter()
                    .collect(),
            }
            .limit()
        };
        assert_eq!(limit("5"), 5);
        assert_eq!(limit("0"), 1);
        assert_eq!(limit("100000"), MOST_ROWS);
        assert_eq!(limit("lots"), SOME_ROWS);
        assert_eq!(
            Call {
                query: Query::TopHosts,
                arguments: BTreeMap::new()
            }
            .limit(),
            SOME_ROWS
        );
    }

    /// The schema's enum is the list, not a copy of it that can fall behind.
    #[test]
    fn the_schema_offers_exactly_the_queries_that_exist() {
        let schema = schema();
        let names = schema
            .pointer("/properties/query/enum")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(names.len(), EVERY_QUERY.len());
        for query in EVERY_QUERY {
            assert!(
                names
                    .iter()
                    .any(|name| name.as_str() == Some(query.as_str())),
                "{} is missing from the schema",
                query.as_str()
            );
        }
    }

    /// Every query is described to the model, and every parameter of it. A query the model is not told about
    /// is a query it will not call, which is a feature nobody can reach.
    #[test]
    fn the_instructions_describe_every_query_and_every_parameter() {
        let text = instructions("Monday 29 September 2026, 12:00 UTC");
        for query in EVERY_QUERY {
            assert!(text.contains(query.as_str()), "{}", query.as_str());
            for parameter in query.parameters() {
                assert!(
                    text.contains(parameter.name),
                    "{} of {}",
                    parameter.name,
                    query.as_str()
                );
            }
        }
        // And the rule that matters most.
        assert!(text.contains("Never invent a number"));
        assert!(text.contains("call coverage"));
    }
}
