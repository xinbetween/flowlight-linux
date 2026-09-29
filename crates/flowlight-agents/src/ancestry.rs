//! Finding the agent a process is working for, by walking up the process tree.
//!
//! `claude` does not make requests. It spawns `node`, which spawns `bash`, which spawns `git`, which spawns
//! `git-remote-https`, which makes the request. Attributing that request to `git-remote-https` is true and
//! useless — and on the macOS build it is the thing that made the Agents view worth building at all.
//!
//! # Why the *nearest* agent and not the outermost
//!
//! One agent can start another: a coding agent running a test suite that itself calls a model. The request
//! belongs to whichever agent most immediately caused it, because that is the one whose rules should decide
//! it and whose history it should appear in. Walking up and stopping at the first match gives that.
//!
//! # Why this cannot simply trust the name
//!
//! A process called `claude` might be a user's shell alias, a script in `~/bin`, or the agent. There is no
//! way to tell from the outside and no attempt is made to: the name is the identity everywhere else in
//! Flowlight, and inventing a stricter rule here would mean the Agents view and the Processes view
//! disagreeing about what a thing is called.

use std::collections::BTreeSet;

/// How far up to walk before giving up.
///
/// A process tree is rarely more than a dozen deep. The cap is not about depth but about the walk
/// terminating at all: `/proc` is read one entry at a time and a process can exit between two reads,
/// leaving a parent identifier that now belongs to something else.
const MAX_DEPTH: usize = 32;

/// The agents worth recognising, by the name their executable has.
///
/// A list rather than a heuristic, because the alternative — "anything that spawns a lot of children and
/// talks to an API" — describes `make`. It is deliberately short and deliberately easy to add to; an agent
/// not on it is attributed to itself, which is the same behaviour as before this module existed.
pub const KNOWN: &[&str] = &[
    "claude",
    "claude-code",
    "codex",
    "cursor",
    "cursor-agent",
    "aider",
    "gemini",
    "goose",
    "opencode",
    "continue",
    "cline",
    "amp",
    "crush",
    "copilot",
    "devin",
    "windsurf",
];

/// Whether a process name is one of the agents this recognises.
///
/// Case-insensitive, because an executable is `Cursor` on one machine and `cursor` on another, and the
/// version suffix some installers leave behind is ignored for the same reason a version is never an
/// identity anywhere else in Flowlight.
pub fn is_agent(name: &str) -> bool {
    let name = name.trim().to_ascii_lowercase();
    KNOWN.iter().any(|known| name == *known)
}

/// One process, as much of it as this needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    /// What it is called — the same name the rest of Flowlight uses.
    pub name: String,
    /// Its parent.
    pub parent: i32,
}

/// The agent a process is working for, if any.
///
/// `parent_of` is how the caller reads a process; on Linux that is `/proc`, and in the tests it is a map
/// written out by hand. Returns the process's own name when it is itself an agent, because an agent works
/// for itself.
pub fn agent_for<F>(pid: i32, mut parent_of: F) -> Option<String>
where
    F: FnMut(i32) -> Option<Process>,
{
    let mut seen = BTreeSet::new();
    let mut current = pid;
    for _ in 0..MAX_DEPTH {
        // A process identifier seen twice is a cycle, which cannot happen in a process tree and can happen
        // in a *reading* of one: a process exits mid-walk and its identifier is reused. Stopping is the
        // only correct answer; continuing would loop until the depth cap and attribute the request to
        // whatever the reused identifier now belongs to.
        if !seen.insert(current) {
            return None;
        }
        let process = parent_of(current)?;
        if is_agent(&process.name) {
            return Some(process.name);
        }
        // `init` and the kernel's own parent. Above here there is nothing to find.
        if process.parent <= 1 {
            return None;
        }
        current = process.parent;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A process tree, nearest first: `(pid, name, parent)`.
    fn tree(entries: &[(i32, &str, i32)]) -> impl Fn(i32) -> Option<Process> + use<> {
        let map: BTreeMap<i32, Process> = entries
            .iter()
            .map(|(pid, name, parent)| {
                (
                    *pid,
                    Process {
                        name: (*name).to_owned(),
                        parent: *parent,
                    },
                )
            })
            .collect();
        move |pid| map.get(&pid).cloned()
    }

    /// The shape this exists for. The request is made by `git-remote-https`, four processes below the agent
    /// that caused it, and attributing it to `git-remote-https` is true and useless.
    #[test]
    fn a_request_from_deep_in_an_agents_tree_belongs_to_the_agent() {
        let processes = tree(&[
            (500, "git-remote-https", 400),
            (400, "git", 300),
            (300, "bash", 200),
            (200, "node", 100),
            (100, "claude", 1),
        ]);
        assert_eq!(agent_for(500, &processes).as_deref(), Some("claude"));
    }

    #[test]
    fn an_agent_works_for_itself() {
        let processes = tree(&[(100, "claude", 1)]);
        assert_eq!(agent_for(100, &processes).as_deref(), Some("claude"));
    }

    /// Not everything on a machine is an agent, and a tool that claimed otherwise would be useless in the
    /// opposite direction.
    #[test]
    fn a_process_with_no_agent_above_it_has_no_agent() {
        let processes = tree(&[(500, "curl", 300), (300, "bash", 200), (200, "sshd", 1)]);
        assert_eq!(agent_for(500, &processes), None);
    }

    /// One agent can start another — a coding agent running a test suite that itself calls a model. The
    /// request belongs to whichever most immediately caused it: that is the one whose rules should decide
    /// it and whose history it should appear in.
    #[test]
    fn the_nearest_agent_wins_not_the_outermost() {
        let processes = tree(&[
            (500, "curl", 400),
            (400, "aider", 300),
            (300, "bash", 200),
            (200, "claude", 1),
        ]);
        assert_eq!(agent_for(500, &processes).as_deref(), Some("aider"));
    }

    /// A process that exited between two reads leaves nothing to walk from, which is a missing answer and
    /// not a wrong one.
    #[test]
    fn a_process_that_has_gone_has_no_agent_rather_than_a_guessed_one() {
        let processes = tree(&[(500, "curl", 400)]);
        assert_eq!(agent_for(500, &processes), None);
        assert_eq!(agent_for(999, &processes), None);
    }

    /// Cannot happen in a process tree; can happen in a reading of one, when a process exits mid-walk and
    /// its identifier is reused. Looping until the depth cap would attribute the request to whatever that
    /// identifier now belongs to.
    #[test]
    fn a_cycle_stops_rather_than_attributing_to_whatever_it_lands_on() {
        let processes = tree(&[(500, "curl", 600), (600, "sh", 500), (700, "claude", 1)]);
        assert_eq!(agent_for(500, &processes), None);
    }

    /// A tree deeper than anything real is still a tree that has to terminate.
    #[test]
    fn a_walk_that_never_reaches_the_top_still_ends() {
        let deep: Vec<(i32, &str, i32)> = (1..500).map(|pid| (pid, "sh", pid + 1)).collect();
        assert_eq!(agent_for(1, tree(&deep)), None);
    }

    #[test]
    fn an_agents_name_is_recognised_however_it_is_cased() {
        assert!(is_agent("claude"));
        assert!(is_agent("Cursor"));
        assert!(is_agent("  codex  "));
        assert!(!is_agent("clause"));
        assert!(!is_agent("claude-wrapper"));
        assert!(!is_agent(""));
    }
}
