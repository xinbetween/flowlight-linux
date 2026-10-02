//! Reading the process tree, so that a request can be attributed to the agent that caused it.
//!
//! [`flowlight_agents::ancestry`] decides; this reads. The split is the same one the rest of the project
//! uses — the part that can be wrong in an interesting way is testable on a machine with no `/proc`, and
//! the part that cannot is fifty lines of reading files.

use flowlight_agents::ancestry::{Process, agent_for, is_agent};
use flowlight_common::identity::name_from_path;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long an answer is trusted.
///
/// Process identifiers are reused, so a cached answer is a guess about a process that may no longer be the
/// one that was asked about. Five seconds is short enough that reuse within it is vanishingly unlikely on a
/// machine that is not deliberately churning processes, and long enough to matter: an agent's children are
/// short-lived and numerous, and the walk to the agent is the same walk every time.
const TRUSTED_FOR: Duration = Duration::from_secs(5);

/// How many answers to keep.
const MAX_CACHED: usize = 8_192;

/// Resolves processes to the agent they are working for.
#[derive(Default)]
pub struct Agents {
    cache: HashMap<u32, (Option<String>, Instant)>,
}

impl Agents {
    /// An empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// The agent this process is working for, if any.
    pub fn of(&mut self, tgid: u32) -> Option<String> {
        let now = Instant::now();
        if let Some((answer, at)) = self.cache.get(&tgid)
            && now.duration_since(*at) < TRUSTED_FOR
        {
            return answer.clone();
        }
        if self.cache.len() >= MAX_CACHED {
            // Wholesale rather than least-recently-used: every entry expires in five seconds anyway, so a
            // heap to decide which of them to drop first would be machinery in service of nothing.
            self.cache.clear();
        }
        let answer = agent_for(tgid as i32, read_process);
        self.cache.insert(tgid, (answer.clone(), now));
        answer
    }
}

/// Every task belonging to a process Flowlight treats as an agent.
///
/// Tasks rather than processes: an agent's children are marked in the kernel by the fork tracepoint, which
/// copies the mark from the *forking thread*. A multithreaded agent — which every agent written in Node is
/// — forks from whichever thread happened to be running, so marking only the main one would leave most of
/// its children unmarked.
///
/// `named` is every process somebody has named themselves — in interception's scope, or in a rule scoped to
/// an agent. They are marked as well as the catalogue's names, and this is not a detail: without it,
/// `intercept --agent curl` is accepted, stored, reported back as "connections from curl are redirected",
/// and then nothing ever happens, because no process named `curl` is ever marked and the kernel matches on
/// marks. The catalogue is for *attribution* — working out which agent a process belongs to when nobody
/// said. Somebody who names a process has already said.
pub fn running_agents(named: &std::collections::BTreeSet<String>) -> Vec<(u32, String)> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let Some(process) = read_process(pid) else {
            continue;
        };
        if !is_agent(&process.name) && !named.contains(&process.name.trim().to_ascii_lowercase()) {
            continue;
        }
        let tasks = std::fs::read_dir(entry.path().join("task"));
        match tasks {
            Ok(tasks) => {
                for task in tasks.flatten() {
                    if let Some(tid) = task
                        .file_name()
                        .to_str()
                        .and_then(|name| name.parse::<u32>().ok())
                    {
                        found.push((tid, process.name.clone()));
                    }
                }
            }
            // A process that exited between the listing and the read is the normal case, not an error.
            Err(_) => found.push((pid as u32, process.name.clone())),
        }
    }
    found
}

/// One process, out of `/proc`.
///
/// The name is the same identity the rest of Flowlight uses — from the executable path where there is one,
/// and from the kernel's `comm` where the process has already gone. A process that exits mid-walk is the
/// normal case for anything an agent shells out to.
fn read_process(pid: i32) -> Option<Process> {
    let parent = parent_of(pid)?;
    let name = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|path| path.to_str().and_then(name_from_path).map(str::to_owned))
        .or_else(|| {
            std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|comm| comm.trim().to_owned())
        })
        .filter(|name| !name.is_empty())?;
    Some(Process { name, parent })
}

/// The parent identifier out of `/proc/<pid>/stat`.
///
/// Parsed from the last `)` rather than by splitting on spaces, because the second field is the process's
/// `comm` in parentheses and `comm` can contain spaces *and* parentheses. A process named `evil ) 1 R 1`
/// would otherwise report whatever parent it liked, and naming a process is something any user can do.
pub fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')').map(|(_, rest)| rest)?;
    // What follows is ` <state> <ppid> …`.
    after_comm.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The second field of `stat` is `comm` in parentheses, and `comm` can contain spaces and parentheses.
    /// Splitting on whitespace from the left reads a field of the process's own choosing as the parent.
    #[test]
    fn a_process_named_to_break_the_parser_does_not_break_it() {
        // This is the parse, applied to text rather than to /proc, which is the only part worth testing.
        let parse = |stat: &str| -> Option<i32> {
            stat.rsplit_once(')')
                .map(|(_, rest)| rest)?
                .split_whitespace()
                .nth(1)?
                .parse()
                .ok()
        };
        assert_eq!(parse("42 (curl) S 17 42 42 0 -1 4194304"), Some(17));
        assert_eq!(parse("42 (a b c) S 17 42"), Some(17));
        assert_eq!(parse("42 (evil ) 1 R 1) S 17 42"), Some(17));
        assert_eq!(parse("42 ((()) S 17 42"), Some(17));
        assert_eq!(parse(""), None);
        assert_eq!(parse("nonsense"), None);
    }

    /// Nothing about a process that is not there is knowable, and a guess would be worse than nothing.
    #[test]
    fn a_process_that_does_not_exist_has_no_parent() {
        assert_eq!(parent_of(-1), None);
        assert_eq!(parent_of(0x7fff_ffff), None);
    }

    /// The daemon's own process is real, has a parent, and is not an agent.
    #[test]
    fn this_process_can_be_read() {
        let mine = std::process::id() as i32;
        assert!(parent_of(mine).is_some());
        assert!(read_process(mine).is_some());
    }

    /// This process is not an agent, and the scan must complete on a real `/proc` without complaining.
    #[test]
    fn the_scan_for_agents_completes_on_this_machine() {
        let running = running_agents(&std::collections::BTreeSet::new());
        assert!(running.iter().all(|(_, name)| is_agent(name)));
    }

    /// A process nobody put in the catalogue is still marked when somebody names it.
    ///
    /// This test is this machine's own process, named by its own name: if naming a process did not reach
    /// the scan, `intercept --agent <anything not on the list>` would be accepted, stored, reported back as
    /// working, and do nothing at all. That is what it did.
    #[test]
    fn naming_a_process_is_enough_to_have_it_marked() {
        let mine = std::process::id() as i32;
        let Some(me) = read_process(mine) else {
            return;
        };
        assert!(
            !is_agent(&me.name),
            "this test needs a name not in the catalogue, got {}",
            me.name
        );

        let unnamed = running_agents(&std::collections::BTreeSet::new());
        assert!(!unnamed.iter().any(|(_, name)| *name == me.name));

        let named = std::collections::BTreeSet::from([me.name.trim().to_ascii_lowercase()]);
        let found = running_agents(&named);
        assert!(
            found.iter().any(|(_, name)| *name == me.name),
            "naming {} did not get it marked",
            me.name
        );
    }

    /// Two answers in a row for the same process must be the same answer, and must not require two walks.
    #[test]
    fn an_answer_is_reused_for_a_moment() {
        let mut agents = Agents::new();
        let mine = std::process::id();
        assert_eq!(agents.of(mine), agents.of(mine));
        assert_eq!(agents.cache.len(), 1);
    }
}
