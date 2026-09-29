//! Reading the process tree, so that a request can be attributed to the agent that caused it.
//!
//! [`flowlight_agents::ancestry`] decides; this reads. The split is the same one the rest of the project
//! uses — the part that can be wrong in an interesting way is testable on a machine with no `/proc`, and
//! the part that cannot is fifty lines of reading files.

use flowlight_agents::ancestry::{Process, agent_for};
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

    /// Two answers in a row for the same process must be the same answer, and must not require two walks.
    #[test]
    fn an_answer_is_reused_for_a_moment() {
        let mut agents = Agents::new();
        let mine = std::process::id();
        assert_eq!(agents.of(mine), agents.of(mine));
        assert_eq!(agents.cache.len(), 1);
    }
}
