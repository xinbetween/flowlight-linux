//! Starting an agent so that it is governed before it runs.
//!
//! The order is the whole point. A process is created, stopped before it has executed a single instruction of
//! its own program, marked in the kernel as belonging to an agent, and only then released to run. Nothing it
//! does — including a connection in its first millisecond — happens unmarked.
//!
//! That is what the scan cannot promise. Marking on a timer notices an agent within a second and the kernel
//! carries the mark to everything it forks, which is right for a long-lived agent and has a hole at the
//! beginning: an agent that connects immediately connects before anything has noticed it exists.
//!
//! # Why this runs as you and not as root
//!
//! Because the agent has to. Everything else in Flowlight needs root — loading a probe does — and this needs
//! the opposite: an agent started by root would run as root, read root's configuration and write root's files.
//! So it refuses to start anything when it is root, and says what to do instead.
//!
//! # How the mark gets there first
//!
//! By marking *this* process and then forking. The kernel's fork tracepoint copies an agent's mark from parent
//! to child, in the kernel, at the moment the child is created — which is the same machinery that already
//! carries a mark from an agent to everything it starts. So the launcher marks itself, spawns the agent, and
//! the child is marked before it has run an instruction.
//!
//! The obvious alternative does not work. Holding the child between `fork` and `exec` — a pipe it blocks on,
//! released once the kernel has been told — deadlocks: `Command::spawn` does not return until the child execs,
//! because that is how it reports whether the exec succeeded. The parent would be waiting for the child to
//! exec and the child waiting for the parent to let it. Marking the parent needs none of that, and reuses a
//! path that is already carrying marks on every fork this machine makes.

use anyhow::{Context as _, Result, bail};
use flowlight_agents::launch::Environment;
use std::path::Path;
use std::process::Command;

/// What the daemon said about interception, as much of it as launching needs.
#[derive(Debug, Clone, Default)]
pub struct Governing {
    /// Where the bundle of this machine's roots plus Flowlight's is, if there is one.
    pub bundle: Option<String>,
    /// Whether this agent's connections are being terminated.
    pub terminated: bool,
}

/// Asks the daemon what it is doing about this agent.
pub fn governing(socket: &Path, agent: &str) -> Result<Governing> {
    let view: crate::client::InterceptReply = crate::client::ask(socket, r#"{"op":"intercept"}"#)
        .context(
            "asking the daemon what it is intercepting. `flowlightd launch` talks to a running daemon: it \
             does not read the database, because it runs as you and the database does not.",
        )?;
    Ok(Governing {
        terminated: view.running && view.agents.iter().any(|named| named == agent),
        bundle: view.bundle,
    })
}

/// Starts the command, marked before it runs, and waits for it.
///
/// Returns whatever the agent exited with, so that this is transparent to whatever started *it*: a supervisor
/// watching exit statuses sees the agent's, not Flowlight's.
pub fn run(
    socket: &Path,
    agent: &str,
    command: &[String],
    environment: &Environment,
) -> Result<std::process::ExitStatus> {
    refuse_if_root()?;
    let (program, arguments) = command
        .split_first()
        .context("nothing to run. `flowlightd launch -- claude`")?;

    // This process, marked, before anything is forked from it. The kernel copies the mark to the child at the
    // fork itself, so there is no window in which the agent exists and is not an agent.
    let ours = std::process::id();
    crate::client::ask::<bool>(
        socket,
        &format!(r#"{{"op":"mark","pid":{ours},"agent":{}}}"#, quoted(agent)),
    )
    .with_context(|| {
        format!(
            "telling the daemon that what this starts belongs to {agent}. Nothing was started: an agent \
             Flowlight is not governing is what this command exists to prevent."
        )
    })?;

    let mut builder = Command::new(program);
    builder.args(arguments);
    for (name, value) in &environment.variables {
        builder.env(name, value);
    }
    let mut child = builder.spawn().with_context(|| {
        format!("starting {program}. It has to be something on the path, or a path to something.")
    })?;
    child.wait().context("waiting for the agent to finish")
}

/// Refuses to start anything as root.
fn refuse_if_root() -> Result<()> {
    // SAFETY: a call that reads the current process's own identity and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let whose = std::env::var("SUDO_USER").ok();
    bail!(
        "this is the one Flowlight command that must not be run as root: an agent started by root would run \
         as root, read root's configuration and write root's files.{}",
        whose.map_or_else(
            || " Run it as the person the agent belongs to.".to_owned(),
            |user| format!(" Run it as {user}, without sudo.")
        )
    )
}

/// A string as JSON.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything else needs root and this needs the opposite, which is worth a test rather than a comment:
    /// the check is the only thing standing between a person and an agent running as root.
    #[test]
    fn root_is_refused_with_something_to_do_about_it() {
        // SAFETY: reads this process's own identity.
        let root = unsafe { libc::geteuid() } == 0;
        match refuse_if_root() {
            Ok(()) => assert!(!root, "running as root and did not refuse"),
            Err(err) => {
                assert!(root, "not running as root and refused anyway");
                let said = format!("{err:#}");
                assert!(said.contains("must not be run as root"), "{said}");
            }
        }
    }

    #[test]
    fn nothing_to_run_is_refused_rather_than_run() {
        let failed = run(
            Path::new("/nonexistent"),
            "claude",
            &[],
            &Environment::default(),
        );
        // Either the nothing-to-run message, or the root refusal when a test happens to be run as root.
        let said = format!("{:#}", failed.unwrap_err());
        assert!(
            said.contains("nothing to run") || said.contains("must not be run as root"),
            "{said}"
        );
    }

    /// Nothing is started when the mark could not be written. An agent running ungoverned is the outcome this
    /// whole command exists to prevent, so it has to be an error rather than a warning.
    #[test]
    fn a_mark_that_could_not_be_written_starts_nothing() {
        // SAFETY: reads this process's own identity.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let failed = run(
            Path::new("/nonexistent/flowlight.sock"),
            "claude",
            &["/bin/true".to_owned()],
            &Environment::default(),
        );
        let said = format!("{:#}", failed.unwrap_err());
        assert!(said.contains("Nothing was started"), "{said}");
    }

    #[test]
    fn a_name_is_quoted_as_json() {
        assert_eq!(quoted("claude"), "\"claude\"");
        assert_eq!(quoted("a\"name"), "\"a\\\"name\"");
    }
}
