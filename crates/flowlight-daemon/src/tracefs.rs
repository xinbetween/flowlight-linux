//! Finding the kernel's description of its own tracepoints.
//!
//! `tracefs` is mounted at `/sys/kernel/tracing` on anything current and at `/sys/kernel/debug/tracing` on
//! anything older, and on a few systems at neither until somebody mounts it. All three cases produce a
//! different sentence, because "could not read the tracepoint" is not a thing anyone can act on.

use anyhow::{Context as _, bail};
use std::path::{Path, PathBuf};

/// The two places a distribution mounts tracefs, newest first.
const CANDIDATES: [&str; 2] = ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"];

/// Where tracefs is mounted, if it is, without reading anything out of it.
///
/// Separate from [`format_text`] because the two questions have different permissions: the directory's
/// existence is visible to anybody, and the file inside it is readable only by root. Asking the first is how
/// `check` can tell "there is no tracefs here" from "you are not root", which are a mount command and a
/// `sudo` and should not be the same sentence.
pub fn mounted(root: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = root {
        return path.join("events").is_dir().then(|| path.to_path_buf());
    }
    // `/proc/mounts` rather than the directory, because the directory is `drwx------` on Ubuntu and a person
    // asking whether it exists is refused entry and told no. The mount table is readable by everybody and is
    // the thing that actually knows.
    if let Ok(table) = std::fs::read_to_string("/proc/mounts") {
        for line in table.lines() {
            let mut fields = line.split_whitespace();
            let (_source, point, kind) = (fields.next(), fields.next(), fields.next());
            if kind == Some("tracefs")
                && let Some(point) = point
            {
                return Some(PathBuf::from(point));
            }
        }
    }
    CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|root| root.join("events").is_dir())
}

/// Reads the `format` file for one tracepoint.
///
/// `root` overrides the search, for the case where tracefs is mounted somewhere unusual — and for tests,
/// which is the same case with a different motive.
pub fn format_text(root: Option<&Path>, category: &str, name: &str) -> anyhow::Result<String> {
    let roots: Vec<PathBuf> = match root {
        Some(path) => vec![path.to_path_buf()],
        None => CANDIDATES.iter().map(PathBuf::from).collect(),
    };

    let mut tried = Vec::new();
    for root in &roots {
        let path = root.join("events").join(category).join(name).join("format");
        match std::fs::read_to_string(&path) {
            Ok(text) => return Ok(text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                tried.push(path.display().to_string());
            }
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(err).context(format!(
                    "reading {}: tracefs is mounted but not readable. Flowlight needs root",
                    path.display()
                ));
            }
            Err(err) => return Err(err).context(format!("reading {}", path.display())),
        }
    }

    // Distinguish "tracefs is not there" from "this kernel does not have that tracepoint", because the first
    // is a mount command and the second is a kernel that cannot run this at all.
    let mounted = roots.iter().any(|root| root.join("events").is_dir());
    if mounted {
        bail!(
            "this kernel has no {category}/{name} tracepoint, so connections cannot be attributed on it. \
             Flowlight needs a kernel with CONFIG_NET built in, which is every distribution kernel since 4.18"
        );
    }
    bail!(
        "tracefs is not mounted, so the kernel's tracepoint layout cannot be read. \
         Mount it with `mount -t tracefs none /sys/kernel/tracing` and try again. Looked in: {}",
        tried.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The message a person actually gets when tracefs is missing has to name the fix. This asserts the fix
    /// is in it, because an error string is the one part of a daemon nobody tests and everybody reads.
    #[test]
    fn a_missing_tracefs_is_reported_with_the_command_that_fixes_it() {
        let dir = std::env::temp_dir().join("flowlight-tracefs-absent");
        let err = format_text(Some(&dir), "sock", "inet_sock_set_state").unwrap_err();
        let message = format!("{err}");
        assert!(message.contains("mount -t tracefs"), "{message}");
    }

    /// tracefs mounted but this tracepoint absent is a different problem with a different answer, and the
    /// two must not collapse into one message.
    #[test]
    fn a_missing_tracepoint_is_not_reported_as_a_missing_tracefs() {
        let dir = std::env::temp_dir().join("flowlight-tracefs-present");
        std::fs::create_dir_all(dir.join("events")).unwrap();
        let err = format_text(Some(&dir), "sock", "nonexistent").unwrap_err();
        let message = format!("{err}");
        assert!(
            message.contains("no sock/nonexistent tracepoint"),
            "{message}"
        );
        assert!(!message.contains("mount -t tracefs"), "{message}");
    }

    #[test]
    fn a_format_file_that_is_there_is_read() {
        let dir = std::env::temp_dir().join("flowlight-tracefs-ok");
        let events = dir.join("events").join("sock").join("demo");
        std::fs::create_dir_all(&events).unwrap();
        std::fs::write(events.join("format"), "name: demo\n").unwrap();
        assert_eq!(
            format_text(Some(&dir), "sock", "demo").unwrap(),
            "name: demo\n"
        );
    }
}
