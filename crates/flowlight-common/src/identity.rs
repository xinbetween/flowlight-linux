//! What to call a process, and what to key its rules on.
//!
//! Every allowlist, rule, guardrail and attribution is keyed on identity, so getting this wrong does not
//! produce a wrong label — it produces rules that silently match nothing. The design note calls this the open
//! problem, and it is the first thing built because it is the one that cannot be retrofitted.
//!
//! macOS has bundle identifiers: stable, unique, assigned by the developer. Linux has none of that. What it
//! has instead is an executable path, a sixteen-byte `comm`, and a cgroup — each of which lies in a different
//! way.
//!
//! # Where the path lies
//!
//! Installers that keep one file per release make the filename the version. The macOS build hit this with
//! Claude Code at `~/.local/share/claude/versions/2.1.283`, where naming the process after its executable gave
//! the agent a new identity on every update and took its allowlist and history with it. Linux has the same
//! shape several times over:
//!
//! - `/nix/store/<32-char-hash>-claude-code-2.1.283/bin/claude`
//! - `~/.asdf/installs/nodejs/20.11.0/bin/node`
//! - `~/.local/share/pnpm/global/5/node_modules/...`
//!
//! And one shape that is Linux's alone: `/proc/<pid>/exe` for a process whose file has been replaced resolves
//! to `"/usr/bin/curl (deleted)"`. Every upgrade of a running program produces it, so it is the common case
//! during exactly the window where attribution matters most.
//!
//! # Where `comm` lies
//!
//! The kernel truncates it to fifteen characters plus a NUL (`TASK_COMM_LEN`). `claude` survives;
//! `claude-code-wrapper` becomes `claude-code-wra`. Anything matching on `comm` alone inherits that, which is
//! why it is a fallback here and never the answer when a path is available.

use alloc::{
    format,
    string::{String, ToString},
};

/// Path components that describe a layout rather than a program, so they are never the name.
const LAYOUT: &[&str] = &[
    "bin",
    "sbin",
    "libexec",
    "lib",
    "lib64",
    "share",
    "local",
    "opt",
    "usr",
    "srv",
    "versions",
    "installs",
    "current",
    "latest",
    "stable",
    "node_modules",
    ".bin",
    "store",
    "profiles",
    "per-user",
    "result",
];

/// What the kernel appends to `/proc/<pid>/exe` when the executable has been unlinked.
const DELETED: &str = " (deleted)";

/// Whether a path component is a version rather than a name.
///
/// `2.1.283`, `v2.1.283`, `20.11.0-1`. Digits and dots, an optional leading `v`, an optional build tail. The
/// `v` form is why "contains a letter" is not enough on its own.
pub fn is_version(component: &str) -> bool {
    let s = component
        .strip_prefix('v')
        .or_else(|| component.strip_prefix('V'))
        .unwrap_or(component);
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => {}
        _ => return false,
    }
    s.contains('.')
        && s.chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
}

/// Whether a component is a content-addressed store entry: a long hash, or a hash followed by a name.
///
/// Nix store paths are `<32 base32 chars>-<name>-<version>`. The hash carries no meaning to a person and
/// changes with every rebuild, so an identity containing one is an identity that changes for reasons the user
/// did not cause.
fn strip_store_hash(component: &str) -> &str {
    let Some((hash, rest)) = component.split_once('-') else {
        return component;
    };
    let hashish = hash.len() >= 24 && hash.chars().all(|c| c.is_ascii_alphanumeric());
    if hashish && !rest.is_empty() {
        rest
    } else {
        component
    }
}

/// Removes the kernel's `" (deleted)"` marker from a resolved `/proc/<pid>/exe`.
///
/// Worth its own function rather than a line inside the parser: the marker is a statement about the *file*,
/// never about the program, and a caller that wants to know the file is gone should ask that question rather
/// than read it out of a name.
pub fn strip_deleted_marker(path: &str) -> &str {
    path.strip_suffix(DELETED).unwrap_or(path)
}

/// Whether a resolved executable path says the file behind it has been unlinked.
///
/// Usually an upgrade in progress. The daemon has no use for this yet; Coverage will, because "the binary was
/// replaced while we were watching it" is a better explanation than a name that quietly changed.
pub fn executable_was_replaced(path: &str) -> bool {
    path.ends_with(DELETED)
}

/// The name of the tool a path belongs to, ignoring version directories, layout directories and store hashes.
///
/// Returns `None` when nothing in the path qualifies, which leaves the caller to fall back to `comm` and then
/// to the pid — in that order, because each is worse than the last and saying so is better than guessing.
pub fn name_from_path(path: &str) -> Option<&str> {
    strip_deleted_marker(path)
        .split('/')
        .rev()
        .map(strip_store_hash)
        .find(|component| {
            !component.is_empty()
                && component.chars().any(|c| c.is_alphabetic())
                && !is_version(component)
                && !component.starts_with('.')
                && !LAYOUT.contains(&component.to_ascii_lowercase().as_str())
        })
}

/// How confident we are about a name, which the interface has to be able to show.
///
/// A rule keyed on something derived from `comm` may be keyed on a truncation, and a person deciding whether
/// their allowlist is working deserves to know which of these they are looking at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Derived from a readable executable path.
    Path,
    /// Derived from `comm`, and possibly truncated to fifteen characters.
    Comm,
    /// Nothing was readable. The identity is the pid and does not outlive it.
    Pid,
}

impl Confidence {
    /// A word for the interface and for the JSON, chosen so that the least trustworthy is also the one that
    /// reads as least trustworthy.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Comm => "comm",
            Self::Pid => "pid",
        }
    }
}

/// What a process is called and how much that is worth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The key rules are matched against.
    pub key: String,
    /// Where the key came from, and therefore how much it is worth.
    pub confidence: Confidence,
}

impl Identity {
    /// Derives an identity from what `/proc` could be read for a process.
    ///
    /// `exe` is `/proc/<pid>/exe` resolved, which fails for a process that has exited or one we may not read.
    /// `comm` is `/proc/<pid>/comm`, always available while the process lives and always possibly truncated.
    pub fn derive(exe: Option<&str>, comm: Option<&str>, pid: i32) -> Self {
        if let Some(name) = exe.and_then(name_from_path) {
            return Self {
                key: name.to_string(),
                confidence: Confidence::Path,
            };
        }
        // `comm` can itself be a version, if the running file is one — the same trap, arriving by the other
        // route. A version is never an identity, whichever field it came from.
        if let Some(name) = comm
            .map(str::trim)
            .filter(|c| !c.is_empty() && !is_version(c))
        {
            return Self {
                key: name.to_string(),
                confidence: Confidence::Comm,
            };
        }
        Self {
            key: format!("pid {pid}"),
            confidence: Confidence::Pid,
        }
    }

    /// Whether this identity is stable enough to key a saved rule on.
    ///
    /// A pid is not: it is reused, and a rule keyed on one would later match an unrelated process. The
    /// interface should refuse to write such a rule rather than write one that quietly means something else
    /// next week.
    pub fn is_stable(&self) -> bool {
        self.confidence != Confidence::Pid
    }

    /// Whether the name may have been cut short by the kernel, so the interface can say so.
    pub fn may_be_truncated(&self) -> bool {
        self.confidence == Confidence::Comm && self.key.len() >= 15
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The failure this whole module exists to prevent, in the shape the macOS build met it: an installer that
    // keeps one executable per release, where naming the process after its file gives the agent a new identity
    // on every update and takes its allowlist and history with it.
    #[test]
    fn a_versioned_install_is_named_for_the_tool_not_the_release() {
        assert_eq!(
            name_from_path("/home/x/.local/share/claude/versions/2.1.283"),
            Some("claude")
        );
        assert_eq!(
            name_from_path("/home/x/.local/share/claude/versions/2.1.283/bin/claude"),
            Some("claude")
        );
    }

    #[test]
    fn a_nix_store_path_loses_its_hash() {
        assert_eq!(
            name_from_path(
                "/nix/store/8k4rj2qz9vx1p7m3n5w6y8t0abcdefgh-claude-code-2.1.283/bin/claude"
            ),
            Some("claude"),
        );
    }

    /// The hash is what makes a store path change on every rebuild. Without stripping it, the fallback would
    /// be the directory name, and the identity would move for reasons nobody caused.
    #[test]
    fn a_store_hash_is_not_itself_an_identity() {
        assert_eq!(
            name_from_path("/nix/store/8k4rj2qz9vx1p7m3n5w6y8t0abcdefgh-claude-code-2.1.283"),
            Some("claude-code-2.1.283"),
        );
    }

    #[test]
    fn version_manager_layouts_name_the_tool() {
        assert_eq!(
            name_from_path("/home/x/.asdf/installs/nodejs/20.11.0/bin/node"),
            Some("node")
        );
        assert_eq!(name_from_path("/usr/local/bin/curl"), Some("curl"));
        assert_eq!(name_from_path("/opt/google/chrome/chrome"), Some("chrome"));
    }

    #[test]
    fn versions_are_recognised_in_every_form_they_arrive_in() {
        for v in ["2.1.283", "v2.1.283", "V2.1.283", "20.11.0-1", "1.0"] {
            assert!(is_version(v), "{v} should read as a version");
        }
        for name in ["claude", "python3.13", "node", "lib64", "x86_64", "v8"] {
            assert!(!is_version(name), "{name} should not read as a version");
        }
    }

    /// `python3.13` contains digits and a dot and is still a name. Treating it as a version would erase every
    /// Python on the machine into its parent directory.
    #[test]
    fn a_name_containing_digits_survives() {
        assert_eq!(
            name_from_path("/home/x/.pyenv/versions/3.13.5/bin/python3.13"),
            Some("python3.13")
        );
    }

    #[test]
    fn a_path_of_nothing_but_layout_has_no_name() {
        assert_eq!(name_from_path("/usr/local/bin/"), None);
        assert_eq!(name_from_path(""), None);
    }

    /// Upgrading a package while the old binary is still running is not an edge case, it is Tuesday. Without
    /// stripping the marker the identity becomes `curl (deleted)` — a name that matches no rule anyone wrote,
    /// for the duration of every upgrade.
    #[test]
    fn a_replaced_executable_is_still_the_same_program() {
        assert_eq!(name_from_path("/usr/bin/curl (deleted)"), Some("curl"));
        assert!(executable_was_replaced("/usr/bin/curl (deleted)"));
        assert!(!executable_was_replaced("/usr/bin/curl"));
        let id = Identity::derive(Some("/usr/bin/curl (deleted)"), Some("curl"), 42);
        assert_eq!(id.key, "curl");
        assert_eq!(id.confidence, Confidence::Path);
    }

    /// A file genuinely named `(deleted)` would be pathological, but the marker is only a marker at the end of
    /// the whole path — not wherever the word appears.
    #[test]
    fn the_deleted_marker_is_only_stripped_from_the_end() {
        assert_eq!(
            strip_deleted_marker("/usr/bin/curl (deleted)/x"),
            "/usr/bin/curl (deleted)/x"
        );
    }

    // Confidence

    #[test]
    fn a_readable_path_is_the_best_answer() {
        let id = Identity::derive(Some("/usr/bin/curl"), Some("curl"), 42);
        assert_eq!(id.key, "curl");
        assert_eq!(id.confidence, Confidence::Path);
        assert!(id.is_stable());
    }

    #[test]
    fn comm_is_used_only_when_the_path_is_gone() {
        let id = Identity::derive(None, Some("claude"), 42);
        assert_eq!(id.key, "claude");
        assert_eq!(id.confidence, Confidence::Comm);
    }

    /// The same trap arriving by the other route: if the running file is a version, `comm` is a version too.
    #[test]
    fn a_version_in_comm_is_still_not_an_identity() {
        let id = Identity::derive(None, Some("2.1.283"), 42);
        assert_eq!(id.confidence, Confidence::Pid);
        assert!(!id.is_stable());
    }

    /// A pid is reused. A rule keyed on one would later match an unrelated process, so the interface has to be
    /// able to refuse to write it.
    #[test]
    fn a_pid_identity_is_never_stable() {
        let id = Identity::derive(None, None, 42);
        assert_eq!(id.key, "pid 42");
        assert!(!id.is_stable());
    }

    /// The kernel cuts `comm` at fifteen characters. A rule keyed on the result may be keyed on a truncation,
    /// and the person reading their allowlist deserves to be told that rather than left to wonder.
    #[test]
    fn a_comm_at_the_kernel_limit_is_flagged_as_possibly_cut_short() {
        let id = Identity::derive(None, Some("claude-code-wra"), 42);
        assert!(id.may_be_truncated());
        let short = Identity::derive(None, Some("claude"), 42);
        assert!(!short.may_be_truncated());
    }

    #[test]
    fn a_path_derived_name_is_never_flagged_as_truncated() {
        let id = Identity::derive(
            Some("/usr/bin/claude-code-wrapper"),
            Some("claude-code-wra"),
            42,
        );
        assert_eq!(id.key, "claude-code-wrapper");
        assert!(!id.may_be_truncated());
    }
}
