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
//! # Where `comm` lies
//!
//! The kernel truncates it to fifteen characters plus a NUL (`TASK_COMM_LEN`). `claude` survives;
//! `claude-code-wrapper` becomes `claude-code-wra`. Anything matching on `comm` alone inherits that, which is
//! why it is a fallback here and never the answer when a path is available.

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

/// The name of the tool a path belongs to, ignoring version directories, layout directories and store hashes.
///
/// Returns `None` when nothing in the path qualifies, which leaves the caller to fall back to `comm` and then
/// to the pid — in that order, because each is worse than the last and saying so is better than guessing.
pub fn name_from_path(path: &str) -> Option<&str> {
    path.split('/')
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
                key: name.to_owned(),
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
                key: name.to_owned(),
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
