//! Logic shared between the eBPF programs and the daemon.
//!
//! Nothing here depends on Linux, which is deliberate: it means this crate builds and its tests run on any
//! machine, including the ones the rest of the project cannot be compiled on. Anything that needs a kernel
//! lives elsewhere and is checked by CI.

pub mod identity;

#[cfg(test)]
mod tests {
    use super::identity::*;

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
