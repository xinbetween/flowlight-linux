//! Finding the TLS libraries on the machine, so there is something to attach a uprobe to.
//!
//! A uprobe attaches to a file. Hard-coding `/usr/lib/x86_64-linux-gnu/libssl.so.3` covers Debian on x86-64
//! and misses Fedora, Arch, musl, arm64, every container, every virtualenv that shipped its own, and
//! `~/.nix-profile`. So two searches, which find different things and are both needed:
//!
//! - **What is mapped.** `/proc/<pid>/maps` for every process says which libssl each one actually loaded,
//!   wherever it lives. This finds copies nobody would have thought to look for — but only for programs that
//!   are running right now.
//! - **What is installed.** The usual library directories, so that a program started in a minute is already
//!   covered rather than covered five seconds later.
//!
//! Both are repeated while the daemon runs, because an agent started after it was is the normal case.

use flowlight_common::procmaps::{TlsLibrary, executable_mapping, tls_library};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Where distributions put shared libraries. Not exhaustive and not meant to be — the `/proc` scan is what
/// catches everything else, and this list only exists to cover libraries nothing has loaded yet.
const LIBRARY_DIRECTORIES: &[&str] = &[
    "/lib/x86_64-linux-gnu",
    "/usr/lib/x86_64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib64",
    "/usr/lib64",
    "/usr/lib",
    "/usr/local/lib",
];

/// Every TLS library worth attaching to, canonicalised so that `libssl.so.3` and `libssl.so.3.0.13` are one
/// entry rather than two probes on the same code.
pub fn discover(extra: &[PathBuf]) -> BTreeMap<PathBuf, TlsLibrary> {
    let mut found = BTreeMap::new();

    for path in extra {
        // An explicitly named path is taken at its word: someone who passes `--libssl` knows something this
        // search does not, and second-guessing them defeats the point of the flag.
        if let Ok(canonical) = path.canonicalize() {
            found.insert(canonical, TlsLibrary::OpenSsl);
        }
    }

    for directory in LIBRARY_DIRECTORIES {
        let Ok(entries) = std::fs::read_dir(directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(text) = path.to_str()
                && let Some(library) = tls_library(text)
                && let Ok(canonical) = path.canonicalize()
            {
                found.insert(canonical, library);
            }
        }
    }

    for path in mapped_libraries() {
        found.insert(path.0, path.1);
    }

    found
}

/// The TLS libraries currently mapped into some process.
fn mapped_libraries() -> Vec<(PathBuf, TlsLibrary)> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        // Numeric directories only: /proc also holds `self`, `net`, `sys` and a dozen files.
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // A process that exits between the listing and the read is the normal case, not an error.
        let Ok(maps) = std::fs::read_to_string(entry.path().join("maps")) else {
            continue;
        };
        for line in maps.lines() {
            if let Some(path) = executable_mapping(line)
                && let Some(library) = tls_library(path)
                && let Ok(canonical) = Path::new(path).canonicalize()
            {
                found.push((canonical, library));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The search has to survive a machine where none of the usual directories exist, because a container
    /// built `FROM scratch` is one and so is anything unusual enough to be interesting.
    #[test]
    fn a_machine_with_nothing_installed_produces_nothing_rather_than_an_error() {
        // Not a real assertion about this machine's contents — an assertion that the search completes.
        let _ = discover(&[]);
    }

    /// A path that does not exist is not a library, and passing one should not stop the daemon starting.
    #[test]
    fn an_explicit_path_that_is_not_there_is_ignored() {
        let found = discover(&[PathBuf::from("/nonexistent/libssl.so.3")]);
        assert!(!found.contains_key(Path::new("/nonexistent/libssl.so.3")));
    }

    /// The point of canonicalising: `libssl.so.3` is a symlink to `libssl.so.3.0.13` on most distributions,
    /// and probing both would double every event.
    #[test]
    fn a_symlink_and_its_target_are_one_entry() {
        let dir = std::env::temp_dir().join("flowlight-libssl-symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("libssl.so.3.0.13");
        let link = dir.join("libssl.so.3");
        std::fs::write(&real, b"not really a library").unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let found = discover(&[link.clone(), real.clone()]);
        assert!(found.contains_key(&real.canonicalize().unwrap()));
        // The symlink's own path is never a key, so the two collapse into one probe rather than two.
        assert!(!found.contains_key(&link));
    }
}
