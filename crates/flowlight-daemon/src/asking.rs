//! The key a hosted model needs, and where it is kept.
//!
//! Not in the database. A database gets copied: this one holds a history somebody may reasonably hand to a
//! colleague or attach to a bug report, and a key inside it travels with it. It lives in its own file next to
//! the database, mode 600, and is read at the moment it is needed and not before.
//!
//! # Why the mode is checked on the way in
//!
//! Because a key file that anybody on the machine can read is not a key file, and the failure is silent: it
//! works perfectly. Refusing to read it is the only moment anybody would find out.

use anyhow::{Context as _, Result, bail};
use std::path::{Path, PathBuf};

/// What the key file is called, beside the database.
const NAME: &str = "ask.key";

/// Where the key for a hosted provider lives, given where the database is.
///
/// Derived rather than configured, so that `--database` moves everything together and there is not a second
/// flag to get wrong.
pub fn key_path(database: &Path) -> PathBuf {
    database
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(NAME)
}

/// Whether there is a key on file. Does not read it.
pub fn have_key(database: &Path) -> bool {
    key_path(database).exists()
}

/// Reads the key, or an empty string when there is none.
///
/// Refuses a file anybody else can read. A key readable by every local user is the exact thing this tool
/// exists to point at in other people's software.
pub fn key(database: &Path) -> Result<String> {
    let path = key_path(database);
    if !path.exists() {
        return Ok(String::new());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let mode = std::fs::metadata(&path)
            .with_context(|| format!("looking at {}", path.display()))?
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            bail!(
                "{} is mode {mode:o}, so somebody besides its owner can read the key in it. \
                 `chmod 600 {}` and try again.",
                path.display(),
                path.display()
            );
        }
    }
    Ok(std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .to_owned())
}

/// Writes the key, or removes it when what was given is empty.
pub fn set_key(database: &Path, value: &str) -> Result<()> {
    let path = key_path(database);
    let value = value.trim();
    if value.is_empty() {
        if path.exists() {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Created restricted rather than created and then restricted: between the two there is a moment when the
    // key is on disk and readable, and a moment is all anything needs.
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("writing {}", path.display()))?
    };
    #[cfg(not(unix))]
    let mut file =
        std::fs::File::create(&path).with_context(|| format!("writing {}", path.display()))?;
    use std::io::Write as _;
    file.write_all(value.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Reads a key out of a file somebody already has, for `--key-file`.
///
/// A path rather than a flag with the key in it, because a key on a command line is a key in the shell's
/// history and in every process listing on the machine for as long as the command runs.
pub fn key_from(path: &Path) -> Result<String> {
    let value = std::fs::read_to_string(path)
        .with_context(|| format!("reading the key from {}", path.display()))?
        .trim()
        .to_owned();
    if value.is_empty() {
        bail!("{} is empty, so there is no key in it", path.display());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory of its own for one test, removed afterwards.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let path =
                std::env::temp_dir().join(format!("flowlight-key-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn database(&self) -> PathBuf {
            self.0.join("flowlight.db")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_key_lives_beside_the_database_and_not_in_it() {
        let scratch = Scratch::new("beside");
        assert_eq!(key_path(&scratch.database()), scratch.0.join("ask.key"));
    }

    #[test]
    fn a_key_written_is_a_key_read_back() {
        let scratch = Scratch::new("roundtrip");
        assert!(!have_key(&scratch.database()));
        assert_eq!(key(&scratch.database()).unwrap(), "");

        set_key(&scratch.database(), "  sekrit\n").unwrap();
        assert!(have_key(&scratch.database()));
        assert_eq!(key(&scratch.database()).unwrap(), "sekrit");
    }

    /// Written restricted, not written and then restricted.
    #[test]
    #[cfg(unix)]
    fn a_key_is_created_readable_by_nobody_else() {
        use std::os::unix::fs::MetadataExt as _;
        let scratch = Scratch::new("mode");
        set_key(&scratch.database(), "sekrit").unwrap();
        let mode = std::fs::metadata(key_path(&scratch.database()))
            .unwrap()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{mode:o}");
    }

    /// A key anybody can read is not a key, and the failure is silent unless somebody refuses it.
    #[test]
    #[cfg(unix)]
    fn a_key_file_anybody_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let scratch = Scratch::new("loose");
        set_key(&scratch.database(), "sekrit").unwrap();
        std::fs::set_permissions(
            key_path(&scratch.database()),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let failed = key(&scratch.database());
        let message = format!("{:#}", failed.unwrap_err());
        assert!(message.contains("chmod 600"), "{message}");
    }

    #[test]
    fn an_empty_key_removes_the_file() {
        let scratch = Scratch::new("forget");
        set_key(&scratch.database(), "sekrit").unwrap();
        set_key(&scratch.database(), "").unwrap();
        assert!(!have_key(&scratch.database()));
        // And removing one that is not there is not an error.
        set_key(&scratch.database(), "").unwrap();
    }

    #[test]
    fn a_key_can_come_from_a_file_somebody_already_has() {
        let scratch = Scratch::new("from");
        let path = scratch.0.join("elsewhere.key");
        std::fs::write(&path, "from-a-file\n").unwrap();
        assert_eq!(key_from(&path).unwrap(), "from-a-file");
        std::fs::write(&path, "  \n").unwrap();
        assert!(key_from(&path).is_err());
    }
}
