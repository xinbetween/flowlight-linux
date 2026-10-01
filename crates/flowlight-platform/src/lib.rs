//! What a machine can and cannot do, read from the files that say so.
//!
//! Everything Flowlight needs of a machine is a fact somebody can check: a kernel new enough to have the
//! probes, a `tracefs` to read a tracepoint's layout out of, permission to load a program, and — for refusing
//! connections rather than only watching them — a cgroup v2 hierarchy. Each of those is readable, and the
//! difference between "this does not work here" and "this does not work here *because*" is this crate.
//!
//! # Every reader takes its root
//!
//! `hierarchy("/sys/fs/cgroup")` on a machine and `hierarchy(temporary_directory)` in a test. That is not
//! tidiness: the whole point of this crate is the shapes a machine can be in, and the only way to have a test
//! for the hybrid cgroup hierarchy on a machine that does not have one is to write the directory out.
//!
//! It also means this crate builds and its tests run anywhere, including the machines the rest of the project
//! cannot be compiled on.

use std::path::{Path, PathBuf};

/// The kernel, as far as Flowlight is concerned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kernel {
    /// What `uname -r` says, in full.
    pub release: String,
    /// The first number.
    pub major: u32,
    /// The second.
    pub minor: u32,
}

/// The oldest kernel the probes attach to, and why it is that one.
///
/// 4.18 is where `bpf_get_current_cgroup_id` and the socket-path tracepoint arrived together; it is also what
/// RHEL 8 shipped, which is the oldest thing anybody runs an agent on.
pub const OLDEST_KERNEL: (u32, u32) = (4, 18);

impl Kernel {
    /// Reads a release string. `6.8.0-45-generic`, `5.14.0-427.el9.x86_64`, `6.6.9-arch1-1`.
    ///
    /// Everything after the first two numbers is the distribution's business and is kept as text rather than
    /// parsed: a patch level is not a thing Flowlight has ever needed, and `427.el9` is not a number.
    pub fn parse(release: &str) -> Option<Self> {
        let release = release.trim();
        let mut numbers = release
            .split(|c: char| !c.is_ascii_digit())
            .filter(|part| !part.is_empty());
        let major = numbers.next()?.parse().ok()?;
        let minor = numbers.next()?.parse().ok()?;
        Some(Self {
            release: release.to_owned(),
            major,
            minor,
        })
    }

    /// Whether the probes can attach to this kernel at all.
    pub fn is_new_enough(&self) -> bool {
        (self.major, self.minor) >= OLDEST_KERNEL
    }
}

/// What a machine's cgroup layout is, as far as refusing connections is concerned.
///
/// `cgroup/connect4` is a v2 program type. On a machine with no v2 hierarchy there is nothing to attach it to,
/// and Flowlight can watch but not refuse — which is a sentence worth saying rather than an attach that fails
/// with `ENOENT` and a path in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hierarchy {
    /// cgroup v2 alone, mounted here. What every distribution has done since 2019.
    Unified(PathBuf),
    /// v1 and v2 side by side, with v2 here — `/sys/fs/cgroup/unified`, usually. RHEL 8's default, and
    /// Ubuntu's before 21.10.
    Hybrid(PathBuf),
    /// v1 only. Nothing can be refused.
    LegacyOnly,
}

impl Hierarchy {
    /// Where to attach, when there is somewhere.
    pub fn root(&self) -> Option<&Path> {
        match self {
            Self::Unified(path) | Self::Hybrid(path) => Some(path),
            Self::LegacyOnly => None,
        }
    }

    /// What this means for refusing connections, in a sentence.
    pub fn described(&self) -> String {
        match self {
            Self::Unified(path) => format!("cgroup v2 at {}", path.display()),
            Self::Hybrid(path) => format!(
                "a hybrid hierarchy, with cgroup v2 at {} — which is where the hooks go",
                path.display()
            ),
            Self::LegacyOnly => {
                "cgroup v1 only, so connections cannot be refused — `cgroup/connect4` is a v2 program type. \
                 Watching is unaffected. Booting with `systemd.unified_cgroup_hierarchy=1` changes it."
                    .to_owned()
            }
        }
    }
}

/// Reads the cgroup layout under a root, which is `/sys/fs/cgroup` on a machine.
///
/// `cgroup.controllers` is the file that only exists in a v2 tree, which is why it is what is looked for
/// rather than the mount type: a v1 tree has `cgroup.procs` too, and a bind mount of either looks the same to
/// `statfs`.
pub fn hierarchy(root: &Path) -> Hierarchy {
    if root.join("cgroup.controllers").is_file() {
        return Hierarchy::Unified(root.to_path_buf());
    }
    // Where a hybrid hierarchy keeps the v2 tree. Named rather than searched for, because these two are the
    // only places anything has ever mounted it.
    for inside in ["unified", "systemd"] {
        let candidate = root.join(inside);
        if candidate.join("cgroup.controllers").is_file() {
            return Hierarchy::Hybrid(candidate);
        }
    }
    Hierarchy::LegacyOnly
}

/// What SELinux is doing, which decides whether a confined service may load a program at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Selinux {
    /// Not in the kernel, or not mounted.
    Absent,
    /// Loaded, and refusals are logged rather than applied.
    Permissive,
    /// Loaded, and applied.
    Enforcing,
}

impl Selinux {
    /// What it means for Flowlight, in a sentence.
    pub fn described(self) -> &'static str {
        match self {
            Self::Absent => "SELinux is not enforcing anything here",
            Self::Permissive => {
                "SELinux is permissive, so a denial would be logged rather than applied"
            }
            Self::Enforcing => {
                "SELinux is enforcing. Running from a terminal is unconfined and unaffected; a confined \
                 service may be denied `bpf` — `ausearch -m avc -ts recent` says so when it happens"
            }
        }
    }
}

/// Reads what SELinux is doing, under a root which is `/sys/fs` on a machine.
pub fn selinux(root: &Path) -> Selinux {
    match std::fs::read_to_string(root.join("selinux/enforce")) {
        Ok(text) => {
            if text.trim() == "1" {
                Selinux::Enforcing
            } else {
                Selinux::Permissive
            }
        }
        Err(_) => Selinux::Absent,
    }
}

/// What the kernel has been told about who may load a BPF program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bpf {
    /// `kernel.unprivileged_bpf_disabled`, when it is readable. Flowlight runs as root, so this says nothing
    /// about whether *it* can load anything — it is in the report because a machine where it is 2 is a machine
    /// somebody has made decisions about, and that is worth knowing before guessing at a failure.
    pub unprivileged_disabled: Option<String>,
    /// Whether anything is permitted to load programs at all. `/proc/sys/kernel/bpf_stats_enabled` is not it;
    /// there is no single switch, and a kernel built without `CONFIG_BPF_SYSCALL` has no `bpf` syscall rather
    /// than a file saying so — which is why loading is the only real test and this is context for it.
    pub syscall_present: bool,
}

/// Reads what is knowable about BPF, under a proc root which is `/proc` on a machine.
pub fn bpf(proc_root: &Path) -> Bpf {
    let read = |path: &str| {
        std::fs::read_to_string(proc_root.join(path))
            .ok()
            .map(|text| text.trim().to_owned())
    };
    Bpf {
        unprivileged_disabled: read("sys/kernel/unprivileged_bpf_disabled"),
        // Every kernel with `CONFIG_BPF_SYSCALL` has this directory; one built without it does not.
        syscall_present: proc_root
            .join("sys/kernel")
            .join("unprivileged_bpf_disabled")
            .exists()
            || proc_root.join("sys/net/core/bpf_jit_enable").exists(),
    }
}

/// Reads a user out of `/etc/passwd`, by name or by the number they already gave.
///
/// By hand rather than through `getpwnam`, for the reason the ASN lookup speaks DNS itself: the daemon is
/// statically linked against musl, which resolves a name by reading this file and not by asking NSS. Parsing
/// it here means the answer is the same whatever it was linked against, and it can be tested against a file
/// written out rather than against whoever happens to exist on the machine running the tests.
///
/// A name that is not in the file is `None`, which is a refusal and not a guess: the alternative is a socket
/// belonging to a uid nobody has.
pub fn user(passwd: &Path, named: &str) -> Option<(u32, u32)> {
    let named = named.trim();
    if named.is_empty() {
        return None;
    }

    // A number is taken at its word. Somebody who writes `--socket-owner 1000` knows which uid they mean, and
    // a machine where that uid is in no password file is a normal thing — a container, mostly.
    if let Ok(uid) = named.parse::<u32>() {
        let gid = read_passwd(passwd)
            .into_iter()
            .find(|(_, found, _)| *found == uid)
            .map(|(_, _, gid)| gid);
        return Some((uid, gid.unwrap_or(uid)));
    }

    read_passwd(passwd)
        .into_iter()
        .find(|(name, _, _)| name == named)
        .map(|(_, uid, gid)| (uid, gid))
}

/// Every name, uid and gid in a password file, skipping anything that is not those three things.
fn read_passwd(passwd: &Path) -> Vec<(String, u32, u32)> {
    let Ok(text) = std::fs::read_to_string(passwd) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| {
            // `name:password:uid:gid:…`, and a line that is not that shape is a line to step over rather than
            // a reason to fail: a password file with a comment in it is still a password file.
            let mut fields = line.split(':');
            let name = fields.next()?;
            let _password = fields.next()?;
            let uid = fields.next()?.parse().ok()?;
            let gid = fields.next()?.parse().ok()?;
            Some((name.to_owned(), uid, gid))
        })
        .collect()
}

/// Whether a failure was the machine refusing permission, rather than something being absent.
///
/// The distinction is the whole of a useful report. "This machine has no tracefs" is a mount command; "you are
/// not root" is a `sudo`; and a report that says the first when it means the second tells somebody their
/// machine cannot do something it does perfectly well.
///
/// It looks through the chain rather than at the top, because by the time an error has been given its context
/// the `io::Error` is several layers down — and the kind is the only part of it that is a fact rather than a
/// sentence.
pub fn permission_denied(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|cause| cause.kind() == std::io::ErrorKind::PermissionDenied)
}

/// The kernel release this machine is running, from `uname`.
///
/// Read from `/proc/sys/kernel/osrelease` rather than by calling `uname`, so that it comes from a file like
/// everything else here and can be written out in a test.
pub fn kernel(proc_root: &Path) -> Option<Kernel> {
    let text = std::fs::read_to_string(proc_root.join("sys/kernel/osrelease")).ok()?;
    Kernel::parse(&text)
}

/// One watcher per database, enforced rather than asked for.
///
/// Two daemons against one database is not a crash and not an error: it is both of them attaching uprobes to
/// the same libraries, both reading every call, and both writing it down. Every number the thing reports is
/// then doubled, and nothing says so — which is the worst shape a bug can take in a tool whose whole claim is
/// that its numbers are what happened.
///
/// It is also easy to do by accident. Start the service, then run `sudo flowlightd` to look at something, and
/// that is the state. That is exactly how it was found: a stray daemon left over from one test doubled the
/// output of the next, and the arithmetic was correct both times.
///
/// An advisory lock on a file beside the database, held for as long as the process lives. `flock` rather than
/// a pid file alone, because a pid file left behind by a daemon that was killed is a pid file that locks
/// everybody out of their own machine — the kernel releases this when the process goes, however it goes.
#[derive(Debug)]
pub struct Watching {
    /// Held open, because the lock lives on the open file description rather than on the path.
    _file: std::fs::File,
}

/// Who holds it, when somebody does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Taken {
    /// The lock file.
    pub path: PathBuf,
    /// The pid written in it, when it is readable and looks like one. It is a courtesy rather than a
    /// guarantee: the lock is what is authoritative, and the number is what makes the sentence useful.
    pub pid: Option<u32>,
}

/// Takes the right to watch with this database, or says who already has it.
///
/// The lock file is `<database>.watching`, beside the database rather than in `/run`: the thing being
/// protected is the database, and somebody who names another database with `--database` is not in conflict
/// with this one.
pub fn watch_with(database: &Path) -> Result<Watching, Taken> {
    let path = lock_path(database);
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
    {
        Ok(file) => file,
        // A directory nobody can write to is not two daemons, and refusing to start over it would be worse
        // than the problem: the answer is to let the caller carry on without the guard.
        Err(_) => return Err(Taken { path, pid: None }),
    };

    // `LOCK_NB`, because the point is to be told rather than to wait: a daemon that blocked here would look
    // like one that had started.
    let held = unsafe {
        libc::flock(
            std::os::unix::io::AsRawFd::as_raw_fd(&file),
            libc::LOCK_EX | libc::LOCK_NB,
        )
    };
    if held != 0 {
        let pid = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| text.trim().parse().ok());
        return Err(Taken { path, pid });
    }

    // Written through the handle that already holds the lock, rather than by opening the path again: a second
    // open would be a second file description, which is a second lock, which is the thing being prevented.
    //
    // Best effort, both of them. The lock is what is authoritative; the number only makes the sentence the
    // other daemon prints more useful than "somebody".
    let _ = file.set_len(0);
    let _ = std::io::Write::write_all(&mut &file, format!("{}\n", std::process::id()).as_bytes());

    Ok(Watching { _file: file })
}

/// Where the lock for a database lives.
pub fn lock_path(database: &Path) -> PathBuf {
    let mut path = database.as_os_str().to_owned();
    path.push(".watching");
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("flowlight-platform-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a temporary directory");
        path
    }

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("a directory");
        }
        std::fs::write(path, contents).expect("a file");
    }

    /// Release strings as four distributions actually write them.
    #[test]
    fn a_release_string_is_read_however_the_distribution_writes_it() {
        for (text, major, minor) in [
            ("6.8.0-45-generic", 6, 8),
            ("5.14.0-427.el9.x86_64", 5, 14),
            ("6.6.9-arch1-1", 6, 6),
            ("4.18.0-513.el8.x86_64", 4, 18),
            ("6.17.0-1022-azure\n", 6, 17),
        ] {
            let kernel = Kernel::parse(text).expect(text);
            assert_eq!((kernel.major, kernel.minor), (major, minor), "{text}");
            assert!(kernel.is_new_enough(), "{text}");
        }
        assert!(Kernel::parse("nonsense").is_none());
        assert!(Kernel::parse("5").is_none());
    }

    /// The boundary is a boundary, and 4.17 is on the wrong side of it.
    #[test]
    fn a_kernel_older_than_the_probes_is_not_new_enough() {
        assert!(
            !Kernel::parse("4.17.19-200.fc28.x86_64")
                .unwrap()
                .is_new_enough()
        );
        assert!(
            !Kernel::parse("3.10.0-1160.el7.x86_64")
                .unwrap()
                .is_new_enough()
        );
        assert!(Kernel::parse("4.18.0").unwrap().is_new_enough());
    }

    /// The layout every current distribution has.
    #[test]
    fn a_unified_hierarchy_is_where_the_hooks_go() {
        let root = scratch("unified");
        write(&root.join("cgroup.controllers"), "cpuset cpu io memory\n");
        let found = hierarchy(&root);
        assert_eq!(found, Hierarchy::Unified(root.clone()));
        assert_eq!(found.root(), Some(root.as_path()));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// RHEL 8's default, and the reason the path was worth looking for rather than assuming: the v2 tree is
    /// there, one directory down, and an attach to the top of a hybrid hierarchy fails.
    #[test]
    fn a_hybrid_hierarchy_keeps_the_v2_tree_one_directory_down() {
        let root = scratch("hybrid");
        // v1's files at the top, v2's one level in.
        write(&root.join("cgroup.procs"), "1\n");
        write(&root.join("unified/cgroup.controllers"), "\n");
        let found = hierarchy(&root);
        assert_eq!(found, Hierarchy::Hybrid(root.join("unified")));
        assert!(found.described().contains("hybrid"));
        assert_eq!(found.root(), Some(root.join("unified").as_path()));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// And a machine with neither can watch but not refuse, which the sentence says.
    #[test]
    fn a_machine_with_no_v2_tree_can_watch_but_not_refuse() {
        let root = scratch("legacy");
        write(&root.join("cgroup.procs"), "1\n");
        let found = hierarchy(&root);
        assert_eq!(found, Hierarchy::LegacyOnly);
        assert_eq!(found.root(), None);
        assert!(found.described().contains("cannot be refused"));
        assert!(found.described().contains("Watching is unaffected"));
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The distinction the whole report rests on, and the one a real machine caught being wrong: a directory
    /// that is `drwx------` refuses a person *entry*, so looking inside it to find out whether it exists
    /// answers "it does not" — and the report then told somebody their machine could not be watched.
    #[test]
    fn being_refused_is_not_the_same_as_being_absent() {
        let root = scratch("refused");
        let unreadable = root.join("locked");
        std::fs::create_dir_all(&unreadable).expect("a directory");
        write(&unreadable.join("secret"), "x");
        std::fs::set_permissions(
            &unreadable,
            std::os::unix::fs::PermissionsExt::from_mode(0o000),
        )
        .expect("a mode");

        let refused: anyhow::Error = std::fs::read_to_string(unreadable.join("secret"))
            .map_err(|err| {
                anyhow::Error::new(err)
                    .context("reading the layout")
                    .context("checking")
            })
            .expect_err("a refusal");
        let absent: anyhow::Error = std::fs::read_to_string(root.join("nothing/at/all"))
            .map_err(|err| anyhow::Error::new(err).context("reading the layout"))
            .expect_err("an absence");

        // Running as root would read it anyway, and then this test would be asserting nothing — so it says so
        // rather than passing quietly.
        if permission_denied(&refused) {
            assert!(!permission_denied(&absent), "an absence read as a refusal");
        } else {
            assert_eq!(
                unsafe { libc_geteuid() },
                0,
                "a file with mode 000 was readable, and this is not root"
            );
        }

        let _ = std::fs::set_permissions(
            &unreadable,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `geteuid`, without a dependency for one call in one test.
    unsafe fn libc_geteuid() -> u32 {
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        unsafe { geteuid() }
    }

    /// The thing this prevents, and the reason it exists: two daemons against one database both read every
    /// call and both write it down, and every number is then doubled with nothing saying so.
    #[test]
    fn a_second_watcher_is_told_who_has_the_database() {
        let root = scratch("watching");
        let database = root.join("flowlight.db");

        let first = watch_with(&database).expect("the first one takes it");
        let refused = watch_with(&database).expect_err("the second one is refused");
        assert_eq!(refused.path, lock_path(&database));
        // The pid is a courtesy rather than a guarantee, but it is this process and so it is knowable here.
        assert_eq!(refused.pid, Some(std::process::id()));

        // And when the first one goes, the next one may have it. The kernel releases the lock when the file
        // description closes, which is what makes this survive a daemon that was killed rather than stopped.
        drop(first);
        let second = watch_with(&database).expect("after the first one went");
        drop(second);

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A different database is a different question, so naming one with `--database` is the way out.
    #[test]
    fn two_watchers_with_two_databases_are_not_in_conflict() {
        let root = scratch("two");
        let one = watch_with(&root.join("one.db")).expect("one");
        let other = watch_with(&root.join("other.db")).expect("the other");
        drop(one);
        drop(other);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The socket a window talks to belongs to one person, so naming them has to work the way a person would
    /// write it: by name, or by the number they already know.
    #[test]
    fn a_user_is_found_by_name_or_by_number() {
        let root = scratch("passwd");
        let passwd = root.join("passwd");
        write(
            &passwd,
            "root:x:0:0:root:/root:/bin/bash\n\
             # a comment, which is not a user\n\
             daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
             blessdyb:x:1000:1000:,,,:/home/blessdyb:/bin/bash\n\
             broken:x:not-a-number:1000::/:/bin/false\n",
        );

        assert_eq!(user(&passwd, "blessdyb"), Some((1000, 1000)));
        assert_eq!(user(&passwd, "root"), Some((0, 0)));
        // A number is taken at its word, and its group comes from the file when the file knows it.
        assert_eq!(user(&passwd, "1000"), Some((1000, 1000)));
        // And when it does not, the uid stands for both rather than the lookup failing: a container with no
        // password file is a normal place to run this.
        assert_eq!(user(&passwd, "4242"), Some((4242, 4242)));
        // Names that are not there are refused rather than guessed at.
        assert_eq!(user(&passwd, "nobody-by-that-name"), None);
        assert_eq!(user(&passwd, ""), None);
        assert_eq!(user(&passwd, "broken"), None);
        // A file that is not there is not a reason to invent a uid.
        assert_eq!(user(&root.join("nothing"), "blessdyb"), None);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn what_selinux_is_doing_is_read_from_the_file_that_says() {
        let root = scratch("selinux");
        assert_eq!(selinux(&root), Selinux::Absent);
        write(&root.join("selinux/enforce"), "0\n");
        assert_eq!(selinux(&root), Selinux::Permissive);
        write(&root.join("selinux/enforce"), "1\n");
        assert_eq!(selinux(&root), Selinux::Enforcing);
        assert!(Selinux::Enforcing.described().contains("confined service"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn what_the_kernel_was_told_about_bpf_is_reported_without_being_guessed_at() {
        let root = scratch("bpf");
        let absent = bpf(&root);
        assert_eq!(absent.unprivileged_disabled, None);
        assert!(!absent.syscall_present);

        write(&root.join("sys/kernel/unprivileged_bpf_disabled"), "2\n");
        let found = bpf(&root);
        assert_eq!(found.unprivileged_disabled.as_deref(), Some("2"));
        assert!(found.syscall_present);

        write(&root.join("sys/kernel/osrelease"), "6.8.0-45-generic\n");
        assert_eq!(kernel(&root).unwrap().minor, 8);
        let _ = std::fs::remove_dir_all(&root);
    }
}
