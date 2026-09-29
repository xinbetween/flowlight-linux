//! Finding the TLS libraries that are actually in use, by reading what processes have mapped.
//!
//! A uprobe is attached to a *file*, not a process, so the first question is which file. Guessing at
//! `/usr/lib/x86_64-linux-gnu/libssl.so.3` covers Debian on x86-64 and nothing else: the path differs on
//! Fedora, on Arch, on musl, on arm64, inside every container, inside every Python virtualenv that shipped
//! its own, and inside `~/.nix-profile`.
//!
//! So rather than guess, read `/proc/<pid>/maps` and see what is mapped. That finds the library wherever it
//! is, including copies nobody would have thought to look for — and it finds them per process, which is how
//! a container's own libssl gets probed at all.
//!
//! The parsing is here, where it can be tested against real `maps` lines on a machine that has no `/proc`.

/// One line of `/proc/<pid>/maps`:
///
/// ```text
/// 7f8b4c000000-7f8b4c021000 r-xp 00000000 08:01 1234567   /usr/lib/x86_64-linux-gnu/libssl.so.3
/// ```
///
/// Returns the path only for mappings that are executable and backed by a real file. A library mapped
/// read-only is its data segment; attaching a uprobe needs the segment the code is in.
pub fn executable_mapping(line: &str) -> Option<&str> {
    let mut fields = line.split_whitespace();
    let _range = fields.next()?;
    let permissions = fields.next()?;
    if !permissions.contains('x') {
        return None;
    }
    let _offset = fields.next()?;
    let _device = fields.next()?;
    let _inode = fields.next()?;
    let path = fields.next()?;
    // `[heap]`, `[stack]`, `[vdso]` and friends are not files. Neither is an anonymous mapping, which has no
    // sixth field at all and is why this is `next()` rather than a split from the right.
    if !path.starts_with('/') {
        return None;
    }
    // A library replaced by a package upgrade while still mapped. The old file is gone from the filesystem,
    // so there is nothing left to attach a probe to.
    if line.ends_with(" (deleted)") {
        return None;
    }
    Some(path)
}

/// The TLS implementations there are probes for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsLibrary {
    /// OpenSSL, and its API-compatible forks that keep the `libssl` name. curl, Python, Node, most of
    /// everything.
    OpenSsl,
    /// GnuTLS. wget on most distributions, and a good deal of GNOME.
    GnuTls,
    /// NSS, probed at its NSPR layer. Firefox and Thunderbird.
    Nss,
}

impl TlsLibrary {
    /// A word for the interface.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OpenSsl => "openssl",
            Self::GnuTls => "gnutls",
            Self::Nss => "nss",
        }
    }
}

/// Which TLS implementation a mapped file is, if it is one there are probes for.
///
/// Matches on the file's name rather than its contents. A file called `libssl.so.3` that is not OpenSSL will
/// fail to resolve the symbol and be reported as a library that could not be probed, which is the right
/// outcome and a better one than reading every mapped file on the machine to find out.
pub fn tls_library(path: &str) -> Option<TlsLibrary> {
    let name = path.rsplit('/').next()?;
    // In each case: the versioned name, and the bare `.so` a development package installs.
    if name.starts_with("libssl.so") {
        return Some(TlsLibrary::OpenSsl);
    }
    if name.starts_with("libgnutls.so") {
        return Some(TlsLibrary::GnuTls);
    }
    // NSS's own library is `libnss3`, but the plaintext passes through the portable runtime underneath it.
    // `libnss_files.so` is the name-service switch and has nothing to do with any of this, which is why
    // this matches `libnspr4` rather than anything beginning `libnss`.
    if name.starts_with("libnspr4.so") {
        return Some(TlsLibrary::Nss);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAPS: &str = "\
55a4f2a00000-55a4f2a21000 r-xp 00000000 08:01 1179657                    /usr/bin/curl
7f8b4c000000-7f8b4c021000 r--p 00000000 08:01 1234567                    /usr/lib/x86_64-linux-gnu/libssl.so.3
7f8b4c021000-7f8b4c07f000 r-xp 00021000 08:01 1234567                    /usr/lib/x86_64-linux-gnu/libssl.so.3
7f8b4c07f000-7f8b4c0a0000 r--p 0007f000 08:01 1234567                    /usr/lib/x86_64-linux-gnu/libssl.so.3
7ffd3c9f1000-7ffd3ca12000 rw-p 00000000 00:00 0                          [stack]
7ffd3cbf4000-7ffd3cbf8000 r-xp 00000000 00:00 0                          [vdso]
7f8b4b800000-7f8b4b900000 rw-p 00000000 00:00 0 
";

    #[test]
    fn only_the_executable_segment_of_a_file_is_returned() {
        let mut found = MAPS.lines().filter_map(executable_mapping);
        assert_eq!(found.next(), Some("/usr/bin/curl"));
        assert_eq!(found.next(), Some("/usr/lib/x86_64-linux-gnu/libssl.so.3"));
        // The library's two read-only segments are the same file and must not be offered twice.
        assert_eq!(found.next(), None);
    }

    #[test]
    fn anonymous_and_special_mappings_are_not_files() {
        for line in MAPS
            .lines()
            .filter(|l| l.contains('[') || l.ends_with(" 0 "))
        {
            assert_eq!(executable_mapping(line), None, "{line}");
        }
    }

    /// The old file is unlinked and there is nothing left to attach to. Reporting the path anyway would make
    /// the daemon fail to open a file it just claimed to have found.
    #[test]
    fn a_library_deleted_by_an_upgrade_is_not_offered() {
        let line =
            "7f8b4c021000-7f8b4c07f000 r-xp 00021000 08:01 1234567 /usr/lib/libssl.so.3 (deleted)";
        assert_eq!(executable_mapping(line), None);
    }

    #[test]
    fn openssl_is_recognised_wherever_it_is_installed() {
        for path in [
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib64/libssl.so.1.1",
            "/nix/store/abc-openssl-3.0.13/lib/libssl.so.3",
            "/home/x/.venv/lib/libssl.so",
        ] {
            assert_eq!(tls_library(path), Some(TlsLibrary::OpenSsl), "{path}");
        }
    }

    #[test]
    fn the_other_libraries_are_recognised_too() {
        assert_eq!(
            tls_library("/usr/lib/x86_64-linux-gnu/libgnutls.so.30"),
            Some(TlsLibrary::GnuTls)
        );
        assert_eq!(
            tls_library("/usr/lib/firefox/libnspr4.so"),
            Some(TlsLibrary::Nss)
        );
    }

    #[test]
    fn things_that_are_not_tls_libraries_are_not_claimed() {
        for path in [
            "/usr/bin/curl",
            "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
            "/usr/lib/x86_64-linux-gnu/libc.so.6",
            "/usr/lib/libsslsomethingelse",
            // The name-service switch, which shares four letters with NSS and nothing else.
            "/usr/lib/x86_64-linux-gnu/libnss_files.so.2",
            "/usr/lib/x86_64-linux-gnu/libnss_systemd.so.2",
        ] {
            assert_eq!(tls_library(path), None, "{path}");
        }
    }
}
