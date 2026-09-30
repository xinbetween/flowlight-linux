//! Getting something to trust Flowlight's certificate, and being honest about what cannot be done from here.
//!
//! There is no one trust store on Linux. There is the distribution's, which OpenSSL and curl read; there is
//! Python's `certifi`, which ships its own copy and ignores the distribution's; there is Node, which ignores
//! both and reads `NODE_EXTRA_CA_CERTS`; there is Java's keystore; and there is NSS, which Firefox and some
//! tools keep in a database of its own.
//!
//! # What this does and what it refuses to do
//!
//! It installs into the distribution's store, because that is one file and one command and it is reversible.
//! Everything else it *reports*: the exact path or command, and whether the thing is present on this machine
//! at all. It does not append to somebody's `certifi` bundle behind their back and it does not edit a
//! keystore — both are somebody else's files, both are replaced by the next upgrade of the thing that owns
//! them, and a tool that quietly edits them is a tool nobody can reason about.
//!
//! The two that need an environment variable cannot be done from here at all: a variable has to be set before
//! a process starts, by whoever starts it. That is what the next release is about, and saying so is better
//! than pretending.

use anyhow::{Context as _, Result, bail};
use std::path::{Path, PathBuf};

/// One thing that may need telling, and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// What it is about: `the machine's trust store`, `Python`, `Node`.
    pub what: String,
    /// Whether this machine appears to have the thing at all.
    pub present: bool,
    /// Whether Flowlight can do it, or only say how.
    pub automatic: bool,
    /// What to do, as something to read or to type.
    pub how: String,
}

/// Where a distribution keeps certificates somebody adds, and what updates its bundle afterwards.
const STORES: &[(&str, &str, &str)] = &[
    // Debian, Ubuntu and anything derived from them.
    (
        "/usr/local/share/ca-certificates",
        "flowlight.crt",
        "update-ca-certificates",
    ),
    // Fedora, RHEL, and SUSE's own directory under the same command family.
    (
        "/etc/pki/ca-trust/source/anchors",
        "flowlight.pem",
        "update-ca-trust",
    ),
    (
        "/etc/ca-certificates/trust-source/anchors",
        "flowlight.pem",
        "trust extract-compat",
    ),
];

/// Everything that may need telling about the certificate, in the order worth reading.
pub fn steps(certificate: &Path, bundle: &Path) -> Vec<Step> {
    let mut steps = Vec::new();
    let store = distribution_store();
    steps.push(Step {
        what: "the machine's trust store".to_owned(),
        present: store.is_some(),
        automatic: store.is_some(),
        how: match &store {
            Some((directory, name, command)) => format!(
                "`sudo flowlightd trust --install` copies it to {}/{name} and runs `{command}`. That covers \
                 OpenSSL, curl, git and anything else that reads the machine's store.",
                directory.display()
            ),
            None => "This machine has none of the usual directories for adding a certificate, so there is \
                     nothing to install into. Everything below still works."
                .to_owned(),
        },
    });
    steps.push(Step {
        what: "anything that reads one bundle".to_owned(),
        present: true,
        automatic: false,
        how: format!(
            "`SSL_CERT_FILE={0}` covers OpenSSL command-line tools; `REQUESTS_CA_BUNDLE={0}` covers Python \
             requests; `CURL_CA_BUNDLE={0}` covers curl. That file is this machine's own roots with \
             Flowlight's added, so nothing else stops working.",
            bundle.display()
        ),
    });
    steps.push(Step {
        what: "Node".to_owned(),
        present: which("node").is_some(),
        // Node ignores the machine's store outright, and the only way in is a variable set before it starts.
        automatic: false,
        how: format!(
            "Node does not read the machine's trust store. `NODE_EXTRA_CA_CERTS={}` is the only way in, and \
             it has to be set before node starts — which is what `flowlightd launch` will be for.",
            bundle.display()
        ),
    });
    steps.push(Step {
        what: "Python's certifi".to_owned(),
        present: python_certifi().is_some(),
        automatic: false,
        how: match python_certifi() {
            Some(path) => format!(
                "certifi ships its own bundle and ignores the machine's. Either set \
                 `REQUESTS_CA_BUNDLE={}`, or append the certificate to {} — which the next upgrade of \
                 certifi will replace, which is why Flowlight will not do it for you.",
                bundle.display(),
                path.display()
            ),
            None => "certifi does not appear to be installed for the python on this machine.".to_owned(),
        },
    });
    steps.push(Step {
        what: "Java".to_owned(),
        present: which("keytool").is_some(),
        automatic: false,
        how: format!(
            "`keytool -importcert -alias flowlight -file {} -cacerts -storepass changeit`. It edits the \
             keystore inside your JDK, so it goes away when the JDK is replaced.",
            certificate.display()
        ),
    });
    steps.push(Step {
        what: "NSS (Firefox, and some tools)".to_owned(),
        present: which("certutil").is_some(),
        automatic: false,
        how: format!(
            "`certutil -A -n flowlight -t C,, -i {} -d sql:$HOME/.pki/nssdb`, as the user whose browser it \
             is — not as root.",
            certificate.display()
        ),
    });
    steps
}

/// Installs the certificate into the distribution's trust store.
pub fn install(certificate: &Path) -> Result<String> {
    let Some((directory, name, command)) = distribution_store() else {
        bail!(
            "this machine has none of the usual directories for adding a certificate, so there is nothing to \
             install into. `flowlightd trust` lists what to do instead."
        );
    };
    let contents =
        std::fs::read(certificate).with_context(|| format!("reading {}", certificate.display()))?;
    let target = directory.join(name);
    std::fs::write(&target, &contents).with_context(|| {
        format!(
            "writing {}. This needs root, which is what the daemon runs as.",
            target.display()
        )
    })?;
    run(command)?;
    Ok(format!(
        "installed {} and ran `{command}`",
        target.display()
    ))
}

/// Takes it out again.
pub fn remove() -> Result<String> {
    let Some((directory, name, command)) = distribution_store() else {
        bail!("this machine has no trust store Flowlight installed into");
    };
    let target = directory.join(name);
    if !target.exists() {
        return Ok(format!("{} was not there", target.display()));
    }
    std::fs::remove_file(&target).with_context(|| format!("removing {}", target.display()))?;
    run(command)?;
    Ok(format!("removed {} and ran `{command}`", target.display()))
}

/// Whether the certificate is installed in the distribution's store.
pub fn is_installed() -> bool {
    distribution_store().is_some_and(|(directory, name, _)| directory.join(name).exists())
}

/// Runs the command that rebuilds the machine's bundle.
fn run(command: &str) -> Result<()> {
    let mut words = command.split_whitespace();
    let program = words.next().unwrap_or_default();
    let status = std::process::Command::new(program)
        .args(words)
        .stdout(std::process::Stdio::null())
        .status()
        .with_context(|| format!("running `{command}`"))?;
    if !status.success() {
        bail!("`{command}` exited with {status}");
    }
    Ok(())
}

/// Which of the distribution stores this machine has, if any.
fn distribution_store() -> Option<(PathBuf, &'static str, &'static str)> {
    STORES
        .iter()
        .map(|(directory, name, command)| (PathBuf::from(directory), *name, *command))
        .find(|(directory, _, command)| {
            directory.is_dir() && which(command_name(command)).is_some()
        })
}

/// The program a command line starts with.
fn command_name(command: &str) -> &str {
    command.split_whitespace().next().unwrap_or(command)
}

/// Whether a program is on the path.
fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

/// Where certifi keeps its bundle, if a python on this machine has one.
///
/// Asked of python rather than guessed from a path, because the answer depends on the interpreter, the
/// distribution and whether anybody is in a virtual environment.
fn python_certifi() -> Option<PathBuf> {
    for python in ["python3", "python"] {
        if which(python).is_none() {
            continue;
        }
        let output = std::process::Command::new(python)
            .args(["-c", "import certifi; print(certifi.where())"])
            .output()
            .ok()?;
        if output.status.success() {
            let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_owned());
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything that might need telling is mentioned, and each says whether Flowlight can do it. A step
    /// that claimed to be automatic and was not would be a machine somebody thought was configured.
    #[test]
    fn every_step_says_whether_flowlight_can_do_it() {
        let steps = steps(Path::new("/tmp/ca.pem"), Path::new("/tmp/bundle.pem"));
        assert!(steps.len() >= 6);
        for step in &steps {
            assert!(!step.what.is_empty());
            assert!(!step.how.is_empty(), "{}", step.what);
        }
        // The only one Flowlight does itself is the machine's own store, and only if there is one.
        let automatic: Vec<&Step> = steps.iter().filter(|step| step.automatic).collect();
        assert!(automatic.len() <= 1);
        for step in automatic {
            assert_eq!(step.what, "the machine's trust store");
        }
    }

    /// The two that need an environment variable say that they do, because that is the thing somebody will
    /// otherwise spend an afternoon on.
    #[test]
    fn the_ones_that_need_a_variable_say_so() {
        let steps = steps(Path::new("/tmp/ca.pem"), Path::new("/tmp/bundle.pem"));
        let node = steps.iter().find(|step| step.what == "Node").expect("node");
        assert!(node.how.contains("NODE_EXTRA_CA_CERTS"));
        assert!(!node.automatic);
        let bundle = steps
            .iter()
            .find(|step| step.what.contains("one bundle"))
            .expect("a bundle step");
        assert!(bundle.how.contains("SSL_CERT_FILE"));
        assert!(bundle.how.contains("/tmp/bundle.pem"));
    }

    /// A command line names a program, and that is what has to exist on the path.
    #[test]
    fn a_command_line_is_looked_up_by_its_program() {
        assert_eq!(command_name("trust extract-compat"), "trust");
        assert_eq!(
            command_name("update-ca-certificates"),
            "update-ca-certificates"
        );
    }

    #[test]
    fn a_program_on_the_path_is_found_and_one_that_is_not_is_not() {
        assert!(which("sh").is_some());
        assert!(which("a-program-that-does-not-exist-anywhere").is_none());
    }
}
