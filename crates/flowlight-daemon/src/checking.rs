//! What this machine can and cannot do, before anything is loaded into it.
//!
//! Every other way of finding this out is a failure: a probe that will not attach, a rule that never bites, an
//! empty screen. This asks the same questions in advance and says what each answer costs — which is the
//! difference between "it does not work here" and "it does not work here *because*".
//!
//! Read-only and harmless. It loads nothing, attaches nothing and writes nothing, so it can be run by anybody
//! on any machine, including one where Flowlight has never been started. Run as a person rather than as root it
//! says one thing less — whether a program could be loaded — and says that it cannot know.

use anyhow::Result;
use flowlight_platform::{Hierarchy, Selinux};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

/// One thing that was checked.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    /// What was checked.
    pub about: String,
    /// `yes`, `no`, or `unknown` — the third because running as a person cannot answer everything.
    pub answer: String,
    /// What was found, and what it costs when it is not what Flowlight wants.
    pub said: String,
    /// Whether Flowlight can do its main job without this.
    pub essential: bool,
}

/// Everything that was checked, and whether what is essential is here.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Report {
    /// The findings, in the order they are worth reading.
    pub findings: Vec<Finding>,
    /// Whether every essential thing was found.
    pub ready: bool,
    /// Whether anything inessential is missing — blocking, mostly.
    pub limited: bool,
}

/// `yes`.
fn yes(about: &str, said: String, essential: bool) -> Finding {
    Finding {
        about: about.to_owned(),
        answer: "yes".to_owned(),
        said,
        essential,
    }
}

/// `no`.
fn no(about: &str, said: String, essential: bool) -> Finding {
    Finding {
        about: about.to_owned(),
        answer: "no".to_owned(),
        said,
        essential,
    }
}

/// `unknown`, which is an answer and not a failure.
fn unknown(about: &str, said: String) -> Finding {
    Finding {
        about: about.to_owned(),
        answer: "unknown".to_owned(),
        said,
        essential: false,
    }
}

/// Asks everything, reading from the roots given so that a test can write a machine out.
pub fn report(proc_root: &Path, sys_root: &Path, tracefs: Option<&Path>, root: bool) -> Report {
    let mut findings = Vec::new();

    findings.push(match flowlight_platform::kernel(proc_root) {
        Some(kernel) if kernel.is_new_enough() => yes(
            "kernel",
            format!("{} — new enough for the probes", kernel.release),
            true,
        ),
        Some(kernel) => no(
            "kernel",
            format!(
                "{} is older than {}.{}, where the probes Flowlight attaches arrived. Nothing here will \
                 work on this kernel.",
                kernel.release,
                flowlight_platform::OLDEST_KERNEL.0,
                flowlight_platform::OLDEST_KERNEL.1
            ),
            true,
        ),
        None => unknown(
            "kernel",
            format!(
                "{} could not be read, so the kernel's version is not known here",
                proc_root.join("sys/kernel/osrelease").display()
            ),
        ),
    });

    // Root, because loading a program needs it. Said rather than assumed: `check` is meant to be runnable by
    // somebody who has not been given it.
    findings.push(if root {
        yes(
            "permission to load",
            "running as root, which is what loading an eBPF program needs".to_owned(),
            true,
        )
    } else {
        unknown(
            "permission to load",
            "not running as root. The daemon needs root or CAP_BPF to load anything; whether this machine \
             would allow it cannot be answered from here."
                .to_owned(),
        )
    });

    findings.push(
        match crate::tracefs::format_text(tracefs, "sock", "inet_sock_set_state") {
            Ok(_) => yes(
                "tracefs",
                "the tracepoint's layout was read, which is how the offsets are worked out for this kernel"
                    .to_owned(),
                true,
            ),
            // Told apart by what the machine said, rather than by looking for the directory: on Ubuntu
            // `/sys/kernel/tracing` is `drwx------`, which refuses a person *entry*, so asking whether it
            // exists answers "it does not" — and the first version of this then told somebody their machine
            // could not be watched when the honest answer was "you are not root". A real machine caught that;
            // the one CI runs on has a searchable directory and agreed with the mistake.
            Err(err) if !root && flowlight_platform::permission_denied(&err) => unknown(
                "tracefs",
                format!(
                    "{}. The file describing the tracepoint is readable only by root, so whether its layout \
                     can be read cannot be answered from here.",
                    crate::tracefs::mounted(tracefs).map_or_else(
                        || "tracefs refused to be read".to_owned(),
                        |path| format!("{} is mounted", path.display())
                    )
                ),
            ),
            Err(err) => no(
                "tracefs",
                format!(
                    "{err:#}. Without it the connection tracepoint cannot be read, which is most of what \
                     Flowlight does."
                ),
                true,
            ),
        },
    );

    let layout = flowlight_platform::hierarchy(&sys_root.join("fs/cgroup"));
    findings.push(match &layout {
        Hierarchy::Unified(_) => yes("refusing connections", layout.described(), false),
        Hierarchy::Hybrid(_) => yes("refusing connections", layout.described(), false),
        Hierarchy::LegacyOnly => no("refusing connections", layout.described(), false),
    });

    let libraries = crate::libraries::discover(&[]);
    findings.push(if libraries.is_empty() {
        no(
            "TLS libraries",
            "none were found. Connections will still be attributed; nothing will be read in the clear, \
             which is the half that makes Flowlight worth running."
                .to_owned(),
            false,
        )
    } else {
        let mut named: Vec<String> = libraries
            .iter()
            .map(|(path, library)| format!("{} ({})", path.display(), library.as_str()))
            .collect();
        named.sort();
        yes("TLS libraries", named.join(", "), false)
    });

    let selinux = flowlight_platform::selinux(&sys_root.join("fs"));
    findings.push(match selinux {
        Selinux::Absent | Selinux::Permissive => {
            yes("SELinux", selinux.described().to_owned(), false)
        }
        // Not a failure. Running from a terminal is unconfined, and a service that is confined will say so in
        // the audit log rather than here.
        Selinux::Enforcing => unknown("SELinux", selinux.described().to_owned()),
    });

    let bpf = flowlight_platform::bpf(proc_root);
    findings.push(if bpf.syscall_present {
        yes(
            "BPF in this kernel",
            match &bpf.unprivileged_disabled {
                Some(value) => format!(
                    "present. kernel.unprivileged_bpf_disabled is {value}, which does not apply to root"
                ),
                None => "present".to_owned(),
            },
            true,
        )
    } else {
        no(
            "BPF in this kernel",
            format!(
                "{} has nothing to say about BPF, which is what a kernel built without CONFIG_BPF_SYSCALL \
                 looks like. There is no version of Flowlight that works without it.",
                proc_root.join("sys/kernel").display()
            ),
            true,
        )
    });

    let ready = findings
        .iter()
        .all(|finding| !finding.essential || finding.answer != "no");
    let limited = findings.iter().any(|finding| finding.answer == "no");
    Report {
        findings,
        ready,
        limited,
    }
}

/// Prints it, and says what the answer means for somebody about to run this.
pub fn print(out: &mut impl Write, report: &Report, json: bool) -> Result<()> {
    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string(report).unwrap_or_else(|err| format!("{{\"error\":\"{err}\"}}"))
        )?;
        return Ok(());
    }
    for finding in &report.findings {
        let mark = match finding.answer.as_str() {
            "yes" => "ok  ",
            "no" => "no  ",
            _ => "?   ",
        };
        writeln!(out, "{mark}{:<22} {}", finding.about, finding.said)?;
    }
    writeln!(out)?;
    if report.ready && !report.limited {
        writeln!(out, "Everything Flowlight needs is here.")?;
    } else if report.ready {
        writeln!(
            out,
            "Flowlight will watch this machine. Something it does as well as watching is not available \
             above, and the line says which."
        )?;
    } else {
        writeln!(
            out,
            "Flowlight cannot watch this machine. The lines marked `no` above that are not about refusing \
             connections are the reason."
        )?;
    }
    Ok(())
}
