//! Keeping the kernel inside the budget.
//!
//! [`flowlight_store::Budget`] says what is allowed. This does the arithmetic and writes two answers into
//! the kernel: whether payloads are being read at all, and which processes have used up their share for the
//! day. The kernel's part is two lookups before it copies anything out of an application's memory, which is
//! the only order in which a ceiling means anything.
//!
//! # Why the accounting is here and not there
//!
//! Because it changes. A ceiling is a number somebody should be able to alter without reloading a program
//! into their kernel, and the question "how much has this application sent today" is one a database answers
//! and a BPF map cannot. What the kernel needs is the conclusion.
//!
//! # Why today's total is read back from the database
//!
//! A daemon restarted at noon would otherwise hand every process a fresh allowance, which makes a daily
//! ceiling a per-restart ceiling — and the easiest way to exceed one is to be running on a machine that
//! reboots.

use anyhow::Result;
use aya::maps::{Array, HashMap as BpfHashMap, MapData};
use flowlight_store::{Budget, Store};
use std::collections::{HashMap, HashSet};

/// What happened on one pass.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Change {
    /// The session ran out, and payloads are no longer being read.
    pub session_ended: bool,
    /// A new day began, so every allowance was given back.
    pub day_began: bool,
}

impl Change {
    /// Whether anything happened worth a line.
    pub fn is_quiet(&self) -> bool {
        !self.session_ended && !self.day_began
    }
}

/// The two maps the budget is held against: whether to capture, and who has spent their share.
pub type Maps = (Array<MapData, u8>, BpfHashMap<MapData, u32, u8>);

/// Holds the budget against the kernel.
pub struct Spending {
    capturing: Array<MapData, u8>,
    spent_in_kernel: BpfHashMap<MapData, u32, u8>,
    budget: Budget,
    /// Bytes each process has contributed today, by name.
    spent: HashMap<String, i64>,
    /// Names that have used up their share, so a second crossing is not a second announcement.
    stopped: HashSet<String>,
    /// Processes whose payloads are never read, whatever the budget says. Kept because the kernel's list is
    /// emptied at midnight, and an exclusion that lapses at midnight is not an exclusion.
    ignored: HashSet<u32>,
    /// Which day the arithmetic above is about, in whole days since the epoch.
    day: i64,
    /// Whether the kernel currently believes it is capturing.
    told_kernel: bool,
    /// Whether a failure to tell it has already been said out loud.
    complained: bool,
}

impl Spending {
    /// Takes the two maps and the budget, and seeds today's total from what was already stored.
    pub fn new(
        capturing: Array<MapData, u8>,
        spent_in_kernel: BpfHashMap<MapData, u32, u8>,
        budget: Budget,
        store: &mut Store,
        now: i64,
    ) -> Self {
        let day = now.div_euclid(86_400);
        let spent = store
            .payload_bytes_today(day * 86_400)
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut spending = Self {
            capturing,
            spent_in_kernel,
            budget,
            spent,
            stopped: HashSet::new(),
            ignored: HashSet::new(),
            day,
            told_kernel: false,
            complained: false,
        };
        spending.tell_kernel(budget.reading_payloads(now));
        spending
    }

    /// The budget in force.
    pub fn budget(&self) -> Budget {
        self.budget
    }

    /// Replaces the budget, which is what the interface writing one comes to.
    ///
    /// The kernel is told immediately rather than on the next tick: somebody who has just turned payload
    /// capture off has a reasonable expectation that it is off.
    pub fn set(&mut self, budget: Budget, now: i64) {
        self.budget = budget;
        let capturing = budget.reading_payloads(now);
        self.told_kernel = !capturing;
        self.tell_kernel(capturing);
    }

    /// Never read this process's payloads, whatever the allowance says.
    ///
    /// The one caller is the daemon excluding itself. Export means this process sends what it saw over TLS,
    /// and reading that back would put a record of the export into the next export, for ever.
    pub fn ignore(&mut self, pid: u32) {
        self.ignored.insert(pid);
        let _ = self.spent_in_kernel.insert(pid, 1, 0);
    }

    /// Counts one captured payload, and stops the process if that was its last.
    ///
    /// Called on the event path, so the ceiling takes effect on the next call rather than on the next tick.
    /// A process that crosses it contributes the record that crossed it and nothing after — which is one
    /// record more than the ceiling, and the alternative is discarding evidence already gathered.
    pub fn record(&mut self, process: &str, pid: u32, bytes: u32) -> Option<String> {
        let running = self.spent.entry(process.to_owned()).or_insert(0);
        *running += i64::from(bytes);
        if self.budget.within_daily(*running) {
            return None;
        }
        // Written for this process whether or not the name was already stopped: a name that has stopped
        // keeps starting new processes, and each of them has to be told.
        let _ = self.spent_in_kernel.insert(pid, 1, 0);
        self.stopped
            .insert(process.to_owned())
            .then(|| process.to_owned())
    }

    /// Checks the things that change with the clock rather than with traffic.
    pub fn tick(&mut self, now: i64) -> Change {
        let mut change = Change::default();

        let day = now.div_euclid(86_400);
        if day != self.day {
            self.day = day;
            self.spent.clear();
            self.stopped.clear();
            // Every allowance back, which means emptying the kernel's list rather than waiting for the
            // processes on it to exit.
            let stale: Vec<u32> = self
                .spent_in_kernel
                .keys()
                .filter_map(std::result::Result::ok)
                .collect();
            for pid in stale {
                let _ = self.spent_in_kernel.remove(&pid);
            }
            // Put back. These were never spending an allowance, so giving the allowance back does not
            // include them.
            for pid in &self.ignored {
                let _ = self.spent_in_kernel.insert(pid, 1, 0);
            }
            change.day_began = true;
        }

        let capturing = self.budget.reading_payloads(now);
        if self.told_kernel && !capturing {
            change.session_ended = self.budget.session_expired(now);
        }
        self.tell_kernel(capturing);
        change
    }

    /// Tells the kernel whether to capture, if it does not already know.
    ///
    /// A failure here means nothing is captured at all, silently, which is the worst way for this to go
    /// wrong: the budget says payloads are being read and no payload ever arrives. So it is reported, once,
    /// with what the kernel actually holds afterwards.
    fn tell_kernel(&mut self, capturing: bool) {
        if self.told_kernel == capturing {
            return;
        }
        match self.capturing.set(0, u8::from(capturing), 0) {
            Ok(()) => {
                self.told_kernel = capturing;
                let held = self.capturing.get(&0, 0).unwrap_or(255);
                if held != u8::from(capturing) && !self.complained {
                    self.complained = true;
                    eprintln!(
                        "the kernel's capture switch was set to {} and reads back as {held}; payloads \
                         will not be read",
                        u8::from(capturing)
                    );
                }
            }
            Err(err) => {
                if !self.complained {
                    self.complained = true;
                    eprintln!(
                        "the kernel's capture switch could not be written ({err}); no payloads will be \
                         read at all"
                    );
                }
            }
        }
    }
}

/// Starts a session now, if one has never been started.
///
/// The session begins when the daemon first runs rather than when the database was created, because a
/// database made in March and a daemon started this morning are different events and only one of them is
/// somebody deciding to read traffic.
pub fn begin_session(store: &mut Store, now: i64) -> Result<Budget> {
    let mut budget = store.budget()?;
    if budget.session_began == 0 {
        budget.session_began = now;
        store.set_budget(&budget)?;
    }
    Ok(budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_with_nothing_in_it_is_quiet() {
        assert!(Change::default().is_quiet());
        for change in [
            Change {
                session_ended: true,
                ..Change::default()
            },
            Change {
                day_began: true,
                ..Change::default()
            },
        ] {
            assert!(!change.is_quiet(), "{change:?}");
        }
    }

    /// The session begins when the daemon first runs, not when the database was made: those are different
    /// events and only one of them is somebody deciding to read traffic.
    #[test]
    fn a_session_begins_the_first_time_a_daemon_runs() {
        let mut store = Store::in_memory().unwrap();
        let budget = begin_session(&mut store, 5_000).unwrap();
        assert_eq!(budget.session_began, 5_000);
        // And it is not restarted by the next daemon.
        let again = begin_session(&mut store, 9_000).unwrap();
        assert_eq!(again.session_began, 5_000);
    }
}
