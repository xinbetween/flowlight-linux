//! Asking who operates the addresses this machine has reached.
//!
//! Off until it is asked for, because it is the one part of Flowlight that tells somebody else anything. What
//! leaves is an address, as a DNS question, and nothing else: not which process reached it, not when, not how
//! often. An address on this machine or this network is never asked about at all.
//!
//! # Why so slowly
//!
//! A few a minute, busiest first, never the same one twice. A resolver asked about every connection as it
//! happened would be a second and chattier record of this machine's traffic leaving it — which is the thing
//! Flowlight exists to notice other programs doing.

use flowlight_owners::Lookup;
use flowlight_store::{Language, Store};

/// How many addresses are asked about in one pass.
const PER_PASS: usize = 4;

/// How far back to look for addresses nobody has looked up.
const WINDOW: i64 = 7 * 86_400;

/// What one pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Learnt {
    /// How many addresses were asked about.
    pub asked: usize,
    /// How many came back with an operator.
    pub named: usize,
    /// What went wrong, if anything did.
    pub failure: Option<String>,
}

impl Learnt {
    /// Whether anything happened worth a line.
    pub fn is_quiet(&self) -> bool {
        self.asked == 0 && self.failure.is_none()
    }
}

/// Asks about the busiest few addresses nobody has looked up yet.
pub fn pass(store: &mut Store, lookup: &Lookup, now: i64) -> Learnt {
    let waiting = match store.addresses_without_owners(now - WINDOW, PER_PASS) {
        Ok(waiting) => waiting,
        Err(err) => {
            return Learnt {
                failure: Some(format!(
                    "could not read which addresses are unknown: {err:#}"
                )),
                ..Learnt::default()
            };
        }
    };
    let mut learnt = Learnt::default();
    for address in waiting {
        learnt.asked += 1;
        match lookup.owner(&address) {
            Ok(Some(owner)) => {
                if let Err(err) = store.set_owner(&address, owner.asn, &owner.name, now) {
                    learnt.failure =
                        Some(format!("could not record who operates {address}: {err:#}"));
                    return learnt;
                }
                if owner.asn != 0 {
                    learnt.named += 1;
                }
            }
            // Nobody announces it. Written down as such, or it would be asked about again on every pass for
            // ever — which is the one outcome worse than not knowing.
            Ok(None) => {
                if let Err(err) = store.set_owner(&address, 0, "nobody announces it", now) {
                    learnt.failure = Some(format!(
                        "could not record that {address} is unannounced: {err:#}"
                    ));
                    return learnt;
                }
            }
            Err(err) => {
                // Not recorded, so it is asked about again later. A resolver that is temporarily unreachable
                // is a different thing from an address nobody announces, and conflating them would make the
                // first permanent.
                learnt.failure = Some(format!("{err:#}"));
                return learnt;
            }
        }
    }
    learnt
}

/// What asking would mean, in sentences.
///
/// Said before the first question rather than in a manual, like every other thing here that leaves the
/// machine.
pub fn disclose(resolver: &str, language: Language) -> Vec<String> {
    let mut said = vec![
        language.say("owners.what").to_owned(),
        language.fill("owners.question", &[("resolver", resolver)]),
        language.say("owners.sent").to_owned(),
        language.say("owners.local").to_owned(),
        language.say("owners.rate").to_owned(),
    ];
    said.extend(language.caveat().map(str::to_owned));
    said
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pass_with_nothing_to_ask_about_is_quiet() {
        let mut store = Store::in_memory().unwrap();
        let learnt = pass(&mut store, &Lookup::new(), 1_000);
        assert!(learnt.is_quiet());
        assert_eq!(learnt.asked, 0);
    }

    /// The disclosure has to say the thing somebody would otherwise have to find out: that an address of
    /// theirs is sent to a third party, and which one.
    #[test]
    fn the_disclosure_says_what_leaves_and_where_it_goes() {
        let said = disclose("192.168.1.1:53", Language::English).join(" ");
        assert!(said.contains("192.168.1.1:53"));
        assert!(said.contains("What is sent is an address"));
        assert!(said.contains("never asked about"));
    }
}
