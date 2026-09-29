//! Turning rules into the two hash lookups the kernel does.
//!
//! The kernel's side of blocking is deliberately stupid: two map lookups inside `connect()`. Everything
//! that requires thought happens here, in userspace, where being slow costs nothing and being wrong can be
//! corrected on the next pass.
//!
//! # The hard part is that a rule names a host and the kernel sees an address
//!
//! By the time `connect()` is called the name has been resolved and thrown away. So blocking
//! `api.example.com` means resolving it here and blocking what it currently resolves to. That is exactly
//! right for a host with a stable address, and imprecise for anything behind a large content network — the
//! addresses rotate, and they are shared with everything else on it.
//!
//! Two consequences, both stated rather than hidden: a block can go stale when a host moves, which is why
//! names are re-resolved on a timer; and a block on a shared address is a block on everything at that
//! address. Neither is solvable at this layer, and pretending otherwise would be worse than saying so.

use anyhow::Result;
use aya::maps::{HashMap as BpfHashMap, MapData};
use flowlight_common::block::{ANY_PORT, BlockKey, EVERYONE};
use flowlight_common::connection::{AF_INET, AF_INET6, ipv4_bytes};
use flowlight_store::RuleRow;
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, ToSocketAddrs as _};
use std::time::{Duration, Instant};

/// How long a name's addresses are trusted before it is looked up again.
///
/// Short enough that a host moving is noticed within a minute, long enough that a machine with fifty rules
/// is not a machine making fifty lookups every two seconds.
const RESOLVED_FOR: Duration = Duration::from_secs(60);

/// The port used when asking the resolver, discarded afterwards. Zero is refused by some resolvers and
/// nothing here cares what it is.
const RESOLVER_PORT: u16 = 443;

/// What a pass over the rules did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Addresses newly refused.
    pub added: usize,
    /// Addresses no longer refused.
    pub removed: usize,
    /// Rules whose subject could not be resolved, which are rules that are not in force.
    pub unresolved: Vec<String>,
}

impl Report {
    /// Whether anything happened worth a line.
    pub fn is_quiet(&self) -> bool {
        self.added == 0 && self.removed == 0 && self.unresolved.is_empty()
    }
}

/// Keeps the kernel's table matching the rules.
pub struct Blocking {
    blocked: BpfHashMap<MapData, BlockKey, u8>,
    installed: BTreeSet<BlockKey>,
    resolved: HashMap<String, (Vec<IpAddr>, Instant)>,
    /// Subjects whose failure to resolve has already been said out loud.
    complained: BTreeSet<String>,
}

impl Blocking {
    /// Takes ownership of the kernel's table.
    pub fn new(blocked: BpfHashMap<MapData, BlockKey, u8>) -> Self {
        Self {
            blocked,
            installed: BTreeSet::new(),
            resolved: HashMap::new(),
            complained: BTreeSet::new(),
        }
    }

    /// Makes the kernel's table say what the rules say.
    pub fn apply(&mut self, rules: &[RuleRow]) -> Report {
        let mut report = Report::default();
        let mut desired = BTreeSet::new();

        for rule in rules {
            // 0.2.0 has one scope. An unknown one is skipped rather than guessed at: a rule whose meaning
            // this version does not know is a rule it must not enforce as though it did.
            if rule.scope != "global" {
                continue;
            }
            match self.addresses_for(&rule.subject) {
                Some(addresses) => {
                    for address in addresses {
                        desired.insert(key_for(address, rule.port));
                    }
                }
                None => {
                    if self.complained.insert(rule.subject.clone()) {
                        report.unresolved.push(rule.subject.clone());
                    }
                }
            }
        }

        for key in desired.difference(&self.installed.clone()) {
            if self.blocked.insert(key, 1, 0).is_ok() {
                self.installed.insert(*key);
                report.added += 1;
            }
        }
        for key in self.installed.clone().difference(&desired) {
            // Removed from the table even if the kernel says it was not there, because the alternative is a
            // rule that was deleted and an address that stays refused until a restart.
            let _ = self.blocked.remove(key);
            self.installed.remove(key);
            report.removed += 1;
        }

        report
    }

    /// The addresses a rule's subject currently means.
    fn addresses_for(&mut self, subject: &str) -> Option<Vec<IpAddr>> {
        if let Some(address) = parse_address(subject) {
            return Some(vec![address]);
        }
        if let Some((addresses, at)) = self.resolved.get(subject)
            && at.elapsed() < RESOLVED_FOR
        {
            return Some(addresses.clone());
        }
        let addresses: Vec<IpAddr> = (subject, RESOLVER_PORT)
            .to_socket_addrs()
            .ok()?
            .map(|socket| socket.ip())
            .collect();
        if addresses.is_empty() {
            return None;
        }
        // A name that resolves again is a name whose earlier complaint is spent.
        self.complained.remove(subject);
        self.resolved
            .insert(subject.to_owned(), (addresses.clone(), Instant::now()));
        Some(addresses)
    }
}

/// A literal address, or `None` if the subject is a name.
pub fn parse_address(subject: &str) -> Option<IpAddr> {
    subject.parse().ok()
}

/// The kernel's key for one address and port.
pub fn key_for(address: IpAddr, port: u16) -> BlockKey {
    match address {
        IpAddr::V4(v4) => BlockKey::new(EVERYONE, AF_INET, ipv4_bytes(v4.octets()), port),
        IpAddr::V6(v6) => BlockKey::new(EVERYONE, AF_INET6, v6.octets(), port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_address_is_not_looked_up() {
        assert_eq!(
            parse_address("93.184.216.34"),
            Some("93.184.216.34".parse().unwrap())
        );
        assert_eq!(parse_address("::1"), Some("::1".parse().unwrap()));
        assert_eq!(parse_address("example.com"), None);
        assert_eq!(parse_address(""), None);
    }

    /// The key the kernel builds from what it sees has to be the key userspace wrote. Four bytes of an
    /// IPv4 address in a sixteen-byte field, and the other twelve zero.
    #[test]
    fn a_key_matches_the_shape_the_kernel_builds() {
        let key = key_for("93.184.216.34".parse().unwrap(), 443);
        assert_eq!(key.family, AF_INET);
        assert_eq!(key.port, 443);
        assert_eq!(key.address[..4], [93, 184, 216, 34]);
        assert_eq!(key.address[4..], [0; 12]);
        assert_eq!(key.agent, EVERYONE);

        let v6 = key_for("2606:4700::6441".parse().unwrap(), ANY_PORT);
        assert_eq!(v6.family, AF_INET6);
        assert_eq!(v6.port, ANY_PORT);
        assert_eq!(v6.address[0], 0x26);
    }

    #[test]
    fn a_report_with_nothing_in_it_is_quiet() {
        assert!(Report::default().is_quiet());
        assert!(
            !Report {
                added: 1,
                ..Report::default()
            }
            .is_quiet()
        );
        assert!(
            !Report {
                unresolved: vec!["x".to_owned()],
                ..Report::default()
            }
            .is_quiet()
        );
    }
}
