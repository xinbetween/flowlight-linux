//! Turning rules into the table the kernel consults, and telling the kernel who is who.
//!
//! [`flowlight_rules`] decides what the rules mean and in what order the kernel should ask its questions.
//! This resolves the names, writes the answers in, and keeps the kernel's idea of which process belongs to
//! which agent current. Being slow here costs nothing and being wrong can be corrected on the next pass,
//! which is exactly the opposite of the program on the other side of the map.
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

use aya::maps::{HashMap as BpfHashMap, LruHashMap, MapData};
use flowlight_common::block::{ANY_PORT, BlockKey, EVERYONE};
use flowlight_common::connection::{AF_INET, AF_INET6, ipv4_bytes};
use flowlight_rules::{Action, KeySpec, Rule, Scope, Subject, table};
use flowlight_store::RuleRow;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, ToSocketAddrs as _};
use std::time::{Duration, Instant};

/// How long a name's addresses are trusted before it is looked up again.
const RESOLVED_FOR: Duration = Duration::from_secs(60);

/// The port used when asking the resolver, discarded afterwards. Zero is refused by some resolvers and
/// nothing here cares what it is.
const RESOLVER_PORT: u16 = 443;

/// What a pass over the rules did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Keys newly written.
    pub added: usize,
    /// Keys taken away.
    pub removed: usize,
    /// Rules whose subject could not be resolved, which are rules that are not in force.
    pub unresolved: Vec<String>,
    /// Rules that cannot be enforced before the handshake at all, by their identifiers.
    pub unenforceable: Vec<i64>,
    /// Rows the database holds that this version does not understand.
    pub unreadable: Vec<i64>,
}

impl Report {
    /// Whether anything happened worth a line.
    pub fn is_quiet(&self) -> bool {
        self.added == 0
            && self.removed == 0
            && self.unresolved.is_empty()
            && self.unenforceable.is_empty()
            && self.unreadable.is_empty()
    }
}

/// Keeps the kernel's table matching the rules, and its marks matching the processes.
pub struct Blocking {
    verdicts: BpfHashMap<MapData, BlockKey, u8>,
    marks: LruHashMap<MapData, u32, u32>,
    installed: BTreeMap<BlockKey, u8>,
    resolved: HashMap<String, (Vec<IpAddr>, Instant)>,
    /// Subjects whose failure to resolve has already been said out loud.
    complained: BTreeSet<String>,
    /// Identifiers handed to agents, so the kernel can compare a number instead of a name.
    identities: HashMap<String, u32>,
    /// Which process identifiers have been marked, and with what.
    marked: HashMap<u32, u32>,
}

impl Blocking {
    /// Takes ownership of the two maps.
    pub fn new(
        verdicts: BpfHashMap<MapData, BlockKey, u8>,
        marks: LruHashMap<MapData, u32, u32>,
    ) -> Self {
        Self {
            verdicts,
            marks,
            installed: BTreeMap::new(),
            resolved: HashMap::new(),
            complained: BTreeSet::new(),
            identities: HashMap::new(),
            marked: HashMap::new(),
        }
    }

    /// The number this agent is known by in the kernel, assigning one if it has none.
    ///
    /// Identifiers start at one, because zero means everyone.
    fn identity(&mut self, agent: &str) -> u32 {
        let next = self.identities.len() as u32 + 1;
        *self
            .identities
            .entry(agent.to_owned())
            .or_insert_with(|| next)
    }

    /// Tells the kernel that this process is working for this agent.
    ///
    /// Only the agents themselves are marked here. Everything they start is marked by the fork tracepoint,
    /// in the kernel, because a child can connect before anything in userspace has noticed it exists.
    pub fn mark(&mut self, pid: u32, agent: &str) {
        let identity = self.identity(agent);
        if self.marked.get(&pid) == Some(&identity) {
            return;
        }
        if self.marks.insert(pid, identity, 0).is_ok() {
            self.marked.insert(pid, identity);
        }
    }

    /// Marks every agent currently running, and forgets the ones that are not.
    ///
    /// Called on a timer. An agent is a long-lived process, so noticing it a second after it starts is
    /// fine; its children are another matter entirely, and they are marked in the kernel at fork.
    pub fn mark_all(&mut self, running: &[(u32, String)]) {
        let present: BTreeSet<u32> = running.iter().map(|(pid, _)| *pid).collect();
        for (pid, agent) in running {
            self.mark(*pid, agent);
        }
        let gone: Vec<u32> = self
            .marked
            .keys()
            .filter(|pid| !present.contains(pid))
            .copied()
            .collect();
        for pid in gone {
            self.unmark(pid);
        }
    }

    /// Forgets a process that has gone.
    ///
    /// The kernel forgets it too, on its own exit tracepoint. This is only so that a restarted process with
    /// a reused identifier is marked again rather than assumed to be marked already.
    pub fn unmark(&mut self, pid: u32) {
        if self.marked.remove(&pid).is_some() {
            let _ = self.marks.remove(&pid);
        }
    }

    /// Makes the kernel's table say what the rules say.
    pub fn apply(&mut self, rows: &[RuleRow]) -> Report {
        let mut report = Report::default();
        let rules = self.read(rows, &mut report);
        let table = table(&rules);
        report.unenforceable = table.unenforceable;

        let mut desired = BTreeMap::new();
        for key in &table.keys {
            self.expand(key, &mut desired, &mut report);
        }

        for (key, value) in &desired {
            if self.installed.get(key) == Some(value) {
                continue;
            }
            if self.verdicts.insert(key, value, 0).is_ok() {
                self.installed.insert(*key, *value);
                report.added += 1;
            }
        }
        let stale: Vec<BlockKey> = self
            .installed
            .keys()
            .filter(|key| !desired.contains_key(*key))
            .copied()
            .collect();
        for key in stale {
            // Removed even if the kernel says it was not there, because the alternative is a rule that was
            // deleted and an address that stays refused until a restart.
            let _ = self.verdicts.remove(&key);
            self.installed.remove(&key);
            report.removed += 1;
        }

        report
    }

    /// Reads the database's rows into rules, saying so about any it does not understand.
    ///
    /// A row whose action or scope this version does not know is left out rather than guessed at. A rule
    /// enforced as something other than what it says is worse than a rule not enforced.
    fn read(&self, rows: &[RuleRow], report: &mut Report) -> Vec<Rule> {
        let mut rules = Vec::new();
        for row in rows {
            let (Some(action), Some(scope)) =
                (Action::parse(&row.action), Scope::parse(&row.scope))
            else {
                report.unreadable.push(row.id);
                continue;
            };
            rules.push(Rule {
                id: row.id,
                action,
                scope,
                subject: Subject::parse(&row.subject),
                port: (row.port != 0).then_some(row.port),
            });
        }
        rules
    }

    /// Turns one key into however many the kernel needs: one per address a name resolves to.
    fn expand(&mut self, key: &KeySpec, desired: &mut BTreeMap<BlockKey, u8>, report: &mut Report) {
        let agent = key
            .agent
            .as_deref()
            .map_or(EVERYONE, |agent| self.identity(agent));
        let port = key.port.unwrap_or(ANY_PORT);
        let value = u8::from(key.action.refuses());

        let Some(subject) = key.subject.as_deref() else {
            desired.insert(BlockKey::anything(agent, port), value);
            return;
        };
        match self.addresses_for(subject) {
            Some(addresses) => {
                for address in addresses {
                    desired.insert(kernel_key(agent, address, port), value);
                }
            }
            None => {
                if self.complained.insert(subject.to_owned()) {
                    report.unresolved.push(subject.to_owned());
                }
            }
        }
    }

    /// The addresses a subject currently means.
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

/// The kernel's key for one agent, address and port.
pub fn kernel_key(agent: u32, address: IpAddr, port: u16) -> BlockKey {
    match address {
        IpAddr::V4(v4) => BlockKey::new(agent, AF_INET, ipv4_bytes(v4.octets()), port),
        IpAddr::V6(v6) => BlockKey::new(agent, AF_INET6, v6.octets(), port),
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
        let key = kernel_key(EVERYONE, "93.184.216.34".parse().unwrap(), 443);
        assert_eq!(key.family, AF_INET);
        assert_eq!(key.port, 443);
        assert_eq!(key.address[..4], [93, 184, 216, 34]);
        assert_eq!(key.address[4..], [0; 12]);
        assert_eq!(key.agent, EVERYONE);

        let v6 = kernel_key(7, "2606:4700::6441".parse().unwrap(), ANY_PORT);
        assert_eq!(v6.family, AF_INET6);
        assert_eq!(v6.agent, 7);
        assert_eq!(v6.address[0], 0x26);
    }

    #[test]
    fn a_report_with_nothing_in_it_is_quiet() {
        assert!(Report::default().is_quiet());
        for report in [
            Report {
                added: 1,
                ..Report::default()
            },
            Report {
                unresolved: vec!["x".to_owned()],
                ..Report::default()
            },
            Report {
                unenforceable: vec![1],
                ..Report::default()
            },
            Report {
                unreadable: vec![1],
                ..Report::default()
            },
        ] {
            assert!(!report.is_quiet(), "{report:?}");
        }
    }
}
