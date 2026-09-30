//! What a rule means, which rule wins, and what the answer is.
//!
//! No I/O and no dependencies. That is not tidiness: the macOS build has a `RuleBook` that answers the same
//! questions, and two implementations of "block" that quietly come to mean different things is the failure
//! mode that matters most in a pair of tools people use together. A module with no I/O is a module whose
//! semantics can be written down as cases and run by both test suites, which is what 0.2.9 is for.
//!
//! # What a rule is
//!
//! Four parts, each of which can be left unsaid:
//!
//! - an [`Action`] — allow, block, or ask;
//! - a [`Scope`] — everyone, or one agent;
//! - a [`Subject`] — a host, a pattern of hosts, an address, or anything;
//! - a port, or any port.
//!
//! # Which rule wins
//!
//! The most specific one. Specificity is read in a fixed order — **subject, then port, then scope** — and
//! the order is a claim about what people mean. A rule about a host is a rule about the thing being
//! reached, which is the strongest statement anyone writes; a rule about an agent is a statement about who
//! is asking, which is weaker than a statement about what they are asking for.
//!
//! So `block telemetry.example` for everyone beats `allow *` for one agent, and `allow mcp.sentry.dev for
//! claude` beats `block mcp.sentry.dev` for everyone. Both are what somebody writing those two rules
//! meant.
//!
//! Two rules of equal specificity that disagree are a contradiction, and a contradiction resolves the
//! careful way: **block, then ask, then allow**. Nobody writes that pair on purpose, and of the two ways to
//! be wrong about it, refusing something that should have been allowed is the one somebody notices.
//!
//! # The default is allow
//!
//! Nothing is refused unless a rule says so. This is a tool for watching that can also refuse, not a
//! firewall with a default-deny posture, and the difference should not be discovered by a machine losing
//! its network.

#![no_std]

extern crate alloc;

use alloc::borrow::ToOwned as _;
use alloc::string::String;
use alloc::vec::Vec;

/// What to do about a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// Let it through. The default, and the meaning of an explicit exception.
    Allow,
    /// Put the question to a person. See [`Action::Ask`]'s documentation for what that means here.
    ///
    /// On macOS an agent's connection can be held open while somebody decides. Here it cannot: the decision
    /// happens inside `connect()`, in a BPF program, which may not sleep and may not talk to anyone. So
    /// `ask` **refuses, and records the question**. Answering it writes a rule, and the next attempt —
    /// which every network client makes — gets the answer.
    ///
    /// That is a weaker promise than the macOS one and is stated rather than blurred. What it is not is a
    /// connection that silently hangs.
    Ask,
    /// Refuse it before the SYN.
    Block,
}

impl Action {
    /// A word for the interface and for the database.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Block => "block",
        }
    }

    /// Reads one back.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "allow" => Some(Self::Allow),
            "ask" => Some(Self::Ask),
            "block" => Some(Self::Block),
            _ => None,
        }
    }

    /// Whether the connection is refused.
    ///
    /// `ask` refuses too, which is the whole of the difference between this and the macOS build.
    pub fn refuses(self) -> bool {
        self != Self::Allow
    }
}

/// Who a rule is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// Every process on the machine.
    Everyone,
    /// One agent, and anything it started.
    Agent(String),
}

impl Scope {
    /// How this reads in the database and on the screen.
    pub fn as_text(&self) -> String {
        match self {
            Self::Everyone => "everyone".to_owned(),
            Self::Agent(agent) => alloc::format!("agent:{agent}"),
        }
    }

    /// Reads one back. An unrecognised scope is `None` rather than [`Scope::Everyone`], because a rule
    /// whose meaning this version does not know must not be enforced as though it did.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "everyone" | "global" => Some(Self::Everyone),
            other => other
                .strip_prefix("agent:")
                .filter(|agent| !agent.is_empty())
                .map(|agent| Self::Agent(agent.to_owned())),
        }
    }

    /// Whether this scope covers a request from this agent.
    fn covers(&self, agent: Option<&str>) -> bool {
        match self {
            Self::Everyone => true,
            Self::Agent(mine) => agent == Some(mine.as_str()),
        }
    }
}

/// What a rule is about reaching.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    /// Anything at all.
    Anything,
    /// Exactly this host.
    Host(String),
    /// Any subdomain of this host, and not the host itself.
    ///
    /// `*.example.com` is `a.example.com` and `a.b.example.com`, and not `example.com`. That is a choice
    /// and it is the predictable one: a pattern that silently included the apex would make
    /// `block *.example.com` and `allow example.com` a contradiction nobody wrote.
    Subdomains(String),
    /// A literal address, which is what a rule means by the time the kernel sees it.
    Address(String),
}

impl Subject {
    /// Reads a subject out of what somebody typed.
    pub fn parse(text: &str) -> Self {
        let text = text.trim();
        if text == "*" || text.is_empty() {
            return Self::Anything;
        }
        if let Some(rest) = text.strip_prefix("*.") {
            return Self::Subdomains(rest.to_ascii_lowercase());
        }
        // An address is a host that happens to be written as numbers, and telling them apart matters only
        // because a pattern cannot be resolved and an address does not need to be.
        if looks_like_an_address(text) {
            return Self::Address(text.to_owned());
        }
        Self::Host(text.to_ascii_lowercase())
    }

    /// How this reads in the database and on the screen.
    pub fn as_text(&self) -> String {
        match self {
            Self::Anything => "*".to_owned(),
            Self::Host(host) | Self::Address(host) => host.clone(),
            Self::Subdomains(host) => alloc::format!("*.{host}"),
        }
    }

    /// Whether this subject is one the kernel can be told about.
    ///
    /// A pattern cannot: the kernel has an address, and a pattern has to be matched against a name that was
    /// resolved and thrown away before `connect()` was called. So a pattern is enforced by watching what is
    /// reached and refusing the address afterwards, which costs the first connection.
    pub fn is_resolvable(&self) -> bool {
        matches!(self, Self::Host(_) | Self::Address(_))
    }

    /// Whether this subject covers a host.
    pub fn covers_host(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        match self {
            Self::Anything => true,
            Self::Host(mine) | Self::Address(mine) => host == *mine,
            Self::Subdomains(mine) => host
                .strip_suffix(mine.as_str())
                .is_some_and(|prefix| prefix.ends_with('.')),
        }
    }

    /// Whether this subject covers an address.
    fn covers_address(&self, address: &str) -> bool {
        match self {
            Self::Anything => true,
            Self::Address(mine) => address == mine,
            // A name is not an address until something resolves it, and this module does not resolve
            // anything. The caller supplies whichever it knows.
            Self::Host(_) | Self::Subdomains(_) => false,
        }
    }

    /// How specific this is, on its own.
    fn weight(&self) -> u8 {
        match self {
            Self::Anything => 0,
            Self::Subdomains(_) => 1,
            Self::Host(_) | Self::Address(_) => 2,
        }
    }
}

/// Whether some text is a literal address rather than a name.
///
/// Deliberately crude, and correct for the only question being asked: names contain letters, addresses do
/// not, except for IPv6, which contains colons and nothing else does.
fn looks_like_an_address(text: &str) -> bool {
    if text.contains(':') {
        return true;
    }
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Its identifier in the database, so that a verdict can name the rule that produced it.
    pub id: i64,
    /// What to do.
    pub action: Action,
    /// Who it is about.
    pub scope: Scope,
    /// What it is about reaching.
    pub subject: Subject,
    /// Which port, or every port.
    pub port: Option<u16>,
}

impl Rule {
    /// How specific this rule is.
    ///
    /// Subject, then port, then scope — in that order and with that weighting, so that a more specific
    /// subject always beats a more specific anything else. The numbers exist to make the ordering total;
    /// the ordering is the decision.
    pub fn specificity(&self) -> u8 {
        self.subject.weight() * 4 + u8::from(self.port.is_some()) * 2 + u8::from(self.is_scoped())
    }

    /// Whether this rule names an agent.
    pub fn is_scoped(&self) -> bool {
        matches!(self.scope, Scope::Agent(_))
    }

    /// Whether this rule applies to a connection.
    ///
    /// Public because simulation asks the same question of the same rules, and a second implementation of
    /// "does this apply" is a second thing to keep in step with the macOS build.
    pub fn applies(&self, facts: &Facts) -> bool {
        if !self.scope.covers(facts.agent.as_deref()) {
            return false;
        }
        // A rule naming a port cannot be judged against a fact that has none. Treating "unknown" as "the
        // port I meant" would make a simulation claim changes that may not happen, and treating it as "not
        // the port I meant" is the answer that cannot mislead.
        match (self.port, facts.port) {
            (Some(mine), Some(theirs)) if mine != theirs => return false,
            (Some(_), None) => return false,
            _ => {}
        }
        match (&facts.host, &facts.address) {
            // A connection we know the name of is judged by name, and by address only if no name matched:
            // a rule naming a host should not be defeated by that host having an address.
            (Some(host), address) => {
                self.subject.covers_host(host)
                    || address
                        .as_ref()
                        .is_some_and(|address| self.subject.covers_address(address))
            }
            (None, Some(address)) => self.subject.covers_address(address),
            (None, None) => matches!(self.subject, Subject::Anything),
        }
    }
}

/// What is known about a connection when it is judged.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Facts {
    /// The agent that caused it, if any.
    pub agent: Option<String>,
    /// The host, when it is known — which at `connect()` it is not.
    pub host: Option<String>,
    /// The address, as text.
    pub address: Option<String>,
    /// The port, when it is known.
    ///
    /// At `connect()` it always is. Replaying history is another matter: a stored request records the host
    /// it went to and not the port, because the port is not something a probe on a TLS library ever sees.
    /// A rule naming a port therefore cannot be judged against such a row, and does not pretend to be —
    /// see [`Rule::applies`].
    pub port: Option<u16>,
}

/// The answer, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// What to do.
    pub action: Action,
    /// The rule that decided, or `None` when nothing matched and the default applied.
    pub rule: Option<i64>,
}

impl Verdict {
    /// The answer when no rule has anything to say.
    pub const fn default_allow() -> Self {
        Self {
            action: Action::Allow,
            rule: None,
        }
    }
}

/// Decides what to do about a connection.
///
/// The most specific matching rule wins. Among equally specific rules that disagree, the most restrictive
/// wins — a contradiction nobody wrote on purpose, resolved the careful way.
pub fn decide(facts: &Facts, rules: &[Rule]) -> Verdict {
    let mut best: Option<&Rule> = None;
    for rule in rules {
        if !rule.applies(facts) {
            continue;
        }
        let better = match best {
            None => true,
            Some(current) => match rule.specificity().cmp(&current.specificity()) {
                core::cmp::Ordering::Greater => true,
                core::cmp::Ordering::Less => false,
                // `Action` is ordered allow, ask, block, so the greater one is the stricter one.
                core::cmp::Ordering::Equal => rule.action > current.action,
            },
        };
        if better {
            best = Some(rule);
        }
    }
    best.map_or_else(Verdict::default_allow, |rule| Verdict {
        action: rule.action,
        rule: Some(rule.id),
    })
}

/// One entry in the table the kernel consults, before its subject has been resolved to addresses.
///
/// The kernel cannot run [`decide`]: it may not loop, and it has an address where a rule has a name. So
/// precedence is expressed for it as a lookup order — most specific key first, first key found wins — and
/// this produces the keys. Each is the strictest thing said at exactly that level of specificity, which is
/// what makes "first found wins" equivalent to "most specific wins".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeySpec {
    /// The agent, or `None` for everyone.
    pub agent: Option<String>,
    /// The host or address to resolve, or `None` for anything at all.
    pub subject: Option<String>,
    /// The port, or `None` for any port.
    pub port: Option<u16>,
    /// What to do.
    pub action: Action,
}

impl KeySpec {
    /// How specific this is, on the same scale [`Rule::specificity`] uses.
    pub fn specificity(&self) -> u8 {
        u8::from(self.subject.is_some()) * 4
            + u8::from(self.port.is_some()) * 2
            + u8::from(self.agent.is_some())
    }
}

/// The table the kernel consults, and the rules that could not be put into it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    /// The keys, most specific first.
    pub keys: Vec<KeySpec>,
    /// Rules that cannot be enforced before the handshake, and why.
    ///
    /// A pattern is the only kind: it has to be matched against a name, and the name was resolved and
    /// thrown away before `connect()` was called. Reported rather than dropped, because a rule that is
    /// written and silently not enforced is worse than one that was refused.
    pub unenforceable: Vec<i64>,
}

/// Turns rules into the table the kernel consults.
///
/// Rules at the same level of specificity about the same thing are merged, strictest first — the same
/// resolution [`decide`] uses for a contradiction, applied in the one place the kernel cannot.
pub fn table(rules: &[Rule]) -> Table {
    let mut table = Table::default();
    let mut merged: Vec<KeySpec> = Vec::new();

    for rule in rules {
        let subject = match &rule.subject {
            Subject::Anything => None,
            Subject::Host(host) | Subject::Address(host) => Some(host.clone()),
            Subject::Subdomains(_) => {
                table.unenforceable.push(rule.id);
                continue;
            }
        };
        let agent = match &rule.scope {
            Scope::Everyone => None,
            Scope::Agent(agent) => Some(agent.clone()),
        };
        let candidate = KeySpec {
            agent,
            subject,
            port: rule.port,
            action: rule.action,
        };
        match merged.iter_mut().find(|existing| {
            existing.agent == candidate.agent
                && existing.subject == candidate.subject
                && existing.port == candidate.port
        }) {
            Some(existing) => existing.action = existing.action.max(candidate.action),
            None => merged.push(candidate),
        }
    }

    merged.sort_by(|a, b| b.specificity().cmp(&a.specificity()).then(a.cmp(b)));
    table.keys = merged;
    table
}

/// One thing a candidate rule would change, and how often it happened.
///
/// Aggregated rather than listed. A day of traffic is thousands of rows and a handful of distinct answers,
/// and "this would have blocked 1,284 requests to `api.example.com`" is the sentence somebody can act on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Change {
    /// The host or address this is about, whichever the history recorded.
    pub subject: String,
    /// The agent, if the traffic belonged to one.
    pub agent: Option<String>,
    /// The port, when the history recorded one.
    pub port: Option<u16>,
    /// What happens today.
    pub before: Action,
    /// What would happen with the candidate rule in place.
    pub after: Action,
    /// How many times this traffic occurred in the window.
    pub occurrences: i64,
}

/// What adding a rule would change, judged against traffic that actually happened.
///
/// Every piece of history is decided twice — once with the rules as they are, once with the candidate added
/// — and only the answers that move are reported. That is the whole idea, and it is the difference between
/// a rule somebody can enable and a rule nobody dares to: the macOS build learned that the long way round.
///
/// Note what this is not. It is a claim about the past, not a promise about the future: a host that was not
/// reached yesterday does not appear, and a name that resolves elsewhere tomorrow will behave differently.
/// Reporting only what is derivable from evidence is the point.
pub fn simulate(existing: &[Rule], candidate: &Rule, history: &[(Facts, i64)]) -> Vec<Change> {
    let mut with_candidate: Vec<Rule> = existing.to_vec();
    // An identifier already in use would make the verdict ambiguous about which rule decided.
    let mut candidate = candidate.clone();
    if existing.iter().any(|rule| rule.id == candidate.id) {
        candidate.id = existing.iter().map(|rule| rule.id).max().unwrap_or(0) + 1;
    }
    with_candidate.push(candidate);

    let mut changes: Vec<Change> = Vec::new();
    for (facts, occurrences) in history {
        let before = decide(facts, existing);
        let after = decide(facts, &with_candidate);
        if before.action == after.action {
            continue;
        }
        let Some(subject) = facts.host.clone().or_else(|| facts.address.clone()) else {
            continue;
        };
        let change = Change {
            subject,
            agent: facts.agent.clone(),
            port: facts.port,
            before: before.action,
            after: after.action,
            occurrences: *occurrences,
        };
        match changes.iter_mut().find(|existing| {
            existing.subject == change.subject
                && existing.agent == change.agent
                && existing.port == change.port
                && existing.before == change.before
                && existing.after == change.after
        }) {
            Some(existing) => existing.occurrences += change.occurrences,
            None => changes.push(change),
        }
    }
    // Busiest first: the thing that would change most is the thing worth reading about.
    changes.sort_by(|a, b| b.occurrences.cmp(&a.occurrences).then(a.cmp(b)));
    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: i64, action: Action, scope: &str, subject: &str, port: Option<u16>) -> Rule {
        Rule {
            id,
            action,
            scope: Scope::parse(scope).unwrap(),
            subject: Subject::parse(subject),
            port,
        }
    }

    fn facts(agent: Option<&str>, host: Option<&str>, address: Option<&str>, port: u16) -> Facts {
        Facts {
            agent: agent.map(|text| text.to_owned()),
            host: host.map(|text| text.to_owned()),
            address: address.map(|text| text.to_owned()),
            port: Some(port),
        }
    }

    /// This is a tool for watching that can also refuse, not a firewall with a default-deny posture, and
    /// the difference should not be discovered by a machine losing its network.
    #[test]
    fn nothing_is_refused_unless_a_rule_says_so() {
        let verdict = decide(&facts(None, Some("example.com"), None, 443), &[]);
        assert_eq!(verdict, Verdict::default_allow());
        assert_eq!(verdict.action, Action::Allow);
        assert!(!verdict.action.refuses());
    }

    #[test]
    fn a_rule_naming_a_host_decides_a_connection_to_it() {
        let rules = [rule(
            1,
            Action::Block,
            "everyone",
            "telemetry.example",
            None,
        )];
        let verdict = decide(&facts(None, Some("telemetry.example"), None, 443), &rules);
        assert_eq!(verdict.action, Action::Block);
        assert_eq!(verdict.rule, Some(1));
    }

    /// The commonest pair anybody writes: block a thing, and let one agent have it anyway.
    #[test]
    fn an_exception_for_one_agent_beats_a_block_for_everyone() {
        let rules = [
            rule(1, Action::Block, "everyone", "mcp.sentry.dev", None),
            rule(2, Action::Allow, "agent:claude", "mcp.sentry.dev", None),
        ];
        assert_eq!(
            decide(
                &facts(Some("claude"), Some("mcp.sentry.dev"), None, 443),
                &rules
            )
            .action,
            Action::Allow
        );
        assert_eq!(
            decide(
                &facts(Some("codex"), Some("mcp.sentry.dev"), None, 443),
                &rules
            )
            .action,
            Action::Block
        );
    }

    /// The other direction, and the reason subject outranks scope. A rule about a host is a statement about
    /// the thing being reached, which is stronger than a statement about who is asking.
    #[test]
    fn a_rule_about_a_host_beats_a_blanket_rule_about_an_agent() {
        let rules = [
            rule(1, Action::Allow, "agent:claude", "*", None),
            rule(2, Action::Block, "everyone", "telemetry.example", None),
        ];
        assert_eq!(
            decide(
                &facts(Some("claude"), Some("telemetry.example"), None, 443),
                &rules
            )
            .action,
            Action::Block
        );
    }

    #[test]
    fn a_rule_naming_a_port_beats_one_that_does_not() {
        let rules = [
            rule(1, Action::Block, "everyone", "example.com", None),
            rule(2, Action::Allow, "everyone", "example.com", Some(443)),
        ];
        assert_eq!(
            decide(&facts(None, Some("example.com"), None, 443), &rules).action,
            Action::Allow
        );
        assert_eq!(
            decide(&facts(None, Some("example.com"), None, 80), &rules).action,
            Action::Block
        );
    }

    /// Nobody writes this on purpose. Of the two ways to be wrong about it, refusing something that should
    /// have been allowed is the one somebody notices.
    #[test]
    fn a_contradiction_resolves_the_careful_way() {
        let rules = [
            rule(1, Action::Allow, "everyone", "example.com", None),
            rule(2, Action::Block, "everyone", "example.com", None),
        ];
        assert_eq!(
            decide(&facts(None, Some("example.com"), None, 443), &rules).action,
            Action::Block
        );
        // And in the other order, so that the answer does not depend on which was written first.
        let reversed = [rules[1].clone(), rules[0].clone()];
        assert_eq!(
            decide(&facts(None, Some("example.com"), None, 443), &reversed).action,
            Action::Block
        );
    }

    #[test]
    fn ask_sits_between_allow_and_block() {
        assert!(Action::Block > Action::Ask);
        assert!(Action::Ask > Action::Allow);
        assert!(Action::Ask.refuses());
        let rules = [
            rule(1, Action::Allow, "everyone", "example.com", None),
            rule(2, Action::Ask, "everyone", "example.com", None),
        ];
        assert_eq!(
            decide(&facts(None, Some("example.com"), None, 443), &rules).action,
            Action::Ask
        );
    }

    // Subjects

    /// A pattern that silently included the apex would make `block *.example.com` and `allow example.com` a
    /// contradiction nobody wrote.
    #[test]
    fn a_subdomain_pattern_is_subdomains_and_not_the_host_itself() {
        let rules = [rule(1, Action::Block, "everyone", "*.example.com", None)];
        for host in ["a.example.com", "a.b.example.com"] {
            assert_eq!(
                decide(&facts(None, Some(host), None, 443), &rules).action,
                Action::Block,
                "{host}"
            );
        }
        for host in ["example.com", "notexample.com", "example.com.evil.test"] {
            assert_eq!(
                decide(&facts(None, Some(host), None, 443), &rules).action,
                Action::Allow,
                "{host}"
            );
        }
    }

    /// `notexample.com` ends with `example.com` and is a different domain. Suffix matching without the dot
    /// is the classic way to block the wrong thing, or fail to block the right one.
    #[test]
    fn a_suffix_that_is_not_a_subdomain_does_not_match() {
        let subject = Subject::parse("*.example.com");
        assert!(subject.covers_host("a.example.com"));
        assert!(!subject.covers_host("notexample.com"));
        assert!(!subject.covers_host("example.com"));
    }

    #[test]
    fn hosts_are_matched_without_regard_to_case_or_a_trailing_dot() {
        let rules = [rule(1, Action::Block, "everyone", "Example.COM", None)];
        for host in ["example.com", "EXAMPLE.com", "example.com."] {
            assert_eq!(
                decide(&facts(None, Some(host), None, 443), &rules).action,
                Action::Block,
                "{host}"
            );
        }
    }

    /// At `connect()` there is no name — it was resolved and thrown away. A rule naming an address is the
    /// only kind that can decide there.
    #[test]
    fn a_connection_with_no_name_is_judged_by_its_address() {
        let rules = [rule(1, Action::Block, "everyone", "93.184.216.34", None)];
        assert_eq!(
            decide(&facts(None, None, Some("93.184.216.34"), 443), &rules).action,
            Action::Block
        );
        assert_eq!(
            decide(&facts(None, None, Some("93.184.216.35"), 443), &rules).action,
            Action::Allow
        );
    }

    /// A rule naming a host should not be defeated by that host having an address, nor the other way
    /// round: whichever the caller knows is what the rule is asked about.
    #[test]
    fn a_connection_with_both_is_judged_by_either() {
        let by_host = [rule(1, Action::Block, "everyone", "example.com", None)];
        let by_address = [rule(1, Action::Block, "everyone", "93.184.216.34", None)];
        let both = facts(None, Some("example.com"), Some("93.184.216.34"), 443);
        assert_eq!(decide(&both, &by_host).action, Action::Block);
        assert_eq!(decide(&both, &by_address).action, Action::Block);
    }

    #[test]
    fn a_rule_about_anything_applies_to_a_connection_we_know_nothing_about() {
        let rules = [rule(1, Action::Block, "agent:claude", "*", None)];
        assert_eq!(
            decide(&facts(Some("claude"), None, None, 443), &rules).action,
            Action::Block
        );
        assert_eq!(
            decide(&facts(Some("codex"), None, None, 443), &rules).action,
            Action::Allow
        );
    }

    #[test]
    fn addresses_and_names_are_told_apart() {
        assert_eq!(
            Subject::parse("93.184.216.34"),
            Subject::Address("93.184.216.34".to_owned())
        );
        assert_eq!(Subject::parse("::1"), Subject::Address("::1".to_owned()));
        assert_eq!(
            Subject::parse("example.com"),
            Subject::Host("example.com".to_owned())
        );
        assert_eq!(Subject::parse("*"), Subject::Anything);
        assert_eq!(Subject::parse(""), Subject::Anything);
        // Four numeric parts and nothing else is an address; three is a name that looks unusual.
        assert_eq!(Subject::parse("1.2.3"), Subject::Host("1.2.3".to_owned()));
    }

    /// A pattern cannot be handed to the kernel: it has an address, and the name was thrown away before
    /// `connect()`. The interface has to be able to say which rules are enforced there and which are not.
    #[test]
    fn a_pattern_is_not_something_the_kernel_can_be_told() {
        assert!(Subject::parse("example.com").is_resolvable());
        assert!(Subject::parse("93.184.216.34").is_resolvable());
        assert!(!Subject::parse("*.example.com").is_resolvable());
        assert!(!Subject::parse("*").is_resolvable());
    }

    // The table the kernel consults

    /// The kernel cannot run `decide`: it may not loop, and it has an address where a rule has a name. So
    /// precedence becomes a lookup order, and this is what makes the two agree.
    #[test]
    fn the_table_is_ordered_the_way_precedence_is() {
        let rules = [
            rule(1, Action::Block, "agent:claude", "*", None),
            rule(2, Action::Block, "everyone", "example.com", None),
            rule(3, Action::Allow, "agent:claude", "example.com", Some(443)),
        ];
        let table = table(&rules);
        let specificities: Vec<u8> = table.keys.iter().map(KeySpec::specificity).collect();
        assert_eq!(specificities, [7, 4, 1]);
        assert_eq!(table.keys[0].action, Action::Allow);
        assert_eq!(table.keys[0].subject.as_deref(), Some("example.com"));
        assert_eq!(table.keys[0].agent.as_deref(), Some("claude"));
    }

    /// Two rules saying different things about exactly the same thing are one key, resolved the same way
    /// `decide` resolves a contradiction.
    #[test]
    fn rules_at_the_same_specificity_about_the_same_thing_become_one_key() {
        let rules = [
            rule(1, Action::Allow, "everyone", "example.com", None),
            rule(2, Action::Block, "everyone", "example.com", None),
        ];
        let table = table(&rules);
        assert_eq!(table.keys.len(), 1);
        assert_eq!(table.keys[0].action, Action::Block);
    }

    /// A pattern has to be matched against a name, and the name was resolved and thrown away before
    /// `connect()`. A rule that is written and silently not enforced is worse than one that was refused.
    #[test]
    fn a_pattern_is_reported_as_unenforceable_rather_than_dropped() {
        let rules = [
            rule(1, Action::Block, "everyone", "*.example.com", None),
            rule(2, Action::Block, "everyone", "example.com", None),
        ];
        let table = table(&rules);
        assert_eq!(table.unenforceable, [1]);
        assert_eq!(table.keys.len(), 1);
        assert_eq!(table.keys[0].subject.as_deref(), Some("example.com"));
    }

    /// The whole table, for a set of rules whose ordering is the point. Reading down it is reading
    /// precedence: the kernel takes the first key it finds.
    #[test]
    fn every_level_of_specificity_has_its_own_place_in_the_order() {
        let rules = [
            rule(1, Action::Block, "everyone", "*", None),
            rule(2, Action::Block, "agent:claude", "*", None),
            rule(3, Action::Block, "everyone", "*", Some(443)),
            rule(4, Action::Block, "agent:claude", "*", Some(443)),
            rule(5, Action::Block, "everyone", "a.example", None),
            rule(6, Action::Block, "agent:claude", "a.example", None),
            rule(7, Action::Block, "everyone", "a.example", Some(443)),
            rule(8, Action::Block, "agent:claude", "a.example", Some(443)),
        ];
        let specificities: Vec<u8> = table(&rules)
            .keys
            .iter()
            .map(KeySpec::specificity)
            .collect();
        assert_eq!(specificities, [7, 6, 5, 4, 3, 2, 1, 0]);
    }

    #[test]
    fn a_table_of_no_rules_is_empty_rather_than_anything_else() {
        assert_eq!(table(&[]), Table::default());
    }

    // Simulation

    /// One row of history as these tests write it: agent, host, port, and how many times.
    type Past<'a> = (Option<&'a str>, Option<&'a str>, Option<u16>, i64);

    fn history(rows: &[Past<'_>]) -> Vec<(Facts, i64)> {
        rows.iter()
            .map(|(agent, host, port, count)| {
                (
                    Facts {
                        agent: agent.map(|text| text.to_owned()),
                        host: host.map(|text| text.to_owned()),
                        address: None,
                        port: *port,
                    },
                    *count,
                )
            })
            .collect()
    }

    /// The whole idea: a number somebody can act on before the rule is real.
    #[test]
    fn a_candidate_rule_says_what_it_would_have_changed() {
        let past = history(&[
            (Some("claude"), Some("telemetry.example"), None, 1_284),
            (Some("claude"), Some("api.anthropic.com"), None, 40),
        ]);
        let candidate = rule(9, Action::Block, "everyone", "telemetry.example", None);
        let changes = simulate(&[], &candidate, &past);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].subject, "telemetry.example");
        assert_eq!(changes[0].before, Action::Allow);
        assert_eq!(changes[0].after, Action::Block);
        assert_eq!(changes[0].occurrences, 1_284);
    }

    /// A rule that changes nothing is the commonest thing anybody types, and saying "nothing" is the whole
    /// value of asking first.
    #[test]
    fn a_rule_that_changes_nothing_reports_nothing() {
        let past = history(&[(None, Some("example.com"), None, 10)]);
        let candidate = rule(9, Action::Block, "everyone", "somewhere.else", None);
        assert!(simulate(&[], &candidate, &past).is_empty());
        // And one that agrees with what is already there.
        let existing = [rule(1, Action::Block, "everyone", "example.com", None)];
        let same = rule(9, Action::Block, "everyone", "example.com", None);
        assert!(simulate(&existing, &same, &past).is_empty());
    }

    /// An exception is a change in the other direction, and is exactly as worth previewing.
    #[test]
    fn an_exception_reports_what_it_would_let_through() {
        let past = history(&[(Some("claude"), Some("mcp.sentry.dev"), None, 12)]);
        let existing = [rule(1, Action::Block, "everyone", "mcp.sentry.dev", None)];
        let candidate = rule(9, Action::Allow, "agent:claude", "mcp.sentry.dev", None);
        let changes = simulate(&existing, &candidate, &past);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].before, Action::Block);
        assert_eq!(changes[0].after, Action::Allow);
    }

    /// The rule that already exists must keep deciding: a candidate is added to the book, not put in place
    /// of it, or every simulation would report the rest of the rules being switched off.
    #[test]
    fn the_rules_that_are_there_still_decide() {
        let past = history(&[
            (None, Some("a.example"), None, 5),
            (None, Some("b.example"), None, 5),
        ]);
        let existing = [rule(1, Action::Block, "everyone", "a.example", None)];
        let candidate = rule(9, Action::Block, "everyone", "b.example", None);
        let changes = simulate(&existing, &candidate, &past);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].subject, "b.example");
    }

    /// A candidate whose identifier collides with a real rule would make the verdict ambiguous about which
    /// of the two decided.
    #[test]
    fn a_candidate_that_reuses_an_identifier_is_given_another() {
        let past = history(&[(None, Some("a.example"), None, 5)]);
        let existing = [rule(1, Action::Allow, "everyone", "a.example", None)];
        let candidate = rule(1, Action::Block, "everyone", "a.example", None);
        let changes = simulate(&existing, &candidate, &past);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].after, Action::Block);
    }

    /// A stored request records the host and not the port, because a probe on a TLS library never sees one.
    /// A rule naming a port must not claim it would have changed such a request.
    #[test]
    fn a_rule_naming_a_port_claims_nothing_about_history_without_one() {
        let past = history(&[(None, Some("example.com"), None, 10)]);
        let candidate = rule(9, Action::Block, "everyone", "example.com", Some(443));
        assert!(simulate(&[], &candidate, &past).is_empty());

        // And where the port is known, it decides.
        let with_ports = history(&[(None, Some("example.com"), Some(443), 10)]);
        assert_eq!(simulate(&[], &candidate, &with_ports).len(), 1);
    }

    /// A day of traffic is thousands of rows and a handful of distinct answers.
    #[test]
    fn the_same_change_seen_twice_is_counted_once() {
        let past = history(&[
            (Some("claude"), Some("a.example"), None, 100),
            (Some("claude"), Some("a.example"), None, 40),
        ]);
        let candidate = rule(9, Action::Block, "everyone", "a.example", None);
        let changes = simulate(&[], &candidate, &past);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].occurrences, 140);
    }

    /// The thing that would change most is the thing worth reading about first.
    #[test]
    fn the_busiest_change_is_reported_first() {
        let past = history(&[
            (None, Some("quiet.example"), None, 2),
            (None, Some("busy.example"), None, 900),
        ]);
        let candidate = rule(9, Action::Block, "everyone", "*", None);
        let changes = simulate(&[], &candidate, &past);
        assert_eq!(
            changes.first().map(|c| c.subject.as_str()),
            Some("busy.example")
        );
    }

    /// Traffic with neither a name nor an address cannot be described, so it is left out rather than
    /// reported as a change to nothing.
    #[test]
    fn history_with_nothing_to_name_is_left_out() {
        let past = [(Facts::default(), 10)];
        let candidate = rule(9, Action::Block, "everyone", "*", None);
        assert!(simulate(&[], &candidate, &past).is_empty());
    }

    // Round-tripping, because these go through a database

    #[test]
    fn every_part_of_a_rule_survives_being_written_down_and_read_back() {
        for text in ["allow", "ask", "block"] {
            assert_eq!(Action::parse(text).map(Action::as_str), Some(text));
        }
        assert_eq!(Action::parse("maybe"), None);

        for scope in [Scope::Everyone, Scope::Agent("claude".to_owned())] {
            assert_eq!(Scope::parse(&scope.as_text()).as_ref(), Some(&scope));
        }
        for subject in ["*", "example.com", "*.example.com", "93.184.216.34"] {
            assert_eq!(Subject::parse(subject).as_text(), subject);
        }
    }

    /// 0.2.0 wrote `global`. A database from it must keep working, and a scope this version does not
    /// understand must not be enforced as though it did.
    #[test]
    fn an_older_scope_is_understood_and_an_unknown_one_is_not() {
        assert_eq!(Scope::parse("global"), Some(Scope::Everyone));
        assert_eq!(Scope::parse("agent:"), None);
        assert_eq!(Scope::parse("something-new"), None);
    }
}

// MARK: Interception

/// Whether a pattern with `*` in it covers a string.
///
/// `*` stands for any run of characters, including none. Nothing else is special: a `?` in a path is a query
/// string, not a wildcard, and treating it as one would make `/v1/*` behave differently depending on whether
/// the request happened to carry parameters.
///
/// Iterative rather than recursive, and with no backtracking stack, because this runs on a request path that
/// somebody else chose. A pattern of alternating stars against a long path must not be a way to make the
/// machine stop answering.
pub fn glob(pattern: &str, subject: &str) -> bool {
    let pattern: &[u8] = pattern.as_bytes();
    let subject: &[u8] = subject.as_bytes();
    let (mut p, mut s) = (0, 0);
    // Where to resume if the current run of literal characters turns out not to match: just after the last
    // star, with the subject one character further on than when that star was last tried.
    let (mut star, mut resume) = (None, 0);
    while s < subject.len() {
        match (pattern.get(p), subject.get(s)) {
            (Some(b'*'), _) => {
                star = Some(p);
                resume = s;
                p += 1;
            }
            (Some(expected), Some(found)) if expected == found => {
                p += 1;
                s += 1;
            }
            _ => match star {
                Some(at) => {
                    p = at + 1;
                    resume += 1;
                    s = resume;
                }
                None => return false,
            },
        }
    }
    // Trailing stars match nothing at all, which is how `/v1/*` covers `/v1/`.
    while pattern.get(p) == Some(&b'*') {
        p += 1;
    }
    p == pattern.len()
}

/// A canned answer for one request: "reply to `POST api.example.com/v1/items` with a 503".
///
/// It exists to watch an agent cope with an API that fails, stalls, or answers with something odd, without
/// breaking the real service or waiting for it to misbehave on its own. The first enabled rule that matches
/// answers; everything else is relayed untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mock {
    /// Its identifier, so `forget` can take it away.
    pub id: i64,
    /// Whether it answers at all.
    pub enabled: bool,
    /// `api.example.com` or `*.example.com`, read the same way a rule's subject is.
    pub subject: Subject,
    /// A glob against the path. `*` for any path.
    pub path: String,
    /// The method, uppercased, or empty for any.
    pub method: String,
    /// The status to answer with.
    pub status: u16,
    /// Headers, as name and value.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: String,
    /// Seconds to wait before answering, so "the API stalls" is testable.
    pub delay: u32,
    /// Whether this answer is a refusal rather than a stand-in for the server.
    ///
    /// It changes only what the answer calls itself. The same machinery gives it, but "Flowlight refused
    /// this" and "Flowlight pretended to be the server" are not the same thing to read in a log.
    pub refusal: bool,
    /// Why, for whoever reads the list later.
    pub note: Option<String>,
}

impl Mock {
    /// Whether this answers that request.
    pub fn answers(&self, host: &str, method: &str, path: &str) -> bool {
        self.enabled
            && self.subject.covers_host(host)
            && self.covers_method(method)
            && glob(&self.path, path)
    }

    /// Whether this rule's method covers one. Empty and `ANY` mean every method.
    fn covers_method(&self, method: &str) -> bool {
        let mine = self.method.trim();
        mine.is_empty()
            || mine.eq_ignore_ascii_case("any")
            || mine.eq_ignore_ascii_case("*")
            || mine.eq_ignore_ascii_case(method)
    }

    /// How this reads in a list.
    pub fn title(&self) -> String {
        alloc::format!(
            "{} {}{}",
            if self.method.trim().is_empty() {
                "ANY"
            } else {
                self.method.trim()
            },
            self.subject.as_text(),
            self.path
        )
    }
}

/// The first enabled mock that answers a request, or nothing when it should go upstream untouched.
pub fn mocked<'a>(mocks: &'a [Mock], host: &str, method: &str, path: &str) -> Option<&'a Mock> {
    mocks.iter().find(|mock| mock.answers(host, method, path))
}

/// Whether any enabled mock could answer for this host.
///
/// Asked once per connection, before anything is framed, so a host nobody mocks does not pay for the feature
/// — and, more to the point, is not terminated and re-encrypted for no reason.
pub fn mocks_anything(mocks: &[Mock], host: &str) -> bool {
    mocks
        .iter()
        .any(|mock| mock.enabled && mock.subject.covers_host(host))
}

#[cfg(test)]
mod interception_tests {
    use super::*;
    use alloc::vec;

    fn mock(subject: &str, method: &str, path: &str) -> Mock {
        Mock {
            id: 1,
            enabled: true,
            subject: Subject::parse(subject),
            path: path.to_owned(),
            method: method.to_owned(),
            status: 503,
            headers: Vec::new(),
            body: String::new(),
            delay: 0,
            refusal: false,
            note: None,
        }
    }

    #[test]
    fn a_star_stands_for_any_run_of_characters() {
        assert!(glob("*", "/anything"));
        assert!(glob("/v1/*", "/v1/messages"));
        assert!(glob("/v1/*", "/v1/"));
        assert!(!glob("/v1/*", "/v2/messages"));
        assert!(glob("*/messages", "/v1/messages"));
        assert!(glob("/v1/*/stream", "/v1/a/b/stream"));
        assert!(!glob("/v1/*/stream", "/v1/a/b/streaming"));
        assert!(glob("/exact", "/exact"));
        assert!(!glob("/exact", "/exactly"));
    }

    /// A `?` is a query string, not a wildcard. Treating it as one would make `/v1/*` behave differently
    /// depending on whether the request happened to carry parameters.
    #[test]
    fn nothing_but_a_star_is_special() {
        assert!(glob("/v1/x?a=1", "/v1/x?a=1"));
        assert!(!glob("/v1/x?a=1", "/v1/xya=1"));
        assert!(glob("/v1/*", "/v1/x?a=1"));
    }

    /// A pattern of alternating stars against a long path must not be a way to make the machine stop
    /// answering. This runs in the proxy, on a path somebody else chose.
    #[test]
    fn a_pathological_pattern_still_finishes() {
        let pattern = "*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
        let subject = "a".repeat(2_000);
        assert!(!glob(pattern, &subject));
        assert!(glob("*a*a*a*b", "aaaaaaaaaaaaaaaaaaaab"));
    }

    #[test]
    fn a_mock_answers_what_it_names_and_nothing_else() {
        let rule = mock("api.example.com", "POST", "/v1/*");
        assert!(rule.answers("api.example.com", "POST", "/v1/messages"));
        assert!(!rule.answers("api.example.com", "GET", "/v1/messages"));
        assert!(!rule.answers("other.example.com", "POST", "/v1/messages"));
        assert!(!rule.answers("api.example.com", "POST", "/v2/messages"));
    }

    #[test]
    fn an_empty_method_is_every_method() {
        for named in ["", "  ", "ANY", "any", "*"] {
            let rule = mock("api.example.com", named, "*");
            assert!(rule.answers("api.example.com", "DELETE", "/"), "{named}");
        }
        // And a named one is case-insensitive, because a method written lowercase is the same method.
        assert!(mock("api.example.com", "post", "*").answers("api.example.com", "POST", "/"));
    }

    #[test]
    fn a_mock_that_is_off_answers_nothing() {
        let mut rule = mock("api.example.com", "", "*");
        rule.enabled = false;
        assert!(!rule.answers("api.example.com", "GET", "/"));
        assert!(mocked(&[rule.clone()], "api.example.com", "GET", "/").is_none());
        assert!(!mocks_anything(&[rule], "api.example.com"));
    }

    /// The first enabled rule that matches answers. Ordering is the whole of the precedence here, unlike
    /// [`decide`], because a mock is a canned answer rather than a claim about what is allowed.
    #[test]
    fn the_first_matching_mock_answers() {
        let mut first = mock("*.example.com", "", "*");
        first.id = 1;
        first.status = 500;
        let mut second = mock("api.example.com", "", "*");
        second.id = 2;
        second.status = 503;
        let rules = vec![first, second];
        let chosen = mocked(&rules, "api.example.com", "GET", "/").expect("one matches");
        assert_eq!(chosen.id, 1);
    }

    /// Asked once per connection: a host nobody mocks is not terminated and re-encrypted for no reason.
    #[test]
    fn a_host_nobody_mocks_is_left_alone() {
        let rules = vec![mock("api.example.com", "", "*")];
        assert!(mocks_anything(&rules, "api.example.com"));
        assert!(!mocks_anything(&rules, "github.com"));
        // A subdomain pattern covers subdomains and not the apex, exactly as a rule's subject does.
        let rules = vec![mock("*.example.com", "", "*")];
        assert!(mocks_anything(&rules, "a.example.com"));
        assert!(!mocks_anything(&rules, "example.com"));
    }

    #[test]
    fn a_title_says_what_it_matches() {
        assert_eq!(
            mock("api.example.com", "post", "/v1/*").title(),
            "post api.example.com/v1/*"
        );
        assert_eq!(mock("*.example.com", "", "*").title(), "ANY *.example.com*");
    }
}
