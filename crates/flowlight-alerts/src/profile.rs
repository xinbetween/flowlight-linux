//! Why one process's traffic stands out, with the count behind each reason.
//!
//! A ranked list with no arithmetic behind it is a horoscope — the same rule the alerts follow, applied to a
//! different question. An alert says *something happened*; this says *this one is not like the others*, which
//! is a judgement and has to show its working or it is a rumour.
//!
//! # Why the weights are relative and say so
//!
//! Each signal carries a weight and they are added up to order the list. The total means nothing on its own:
//! it is not a risk score, there is no threshold, and a process at the top is a process to look at rather than
//! a process that has done something. Saying that plainly is the difference between a useful ordering and a
//! number people will quote.

use alloc::string::{String, ToString as _};
use alloc::vec::Vec;

/// One reason a process's traffic stands out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Signal {
    /// It reached far more distinct hosts than anything else did.
    ManyHosts,
    /// Most of what it reached had no name — addresses rather than hosts.
    Hostless,
    /// The names it reached look generated rather than chosen.
    GeneratedNames,
    /// It sent far more than it received.
    MostlyUploading,
    /// Nothing of what it sent could be read.
    NothingRead,
}

impl Signal {
    /// How much this contributes to the ordering. Relative only.
    pub fn weight(self) -> u32 {
        match self {
            Self::ManyHosts => 2,
            Self::Hostless => 3,
            Self::GeneratedNames => 3,
            Self::MostlyUploading => 2,
            Self::NothingRead => 1,
        }
    }
}

/// One reason, with the numbers that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// Which signal.
    pub signal: Signal,
    /// The sentence, with the arithmetic in it.
    pub said: String,
    /// Its weight in the ordering.
    pub weight: u32,
}

/// What is known about one process over a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Traffic {
    /// Distinct hosts it reached, by name.
    pub hosts: i64,
    /// Distinct addresses it connected to.
    pub addresses: i64,
    /// Connections it opened whose destination had no name recorded.
    pub unnamed: i64,
    /// Bytes it sent.
    pub sent: i64,
    /// Bytes it received.
    pub received: i64,
    /// Connections nothing could be read from.
    pub unread: i64,
    /// Connections it opened.
    pub connections: i64,
}

/// A process, and why it stands out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    /// What it is called.
    pub process: String,
    /// The reasons, strongest first.
    pub reasons: Vec<Reason>,
    /// The sum of their weights. Relative only, and not a score of anything.
    pub weight: u32,
}

/// Why this process stands out, given what everything else did.
///
/// `usual_hosts` is the median number of hosts a process on this machine reached in the window. Compared
/// against the median rather than the mean, because one process reaching four hundred hosts is exactly the
/// case being looked for and it should not be allowed to redefine normal on its way past.
pub fn standing(process: &str, traffic: Traffic, usual_hosts: f64, names: &[&str]) -> Standing {
    let mut reasons = Vec::new();

    if traffic.hosts >= 10 && traffic.hosts as f64 > usual_hosts.max(1.0) * 4.0 {
        reasons.push(Reason {
            signal: Signal::ManyHosts,
            said: alloc::format!(
                "reached {} distinct host(s), where the usual process on this machine reached {usual_hosts:.0}",
                traffic.hosts
            ),
            weight: Signal::ManyHosts.weight(),
        });
    }

    if traffic.connections >= 5 && traffic.unnamed * 2 > traffic.connections {
        reasons.push(Reason {
            signal: Signal::Hostless,
            said: alloc::format!(
                "{} of its {} connection(s) went to an address with no name recorded",
                traffic.unnamed,
                traffic.connections
            ),
            weight: Signal::Hostless.weight(),
        });
    }

    let generated = names.iter().filter(|name| looks_generated(name)).count();
    if generated >= 3 && generated * 2 > names.len() {
        reasons.push(Reason {
            signal: Signal::GeneratedNames,
            said: alloc::format!(
                "{generated} of the {} name(s) it reached look generated rather than chosen",
                names.len()
            ),
            weight: Signal::GeneratedNames.weight(),
        });
    }

    if traffic.sent > 5 * 1_024 * 1_024 && traffic.sent > traffic.received.max(1) * 10 {
        reasons.push(Reason {
            signal: Signal::MostlyUploading,
            said: alloc::format!(
                "sent {} and received {} — {:.0} times as much out as in",
                crate::bytes_said(traffic.sent),
                crate::bytes_said(traffic.received),
                traffic.sent as f64 / traffic.received.max(1) as f64
            ),
            weight: Signal::MostlyUploading.weight(),
        });
    }

    if traffic.unread > 0 && traffic.unread == traffic.connections {
        reasons.push(Reason {
            signal: Signal::NothingRead,
            said: alloc::format!(
                "opened {} connection(s) and nothing was read from any of them",
                traffic.connections
            ),
            weight: Signal::NothingRead.weight(),
        });
    }

    reasons.sort_by(|left, right| {
        right
            .weight
            .cmp(&left.weight)
            .then(left.signal.cmp(&right.signal))
    });
    let weight = reasons.iter().map(|reason| reason.weight).sum();
    Standing {
        process: process.to_string(),
        reasons,
        weight,
    }
}

/// The middle value of a set of counts.
///
/// The median rather than the mean, because the thing being looked for is one process far above the rest, and
/// a mean lets it drag normal up towards itself on the way past.
pub fn median(counts: &mut [i64]) -> f64 {
    if counts.is_empty() {
        return 0.0;
    }
    counts.sort_unstable();
    let middle = counts.len() / 2;
    if counts.len() % 2 == 1 {
        counts.get(middle).copied().unwrap_or(0) as f64
    } else {
        let left = counts.get(middle - 1).copied().unwrap_or(0) as f64;
        let right = counts.get(middle).copied().unwrap_or(0) as f64;
        (left + right) / 2.0
    }
}

/// Whether a name looks generated rather than chosen.
///
/// A label of mostly digits, or a long one with no vowels in it. Crude on purpose and stated as crude: it
/// matches the shape of a content network's own names as readily as anything sinister, which is why it is one
/// signal among several rather than a verdict.
pub fn looks_generated(host: &str) -> bool {
    let Some(label) = host.split('.').next() else {
        return false;
    };
    if label.len() < 6 {
        return false;
    }
    let digits = label.chars().filter(char::is_ascii_digit).count();
    if digits * 2 >= label.len() {
        return true;
    }
    let vowels = label
        .chars()
        .filter(|character| matches!(character.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
        .count();
    label.len() >= 12 && vowels * 6 < label.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn busy() -> Traffic {
        Traffic {
            hosts: 40,
            addresses: 40,
            unnamed: 0,
            sent: 1_000,
            received: 1_000,
            unread: 0,
            connections: 40,
        }
    }

    /// One process reaching four hundred hosts is the case being looked for; it must not be allowed to
    /// redefine normal on its way past.
    #[test]
    fn normal_is_the_middle_and_not_the_average() {
        let mut counts = vec![2, 3, 4, 5, 400];
        assert_eq!(median(&mut counts), 4.0);
        assert_eq!(median(&mut [1, 3]), 2.0);
        assert_eq!(median(&mut []), 0.0);
    }

    #[test]
    fn reaching_far_more_hosts_than_anything_else_is_a_reason() {
        let standing = standing("crawler", busy(), 4.0, &[]);
        assert_eq!(standing.reasons.len(), 1);
        assert_eq!(standing.reasons[0].signal, Signal::ManyHosts);
        assert!(standing.reasons[0].said.contains("40 distinct host(s)"));
        assert!(standing.reasons[0].said.contains("reached 4"));
    }

    /// A handful of hosts is not a lot of hosts, however much above the median it is.
    #[test]
    fn a_small_number_is_never_a_lot() {
        let quiet = Traffic {
            hosts: 3,
            connections: 3,
            ..busy()
        };
        assert!(standing("curl", quiet, 0.5, &[]).reasons.is_empty());
    }

    #[test]
    fn mostly_addresses_rather_than_names_is_a_reason() {
        let traffic = Traffic {
            hosts: 1,
            unnamed: 8,
            connections: 10,
            ..busy()
        };
        let standing = standing("mystery", traffic, 4.0, &[]);
        assert!(
            standing
                .reasons
                .iter()
                .any(|r| r.signal == Signal::Hostless)
        );
        assert!(
            standing.reasons[0]
                .said
                .contains("8 of its 10 connection(s)"),
            "{}",
            standing.reasons[0].said
        );
    }

    #[test]
    fn a_name_that_looks_generated_is_recognised() {
        assert!(looks_generated("a1b2c3d4.example.com"));
        assert!(looks_generated("xkcdvbnmqrst.example.com"));
        assert!(!looks_generated("api.example.com"));
        assert!(!looks_generated("github.com"));
        // Short labels are not judged: there is nothing to judge.
        assert!(!looks_generated("cdn.x.com"));
    }

    #[test]
    fn mostly_generated_names_is_a_reason_and_a_few_are_not() {
        let names = [
            "a1b2c3d4.example",
            "9f8e7d6c.example",
            "5a4b3c2d.example",
            "api.example",
        ];
        let odd = standing("odd", busy(), 100.0, &names);
        assert!(
            odd.reasons
                .iter()
                .any(|r| r.signal == Signal::GeneratedNames),
            "{:?}",
            odd.reasons
        );

        let mostly_chosen = [
            "api.example",
            "cdn.example",
            "auth.example",
            "a1b2c3d4.example",
        ];
        let fine = standing("fine", busy(), 100.0, &mostly_chosen);
        assert!(
            !fine
                .reasons
                .iter()
                .any(|r| r.signal == Signal::GeneratedNames)
        );
    }

    #[test]
    fn sending_far_more_than_it_receives_is_a_reason() {
        let traffic = Traffic {
            sent: 100 * 1_024 * 1_024,
            received: 1_024,
            ..busy()
        };
        let standing = standing("uploader", traffic, 100.0, &[]);
        let reason = standing
            .reasons
            .iter()
            .find(|r| r.signal == Signal::MostlyUploading)
            .expect("a reason");
        assert!(reason.said.contains("100.0 MB"), "{}", reason.said);
        assert!(reason.said.contains("times as much out as in"));
    }

    /// The case Coverage exists to name, said again here because this is where somebody is looking at one
    /// process rather than at the machine.
    #[test]
    fn nothing_read_at_all_is_a_reason() {
        let traffic = Traffic {
            unread: 12,
            connections: 12,
            hosts: 1,
            ..Traffic::default()
        };
        let nothing = standing("gh", traffic, 4.0, &[]);
        assert!(
            nothing
                .reasons
                .iter()
                .any(|r| r.signal == Signal::NothingRead)
        );
        // And some read is not none read.
        let some = Traffic {
            unread: 6,
            ..traffic
        };
        assert!(
            !standing("gh", some, 4.0, &[])
                .reasons
                .iter()
                .any(|r| r.signal == Signal::NothingRead)
        );
    }

    /// The reasons are ordered by weight, and the total is their sum — which means nothing on its own.
    #[test]
    fn the_reasons_are_ordered_and_the_weight_is_their_sum() {
        let traffic = Traffic {
            hosts: 40,
            unnamed: 30,
            connections: 40,
            sent: 100 * 1_024 * 1_024,
            received: 1_024,
            unread: 0,
            addresses: 40,
        };
        let standing = standing("everything", traffic, 4.0, &[]);
        assert!(standing.reasons.len() >= 3);
        let weights: Vec<u32> = standing.reasons.iter().map(|r| r.weight).collect();
        let mut sorted = weights.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a));
        assert_eq!(weights, sorted, "strongest first");
        assert_eq!(standing.weight, weights.iter().sum::<u32>());
    }

    #[test]
    fn a_process_doing_nothing_unusual_has_nothing_said_about_it() {
        let ordinary = Traffic {
            hosts: 3,
            addresses: 3,
            unnamed: 0,
            sent: 1_000,
            received: 5_000,
            unread: 0,
            connections: 3,
        };
        let standing = standing("curl", ordinary, 4.0, &["api.example"]);
        assert!(standing.reasons.is_empty());
        assert_eq!(standing.weight, 0);
    }
}
