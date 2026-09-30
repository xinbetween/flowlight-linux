//! Turning an address into a question, and an answer into a name somebody recognises.
//!
//! Team Cymru publish the routing table over DNS: ask `1.1.1.1.origin.asn.cymru.com` for a `TXT` record and
//! the answer names the autonomous system that announces the prefix the address is in. Ask
//! `AS13335.asn.cymru.com` and the answer names who that system belongs to.
//!
//! # Why an address is ever sent anywhere
//!
//! It is the one thing in Flowlight that asks somebody else a question, and it is off until it is asked for.
//! What is sent is an address and nothing else — not which process reached it, not when, not how often. A
//! private address is never sent at all, because the answer is already known and the question would be about
//! this network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Who operates an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owner {
    /// The autonomous system number.
    pub asn: u32,
    /// Who it belongs to, as a person would say it.
    pub name: String,
}

impl Owner {
    /// The answer for an address on this machine or this network, which is never asked about.
    pub fn local() -> Self {
        Self {
            asn: 0,
            name: "this network".to_owned(),
        }
    }
}

/// The name to ask about an address, or nothing when the address is one that is never asked about.
pub fn question(address: &str) -> Option<String> {
    let parsed: IpAddr = address.trim().parse().ok()?;
    if is_special(&parsed) {
        return None;
    }
    Some(match parsed {
        IpAddr::V4(four) => {
            let [a, b, c, d] = four.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com")
        }
        IpAddr::V6(six) => {
            // Every nibble, reversed, separated by dots — the same shape as a reverse lookup.
            let mut name = String::with_capacity(80);
            for byte in six.octets().iter().rev() {
                name.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            name.push_str("origin6.asn.cymru.com");
            name
        }
    })
}

/// The name to ask about an autonomous system.
pub fn description_question(asn: u32) -> String {
    format!("AS{asn}.asn.cymru.com")
}

/// The system number out of an origin answer: `13335 | 1.1.1.0/24 | US | arin | 2010-07-14`.
///
/// More than one system may announce a prefix, in which case they are listed space-separated in the first
/// field. The first is taken, because the alternative is a name that says "one of these".
pub fn asn_of(text: &str) -> Option<u32> {
    text.split('|')
        .next()?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// The operator's name out of a description answer: `13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US`.
pub fn name_of(text: &str) -> Option<String> {
    let described = text.rsplit('|').next()?.trim();
    if described.is_empty() {
        return None;
    }
    Some(display_name(described))
}

/// `Anthropic, PBC` out of `ANTHROPIC - Anthropic, PBC, US`.
///
/// Registries are inconsistent about this field. Some put a handle and a name, some put only a handle, and
/// some put a street address — so the handle is kept as a fallback and used when what follows it looks like
/// somewhere rather than someone.
pub fn display_name(described: &str) -> String {
    let trimmed = described.trim();
    let (handle, mut text) = match trimmed.split_once(" - ") {
        Some((handle, rest)) => (handle.trim(), rest.trim().to_owned()),
        None => ("", trimmed.to_owned()),
    };
    // A trailing country code, which nearly every registry appends.
    if let Some((before, last)) = text.rsplit_once(", ")
        && last.len() == 2
        && last
            .chars()
            .all(|character| character.is_ascii_alphabetic())
    {
        text = before.trim().to_owned();
    }
    // Some registries put a street address where the organisation belongs.
    let somewhere = [
        "building", "avenue", "road", "street", "floor", "tower", "district", "no.", "suite",
    ];
    let lowered = text.to_lowercase();
    if !handle.is_empty() && somewhere.iter().any(|word| lowered.contains(word)) {
        return capitalised(handle.split('-').next().unwrap_or(handle));
    }
    if text.is_empty() {
        return if handle.is_empty() {
            trimmed.to_owned()
        } else {
            capitalised(handle)
        };
    }
    text
}

/// A handle as a word rather than as shouting.
fn capitalised(handle: &str) -> String {
    let lowered = handle.trim().to_lowercase();
    let mut characters = lowered.chars();
    match characters.next() {
        Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
        None => lowered,
    }
}

/// Whether an address is one that is never asked about.
///
/// Private, loopback, link-local, multicast and the documentation ranges. The answer for all of them is
/// already known, and asking would be telling somebody else about this network.
pub fn is_special(address: &IpAddr) -> bool {
    match address {
        IpAddr::V4(four) => {
            four.is_private()
                || four.is_loopback()
                || four.is_link_local()
                || four.is_broadcast()
                || four.is_documentation()
                || four.is_unspecified()
                || four.is_multicast()
                // Carrier-grade NAT, which is somebody's network and not a destination.
                || matches!(four.octets(), [100, second, _, _] if (64..128).contains(&second))
                || four == &Ipv4Addr::new(0, 0, 0, 0)
        }
        IpAddr::V6(six) => {
            six.is_loopback()
                || six.is_unspecified()
                || six.is_multicast()
                // Unique local, and link-local.
                || matches!(six.segments(), [first, ..] if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80)
                // The documentation range.
                || matches!(six.segments(), [0x2001, 0x0db8, ..])
                || six == &Ipv6Addr::UNSPECIFIED
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_becomes_a_question_with_its_octets_reversed() {
        assert_eq!(
            question("1.2.3.4").as_deref(),
            Some("4.3.2.1.origin.asn.cymru.com")
        );
    }

    #[test]
    fn an_ipv6_address_becomes_a_question_of_nibbles() {
        let asked = question("2606:4700::1111").expect("a public address");
        assert!(asked.ends_with("origin6.asn.cymru.com"), "{asked}");
        // Thirty-two nibbles, each with a dot.
        assert_eq!(asked.matches('.').count(), 32 + 3);
        assert!(asked.starts_with("1.1.1.1."), "{asked}");
    }

    /// Asking about a private address would be telling somebody else about this network, and the answer is
    /// already known.
    #[test]
    fn an_address_on_this_network_is_never_asked_about() {
        for private in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.1.1",
            "172.16.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "2001:db8::1",
        ] {
            assert_eq!(question(private), None, "{private}");
        }
        assert!(question("1.1.1.1").is_some());
        assert!(question("2606:4700::1111").is_some());
        assert_eq!(question("not an address"), None);
    }

    #[test]
    fn the_system_number_is_the_first_field() {
        assert_eq!(
            asn_of("13335 | 1.1.1.0/24 | US | arin | 2010-07-14"),
            Some(13335)
        );
        // More than one system may announce a prefix; the first is taken.
        assert_eq!(asn_of("13335 396982 | 1.1.1.0/24 | US"), Some(13335));
        assert_eq!(asn_of("not a number | x"), None);
    }

    #[test]
    fn the_name_is_the_last_field() {
        assert_eq!(
            name_of("13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US").as_deref(),
            Some("CLOUDFLARENET")
        );
        assert_eq!(name_of("13335 | US | arin | 2010 | ").as_deref(), None);
    }

    /// Registries are inconsistent about this field, and each shape here is one somebody has actually
    /// published.
    #[test]
    fn a_description_is_turned_into_something_readable() {
        assert_eq!(
            display_name("ANTHROPIC - Anthropic, PBC, US"),
            "Anthropic, PBC"
        );
        assert_eq!(display_name("CLOUDFLARENET, US"), "CLOUDFLARENET");
        assert_eq!(display_name("GOOGLE - Google LLC, US"), "Google LLC");
        // Only a handle.
        assert_eq!(display_name("EXAMPLE-AS"), "EXAMPLE-AS");
        // A street address where the organisation belongs: the handle is better than the building.
        assert_eq!(
            display_name("SOMECORP - 5th Floor, Some Tower, Some District, CN"),
            "Somecorp"
        );
    }

    #[test]
    fn a_system_has_its_own_question() {
        assert_eq!(description_question(13335), "AS13335.asn.cymru.com");
    }
}
