//! Asking, once per address, with a cache and a ceiling.
//!
//! # Why this is slow on purpose
//!
//! It asks somebody else a question about an address this machine reached. That is worth doing sparingly and
//! worth doing visibly: one address at a time, a few a minute, never the same one twice, and never one that is
//! already known. A resolver that asked about every connection as it happened would be a second, chattier
//! record of this machine's traffic leaving it.

use crate::cymru::{self, Owner};
use crate::message;
use anyhow::{Context as _, Result, bail};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::Duration;

/// How long to wait for a resolver.
const PATIENCE: Duration = Duration::from_secs(4);

/// Where to ask, when `/etc/resolv.conf` says nothing.
///
/// Cloudflare's resolver, which is also the address most likely to be in the first answer anybody tries.
const FALLBACK: &str = "1.1.1.1:53";

/// Asking who operates an address.
pub struct Lookup {
    /// Where to ask.
    resolver: SocketAddr,
    /// The next identifier to use, so an answer can be matched to its question.
    next: std::cell::Cell<u16>,
}

impl Lookup {
    /// Reads the machine's resolver, or falls back to a public one.
    pub fn new() -> Self {
        Self {
            resolver: resolver().unwrap_or_else(|| {
                FALLBACK
                    .parse()
                    .unwrap_or(SocketAddr::from(([1, 1, 1, 1], 53)))
            }),
            // Started from the clock rather than from zero, so two daemons on one machine are not asking the
            // same questions with the same identifiers.
            next: std::cell::Cell::new(seed()),
        }
    }

    /// Where it asks.
    pub fn resolver(&self) -> SocketAddr {
        self.resolver
    }

    /// Who operates this address.
    ///
    /// Two questions: which system announces the prefix, and who that system belongs to. An address on this
    /// network is answered without asking anybody.
    pub fn owner(&self, address: &str) -> Result<Option<Owner>> {
        let parsed: IpAddr = address
            .trim()
            .parse()
            .with_context(|| format!("`{address}` is not an address"))?;
        if cymru::is_special(&parsed) {
            return Ok(Some(Owner::local()));
        }
        let Some(question) = cymru::question(address) else {
            return Ok(Some(Owner::local()));
        };
        let origin = self.ask(&question)?;
        let Some(asn) = origin.iter().find_map(|text| cymru::asn_of(text)) else {
            // Nobody announces it. That is an answer, and a different one from "the lookup failed".
            return Ok(None);
        };
        let described = self.ask(&cymru::description_question(asn))?;
        let name = described
            .iter()
            .find_map(|text| cymru::name_of(text))
            .unwrap_or_else(|| format!("AS{asn}"));
        Ok(Some(Owner { asn, name }))
    }

    /// One question, one datagram, one answer.
    fn ask(&self, name: &str) -> Result<Vec<String>> {
        let id = self.next.get().wrapping_add(1);
        self.next.set(id);

        let socket =
            UdpSocket::bind(("0.0.0.0", 0)).context("opening a socket to ask a resolver")?;
        socket
            .set_read_timeout(Some(PATIENCE))
            .context("setting a timeout on the resolver socket")?;
        socket
            .send_to(&message::query(id, name)?, self.resolver)
            .with_context(|| format!("asking {} about {name}", self.resolver))?;

        let mut buffer = [0_u8; 1500];
        let (read, from) = socket
            .recv_from(&mut buffer)
            .with_context(|| format!("waiting for {} to answer about {name}", self.resolver))?;
        // An answer from somewhere else is not an answer. The identifier is checked too, in the parser.
        if from.ip() != self.resolver.ip() {
            bail!(
                "something at {from} answered a question asked of {}",
                self.resolver
            );
        }
        let answered = message::answer(id, buffer.get(..read).unwrap_or_default())?;
        Ok(answered.texts)
    }
}

impl Default for Lookup {
    fn default() -> Self {
        Self::new()
    }
}

/// The first nameserver in `/etc/resolv.conf`.
///
/// Read rather than asked of a library, because the library that answers this question brings a runtime with
/// it. A machine whose resolver is configured somewhere else entirely gets the fallback, and `owners` says
/// which one it is using.
pub fn resolver() -> Option<SocketAddr> {
    let text = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') {
                return None;
            }
            let address = line.strip_prefix("nameserver")?.trim();
            address.parse::<IpAddr>().ok()
        })
        // Loopback is usually a stub resolver, which is exactly the right thing to ask.
        .map(|address| SocketAddr::new(address, 53))
        .next()
}

/// A starting identifier that is not zero.
fn seed() -> u16 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |since| since.subsec_nanos() as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An address on this machine is answered without anybody being asked, which is the property that keeps
    /// a private network private.
    #[test]
    fn a_local_address_is_answered_without_asking() {
        // A resolver that is not there, so any question at all would fail rather than hang.
        let lookup = Lookup {
            resolver: SocketAddr::from(([127, 0, 0, 1], 9)),
            next: std::cell::Cell::new(1),
        };
        for local in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "::1", "fd00::1"] {
            assert_eq!(
                lookup.owner(local).unwrap(),
                Some(Owner::local()),
                "{local}"
            );
        }
    }

    #[test]
    fn something_that_is_not_an_address_is_an_error_rather_than_a_question() {
        let lookup = Lookup::new();
        assert!(lookup.owner("example.com").is_err());
        assert!(lookup.owner("").is_err());
    }

    /// Two daemons on one machine should not be asking the same questions with the same identifiers.
    #[test]
    fn identifiers_move() {
        let lookup = Lookup::new();
        let first = lookup.next.get();
        lookup.next.set(first.wrapping_add(1));
        assert_ne!(lookup.next.get(), first);
    }

    #[test]
    fn a_resolver_is_read_from_the_machine_or_fallen_back_to() {
        let lookup = Lookup::new();
        assert_eq!(lookup.resolver().port(), 53);
    }
}
