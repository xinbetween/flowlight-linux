//! Refusing a connection before the SYN.
//!
//! Everything so far watches. This is the first thing that changes what a machine does, and it is worth
//! being clear about how little it is doing: a `cgroup/connect` hook decides, before the handshake starts,
//! whether the address a process asked for is one it is allowed to reach. The application gets `EPERM` from
//! `connect()` — the same answer a firewall gives — and nothing is intercepted, terminated or modified.
//!
//! # Why this is better than the macOS equivalent
//!
//! On macOS a block goes through the proxy, so blocking and inspecting are the same mechanism and a blocked
//! connection is one that was first accepted. Here they are independent: the refusal happens in the kernel
//! at `connect()`, the reading happens in the TLS library, and neither needs the other. A connection can be
//! refused without any of the inspection machinery being involved at all.
//!
//! # What a block is keyed on, and what it costs
//!
//! An address and a port, because that is what the kernel has at `connect()`. It does **not** have a
//! hostname: the name was resolved before this point, and the hook sees the result. So blocking
//! `api.example.com` means resolving it and blocking what it resolves to — which is exactly right for a
//! single host and imprecise for anything behind a large content network, where the addresses rotate and
//! are shared with everything else on it.
//!
//! That is a real limitation and it is stated rather than papered over: this refuses *addresses*, and a
//! host is a set of addresses that was true when it was looked up.

/// A rule in the kernel's table: whose connection, to where.
///
/// `#[repr(C)]` and fixed-width, like everything else that crosses the map boundary.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockKey {
    /// Which agent this applies to, or [`EVERYONE`].
    ///
    /// Unused in 0.2.0, where every rule is global, and present because the alternative is a map whose key
    /// changes shape in the next release — and a key that changes shape is a kernel and a userspace that
    /// disagree about what they are looking at, silently.
    pub agent: u32,
    /// [`crate::connection::AF_INET`] or [`crate::connection::AF_INET6`].
    pub family: u16,
    /// The port, in host order. [`ANY_PORT`] for every port.
    pub port: u16,
    /// The address, IPv4 in the first four bytes.
    pub address: [u8; 16],
}

/// A rule that applies to every process on the machine.
pub const EVERYONE: u32 = 0;

/// A rule that applies whatever port was asked for.
pub const ANY_PORT: u16 = 0;

impl BlockKey {
    /// A rule for one address and port.
    pub const fn new(agent: u32, family: u16, address: [u8; 16], port: u16) -> Self {
        Self {
            agent,
            family,
            port,
            address,
        }
    }

    /// The same rule with the port removed, which is how the kernel asks its second question.
    ///
    /// Two lookups rather than one: a rule naming a port is more specific than one that does not, and the
    /// alternative — iterating the table — is not something a BPF program may do.
    pub const fn any_port(&self) -> Self {
        Self {
            port: ANY_PORT,
            ..*self
        }
    }
}

/// One connection that was refused, on its way up to be reported.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockEvent {
    /// The process.
    pub tgid: u32,
    /// The thread that called `connect()`.
    pub pid: u32,
    /// `bpf_get_current_comm()`.
    pub comm: [u8; crate::connection::TASK_COMM_LEN],
    /// The address it was refused.
    pub address: [u8; 16],
    /// The port, in host order.
    pub port: u16,
    /// The family.
    pub family: u16,
    /// Which rule matched: [`EVERYONE`], or an agent.
    pub agent: u32,
}

impl BlockEvent {
    /// An empty event, which is how the eBPF program starts one.
    pub const fn zeroed() -> Self {
        Self {
            tgid: 0,
            pid: 0,
            comm: [0; crate::connection::TASK_COMM_LEN],
            address: [0; 16],
            port: 0,
            family: 0,
            agent: EVERYONE,
        }
    }

    /// The process name, without its NUL padding, or `None` if it is not text.
    pub fn comm_str(&self) -> Option<&str> {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(crate::connection::TASK_COMM_LEN);
        core::str::from_utf8(self.comm.get(..end)?).ok()
    }

    /// The address that was refused.
    pub fn destination(&self) -> Option<core::net::IpAddr> {
        crate::connection::address_of(self.family, &self.address)
    }
}

#[cfg(feature = "user")]
// SAFETY: `#[repr(C)]`, integers and arrays of integers only. No pointers, no invalid bit patterns.
unsafe impl aya::Pod for BlockKey {}

#[cfg(feature = "user")]
// SAFETY: as above.
unsafe impl aya::Pod for BlockEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::{AF_INET, AF_INET6, ipv4_bytes};

    /// Both sides of the map are compiled separately, for different targets. If either number moves, one of
    /// them is reading the other's bytes at the wrong offsets and will not say so.
    #[test]
    fn the_wire_types_are_the_size_both_sides_agree_on() {
        assert_eq!(size_of::<BlockKey>(), 24);
        assert_eq!(size_of::<BlockEvent>(), 48);
    }

    /// A rule naming a port and a rule naming none are different rules, and the kernel asks for both.
    #[test]
    fn a_rule_without_a_port_is_a_different_key() {
        let specific = BlockKey::new(EVERYONE, AF_INET, ipv4_bytes([93, 184, 216, 34]), 443);
        let any = specific.any_port();
        assert_ne!(specific, any);
        assert_eq!(any.port, ANY_PORT);
        assert_eq!(any.address, specific.address);
        assert_eq!(any.any_port(), any);
    }

    /// Two addresses that differ only past the fourth byte are the same IPv4 address, and must produce the
    /// same key — which is why the widening is a shared function rather than done at each call site.
    #[test]
    fn an_ipv4_rule_ignores_the_bytes_that_are_not_the_address() {
        let a = BlockKey::new(EVERYONE, AF_INET, ipv4_bytes([10, 0, 0, 1]), 443);
        let mut b = a;
        b.address = ipv4_bytes([10, 0, 0, 1]);
        assert_eq!(a, b);
    }

    #[test]
    fn a_refusal_reports_the_address_it_refused() {
        let event = BlockEvent {
            family: AF_INET,
            address: ipv4_bytes([93, 184, 216, 34]),
            port: 443,
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
            ..BlockEvent::zeroed()
        };
        assert_eq!(event.comm_str(), Some("curl"));
        assert_eq!(
            event.destination().map(|a| a.to_string()),
            Some("93.184.216.34".to_owned())
        );

        let v6 = BlockEvent {
            family: AF_INET6,
            address: [
                0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0x41,
            ],
            ..BlockEvent::zeroed()
        };
        assert_eq!(
            v6.destination().map(|a| a.to_string()),
            Some("2606:4700::6441".to_owned())
        );
    }
}
