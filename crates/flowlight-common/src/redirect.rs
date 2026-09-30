//! Sending a connection to Flowlight's proxy instead of where it was going, and remembering where that was.
//!
//! The kernel rewrites the destination inside `connect()`, before anything has been sent. The application is
//! not told and does not need to be: it opens a connection, something answers, and the TLS handshake decides
//! whether it believes the certificate it is given.
//!
//! # Why the original destination has to be carried in a map
//!
//! Because after the rewrite it is gone. The proxy accepts a connection from `127.0.0.1` and has no way to
//! ask the kernel where it was meant to go: there is no conntrack entry, because nothing was translated by
//! netfilter, and `SO_ORIGINAL_DST` answers only for connections netfilter redirected.
//!
//! So the program that rewrites the address writes down what it was, and something on the other side reads it.
//!
//! # Why it is remembered twice, under two keys
//!
//! Inside `connect()` the source port does not exist yet — the socket has not been bound. The socket's cookie
//! does, and it is the same cookie later, so the destination is first stored against the cookie and then moved
//! to be stored against the source port once the kernel has chosen one. The source port is the only thing the
//! proxy has: a connection it accepts is from `127.0.0.1:something`, and `something` is that port.

/// Where a connection was going before it was redirected.
///
/// `#[repr(C)]` and fixed-width, like everything else that crosses the map boundary.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Original {
    /// The address, as sixteen bytes in network order. IPv4 uses the first four.
    pub address: [u8; 16],
    /// The process that asked, so that what the proxy did can be attributed to it.
    pub tgid: u32,
    /// The agent it is working for.
    pub agent: u32,
    /// The port it asked for, in host order.
    pub port: u16,
    /// [`crate::connection::AF_INET`] or [`crate::connection::AF_INET6`].
    pub family: u16,
}

/// Twenty-eight bytes: sixteen of address, two words, and two shorts.
///
/// Asserted because this crosses a map boundary between a program in the kernel and a process outside it, and
/// the two agreeing about its size is the whole basis for either of them reading the other's bytes.
pub const ORIGINAL_SIZE: usize = 28;

const _: () = assert!(core::mem::size_of::<Original>() == ORIGINAL_SIZE);

impl Original {
    /// Nothing, for a slot that has not been filled in.
    pub const fn empty() -> Self {
        Self {
            address: [0; 16],
            tgid: 0,
            agent: 0,
            port: 0,
            family: 0,
        }
    }

    /// Whether this says anything.
    pub fn is_set(&self) -> bool {
        self.family != 0 && self.port != 0
    }
}

/// Where the proxy listens, in the array userspace writes it into.
///
/// An array of one rather than a constant, because the port is chosen by whoever starts the daemon and the
/// program has to be told.
pub const PROXY_PORT: u32 = 0;

/// The value stored for a port or an agent that is in scope. Presence is the answer; the value is padding
/// because a BPF hash map has to have one.
pub const IN_SCOPE: u8 = 1;

#[cfg(feature = "user")]
// SAFETY: `#[repr(C)]`, fixed-width fields, no padding that matters, and no pointers.
unsafe impl aya::Pod for Original {}
