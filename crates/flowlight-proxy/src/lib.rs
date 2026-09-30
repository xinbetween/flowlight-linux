//! The certificate authority and terminating proxy behind interception.
//!
//! Off unless it is asked for, and it is the only part of Flowlight that changes what an application sees.
//! Everything else reads what a process hands its TLS library, before encryption, and alters nothing on the
//! wire. This stands in the middle of a connection, presents a certificate of its own, and can answer a request
//! the server never received.
//!
//! # What it is for, and what it is not for
//!
//! It is not for watching. The uprobes see every request whether interception is on or not, so nothing here
//! records traffic — a proxy that also recorded would put a second copy of every request into the database and
//! there would be no way to tell the two apart afterwards. What it records is only what it *did*: a request it
//! answered, and the rule that answered it.
//!
//! # The pieces
//!
//! - [`authority`] — the certificate authority created on this machine, and the leaves it signs.
//! - [`http`] — reading just enough HTTP/1.1 to decide, and passing the rest through byte for byte.
//! - [`serve`] — the sockets, the TLS on both sides, and the decision in the middle.

pub mod authority;
pub mod http;
pub mod serve;

pub use authority::Authority;
pub use serve::{Decided, Proxy, Reached};
