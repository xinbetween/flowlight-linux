//! Who operates an address, for the traffic that has no hostname.
//!
//! Every connection Flowlight records at `connect()` has an address and no name: the name was resolved and
//! thrown away before the kernel saw it. Coverage can say how many such connections a process made; saying
//! *whose* they were is the difference between a number and a lead.
//!
//! - [`message`] — just enough DNS to ask one question and read one answer.
//! - [`cymru`] — turning an address into a question, and an answer into a name somebody recognises.
//! - [`lookup`] — asking, once per address, with a cache and a ceiling.
//!
//! The whole thing is off until it is asked for, because it is the one part of Flowlight that tells somebody
//! else anything.

pub mod cymru;
pub mod lookup;
pub mod message;

pub use cymru::Owner;
pub use lookup::Lookup;
