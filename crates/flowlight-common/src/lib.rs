//! Logic shared between the eBPF programs and the daemon.
//!
//! Nothing here depends on Linux, which is deliberate: it means this crate builds and its tests run on any
//! machine, including the ones the rest of the project cannot be compiled on. Anything that needs a kernel
//! lives elsewhere and is checked by CI.
//!
//! That constraint does real work. The kernel's tracepoint layout differs between kernel versions, and the
//! rule for reading it is therefore the sort of thing that would normally only be discovered on a machine
//! nobody has. Here it is [`tracepoint`] and [`connection::Layout`]: plain text in, offsets out, tested
//! against recorded layouts from both sides of the change.
//!
//! # Features
//!
//! - `alloc` (default) — the parts that own strings. The eBPF programs take this crate without it.
//! - `user` — implements `aya::Pod` for the types that cross a map boundary. Daemon only.

#![cfg_attr(not(test), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod connection;
pub mod http;
#[cfg(feature = "alloc")]
pub mod identity;
pub mod procmaps;
pub mod tls;
pub mod tracepoint;
