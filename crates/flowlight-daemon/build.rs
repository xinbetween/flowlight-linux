//! Builds the eBPF programs and hands the object to the binary through `OUT_DIR`.
//!
//! The alternative — a committed `.o`, or a separate build step people have to remember — makes it possible
//! to ship a daemon whose kernel half is older than its userspace half. The two halves share a struct whose
//! layout has to match exactly, so that is not a class of bug worth leaving available.
//!
//! This needs a nightly toolchain with `rust-src`, and `bpf-linker` on the path. There is no stable way to
//! build `core` for the BPF target, so that is not a choice anyone here made.

use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    aya_build::build_ebpf(
        [Package {
            name: "flowlight-ebpf",
            // Relative to this crate, and only used to tell cargo what to watch for changes.
            root_dir: "../flowlight-ebpf",
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Nightly,
    )
}
