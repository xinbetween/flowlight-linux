//! What the kernel tells us about a connection, and where in its record to find it.
//!
//! Attribution is the question `nettop` answers badly on macOS and the kernel answers properly here: which
//! process opened this connection. The answer is taken from the `sock/inet_sock_set_state` tracepoint at the
//! moment a socket moves from `CLOSE` to `SYN_SENT` — the moment `connect()` commits, which runs in the
//! calling process's own context, so `bpf_get_current_pid_tgid()` is the process that asked.
//!
//! That last clause is the whole reason for choosing this transition over the more obvious ones. A socket
//! reaching `ESTABLISHED` does so from a softirq, on whichever CPU the ACK landed on, in the context of
//! whatever happened to be running — and a probe there attributes the connection to an innocent bystander.
//! The macOS build has no equivalent of this trap, so it is worth naming: **connections are attributed where
//! the syscall is, not where the packet is.**
//!
//! What this costs is stated rather than hidden: inbound connections, which arrive at `SYN_RECV` in exactly
//! that softirq context, are not attributed here at all. Coverage will say so.

use crate::tracepoint::Format;
use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `TASK_COMM_LEN`. Fifteen characters and a NUL, and not negotiable from userspace.
pub const TASK_COMM_LEN: usize = 16;

/// `AF_INET`.
pub const AF_INET: u16 = 2;
/// `AF_INET6`, which is 10 on Linux and something else on every other system that has the constant.
pub const AF_INET6: u16 = 10;
/// `IPPROTO_TCP`.
pub const IPPROTO_TCP: u8 = 6;

/// `TCP_ESTABLISHED`, from `include/net/tcp_states.h`.
pub const TCP_ESTABLISHED: u32 = 1;
/// `TCP_SYN_SENT`: the SYN is on its way out, and we are still in the caller's context.
pub const TCP_SYN_SENT: u32 = 2;
/// `TCP_CLOSE`. The state a socket is in before `connect()`, despite the name.
pub const TCP_CLOSE: u32 = 7;

/// Whether a state transition is a process deliberately opening an outbound connection.
///
/// Deliberately narrow. `CLOSE → SYN_SENT` happens once per `connect()`, in the calling process's context,
/// and nowhere else; anything wider would trade correct attribution for more rows.
pub fn is_outbound_connect(oldstate: u32, newstate: u32) -> bool {
    oldstate == TCP_CLOSE && newstate == TCP_SYN_SENT
}

/// Where each field of the tracepoint record lives on the kernel we are actually running on.
///
/// Filled by the daemon from the kernel's own `format` file and handed to the eBPF program through a map,
/// because the layout moved in 5.6 and a program that assumes either answer is wrong on half the machines it
/// runs on. See [`crate::tracepoint`] for why that matters more than it sounds.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Layout {
    /// Offset of `oldstate`, an `int`.
    pub oldstate: u16,
    /// Offset of `newstate`, an `int`.
    pub newstate: u16,
    /// Offset of `sport`, a `__u16` the tracepoint has already converted to host order.
    pub sport: u16,
    /// Offset of `dport`, likewise host order.
    pub dport: u16,
    /// Offset of `family`.
    pub family: u16,
    /// Offset of `protocol`.
    pub protocol: u16,
    /// Width of `protocol`: two bytes up to Linux 5.5, one from 5.6. The program has to read the right width
    /// or it reads the first byte of `saddr` as part of the protocol number.
    pub protocol_size: u16,
    /// Offset of `saddr`, four bytes, meaningful only when `family` is [`AF_INET`].
    pub saddr: u16,
    /// Offset of `daddr`, four bytes.
    pub daddr: u16,
    /// Offset of `saddr_v6`, sixteen bytes.
    pub saddr_v6: u16,
    /// Offset of `daddr_v6`, sixteen bytes.
    pub daddr_v6: u16,
    /// Unused, and present so that the struct's size does not depend on how the compiler feels about padding
    /// a map value shared between two targets.
    pub reserved: u16,
}

/// Why a kernel's tracepoint layout could not be used.
///
/// Both variants mean the same thing operationally — do not load the program — and they are kept apart
/// because the two produce very different support conversations. A missing field is a kernel that does not
/// have what we need. An unexpected width is a kernel that changed under us, and is the one worth an issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// The kernel's `format` file does not declare this field.
    Missing {
        /// The field we looked for.
        field: &'static str,
    },
    /// The field is there and is not the width every kernel so far has declared it.
    UnexpectedSize {
        /// The field.
        field: &'static str,
        /// What we can read.
        expected: u16,
        /// What the kernel says it is.
        found: u16,
    },
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { field } => write!(
                f,
                "this kernel's sock/inet_sock_set_state tracepoint has no `{field}` field, so connections \
                 cannot be attributed on it"
            ),
            Self::UnexpectedSize {
                field,
                expected,
                found,
            } => write!(
                f,
                "this kernel declares `{field}` as {found} bytes and Flowlight can only read {expected}; \
                 reading it anyway would report plausible wrong numbers, so it does not"
            ),
        }
    }
}

impl core::error::Error for LayoutError {}

/// Looks a field up and insists on the width we know how to read.
fn offset_of(format: &Format<'_>, field: &'static str, expected: u16) -> Result<u16, LayoutError> {
    let found = format.field(field).ok_or(LayoutError::Missing { field })?;
    if found.size != expected {
        return Err(LayoutError::UnexpectedSize {
            field,
            expected,
            found: found.size,
        });
    }
    Ok(found.offset)
}

impl Layout {
    /// Derives the layout from the text of a kernel's `format` file.
    pub fn from_format(format: &Format<'_>) -> Result<Self, LayoutError> {
        let protocol = format
            .field("protocol")
            .ok_or(LayoutError::Missing { field: "protocol" })?;
        // One byte from 5.6, two before it. Any third answer is a kernel we have not seen, and guessing at it
        // is how you get a protocol number made of half an IP address.
        if protocol.size != 1 && protocol.size != 2 {
            return Err(LayoutError::UnexpectedSize {
                field: "protocol",
                expected: 1,
                found: protocol.size,
            });
        }
        Ok(Self {
            oldstate: offset_of(format, "oldstate", 4)?,
            newstate: offset_of(format, "newstate", 4)?,
            sport: offset_of(format, "sport", 2)?,
            dport: offset_of(format, "dport", 2)?,
            family: offset_of(format, "family", 2)?,
            protocol: protocol.offset,
            protocol_size: protocol.size,
            saddr: offset_of(format, "saddr", 4)?,
            daddr: offset_of(format, "daddr", 4)?,
            saddr_v6: offset_of(format, "saddr_v6", 16)?,
            daddr_v6: offset_of(format, "daddr_v6", 16)?,
            reserved: 0,
        })
    }
}

/// One outbound connection, as the kernel saw it and the process that opened it.
///
/// `#[repr(C)]` and fixed-width throughout: this crosses from a BPF program to a userspace process, and the
/// two are compiled for different targets by different toolchains. Anything whose layout the compiler is
/// allowed an opinion about does not belong in here.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEvent {
    /// The thread group — what a person means by "the process", and what `/proc/<n>` is keyed on.
    pub tgid: u32,
    /// The thread that actually called `connect()`. Kept because a pool thread's name is sometimes the only
    /// hint about what part of a large program is talking.
    pub pid: u32,
    /// `bpf_get_current_comm()`: NUL-padded, and cut at fifteen characters by the kernel.
    pub comm: [u8; TASK_COMM_LEN],
    /// Source address, IPv4 in the first four bytes.
    pub saddr: [u8; 16],
    /// Destination address, IPv4 in the first four bytes.
    pub daddr: [u8; 16],
    /// Source port, host order.
    pub sport: u16,
    /// Destination port, host order.
    pub dport: u16,
    /// [`AF_INET`] or [`AF_INET6`].
    pub family: u16,
    /// [`IPPROTO_TCP`]. Recorded rather than assumed, so a future probe on another protocol needs no new
    /// struct and no version negotiation.
    pub protocol: u8,
    /// Unused. Makes the struct's size explicit rather than a consequence of alignment rules.
    pub padding: u8,
}

impl ConnectionEvent {
    /// An event with nothing in it, which is how the eBPF program starts one.
    ///
    /// Zeroing matters more here than it looks: the struct goes straight into a perf buffer, and any byte
    /// left uninitialised is a byte of this process's kernel stack handed to userspace.
    pub const fn zeroed() -> Self {
        Self {
            tgid: 0,
            pid: 0,
            comm: [0; TASK_COMM_LEN],
            saddr: [0; 16],
            daddr: [0; 16],
            sport: 0,
            dport: 0,
            family: 0,
            protocol: 0,
            padding: 0,
        }
    }

    /// The process name, without its NUL padding.
    ///
    /// `None` when the kernel handed us something that is not UTF-8. A process may set `comm` to arbitrary
    /// bytes, and this is the only field in the struct that an untrusted process controls the contents of.
    pub fn comm_str(&self) -> Option<&str> {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(TASK_COMM_LEN);
        core::str::from_utf8(self.comm.get(..end)?).ok()
    }

    /// The address that was connected to.
    pub fn destination(&self) -> Option<IpAddr> {
        address_of(self.family, &self.daddr)
    }

    /// The address it was connected from. Often unspecified at this point in the handshake for IPv6.
    pub fn source(&self) -> Option<IpAddr> {
        address_of(self.family, &self.saddr)
    }
}

/// Widens an IPv4 address into the sixteen bytes the event carries, without touching the rest.
///
/// Destructuring rather than a copy into a slice: this is called from the eBPF program, where a slice write
/// is one more thing for the verifier to have an opinion about and an index is one more thing to get wrong.
pub const fn ipv4_bytes(v4: [u8; 4]) -> [u8; 16] {
    let [a, b, c, d] = v4;
    [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// Reads an address out of sixteen bytes, according to the family they were recorded with.
///
/// Shared rather than duplicated: two places that widen an IPv4 address into sixteen bytes and two that
/// read it back is four chances to disagree about which four bytes matter.
pub fn address_of(family: u16, bytes: &[u8; 16]) -> Option<IpAddr> {
    match family {
        AF_INET => {
            let mut v4 = [0u8; 4];
            v4.copy_from_slice(bytes.get(..4)?);
            Some(IpAddr::V4(Ipv4Addr::from(v4)))
        }
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(*bytes))),
        _ => None,
    }
}

#[cfg(feature = "user")]
// SAFETY: both are `#[repr(C)]` and contain only integers and arrays of integers. They have no padding whose
// contents would be undefined, no pointers, and no invalid bit patterns.
unsafe impl aya::Pod for Layout {}

#[cfg(feature = "user")]
// SAFETY: as above.
unsafe impl aya::Pod for ConnectionEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tracepoint::Format;

    // Repeated here rather than shared with the parser's tests: this is the layout as the *consumer* needs
    // it, and a fixture two modules use is a fixture that gets changed for one of them.
    const MODERN: &str = "\
	field:int oldstate;	offset:16;	size:4;	signed:1;
	field:int newstate;	offset:20;	size:4;	signed:1;
	field:__u16 sport;	offset:24;	size:2;	signed:0;
	field:__u16 dport;	offset:26;	size:2;	signed:0;
	field:__u16 family;	offset:28;	size:2;	signed:0;
	field:__u8 protocol;	offset:30;	size:1;	signed:0;
	field:__u8 saddr[4];	offset:31;	size:4;	signed:0;
	field:__u8 daddr[4];	offset:35;	size:4;	signed:0;
	field:__u8 saddr_v6[16];	offset:39;	size:16;	signed:0;
	field:__u8 daddr_v6[16];	offset:55;	size:16;	signed:0;
";

    const LEGACY: &str = "\
	field:int oldstate;	offset:16;	size:4;	signed:1;
	field:int newstate;	offset:20;	size:4;	signed:1;
	field:__u16 sport;	offset:24;	size:2;	signed:0;
	field:__u16 dport;	offset:26;	size:2;	signed:0;
	field:__u16 family;	offset:28;	size:2;	signed:0;
	field:__u16 protocol;	offset:30;	size:2;	signed:0;
	field:__u8 saddr[4];	offset:32;	size:4;	signed:0;
	field:__u8 daddr[4];	offset:36;	size:4;	signed:0;
	field:__u8 saddr_v6[16];	offset:40;	size:16;	signed:0;
	field:__u8 daddr_v6[16];	offset:56;	size:16;	signed:0;
";

    #[test]
    fn a_modern_kernels_layout_is_read_whole() {
        let layout = Layout::from_format(&Format::new(MODERN)).unwrap();
        assert_eq!(layout.protocol_size, 1);
        assert_eq!(layout.saddr, 31);
        assert_eq!(layout.daddr_v6, 55);
    }

    /// The 5.6 change, as the thing the program actually consumes: same fields, different offsets, and a
    /// `protocol` of a different width that the program has to be told about rather than assume.
    #[test]
    fn an_older_kernels_layout_differs_in_exactly_one_byte_and_everything_after_it() {
        let modern = Layout::from_format(&Format::new(MODERN)).unwrap();
        let legacy = Layout::from_format(&Format::new(LEGACY)).unwrap();
        assert_eq!(legacy.protocol_size, 2);
        assert_eq!(legacy.protocol, modern.protocol);
        assert_eq!(legacy.saddr, modern.saddr + 1);
        assert_eq!(legacy.daddr_v6, modern.daddr_v6 + 1);
        // Everything before `protocol` is untouched, which is what makes this a one-byte shift rather than a
        // different record.
        assert_eq!(legacy.dport, modern.dport);
    }

    /// Refusing to load is the point. A kernel we cannot read has to produce a message, not a row of numbers
    /// that look like an address.
    #[test]
    fn a_kernel_without_the_fields_is_refused_by_name() {
        let err = Layout::from_format(&Format::new("")).unwrap_err();
        assert_eq!(err, LayoutError::Missing { field: "protocol" });
    }

    #[test]
    fn a_field_of_an_unexpected_width_is_refused_rather_than_truncated() {
        let widened = MODERN.replace(
            "field:__u16 dport;	offset:26;	size:2;",
            "field:__u32 dport;	offset:26;	size:4;",
        );
        let err = Layout::from_format(&Format::new(&widened)).unwrap_err();
        assert_eq!(
            err,
            LayoutError::UnexpectedSize {
                field: "dport",
                expected: 2,
                found: 4
            }
        );
    }

    /// A `protocol` that is neither one byte nor two is a kernel nobody here has seen. Guessing would read
    /// part of an address as part of a protocol number and report the result as fact.
    #[test]
    fn an_unrecognised_protocol_width_is_refused() {
        let odd = MODERN.replace(
            "field:__u8 protocol;	offset:30;	size:1;",
            "field:__u64 protocol;	offset:30;	size:8;",
        );
        assert!(Layout::from_format(&Format::new(&odd)).is_err());
    }

    const FORK: &str = "\
	field:char parent_comm[16];	offset:8;	size:16;	signed:0;
	field:pid_t parent_pid;	offset:24;	size:4;	signed:1;
	field:char child_comm[16];	offset:28;	size:16;	signed:0;
	field:pid_t child_pid;	offset:44;	size:4;	signed:1;
";

    const EXIT: &str = "\
	field:char comm[16];	offset:8;	size:16;	signed:0;
	field:pid_t pid;	offset:24;	size:4;	signed:1;
	field:int prio;	offset:28;	size:4;	signed:1;
";

    #[test]
    fn the_scheduler_tracepoints_are_read_the_same_way_as_the_socket_one() {
        let layout = TaskLayout::from_formats(&Format::new(FORK), &Format::new(EXIT)).unwrap();
        assert_eq!(layout.fork_parent, 24);
        assert_eq!(layout.fork_child, 44);
        assert_eq!(layout.exit_pid, 24);
    }

    /// A kernel without the field is a kernel that cannot do this, and saying so beats reading offset zero.
    #[test]
    fn a_scheduler_tracepoint_missing_a_field_is_refused_by_name() {
        let err = TaskLayout::from_formats(&Format::new(""), &Format::new(EXIT)).unwrap_err();
        assert_eq!(
            err,
            LayoutError::Missing {
                field: "parent_pid"
            }
        );
    }

    // The transition

    #[test]
    fn only_the_transition_that_runs_in_the_callers_context_counts() {
        assert!(is_outbound_connect(TCP_CLOSE, TCP_SYN_SENT));
        // SYN_SENT → ESTABLISHED is the ACK arriving, in a softirq, on whatever CPU took the interrupt.
        // Attributing there names whichever process was unlucky enough to be running.
        assert!(!is_outbound_connect(TCP_SYN_SENT, TCP_ESTABLISHED));
        assert!(!is_outbound_connect(TCP_ESTABLISHED, TCP_CLOSE));
    }

    // The wire struct

    /// Both sides of the map are compiled separately, for different targets. If this number moves, one of
    /// them is reading the other's bytes at the wrong offsets and will not say so.
    #[test]
    fn the_wire_struct_is_the_size_both_sides_agree_on() {
        assert_eq!(core::mem::size_of::<ConnectionEvent>(), 64);
        assert_eq!(core::mem::size_of::<Layout>(), 24);
    }

    #[test]
    fn a_comm_is_read_up_to_its_padding() {
        let mut ev = ConnectionEvent::zeroed();
        ev.comm[..4].copy_from_slice(b"curl");
        assert_eq!(ev.comm_str(), Some("curl"));
    }

    /// `comm` is the one field in the struct whose contents an untrusted process chooses. A process that
    /// names itself with invalid UTF-8 should produce no name, not a panic in the daemon reading it.
    #[test]
    fn a_comm_that_is_not_text_produces_no_name_rather_than_a_panic() {
        let mut ev = ConnectionEvent::zeroed();
        ev.comm[..2].copy_from_slice(&[0xff, 0xfe]);
        assert_eq!(ev.comm_str(), None);
    }

    /// The kernel fills all sixteen when it is truncating, so a name that uses every byte has no NUL to stop
    /// at and the length has to come from the array instead.
    #[test]
    fn a_comm_that_fills_the_field_is_not_read_past_it() {
        let ev = ConnectionEvent {
            comm: *b"abcdefghijklmnop",
            ..ConnectionEvent::zeroed()
        };
        assert_eq!(ev.comm_str(), Some("abcdefghijklmnop"));
    }

    #[test]
    fn addresses_are_read_according_to_the_family() {
        let mut ev = ConnectionEvent {
            family: AF_INET,
            ..ConnectionEvent::zeroed()
        };
        ev.daddr[..4].copy_from_slice(&[93, 184, 216, 34]);
        assert_eq!(
            ev.destination().map(|a| a.to_string()),
            Some("93.184.216.34".to_string())
        );

        let v6 = ConnectionEvent {
            family: AF_INET6,
            daddr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            ..ConnectionEvent::zeroed()
        };
        assert_eq!(
            v6.destination().map(|a| a.to_string()),
            Some("2001:db8::1".to_string())
        );
    }

    #[test]
    fn a_widened_v4_address_leaves_the_rest_of_the_field_alone() {
        let ev = ConnectionEvent {
            family: AF_INET,
            daddr: ipv4_bytes([10, 0, 0, 7]),
            ..ConnectionEvent::zeroed()
        };
        assert_eq!(
            ev.destination().map(|a| a.to_string()),
            Some("10.0.0.7".to_string())
        );
        assert_eq!(ipv4_bytes([1, 2, 3, 4])[4..], [0u8; 12]);
    }

    /// A family we did not ask for is not an address. Reading the first four bytes anyway would print a
    /// confident IPv4 address for a Unix socket.
    #[test]
    fn an_unknown_family_has_no_address() {
        let ev = ConnectionEvent {
            family: 1,
            ..ConnectionEvent::zeroed()
        };
        assert_eq!(ev.destination(), None);
    }
}

/// Where the scheduler's fork and exit tracepoints keep the fields this needs.
///
/// Read from the kernel's own `format` files, like [`Layout`], and for the same reason: these offsets have
/// moved before and the cost of assuming is a program that reads plausible wrong numbers in silence.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TaskLayout {
    /// `sched_process_fork`'s `parent_pid`.
    pub fork_parent: u16,
    /// `sched_process_fork`'s `child_pid`.
    pub fork_child: u16,
    /// `sched_process_exit`'s `pid`.
    pub exit_pid: u16,
    /// Unused, and present so the struct's size is a decision rather than a consequence.
    pub reserved: u16,
}

impl TaskLayout {
    /// Derives the layout from the two `format` files, which are read separately and belong together.
    pub fn from_formats(fork: &Format<'_>, exit: &Format<'_>) -> Result<Self, LayoutError> {
        Ok(Self {
            fork_parent: offset_of(fork, "parent_pid", 4)?,
            fork_child: offset_of(fork, "child_pid", 4)?,
            exit_pid: offset_of(exit, "pid", 4)?,
            reserved: 0,
        })
    }
}

#[cfg(feature = "user")]
// SAFETY: `#[repr(C)]` and four integers.
unsafe impl aya::Pod for TaskLayout {}
