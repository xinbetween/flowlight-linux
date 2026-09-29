//! Reading a tracepoint's field layout out of the text the kernel publishes for it.
//!
//! A tracepoint's *name* is stable ABI. Its *layout* is not, and the one this project depends on moved:
//! `sock/inet_sock_set_state` declares `protocol` as `__u16` up to Linux 5.5 and as `__u8` from 5.6, which
//! shifts every field after it by one byte. A program that hard-codes offsets reads the wrong bytes on half
//! the kernels in the world and reports them with complete confidence — addresses that are nearly right,
//! ports that are plausible. Nothing crashes. That is the problem with it.
//!
//! So the offsets are not hard-coded. The kernel writes them, in plain text, at
//! `/sys/kernel/tracing/events/<category>/<name>/format`; the daemon reads that file and hands the numbers to
//! the program through a map. This module is the parser for that text, and it is here rather than in the
//! daemon because here it is testable on a machine with no kernel — against recorded layouts from both sides
//! of the 5.6 change, which is the only way anyone was going to test both.
//!
//! ```text
//! name: inet_sock_set_state
//! ID: 1234
//! format:
//!     field:unsigned short common_type;    offset:0;    size:2;    signed:0;
//!     ...
//!     field:__u8 saddr[4];    offset:31;    size:4;    signed:0;
//! ```

/// One field of a tracepoint's record, as the kernel describes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    /// Byte offset from the start of the record.
    pub offset: u16,
    /// Width in bytes. For an array field this is the whole array.
    pub size: u16,
    /// Whether the kernel declared it signed. Recorded rather than used: nothing here reads a signed field
    /// as anything but a bit pattern, but dropping it would make the parser lossy for no reason.
    pub signed: bool,
}

/// A tracepoint's `format` file, parsed on demand.
///
/// Borrows the text rather than owning a map of it, so that this works in the eBPF programs' no-alloc world
/// as well as the daemon's. The files are a few hundred bytes and read once at startup; a linear scan per
/// lookup is not the cost anyone should be optimising.
#[derive(Debug, Clone, Copy)]
pub struct Format<'a> {
    text: &'a str,
}

impl<'a> Format<'a> {
    /// Wraps the contents of a `format` file.
    pub fn new(text: &'a str) -> Self {
        Self { text }
    }

    /// Every field the file declares, in the order it declares them.
    pub fn fields(&self) -> impl Iterator<Item = (&'a str, Field)> {
        self.text.lines().filter_map(parse_line)
    }

    /// The field with this name, or `None` if the kernel does not publish one.
    ///
    /// `None` is a real answer and the caller has to have one: a field that exists on 6.x and not on 4.18 is
    /// how this file differs between kernels, and "absent" is the honest report of it.
    pub fn field(&self, name: &str) -> Option<Field> {
        self.fields().find(|(n, _)| *n == name).map(|(_, f)| f)
    }
}

/// Parses one `field:…;    offset:…;    size:…;    signed:…;` line.
///
/// Returns `None` for every other line in the file — the header, the blank lines, the `print fmt:` trailer —
/// rather than treating them as errors, because they are not errors, they are the rest of the file.
fn parse_line(line: &str) -> Option<(&str, Field)> {
    let mut name = None;
    let mut offset = None;
    let mut size = None;
    let mut signed = false;

    for part in line.split(';') {
        let part = part.trim();
        if let Some(decl) = part.strip_prefix("field:") {
            name = field_name(decl);
        } else if let Some(value) = part.strip_prefix("offset:") {
            offset = value.trim().parse().ok();
        } else if let Some(value) = part.strip_prefix("size:") {
            size = value.trim().parse().ok();
        } else if let Some(value) = part.strip_prefix("signed:") {
            signed = value.trim() == "1";
        }
    }

    Some((
        name?,
        Field {
            offset: offset?,
            size: size?,
            signed,
        },
    ))
}

/// The identifier out of a C declaration: `const void * skaddr` is `skaddr`, `__u8 saddr[4]` is `saddr`.
fn field_name(decl: &str) -> Option<&str> {
    let without_array = decl.split('[').next().unwrap_or(decl);
    let last = without_array.split_whitespace().next_back()?;
    let name = last.trim_start_matches('*');
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Linux 6.x, where `protocol` is a `__u8`. Taken from a live `format` file rather than written by hand,
    /// because the point of the exercise is that nobody should be writing these numbers.
    pub(crate) const MODERN: &str = "\
name: inet_sock_set_state
ID: 1382
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:const void * skaddr;	offset:8;	size:8;	signed:0;
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

print fmt: \"family=%s protocol=%s sport=%hu dport=%hu\", ...
";

    /// Linux 4.18 through 5.5, where `protocol` is a `__u16` and everything after it sits one byte later.
    /// This single byte is the whole reason the offsets are read at runtime.
    pub(crate) const LEGACY: &str = "\
name: inet_sock_set_state
ID: 1231
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:const void * skaddr;	offset:8;	size:8;	signed:0;
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

print fmt: \"family=%s protocol=%s sport=%hu dport=%hu\", ...
";

    #[test]
    fn a_plain_field_is_read_whole() {
        let f = Format::new(MODERN).field("dport").unwrap();
        assert_eq!(
            f,
            Field {
                offset: 26,
                size: 2,
                signed: false
            }
        );
    }

    /// `int oldstate` is the only signed field anything here looks at, and the flag has to survive the parse
    /// or the parser is quietly lossy.
    #[test]
    fn signedness_survives() {
        assert!(Format::new(MODERN).field("oldstate").unwrap().signed);
        assert!(!Format::new(MODERN).field("sport").unwrap().signed);
    }

    /// `__u8 saddr[4]` — the name is `saddr`, not `saddr[4]`, and the size is the whole array.
    #[test]
    fn an_array_field_is_named_without_its_length() {
        let f = Format::new(MODERN).field("daddr_v6").unwrap();
        assert_eq!(f.offset, 55);
        assert_eq!(f.size, 16);
    }

    /// `const void * skaddr` — three tokens of type and a pointer star before the name.
    #[test]
    fn a_pointer_field_is_named_without_its_star() {
        assert_eq!(Format::new(MODERN).field("skaddr").unwrap().size, 8);
    }

    /// The whole reason this is parsed rather than hard-coded, stated as a test: the same field is at two
    /// different offsets on two kernels that are both still in service.
    #[test]
    fn the_same_field_sits_elsewhere_on_an_older_kernel() {
        assert_eq!(Format::new(MODERN).field("saddr").unwrap().offset, 31);
        assert_eq!(Format::new(LEGACY).field("saddr").unwrap().offset, 32);
        assert_eq!(Format::new(MODERN).field("protocol").unwrap().size, 1);
        assert_eq!(Format::new(LEGACY).field("protocol").unwrap().size, 2);
    }

    #[test]
    fn a_field_the_kernel_does_not_publish_is_absent_rather_than_zero() {
        assert!(Format::new(MODERN).field("cgroup_id").is_none());
    }

    /// Headers, blank lines and the `print fmt:` trailer are the rest of the file, not malformed fields.
    #[test]
    fn nothing_but_field_lines_is_parsed() {
        let f = Format::new(MODERN);
        assert_eq!(f.fields().count(), 15);
        assert_eq!(f.fields().next().map(|(n, _)| n), Some("common_type"));
        assert_eq!(f.fields().last().map(|(n, _)| n), Some("daddr_v6"));
    }

    #[test]
    fn a_file_that_is_not_one_yields_nothing_rather_than_guesses() {
        assert_eq!(Format::new("").fields().count(), 0);
        assert_eq!(Format::new("not a format file at all").fields().count(), 0);
        // A field line the kernel truncated mid-write is not half a field.
        assert_eq!(Format::new("\tfield:__u16 sport;").fields().count(), 0);
    }
}
