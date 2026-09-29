//! Plaintext, taken from the TLS library before it is encrypted.
//!
//! The design note's central claim is that reading before encryption beats terminating the connection: no
//! certificate authority, no trust store to modify, nothing for pinning to reject, and it works on QUIC. This
//! is the wire format for what that produces.
//!
//! A uprobe on `SSL_write` sees the buffer the application is handing to OpenSSL. A uretprobe on `SSL_read`
//! sees the buffer OpenSSL has just filled. Both are plaintext, both belong to a known process, and neither
//! required anybody to trust anything.
//!
//! # What a chunk is not
//!
//! It is not a request. One `SSL_write` may carry a whole request, part of one, several, or sixteen bytes of
//! an HTTP/2 frame header. [`TlsChunk::total`] says how many bytes the call handled and [`TlsChunk::len`] how
//! many came back with it, and when they differ the rest was left behind rather than quietly lost.

/// How much of one call's buffer travels with the event.
///
/// A fixed size because `bpf_perf_event_output` sends a fixed-size record, so this is paid on every chunk
/// whether it is used or not. Four kilobytes covers a TLS record and most single requests; the alternative —
/// several event sizes, chosen at runtime — is complexity bought with a saving nobody has measured.
pub const TLS_CHUNK_BYTES: usize = 4096;

/// Application to network: the buffer handed to `SSL_write`.
pub const DIRECTION_OUT: u8 = 0;
/// Network to application: the buffer `SSL_read` has just filled.
pub const DIRECTION_IN: u8 = 1;

/// Part of one `SSL_read` or `SSL_write`, with the process that made the call.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsChunk {
    /// The `SSL *` this call was made on: the connection, as the application knows it.
    ///
    /// The one field here that is a pointer value rather than data, and it earns its place. A process with
    /// two connections open interleaves their buffers, and HTTP/2 cannot be read out of an interleaved
    /// stream — its header compression is a table built across one connection in order. Without this, a
    /// second connection does not degrade the decoding, it destroys it.
    ///
    /// Meaningless as an address and never dereferenced. It is an identifier that is unique while the
    /// connection is open, which is exactly as long as it needs to be.
    pub ssl: u64,
    /// The process.
    pub tgid: u32,
    /// The thread that made the call.
    pub pid: u32,
    /// `bpf_get_current_comm()`, NUL-padded and cut at fifteen characters.
    pub comm: [u8; crate::connection::TASK_COMM_LEN],
    /// How many bytes of [`TlsChunk::data`] are real.
    pub len: u32,
    /// How many bytes the call handled in total. Larger than `len` means the rest was not captured.
    pub total: u32,
    /// [`DIRECTION_OUT`] or [`DIRECTION_IN`].
    pub direction: u8,
    /// Unused. Keeps the struct's size a decision rather than a consequence.
    pub padding: [u8; 3],
    /// The plaintext.
    pub data: [u8; TLS_CHUNK_BYTES],
}

impl TlsChunk {
    /// An empty chunk, which is how the eBPF program starts one.
    pub const fn zeroed() -> Self {
        Self {
            ssl: 0,
            tgid: 0,
            pid: 0,
            comm: [0; crate::connection::TASK_COMM_LEN],
            len: 0,
            total: 0,
            direction: DIRECTION_OUT,
            padding: [0; 3],
            data: [0; TLS_CHUNK_BYTES],
        }
    }

    /// The bytes that are actually present.
    pub fn bytes(&self) -> &[u8] {
        self.data.get(..self.len as usize).unwrap_or(&self.data)
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

    /// Whether the call carried more than came back with it.
    ///
    /// Worth asking rather than inferring, because "we saw the first four kilobytes of this" and "we saw this"
    /// are different claims and only one of them is usually true.
    pub fn is_truncated(&self) -> bool {
        self.total > self.len
    }

    /// Which way it was going.
    pub fn is_outbound(&self) -> bool {
        self.direction == DIRECTION_OUT
    }
}

#[cfg(feature = "user")]
// SAFETY: `#[repr(C)]`, integers and arrays of integers only. No pointers, no invalid bit patterns.
unsafe impl aya::Pod for TlsChunk {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both sides of the perf buffer are compiled separately, for different targets. If this moves, one of
    /// them reads the other's bytes at the wrong offsets and says nothing about it.
    #[test]
    fn the_wire_struct_is_the_size_both_sides_agree_on() {
        assert_eq!(size_of::<TlsChunk>(), 4144);
    }

    #[test]
    fn a_chunk_carries_only_the_bytes_it_captured() {
        let mut chunk = TlsChunk::zeroed();
        chunk.data[..5].copy_from_slice(b"GET /");
        chunk.len = 5;
        chunk.total = 5;
        assert_eq!(chunk.bytes(), b"GET /");
        assert!(!chunk.is_truncated());
    }

    /// A 60KB POST body arrives as one `SSL_write` and four kilobytes of it come back. Saying so is the
    /// difference between a tool that is honest about what it saw and one that is not.
    #[test]
    fn a_call_larger_than_a_chunk_says_so() {
        let chunk = TlsChunk {
            len: TLS_CHUNK_BYTES as u32,
            total: 61_440,
            ..TlsChunk::zeroed()
        };
        assert!(chunk.is_truncated());
        assert_eq!(chunk.bytes().len(), TLS_CHUNK_BYTES);
    }

    /// `len` is written by a kernel program and read here. A value past the end of the array would be a bug
    /// on the other side of the boundary, and this side still must not read out of bounds for it.
    #[test]
    fn a_length_longer_than_the_buffer_does_not_read_past_it() {
        let chunk = TlsChunk {
            len: u32::MAX,
            ..TlsChunk::zeroed()
        };
        assert_eq!(chunk.bytes().len(), TLS_CHUNK_BYTES);
    }
}
