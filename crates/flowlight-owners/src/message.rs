//! Just enough DNS to ask one question and read one answer.
//!
//! Written out rather than pulled in. A resolver crate brings an async runtime, a configuration language and a
//! cache of its own, for a feature that asks a `TXT` question a few times a minute — and this daemon is threads
//! and blocking reads everywhere else. What is here is a query builder and a parser, both of which are pure and
//! both of which are tested against bytes.
//!
//! # What is not here
//!
//! Recursion, retries over TCP, DNSSEC, EDNS. A truncated answer is reported as truncated rather than retried,
//! because the answers this asks for are two short strings and one that does not fit in a datagram is one
//! something is wrong with.
//!
//! # Why the parser is suspicious
//!
//! It reads a reply from the network. Every length is checked against what is actually present, name
//! compression pointers are followed only backwards and only so many times, and nothing is allocated from a
//! length the message itself claims.

use anyhow::{Result, bail};

/// A `TXT` question.
const TXT: u16 = 16;
/// The internet class.
const IN: u16 = 1;
/// The most compression pointers that will be followed before a name is called a loop.
const MOST_POINTERS: usize = 16;

/// Builds a query for one name.
///
/// The identifier is the caller's, so it can check that the answer is to the question it asked.
pub fn query(id: u16, name: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&id.to_be_bytes());
    // Recursion desired, and nothing else.
    bytes.extend_from_slice(&0x0100_u16.to_be_bytes());
    bytes.extend_from_slice(&1_u16.to_be_bytes()); // one question
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // no answers, authorities or additionals
    for label in name.split('.').filter(|label| !label.is_empty()) {
        if label.len() > 63 {
            bail!("`{label}` is longer than a label may be");
        }
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    bytes.extend_from_slice(&TXT.to_be_bytes());
    bytes.extend_from_slice(&IN.to_be_bytes());
    if bytes.len() > 512 {
        bail!("that name does not fit in a query");
    }
    Ok(bytes)
}

/// What came back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The strings in the `TXT` records, in the order they arrived.
    pub texts: Vec<String>,
    /// Whether the answer was cut short, in which case there may have been more.
    pub truncated: bool,
}

/// Reads the `TXT` strings out of a reply to the question with this identifier.
pub fn answer(id: u16, bytes: &[u8]) -> Result<Answer> {
    let header = bytes.get(..12).unwrap_or_default();
    if header.len() < 12 {
        bail!("a reply shorter than a header");
    }
    if be16(header, 0) != Some(id) {
        bail!("a reply to a different question");
    }
    let flags = be16(header, 2).unwrap_or(0);
    if flags & 0x8000 == 0 {
        bail!("that is a question, not an answer");
    }
    let truncated = flags & 0x0200 != 0;
    match flags & 0x000f {
        0 => {}
        // Not an error worth a message of its own: a name nobody has registered is the ordinary answer for an
        // address in a range nobody has announced.
        3 => {
            return Ok(Answer {
                texts: Vec::new(),
                truncated,
            });
        }
        code => bail!("the resolver answered with code {code}"),
    }
    let questions = be16(header, 4).unwrap_or(0);
    let answers = be16(header, 6).unwrap_or(0);

    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(bytes, at)?;
        // The type and class of the question.
        at = at.checked_add(4).unwrap_or(bytes.len());
    }

    let mut texts = Vec::new();
    for _ in 0..answers {
        at = skip_name(bytes, at)?;
        let kind = be16(bytes, at).unwrap_or(0);
        let length = be16(bytes, at + 8).unwrap_or(0) as usize;
        let start = at + 10;
        let Some(data) = bytes.get(start..start.saturating_add(length)) else {
            bail!("a record claims {length} bytes that are not there");
        };
        if kind == TXT {
            // One or more counted strings, back to back.
            let mut inner = 0;
            while let Some(&count) = data.get(inner) {
                let from = inner + 1;
                let Some(text) = data.get(from..from + count as usize) else {
                    break;
                };
                texts.push(String::from_utf8_lossy(text).into_owned());
                inner = from + count as usize;
            }
        }
        at = start + length;
    }
    Ok(Answer { texts, truncated })
}

/// Steps over a name, following compression pointers only backwards and only so many times.
fn skip_name(bytes: &[u8], mut at: usize) -> Result<usize> {
    let mut pointers = 0;
    loop {
        let Some(&length) = bytes.get(at) else {
            bail!("a name runs past the end of the message");
        };
        if length & 0xc0 == 0xc0 {
            // A pointer, and the name ends here whatever it points at.
            let Some(target) = be16(bytes, at).map(|word| (word & 0x3fff) as usize) else {
                bail!("a pointer runs past the end of the message");
            };
            if target >= at {
                bail!("a compression pointer that does not point backwards");
            }
            pointers += 1;
            if pointers > MOST_POINTERS {
                bail!("a name that is a loop of pointers");
            }
            return Ok(at + 2);
        }
        if length == 0 {
            return Ok(at + 1);
        }
        at = at.saturating_add(1 + length as usize);
        if at > bytes.len() {
            bail!("a label runs past the end of the message");
        }
    }
}

/// A big-endian sixteen-bit number at an offset, if it is there.
fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let high = u16::from(*bytes.get(at)?);
    let low = u16::from(*bytes.get(at + 1)?);
    Some((high << 8) | low)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply built by hand, so the parser is tested against bytes rather than against itself.
    fn reply(id: u16, flags: u16, texts: &[&str], compressed: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&flags.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&(texts.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        // The question, whose name the answers may point back at.
        for label in ["origin", "asn", "cymru", "com"] {
            bytes.push(label.len() as u8);
            bytes.extend_from_slice(label.as_bytes());
        }
        bytes.push(0);
        bytes.extend_from_slice(&TXT.to_be_bytes());
        bytes.extend_from_slice(&IN.to_be_bytes());

        for text in texts {
            if compressed {
                bytes.extend_from_slice(&0xc00c_u16.to_be_bytes());
            } else {
                for label in ["origin", "asn", "cymru", "com"] {
                    bytes.push(label.len() as u8);
                    bytes.extend_from_slice(label.as_bytes());
                }
                bytes.push(0);
            }
            bytes.extend_from_slice(&TXT.to_be_bytes());
            bytes.extend_from_slice(&IN.to_be_bytes());
            bytes.extend_from_slice(&300_u32.to_be_bytes());
            bytes.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
            bytes.push(text.len() as u8);
            bytes.extend_from_slice(text.as_bytes());
        }
        bytes
    }

    #[test]
    fn a_query_is_the_name_in_labels_followed_by_the_type() {
        let bytes = query(0x1234, "origin.asn.cymru.com").unwrap();
        assert_eq!(&bytes[..2], &[0x12, 0x34]);
        assert_eq!(&bytes[4..6], &[0, 1], "one question");
        assert!(bytes.ends_with(&[0, 16, 0, 1]), "a TXT question in IN");
        assert!(bytes.windows(7).any(|window| window == b"\x06origin"));
    }

    #[test]
    fn a_label_longer_than_a_label_may_be_is_refused() {
        assert!(query(1, &"a".repeat(64)).is_err());
    }

    #[test]
    fn the_texts_come_back_in_order() {
        let bytes = reply(
            7,
            0x8180,
            &["13335 | 1.1.1.0/24 | US | arin |", "second"],
            true,
        );
        let read = answer(7, &bytes).unwrap();
        assert_eq!(read.texts.len(), 2);
        assert!(read.texts[0].starts_with("13335 |"));
        assert_eq!(read.texts[1], "second");
        assert!(!read.truncated);
    }

    /// Names in answers are usually pointers back at the question, and skipping them wrongly reads the rest
    /// of the message at the wrong offset — which is a parser that works until it meets a real resolver.
    #[test]
    fn a_name_is_stepped_over_whether_it_is_compressed_or_not() {
        for compressed in [true, false] {
            let bytes = reply(7, 0x8180, &["only"], compressed);
            assert_eq!(answer(7, &bytes).unwrap().texts, vec!["only".to_owned()]);
        }
    }

    /// An answer to a question nobody asked is not an answer. Without this, anything that can guess a source
    /// port can put words in the resolver's mouth.
    #[test]
    fn a_reply_to_another_question_is_refused() {
        let bytes = reply(7, 0x8180, &["x"], true);
        assert!(answer(8, &bytes).is_err());
    }

    #[test]
    fn a_question_is_not_an_answer() {
        let bytes = reply(7, 0x0100, &[], true);
        assert!(answer(7, &bytes).is_err());
    }

    /// A name nobody has registered is the ordinary answer for an address in a range nobody has announced.
    #[test]
    fn no_such_name_is_no_texts_rather_than_an_error() {
        let bytes = reply(7, 0x8183, &[], true);
        let read = answer(7, &bytes).unwrap();
        assert!(read.texts.is_empty());
    }

    #[test]
    fn a_truncated_answer_says_so() {
        let bytes = reply(7, 0x8380, &["x"], true);
        assert!(answer(7, &bytes).unwrap().truncated);
    }

    /// This reads a reply from the network. Every length is checked against what is present, so a truncated
    /// or lying message is an error rather than a panic.
    #[test]
    fn a_truncated_or_lying_message_is_an_error_rather_than_a_panic() {
        let whole = reply(7, 0x8180, &["13335 | 1.1.1.0/24 | US | arin |"], true);
        for upto in 0..whole.len() {
            let _ = answer(7, whole.get(..upto).unwrap_or_default());
        }
        // A record that claims far more data than is present.
        let mut lying = whole.clone();
        let length = lying.len();
        if let Some(slot) = lying.get_mut(length - 34..length - 32) {
            slot.copy_from_slice(&u16::MAX.to_be_bytes());
        }
        assert!(answer(7, &lying).is_err());
    }

    /// A pointer that points forwards is how a parser is made to loop for ever.
    #[test]
    fn a_pointer_that_does_not_point_backwards_is_refused() {
        let mut bytes = reply(7, 0x8180, &["x"], true);
        // Aim the answer's name forwards rather than at the question. The answer begins after the header
        // (twelve bytes), the question's name (`origin.asn.cymru.com` in labels, twenty-two) and its type
        // and class (four).
        let at = 12 + 22 + 4;
        if let Some(slot) = bytes.get_mut(at..at + 2) {
            slot.copy_from_slice(&0xc0ff_u16.to_be_bytes());
        }
        assert!(answer(7, &bytes).is_err());
    }
}
