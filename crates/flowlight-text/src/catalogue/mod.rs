//! The nine catalogues, one module each.
//!
//! English is the original and the one the program's tests assert against. The other eight are translations of
//! it, machine-drafted and not yet read by a native speaker, which is why every disclosure rendered in one of
//! them ends with a sentence saying so.
//!
//! Adding a phrase means adding it to all nine. That is not a convention anybody has to remember — the tests in
//! the crate above compare the key sets, so a language left behind is a test failure rather than a paragraph
//! with a hole in it.
//!
//! Each list is written in the order the sentences appear on a screen, rather than sorted, so that a translator
//! reading a file top to bottom is reading a disclosure in the order somebody else will.

pub mod de;
pub mod en;
pub mod es;
pub mod fr;
pub mod it;
pub mod ja;
pub mod ko;
pub mod pt;
pub mod zh;
