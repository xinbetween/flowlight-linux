//! The parts of the window that can be built and checked without opening it.
//!
//! A library beside the binary so that `examples/markup.rs` exercises the same code the window does, rather
//! than a copy of it that can drift. There is one thing in here and it is the one thing that was wrong.

use adw::prelude::*;

/// A row whose title says what it says, rather than being read as markup.
///
/// The property has to be set **before** the text and not beside it. An `AdwActionRow`'s title is applied as
/// the object is constructed and `use-markup` afterwards, whatever order a builder lists them in — so a
/// builder carrying both still parses the title as markup, and a path with an `&` in it renders as nothing
/// at all.
///
/// That is not a guess. A row built the other way logs `Failed to set text … from markup` and then reports
/// `uses_markup: false`, which is exactly how the first attempt at this fix passed a test that counted
/// declarations instead of watching behaviour. `examples/markup.rs` is that measurement, kept.
///
/// Every row in this window carries text that came off the network — a host, a path, a process name — so
/// every row goes through here.
pub fn literal_row(title: impl AsRef<str>) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_use_markup(false);
    row.set_title(title.as_ref());
    row
}

/// The same, with the line underneath — which is data as often as the title is.
pub fn literal_row_with(title: impl AsRef<str>, subtitle: impl AsRef<str>) -> adw::ActionRow {
    let row = literal_row(title);
    row.set_subtitle(subtitle.as_ref());
    row
}
