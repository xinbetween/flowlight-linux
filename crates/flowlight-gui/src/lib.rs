//! The parts of the window that can be built and checked without opening it.
//!
//! A library beside the binary so that `examples/markup.rs` exercises the same code the window does, rather
//! than a copy of it that can drift. There is one thing in here and it is the one thing that was wrong.

pub mod chart;
pub mod tokens;

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

/// A size, in words.
///
/// In the library because the charts label their axes with it and the rows say it in words, and two
/// formatters would disagree about what 1,536 bytes is called on the same screen.
pub fn size(bytes: i64) -> String {
    if bytes < 1_024 {
        format!("{bytes} B")
    } else if bytes < 1_048_576 {
        format!("{:.1} kB", bytes as f64 / 1_024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    }
}

/// A tile of one figure: what it is, how much of it there is, and the colour that says which kind.
///
/// The number is the content and is sized like it. A label above it in muted text explains it, and the whole
/// thing sits on the one card surface — the same card, everywhere, rather than three rounded rectangles that
/// are nearly the same.
pub fn stat_tile(label: &str, value: &str, token: &str) -> gtk::Box {
    let tile = gtk::Box::new(gtk::Orientation::Vertical, 6);
    tile.add_css_class("fl-card");
    tile.set_hexpand(true);
    tile.set_margin_top(0);
    for (side, amount) in [("top", 12), ("bottom", 12), ("start", 14), ("end", 14)] {
        match side {
            "top" => tile.set_margin_top(amount),
            "bottom" => tile.set_margin_bottom(amount),
            "start" => tile.set_margin_start(amount),
            _ => tile.set_margin_end(amount),
        }
    }

    let what = gtk::Label::new(Some(label));
    what.add_css_class("fl-tile-label");
    what.set_xalign(0.0);
    what.set_ellipsize(gtk::pango::EllipsizeMode::End);

    let figure = gtk::Label::new(Some(value));
    figure.add_css_class("fl-tile-value");
    figure.add_css_class(&format!("fl-{token}"));
    figure.set_xalign(0.0);
    figure.set_ellipsize(gtk::pango::EllipsizeMode::End);

    tile.append(&what);
    tile.append(&figure);
    tile
}

/// A row of tiles, evenly wide, which is how every screen in this window starts.
pub fn tiles(of: &[gtk::Box]) -> gtk::Box {
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 12);
    row.set_homogeneous(true);
    for tile in of {
        row.append(tile);
    }
    row
}

/// A small status word on a tinted capsule — never colour alone, which is why it carries a word.
pub fn pill(text: &str, token: &str) -> gtk::Label {
    let pill = gtk::Label::new(Some(text));
    pill.add_css_class("fl-pill");
    pill.add_css_class(&format!("fl-{token}"));
    pill.set_valign(gtk::Align::Center);
    pill
}

/// Puts the stylesheet on the display, and keeps it matching the system appearance.
///
/// Reloaded rather than written once with both appearances in it: GTK has no media query for the colour
/// scheme, so the palette is generated for whichever one is in force and generated again when it changes.
pub fn dress(display: &gtk::gdk::Display) {
    let provider = gtk::CssProvider::new();
    let manager = adw::StyleManager::default();

    let apply = {
        let provider = provider.clone();
        move |dark: bool| provider.load_from_data(&tokens::stylesheet(dark))
    };
    apply(manager.is_dark());

    gtk::style_context_add_provider_for_display(
        display,
        &provider,
        gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    manager.connect_dark_notify(move |manager| apply(manager.is_dark()));
}
