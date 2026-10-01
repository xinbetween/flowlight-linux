//! Does a row show the text it was given?
//!
//! Not a question about a property — a question about what GTK does while the row is built. The first
//! attempt at this fix set `use-markup` on the builder, which leaves the property reading `false` and still
//! parses the title as markup, so a check that asked the property said yes while the window showed nothing.
//!
//! GTK 4 logs through `g_log_structured`, which goes to the writer function rather than to a log handler —
//! so the complaint is caught there and counted. `G_DEBUG=fatal-warnings` was tried first and is too blunt:
//! it also aborts on an unrelated missing gsettings schema, which says nothing about this.
//!
//! Needs a display. In CI that is `xvfb-run`; on a desktop it is the desktop.
use adw::prelude::*;
use flowlight_gui::{literal_row, literal_row_with};
use gtk::glib;
use std::sync::atomic::{AtomicUsize, Ordering};

/// How many times GTK said it could not set a row's text.
static COMPLAINTS: AtomicUsize = AtomicUsize::new(0);

/// A path with everything in it that markup would read as markup — an ampersand from a query string, and a
/// span a hostile one could put there. Both arrive in this window from the network.
const AWKWARD: &str = "GET example.com/api/v1/suggest?q=&providers=weather&region=CA <span foreground=\"white\">gone</span>";

fn main() {
    glib::log_set_writer_func(|_level, fields| {
        for field in fields {
            if field.key() == "MESSAGE"
                && let Some(message) = field.value_str()
                && (message.contains("from markup") || message.contains("Failed to set text"))
            {
                COMPLAINTS.fetch_add(1, Ordering::SeqCst);
                println!("   GTK could not set a row's text: {message}");
            }
        }
        glib::LogWriterOutput::Handled
    });

    // Without a display there is nothing to ask, and saying so beats a panic with a backtrace in it.
    if let Err(err) = adw::init() {
        println!(
            "libadwaita will not start here: {err}. This needs a display — `xvfb-run` is one."
        );
        std::process::exit(1);
    }

    // The rows the window makes, made the way the window makes them. Any markup complaint from here is fatal
    // because of `G_DEBUG`, so reaching the end is the assertion.
    let row = literal_row(AWKWARD);
    let with = literal_row_with(AWKWARD, AWKWARD);

    assert_eq!(
        row.title(),
        AWKWARD,
        "the row changed the text it was given"
    );
    assert_eq!(with.subtitle().unwrap_or_default(), AWKWARD);
    assert!(
        !row.uses_markup(),
        "the row still treats its text as markup"
    );

    println!("the row shows: {}", row.title());

    // The assertion the whole example exists for. The property reading `false` is not the same as the text
    // having been set as text, which is the mistake this is here to stop being made twice.
    let complaints = COMPLAINTS.load(Ordering::SeqCst);
    if complaints != 0 {
        println!(
            "FAIL: GTK refused to set a row's text {complaints} time(s). The property has to be set \
             before the text, not beside it."
        );
        std::process::exit(1);
    }
    println!("OK: a row shows the text it was given, ampersands and angle brackets and all");
}
