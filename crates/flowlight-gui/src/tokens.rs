//! The palette, in one place, for both the stylesheet and the drawing.
//!
//! These are the same values the macOS app and the website use, with the same semantic roles: `accent` is
//! the one "light" colour and is reserved for what needs a decision; `received` and `sent` carry traffic
//! direction; `critical`, `warning` and `good` are status only and never stand in for the accent.
//!
//! Two consumers, one table. GTK's stylesheet gets `@define-color` lines generated from it, and the charts
//! get numbers, because Cairo draws with floats and knows nothing about CSS. Defining the palette twice is
//! how the chart and the text beside it end up slightly different colours.
//!
//! GTK has no media query for the colour scheme, so the stylesheet is rebuilt and reloaded when libadwaita
//! says the appearance changed, rather than written once with both appearances in it.

/// One colour, as it appears in each appearance. `0xRRGGBB`.
pub struct Token {
    /// The name it is known by, in CSS as `@fl_<name>` and here as itself.
    pub name: &'static str,
    /// Light appearance.
    pub light: u32,
    /// Dark appearance.
    pub dark: u32,
}

/// The palette. Surfaces deepest to lightest, then text, then the semantic roles.
pub const PALETTE: &[Token] = &[
    Token {
        name: "ground",
        light: 0xf4f5f8,
        dark: 0x0d0f16,
    },
    Token {
        name: "surface",
        light: 0xffffff,
        dark: 0x151824,
    },
    Token {
        name: "surface_deep",
        light: 0xf0f1f6,
        dark: 0x10131d,
    },
    Token {
        name: "surface_2",
        light: 0xeceef4,
        dark: 0x1c2030,
    },
    Token {
        name: "line",
        light: 0xdde0e8,
        dark: 0x262b3b,
    },
    Token {
        name: "ink",
        light: 0x11131a,
        dark: 0xeef0f6,
    },
    Token {
        name: "muted",
        light: 0x565d70,
        dark: 0xa3a9bb,
    },
    Token {
        name: "faint",
        light: 0x8a90a2,
        dark: 0x737a8f,
    },
    Token {
        name: "accent",
        light: 0x4a3aa7,
        dark: 0x9085e9,
    },
    Token {
        name: "received",
        light: 0x2a78d6,
        dark: 0x4a93ea,
    },
    Token {
        name: "sent",
        light: 0xd95926,
        dark: 0xe5723f,
    },
    Token {
        name: "critical",
        light: 0xc93b33,
        dark: 0xec6a62,
    },
    Token {
        name: "warning",
        light: 0xb86e00,
        dark: 0xe0a13a,
    },
    Token {
        name: "good",
        light: 0x1f9d6b,
        dark: 0x4fb98a,
    },
    Token {
        name: "tool",
        light: 0x6f4bc7,
        dark: 0xb4a2f2,
    },
];

/// The rules, which do not change with the appearance.
const RULES: &str = include_str!("flowlight.css");

/// One colour by name, as Cairo wants it: three floats from zero to one.
///
/// An unknown name is mid-grey rather than a panic. A chart drawn in the wrong grey is a mistake somebody
/// can see and fix; a window that will not open is one they cannot.
pub fn colour(name: &str, dark: bool) -> (f64, f64, f64) {
    let Some(token) = PALETTE.iter().find(|token| token.name == name) else {
        return (0.5, 0.5, 0.5);
    };
    let value = if dark { token.dark } else { token.light };
    (
        f64::from((value >> 16) & 0xff) / 255.0,
        f64::from((value >> 8) & 0xff) / 255.0,
        f64::from(value & 0xff) / 255.0,
    )
}

/// The whole stylesheet for one appearance: the palette as `@define-color`, then the rules.
pub fn stylesheet(dark: bool) -> String {
    let mut css = String::with_capacity(RULES.len() + PALETTE.len() * 40);
    for token in PALETTE {
        let value = if dark { token.dark } else { token.light };
        css.push_str(&format!("@define-color fl_{} #{value:06x};\n", token.name));
    }
    css.push_str(RULES);
    css
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_token_is_defined_for_both_appearances() {
        // A token that reads the same in both is almost always a token somebody forgot to finish. The two
        // greys are deliberate; nothing else may match.
        let same: Vec<&str> = PALETTE
            .iter()
            .filter(|token| token.light == token.dark)
            .map(|token| token.name)
            .collect();
        assert!(
            same.is_empty(),
            "these read identically in both appearances: {same:?}"
        );
    }

    #[test]
    fn the_stylesheet_carries_the_palette_it_was_asked_for() {
        let light = stylesheet(false);
        let dark = stylesheet(true);
        assert!(
            light.contains("@define-color fl_accent #4a3aa7;"),
            "{light}"
        );
        assert!(dark.contains("@define-color fl_accent #9085e9;"), "{dark}");
        // And the rules come along with it, or the names resolve to nothing.
        assert!(light.contains(".fl-card"));
        assert!(dark.contains(".fl-card"));
    }

    #[test]
    fn a_colour_comes_back_as_cairo_wants_it() {
        let (r, g, b) = colour("sent", false);
        assert!((r - 0xd9 as f64 / 255.0).abs() < 1e-9);
        assert!((g - 0x59 as f64 / 255.0).abs() < 1e-9);
        assert!((b - 0x26 as f64 / 255.0).abs() < 1e-9);
        // Dark is a different colour, not the same one.
        assert_ne!(colour("sent", true), colour("sent", false));
    }

    #[test]
    fn a_name_nobody_defined_is_grey_rather_than_a_crash() {
        assert_eq!(colour("chartreuse", false), (0.5, 0.5, 0.5));
    }
}
