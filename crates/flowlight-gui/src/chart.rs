//! Traffic drawn rather than listed.
//!
//! GTK has no chart widget, so this is a `GtkDrawingArea` and Cairo. That is less of a compromise than it
//! sounds: the one chart this window needs is a two-direction area chart, and the arithmetic for it is forty
//! lines. What it buys is no new dependency on a machine that is already asking a kernel for permission to
//! read other processes' memory.
//!
//! The shape follows the macOS app: what came back is drawn upward from a centre line and what went out is
//! drawn downward from it, so the two directions are read apart at a glance instead of being summed into one
//! line that answers neither question. Both are filled under the stroke, because a thin line on its own
//! disappears at the window sizes people actually use.
//!
//! The arithmetic is separate from the drawing and tested. A chart that is wrong is worse than no chart,
//! and "it looked right on my screen" is not a test.

use crate::tokens;
use gtk::cairo;
use gtk::prelude::*;

/// One bucket of traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bucket {
    /// Its start, in seconds since the epoch.
    pub at: i64,
    /// Bytes that came back.
    pub received: i64,
    /// Bytes that went out.
    pub sent: i64,
}

/// A round number at or above `largest`, for the top of an axis.
///
/// An axis labelled 0 and 1,734 bytes makes a reader do arithmetic to compare two charts. One labelled 0 and
/// 2 kB does not.
///
/// Rounded in the unit it will be *written* in, which is the part worth saying out loud: a ceiling of 100000
/// is a round number in bytes and reads as "97.7 kB" on the axis, because kilobytes here are 1024 bytes.
/// Rounding to one, two or five times a power of ten within the unit gives a number that is round on the
/// screen, which is where somebody reads it.
pub fn ceiling(largest: i64) -> i64 {
    if largest <= 0 {
        return 1;
    }
    // The unit the label will use, from the same thresholds `size` uses.
    let unit: i64 = if largest < 1_024 {
        1
    } else if largest < 1_048_576 {
        1_024
    } else {
        1_048_576
    };

    let mut step = 1_i64;
    loop {
        for multiple in [1, 2, 5] {
            let candidate = step.saturating_mul(multiple).saturating_mul(unit);
            if candidate >= largest {
                return candidate;
            }
        }
        let Some(next) = step.checked_mul(10) else {
            return largest;
        };
        step = next;
    }
}

/// Where a bucket sits across the width, from its position in the series.
///
/// Evenly spaced by index rather than by timestamp, because the series arrives already evenly spaced — the
/// daemon fills the quiet buckets in — and spacing by timestamp as well would only reintroduce rounding.
pub fn across(index: usize, count: usize, width: f64) -> f64 {
    if count <= 1 {
        return 0.0;
    }
    width * index as f64 / (count - 1) as f64
}

/// How far from the centre line a value reaches, in pixels, never past the half it is given.
pub fn reach(value: i64, top: i64, half: f64) -> f64 {
    if top <= 0 || value <= 0 {
        return 0.0;
    }
    let share = value as f64 / top as f64;
    share.clamp(0.0, 1.0) * half
}

/// The chart widget: a drawing area that redraws when it is given new buckets.
pub struct Chart {
    /// The widget to put in a window.
    pub widget: gtk::DrawingArea,
}

impl Chart {
    /// A chart of nothing, ready to be given buckets.
    pub fn new(height: i32) -> Self {
        let widget = gtk::DrawingArea::builder()
            .content_height(height)
            .hexpand(true)
            .build();
        widget.add_css_class("fl-chart");
        Self { widget }
    }

    /// Draws these buckets, replacing whatever was drawn before.
    ///
    /// `dark` is passed rather than read here so that one answer from the style manager is used by every
    /// drawing in a refresh, instead of each one asking and a redraw straddling an appearance change.
    pub fn show(&self, buckets: Vec<Bucket>, dark: bool) {
        self.widget.set_draw_func(move |_, context, width, height| {
            render(context, &buckets, dark, f64::from(width), f64::from(height));
        });
        self.widget.queue_draw();
    }
}

/// The drawing itself, on any Cairo context.
///
/// Public so it can be drawn onto an image surface and looked at without opening a window — which is how
/// this is checked, since a chart that draws nothing is exactly the bug a window makes hardest to notice.
///
/// Errors from Cairo are swallowed deliberately: a failed stroke means a chart with a missing line, and a
/// window that refuses to draw anything because one stroke failed is worse than the missing line.
pub fn render(context: &cairo::Context, buckets: &[Bucket], dark: bool, width: f64, height: f64) {
    let set = |name: &str, alpha: f64| {
        let (r, g, b) = tokens::colour(name, dark);
        context.set_source_rgba(r, g, b, alpha);
    };

    // Room on the left for the axis labels, and a hair top and bottom so a peak is not clipped.
    let left = 52.0;
    let plot = (width - left - 8.0).max(1.0);
    let top = 10.0;
    let floor = (height - 16.0).max(top + 2.0);
    let centre = (top + floor) / 2.0;
    let half = (floor - centre).max(1.0);

    let largest = buckets
        .iter()
        .map(|bucket| bucket.received.max(bucket.sent))
        .max()
        .unwrap_or(0);
    let ceiling = ceiling(largest);

    // The axis: the centre line, and one line at each end of the scale.
    context.set_line_width(1.0);
    for (y, label) in [
        (centre - half, crate::size(ceiling)),
        (centre, "0".to_owned()),
        (centre + half, crate::size(ceiling)),
    ] {
        set("line", 1.0);
        context.move_to(left, y.round() + 0.5);
        context.line_to(left + plot, y.round() + 0.5);
        let _ = context.stroke();

        set("faint", 1.0);
        context.set_font_size(10.0);
        let extents = context
            .text_extents(&label)
            .map(|e| e.width())
            .unwrap_or(0.0);
        context.move_to(left - 6.0 - extents, y + 3.0);
        let _ = context.show_text(&label);
    }

    if buckets.len() < 2 {
        set("faint", 1.0);
        context.set_font_size(11.0);
        context.move_to(left + 8.0, centre - 6.0);
        let _ = context.show_text("Not enough yet to draw");
        return;
    }

    // Each direction: a filled area from the centre line, then the line on top of it.
    for (name, upward) in [("received", true), ("sent", false)] {
        let value = |bucket: &Bucket| if upward { bucket.received } else { bucket.sent };
        let y = |bucket: &Bucket| {
            let distance = reach(value(bucket), ceiling, half);
            if upward {
                centre - distance
            } else {
                centre + distance
            }
        };

        context.move_to(left, centre);
        for (index, bucket) in buckets.iter().enumerate() {
            context.line_to(left + across(index, buckets.len(), plot), y(bucket));
        }
        context.line_to(left + plot, centre);
        context.close_path();
        set(name, 0.35);
        let _ = context.fill();

        for (index, bucket) in buckets.iter().enumerate() {
            let x = left + across(index, buckets.len(), plot);
            if index == 0 {
                context.move_to(x, y(bucket));
            } else {
                context.line_to(x, y(bucket));
            }
        }
        set(name, 1.0);
        context.set_line_width(1.8);
        context.set_line_join(cairo::LineJoin::Round);
        let _ = context.stroke();
    }

    // The centre line goes on top, so neither fill hides where zero is.
    set("line", 1.0);
    context.set_line_width(1.0);
    context.move_to(left, centre.round() + 0.5);
    context.line_to(left + plot, centre.round() + 0.5);
    let _ = context.stroke();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_axis_tops_out_at_a_number_somebody_would_say() {
        // Round where it is read: on the axis, in the unit the label uses.
        assert_eq!(crate::size(ceiling(90_000)), "100.0 kB");
        assert_eq!(crate::size(ceiling(1_734)), "2.0 kB");
        assert_eq!(crate::size(ceiling(600)), "1000 B");
        assert_eq!(crate::size(ceiling(3_000_000)), "5.0 MB");
        // Nothing yet still has a scale, or every value divides by zero.
        assert_eq!(ceiling(0), 1);
        assert_eq!(ceiling(-5), 1);
    }

    #[test]
    fn the_ceiling_is_never_below_what_it_has_to_hold() {
        for value in [
            1_i64, 7, 99, 100, 101, 999, 1_000, 1_001, 123_456, 9_999_999,
        ] {
            assert!(
                ceiling(value) >= value,
                "{value} does not fit under {}",
                ceiling(value)
            );
        }
    }

    #[test]
    fn buckets_spread_across_the_width_and_reach_both_ends() {
        assert_eq!(across(0, 5, 100.0), 0.0);
        assert_eq!(across(4, 5, 100.0), 100.0);
        assert_eq!(across(2, 5, 100.0), 50.0);
        // One bucket has nowhere to be but the start, and must not divide by zero getting there.
        assert_eq!(across(0, 1, 100.0), 0.0);
    }

    #[test]
    fn a_value_reaches_its_share_of_the_half_it_is_given() {
        assert_eq!(reach(50, 100, 80.0), 40.0);
        assert_eq!(reach(100, 100, 80.0), 80.0);
        assert_eq!(reach(0, 100, 80.0), 0.0);
        // A value past the top is clamped rather than drawn outside the chart.
        assert_eq!(reach(400, 100, 80.0), 80.0);
        // And nothing divides by a zero scale.
        assert_eq!(reach(5, 0, 80.0), 0.0);
    }
}
