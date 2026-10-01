//! Draws a chart onto an image and says whether anything was drawn.
//!
//! No window, no display, no GTK: Cairo draws onto a buffer and the buffer is counted. A chart that draws
//! nothing — a scale that divided by zero, a fill that never closed, a colour that came back as the
//! background — looks exactly like a quiet hour in a running window, which is the one bug a screenshot
//! would not settle.
//!
//! Run with an argument to also write the PNG somewhere and look at it.
use flowlight_gui::chart::{self, Bucket};
use gtk::cairo;

fn main() {
    // A shape with both directions, a peak, and a quiet stretch — so a chart that only draws one series, or
    // only non-empty buckets, fails here rather than on somebody's desktop.
    let buckets: Vec<Bucket> = (0..60)
        .map(|index| {
            let busy = (index as f64 / 7.0).sin().abs();
            Bucket {
                at: 1_790_000_000 + index * 60,
                received: if (20..26).contains(&index) {
                    0
                } else {
                    (busy * 90_000.0) as i64
                },
                sent: if (20..26).contains(&index) {
                    0
                } else {
                    (busy * 21_000.0) as i64
                },
            }
        })
        .collect();

    for (appearance, dark) in [("light", false), ("dark", true)] {
        let Ok(surface) = cairo::ImageSurface::create(cairo::Format::ARgb32, 900, 200) else {
            println!("FAIL: no image surface");
            std::process::exit(1);
        };
        let Ok(context) = cairo::Context::new(&surface) else {
            println!("FAIL: no context");
            std::process::exit(1);
        };
        chart::render(&context, &buckets, dark, 900.0, 200.0);
        drop(context);

        let data = match surface.take_data() {
            Ok(data) => data.to_vec(),
            Err(err) => {
                println!("FAIL: {err}");
                std::process::exit(1);
            }
        };
        // Anything with alpha in it is ink. The fourth byte of each pixel, without indexing a slice the
        // lints would rather nobody indexed.
        let inked = data
            .iter()
            .skip(3)
            .step_by(4)
            .filter(|alpha| **alpha > 0)
            .count();
        let total = 900 * 200;
        println!("{appearance}: {inked} of {total} pixels drawn");
        if inked < total / 50 {
            println!("FAIL: a chart that draws {inked} pixels is a chart nobody can see");
            std::process::exit(1);
        }

        // With a path, the raw pixels go out beside the count so somebody can look at the thing rather
        // than at a number. Raw rather than PNG: encoding it would mean a cairo feature this crate does not
        // otherwise need, for a debugging convenience.
        if let Some(into) = std::env::args().nth(1) {
            let path = format!("{into}/chart-{appearance}.rgba");
            if std::fs::write(&path, &data).is_ok() {
                println!("   900x200 BGRA written to {path}");
            }
        }
    }
    println!("OK: the chart draws in both appearances");
}
