//! Asking the database what happened, rather than watching it happen.
//!
//! The reason storage exists. "Which host did that agent reach at three in the morning" is the question
//! people actually have, and a terminal that has scrolled cannot answer it.

use crate::Command;
use anyhow::{Context as _, bail};
use flowlight_store::{RequestRow, Store};
use std::io::Write as _;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Answers one question and exits.
pub fn run(command: &Command, database: &Path, json: bool) -> anyhow::Result<()> {
    if !database.exists() {
        bail!(
            "there is no database at {}. Nothing has been recorded yet, or it was recorded somewhere else \
             — `flowlightd --database PATH` names it.",
            database.display()
        );
    }
    let mut store = Store::open(database)?;
    let mut out = std::io::stdout().lock();

    match command {
        Command::History { since, limit } => {
            let window = parse_window(since)
                .with_context(|| format!("reading `{since}` as a length of time"))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64);
            let rows = store.requests_since(now - window, *limit)?;
            if rows.is_empty() {
                // A count of zero and an empty screen look the same and mean different things. One of them
                // is "nothing happened" and the other is "you are looking in the wrong place".
                let earliest = store.earliest_request()?;
                match earliest {
                    Some(at) => eprintln!(
                        "Nothing in the last {since}. The oldest request held is from {} seconds ago.",
                        now - at
                    ),
                    None => eprintln!("Nothing has been recorded yet."),
                }
                return Ok(());
            }
            for row in rows {
                if json {
                    writeln!(out, "{}", request_json(&row))?;
                } else {
                    writeln!(out, "{}", request_line(&row))?;
                }
            }
        }
        Command::Coverage { since } => {
            let window = parse_window(since)
                .with_context(|| format!("reading `{since}` as a length of time"))?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| since.as_secs() as i64);
            let coverage = store.coverage(now - window)?;
            if json {
                writeln!(out, "{}", coverage_json(&coverage))?;
            } else {
                write!(out, "{}", coverage_report(&coverage, since))?;
            }
        }
        Command::Summary { limit } => {
            let rows = store.summary(*limit)?;
            if rows.is_empty() {
                eprintln!(
                    "The summary is empty. It is what expired detail is folded into, so it stays empty \
                     until some detail has expired."
                );
                return Ok(());
            }
            for row in rows {
                if json {
                    writeln!(
                        out,
                        "{{\"day\":{},\"process\":{},\"host\":{},\"requests\":{},\"bytes\":{}}}",
                        quote(&row.day),
                        quote(&row.process),
                        quote(&row.host),
                        row.requests,
                        row.bytes
                    )?;
                } else {
                    writeln!(
                        out,
                        "{}  {:<24} {:<40} {:>6} requests  {:>10} bytes",
                        row.day, row.process, row.host, row.requests, row.bytes
                    )?;
                }
            }
        }
    }
    Ok(())
}

/// Coverage, as prose.
///
/// Zeroes are printed rather than omitted. The whole point of this screen is that it accounts for the gap
/// between what happened and what was recorded, and a line that disappears when it reads zero turns "nothing
/// was dropped" into "nobody checked".
fn coverage_report(coverage: &flowlight_store::Coverage, window: &str) -> String {
    let mut out = format!("Coverage for the last {window}\n\n");
    out.push_str(&format!(
        "  Read          {} request(s) from {} process(es), over {} connection(s)\n",
        coverage.requests, coverage.processes_read, coverage.connections
    ));

    if coverage.unread.is_empty() {
        out.push_str(
            "  Not read      nothing: every process that opened an HTTPS connection was read\n",
        );
    } else {
        out.push_str("  Not read\n");
        for unread in &coverage.unread {
            out.push_str(&format!(
                "                {:<24} {} connection(s), nothing read\n",
                unread.process, unread.connections
            ));
        }
        out.push_str(
            "\n                A process that opened HTTPS connections and had nothing read from them is\n\
             \x20               using a TLS implementation there is no probe for. Go links its own into the\n\
             \x20               binary, and so does Chrome. Both need symbols resolved per binary rather\n\
             \x20               than per library, which Flowlight does not do yet.\n\n",
        );
    }

    out.push_str(&format!(
        "  Truncated     {} call(s) carried more than four kilobytes; the rest was not captured\n",
        coverage.truncated
    ));
    out.push_str(&format!(
        "  Undecodable   {} HTTP/2 connection(s) could not be followed\n",
        coverage.undecodable
    ));
    out.push_str(&format!(
        "  Named weakly  {} record(s) name a process by its comm, which the kernel cuts at fifteen\n\
         \x20               characters; {} have no name at all\n",
        coverage.named_by_comm, coverage.named_by_pid
    ));
    out.push_str(&format!(
        "  Dropped       {} record(s) were lost by the kernel before Flowlight read them\n",
        coverage.dropped
    ));

    if !coverage.unprobed.is_empty() {
        out.push_str("\n  Unprobed\n");
        for note in &coverage.unprobed {
            out.push_str(&format!("                {}\n", note.subject));
            out.push_str(&format!("                  {}\n", note.detail));
        }
    }

    out.push_str(
        "\n  Inbound connections are never attributed, and UDP and QUIC are not watched at all. Those are\n\
         \x20 design decisions rather than gaps, and they are in the README.\n",
    );
    out
}

/// Coverage, as one JSON object.
fn coverage_json(coverage: &flowlight_store::Coverage) -> String {
    let unread: Vec<String> = coverage
        .unread
        .iter()
        .map(|unread| {
            format!(
                "{{\"process\":{},\"connections\":{}}}",
                quote(&unread.process),
                unread.connections
            )
        })
        .collect();
    let unprobed: Vec<String> = coverage
        .unprobed
        .iter()
        .map(|note| {
            format!(
                "{{\"path\":{},\"reason\":{}}}",
                quote(&note.subject),
                quote(&note.detail)
            )
        })
        .collect();
    format!(
        "{{\"requests\":{},\"processes_read\":{},\"connections\":{},\"truncated\":{},\
         \"undecodable\":{},\"named_by_comm\":{},\"named_by_pid\":{},\"dropped\":{},\
         \"unread\":[{}],\"unprobed\":[{}]}}",
        coverage.requests,
        coverage.processes_read,
        coverage.connections,
        coverage.truncated,
        coverage.undecodable,
        coverage.named_by_comm,
        coverage.named_by_pid,
        coverage.dropped,
        unread.join(","),
        unprobed.join(",")
    )
}

/// One stored request, as a line.
fn request_line(row: &RequestRow) -> String {
    let arrow = if row.direction == "out" { "→" } else { "←" };
    let what = if let Some(method) = &row.method {
        format!(
            "{method} {}{}",
            row.host.as_deref().unwrap_or(""),
            row.target.as_deref().unwrap_or("")
        )
    } else if let Some(status) = row.status {
        format!("{status}  {} bytes", row.bytes)
    } else if let Some(reason) = &row.unreadable {
        format!("HTTP/2 — {reason}")
    } else {
        format!("{} bytes", row.bytes)
    };
    format!(
        "{}  {:<24} pid {:<8} {arrow} {what}",
        row.at, row.process, row.pid
    )
}

/// One stored request, as JSON.
fn request_json(row: &RequestRow) -> String {
    let mut fields = vec![
        format!("\"at\":{}", row.at),
        format!("\"process\":{}", quote(&row.process)),
        format!("\"confidence\":{}", quote(&row.confidence)),
        format!("\"pid\":{}", row.pid),
        format!("\"direction\":{}", quote(&row.direction)),
        format!("\"bytes\":{}", row.bytes),
    ];
    for (name, value) in [
        ("protocol", &row.protocol),
        ("method", &row.method),
        ("target", &row.target),
        ("host", &row.host),
        ("unreadable", &row.unreadable),
    ] {
        if let Some(value) = value {
            fields.push(format!("\"{name}\":{}", quote(value)));
        }
    }
    if let Some(status) = row.status {
        fields.push(format!("\"status\":{status}"));
    }
    if row.truncated {
        fields.push("\"truncated\":true".to_owned());
    }
    format!("{{{}}}", fields.join(","))
}

/// A JSON string. Hand-written because the rows come out of our own database and back into a terminal, and
/// pulling serde into this module to quote four fields would be the larger cost.
fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Reads `30m`, `6h`, `2d`, or a bare number of seconds.
///
/// Deliberately small. `humantime` would parse more forms than anyone types, and this is four lines whose
/// failure mode is a message naming what was not understood.
pub fn parse_window(text: &str) -> anyhow::Result<i64> {
    let text = text.trim();
    let (number, multiplier) = match text.chars().last() {
        Some('s') => (text.get(..text.len() - 1), 1),
        Some('m') => (text.get(..text.len() - 1), 60),
        Some('h') => (text.get(..text.len() - 1), 3_600),
        Some('d') => (text.get(..text.len() - 1), 86_400),
        Some(c) if c.is_ascii_digit() => (Some(text), 1),
        _ => bail!("expected something like `30m`, `6h`, `2d`, or a number of seconds"),
    };
    let number: i64 = number
        .unwrap_or("")
        .parse()
        .map_err(|_| anyhow::anyhow!("expected a number before the unit"))?;
    if number < 0 {
        bail!("a window into the future is not a window");
    }
    Ok(number * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_are_read_in_every_form_anyone_types() {
        assert_eq!(parse_window("90").unwrap(), 90);
        assert_eq!(parse_window("90s").unwrap(), 90);
        assert_eq!(parse_window("30m").unwrap(), 1_800);
        assert_eq!(parse_window("6h").unwrap(), 21_600);
        assert_eq!(parse_window("2d").unwrap(), 172_800);
        assert_eq!(parse_window("  1h  ").unwrap(), 3_600);
    }

    /// The message has to name the forms that work, because the one thing a person knows at that moment is
    /// that what they typed did not.
    #[test]
    fn something_that_is_not_a_window_says_what_one_looks_like() {
        let err = parse_window("yesterday").unwrap_err().to_string();
        assert!(err.contains("30m"), "{err}");
        assert!(parse_window("").is_err());
        assert!(parse_window("h").is_err());
        assert!(parse_window("-1h").is_err());
        assert!(parse_window("1 h").is_err());
    }

    /// The line that matters most on this screen is the one naming a process nothing was read from, and it
    /// has to name it rather than summarise it away.
    #[test]
    fn an_unread_process_is_named_in_the_report() {
        let coverage = flowlight_store::Coverage {
            requests: 12,
            processes_read: 2,
            connections: 30,
            unread: vec![flowlight_store::Unread {
                process: "gh".to_owned(),
                connections: 18,
            }],
            ..flowlight_store::Coverage::default()
        };
        let report = coverage_report(&coverage, "24h");
        assert!(report.contains("gh"), "{report}");
        assert!(
            report.contains("18 connection(s), nothing read"),
            "{report}"
        );
        assert!(report.contains("Go links its own"), "{report}");
    }

    /// A line that disappears when it reads zero turns "nothing was dropped" into "nobody checked".
    #[test]
    fn a_clean_window_still_says_so_rather_than_saying_nothing() {
        let report = coverage_report(&flowlight_store::Coverage::default(), "24h");
        assert!(
            report.contains("every process that opened an HTTPS connection was read"),
            "{report}"
        );
        assert!(report.contains("0 record(s) were lost"), "{report}");
        assert!(report.contains("0 call(s) carried more than"), "{report}");
    }

    #[test]
    fn a_string_with_a_quote_in_it_survives_being_json() {
        assert_eq!(quote(r#"a"b"#), r#""a\"b""#);
        assert_eq!(quote("a\nb"), r#""a\nb""#);
        assert_eq!(quote("a\u{1}b"), r#""a\u0001b""#);
    }
}
