//! Reading a time window out of what a model wrote.
//!
//! Shorthand first — `30m`, `24h`, `7d`, `today`, `yesterday` — because a relative window is what a question
//! actually means and resolving it here beats a model doing date arithmetic. A date is accepted too, for the
//! questions that name one.
//!
//! Everything is UTC. Not because a local timezone would be wrong, but because it would be a second answer to
//! "what does today mean" that disagrees with the one the summary table already gives: its days are UTC days,
//! and two definitions of today in one tool is worse than one that is occasionally surprising.

/// A window, as two seconds since the epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Where it starts.
    pub from: i64,
    /// Where it ends.
    pub to: i64,
}

impl Window {
    /// How long it is, in seconds. Never less than one.
    pub fn length(self) -> i64 {
        (self.to - self.from).max(1)
    }

    /// How this reads in a result, so an answer can quote the window it was actually given.
    pub fn described(self) -> String {
        let seconds = self.length();
        if seconds < 3_600 {
            format!("{} minute(s)", seconds.div_euclid(60).max(1))
        } else if seconds < 86_400 {
            format!("{} hour(s)", seconds.div_euclid(3_600))
        } else {
            format!("{} day(s)", seconds.div_euclid(86_400))
        }
    }
}

/// Resolves what a model wrote into a window, or nothing when it is not readable.
///
/// `to` left out means now, which is the case almost every question is.
pub fn resolve(from: &str, to: Option<&str>, now: i64) -> Option<Window> {
    let end = match to {
        Some(text) => moment(text, now)?,
        None => now,
    };
    let start = match from.trim().to_lowercase().as_str() {
        "today" => start_of_day(now),
        "yesterday" => start_of_day(now) - 86_400,
        _ => match length(from) {
            // A length is counted back from the end of the window, not from now: "the six hours before
            // midnight" is a window somebody can ask for.
            Some(seconds) => end - seconds,
            None => moment(from, now)?,
        },
    };
    // Yesterday means yesterday, not yesterday until now.
    let end = if from.trim().eq_ignore_ascii_case("yesterday") && to.is_none() {
        start + 86_400
    } else {
        end
    };
    if end <= start {
        None
    } else {
        Some(Window {
            from: start,
            to: end,
        })
    }
}

/// Reads `30m`, `6h`, `2d`, `1w` or a bare number of seconds.
pub fn length(text: &str) -> Option<i64> {
    let text = text.trim();
    let (digits, multiplier) = match text.chars().last()? {
        's' => (&text[..text.len() - 1], 1),
        'm' => (&text[..text.len() - 1], 60),
        'h' => (&text[..text.len() - 1], 3_600),
        'd' => (&text[..text.len() - 1], 86_400),
        'w' => (&text[..text.len() - 1], 604_800),
        _ => (text, 1),
    };
    let number: i64 = digits.trim().parse().ok()?;
    if number <= 0 {
        return None;
    }
    number.checked_mul(multiplier)
}

/// Reads a moment: `now`, a length ago, or a date.
fn moment(text: &str, now: i64) -> Option<i64> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("now") {
        return Some(now);
    }
    if text.eq_ignore_ascii_case("today") {
        return Some(start_of_day(now));
    }
    if text.eq_ignore_ascii_case("yesterday") {
        return Some(start_of_day(now) - 86_400);
    }
    if let Some(date) = date(text) {
        return Some(date);
    }
    // A bare number large enough to be a timestamp is one. Smaller than that it is a length, and a length in
    // a `to` field means "that long ago", which is how a model writes "until an hour ago".
    let seconds = length(text)?;
    if seconds > 1_000_000_000 {
        Some(seconds)
    } else {
        Some(now - seconds)
    }
}

/// Reads `YYYY-MM-DD`, or the date part of an ISO-8601 timestamp, as midnight UTC.
///
/// The time part is deliberately ignored rather than parsed. A model that writes a timestamp is answering a
/// question about a day, and a half-implemented ISO parser that silently drops an offset would put the window
/// in the wrong place without saying so.
fn date(text: &str) -> Option<i64> {
    let day = text.split(['T', ' ']).next()?;
    let mut parts = day.split('-');
    let year: i64 = parts.next()?.parse().ok()?;
    let month: i64 = parts.next()?.parse().ok()?;
    let rest = parts.next()?;
    let day_of_month: i64 = rest.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day_of_month) {
        return None;
    }
    if !(1970..=9999).contains(&year) {
        return None;
    }
    Some(days_from_civil(year, month, day_of_month) * 86_400)
}

/// Days since 1970-01-01, by Howard Hinnant's algorithm.
///
/// Written out rather than pulled in, because the alternative is a date library for one function and the
/// algorithm is five lines that have not changed since 2013.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// A moment, as the sentence a model is told the time in.
///
/// Written out rather than pulled in for the same reason as the arithmetic below it: this is the only place in
/// the program that needs a formatted date, and a date library for one string is a dependency for one string.
pub fn clock(now: i64) -> String {
    let days = now.div_euclid(86_400);
    let seconds = now.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    // 1970-01-01 was a Thursday, which is index 4 of a week that starts on Sunday.
    let weekday = (days + 4).rem_euclid(7) as usize;
    let names = [
        "Sunday",
        "Monday",
        "Tuesday",
        "Wednesday",
        "Thursday",
        "Friday",
        "Saturday",
    ];
    let months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    format!(
        "{} {day} {} {year}, {:02}:{:02} UTC",
        names.get(weekday).copied().unwrap_or("Someday"),
        months
            .get((month - 1).clamp(0, 11) as usize)
            .copied()
            .unwrap_or("Somemonth"),
        seconds / 3_600,
        (seconds % 3_600) / 60
    )
}

/// The inverse of [`days_from_civil`], by the same algorithm.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Midnight UTC on the day a moment falls in.
fn start_of_day(now: i64) -> i64 {
    now.div_euclid(86_400) * 86_400
}

/// A bucket size that fits a window: about sixty buckets, rounded to something a person recognises.
pub fn bucket(window: Window, requested: Option<&str>) -> i64 {
    if let Some(named) = requested {
        match named.trim().to_lowercase().as_str() {
            "second" | "seconds" => return 1,
            "minute" | "minutes" => return 60,
            "hour" | "hours" => return 3_600,
            "day" | "days" => return 86_400,
            "week" | "weeks" => return 604_800,
            _ => {}
        }
    }
    let wanted = window.length() / 60;
    for candidate in [1, 60, 300, 900, 3_600, 21_600, 86_400, 604_800] {
        if wanted <= candidate {
            return candidate;
        }
    }
    604_800
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Midnight on Thursday 1 January 1970 plus a known number of days, checked against a date nobody has
    /// to take on trust: 2026-09-29 is 20725 days after the epoch.
    #[test]
    fn a_date_is_the_right_number_of_days_after_the_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 9, 29), 20_725);
        // A leap day, which is the case the algorithm exists for.
        assert_eq!(
            days_from_civil(2024, 2, 29) + 1,
            days_from_civil(2024, 3, 1)
        );
    }

    /// The two directions have to agree, or the time a model is told is not the time a window is about.
    #[test]
    fn a_date_and_its_inverse_agree() {
        for days in [0_i64, 1, 11_017, 20_725, 19_783, 30_000] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days, "{days}");
        }
    }

    /// 1970-01-01 was a Thursday, and 2026-09-29 is a Tuesday. Neither is something to take on trust.
    #[test]
    fn the_clock_says_the_right_day() {
        assert!(clock(0).starts_with("Thursday 1 January 1970, 00:00"));
        let noon = 20_725 * 86_400 + 12 * 3_600 + 34 * 60;
        assert_eq!(clock(noon), "Tuesday 29 September 2026, 12:34 UTC");
    }

    #[test]
    fn a_length_is_read_with_or_without_a_unit() {
        assert_eq!(length("30m"), Some(1_800));
        assert_eq!(length("6h"), Some(21_600));
        assert_eq!(length("2d"), Some(172_800));
        assert_eq!(length("1w"), Some(604_800));
        assert_eq!(length("900"), Some(900));
        assert_eq!(length("0h"), None);
        assert_eq!(length("-1h"), None);
        assert_eq!(length("soon"), None);
    }

    #[test]
    fn a_relative_window_ends_now_unless_told_otherwise() {
        let now = 1_000_000;
        let window = resolve("24h", None, now).unwrap();
        assert_eq!(window.to, now);
        assert_eq!(window.from, now - 86_400);
    }

    /// Yesterday is a day, not "since yesterday". A window that ran to now would answer a different
    /// question from the one asked.
    #[test]
    fn yesterday_is_one_whole_day() {
        // Midday on day 20725.
        let now = 20_725 * 86_400 + 43_200;
        let window = resolve("yesterday", None, now).unwrap();
        assert_eq!(window.from, 20_724 * 86_400);
        assert_eq!(window.to, 20_725 * 86_400);
        assert_eq!(window.length(), 86_400);

        let today = resolve("today", None, now).unwrap();
        assert_eq!(today.from, 20_725 * 86_400);
        assert_eq!(today.to, now);
    }

    #[test]
    fn a_date_is_a_window_from_midnight() {
        let now = 20_725 * 86_400;
        let window = resolve("2026-09-01", Some("2026-09-02"), now).unwrap();
        assert_eq!(window.length(), 86_400);
        assert_eq!(window.from, days_from_civil(2026, 9, 1) * 86_400);
        // The time part of a timestamp is ignored rather than half-parsed.
        assert_eq!(
            resolve("2026-09-01T13:45:00Z", Some("2026-09-02"), now)
                .unwrap()
                .from,
            window.from
        );
    }

    /// A window that ends before it starts is not a window, and a model that wrote one should be told so
    /// rather than handed an empty result it will read as "nothing happened".
    #[test]
    fn a_backwards_window_is_refused() {
        let now = 20_725 * 86_400;
        assert_eq!(resolve("2026-09-02", Some("2026-09-01"), now), None);
        assert_eq!(resolve("nonsense", None, now), None);
    }

    #[test]
    fn a_bucket_fits_the_window_unless_one_is_named() {
        let hour = Window { from: 0, to: 3_600 };
        assert_eq!(bucket(hour, None), 60);
        let week = Window {
            from: 0,
            to: 604_800,
        };
        assert_eq!(bucket(week, None), 21_600);
        assert_eq!(bucket(week, Some("hour")), 3_600);
        assert_eq!(bucket(week, Some("whatever")), 21_600);
    }
}
