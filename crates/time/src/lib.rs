//! Durations and instants as text: the config's durations (D135) and the logs' timestamps (D52).

pub mod duration;

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

/// The last second RFC 3339's four-digit year can name: 9999-12-31T23:59:59Z.
const LAST: u64 = 253_402_300_799;

/// Prints `time` in UTC to the second, as RFC 3339 writes it: `2024-02-29T12:00:00Z`.
///
/// A time before 1970 prints as the epoch, one after year 9999 as its last second.
#[must_use]
pub fn rfc3339(time: SystemTime) -> impl fmt::Display {
    Rfc3339(
        time.duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs().min(LAST)),
    )
}

/// Seconds since the epoch, at most [`LAST`].
struct Rfc3339(u64);

impl fmt::Display for Rfc3339 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (days, second) = (self.0 / 86_400, self.0 % 86_400);
        let (year, month, day) = civil(days);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
            second / 3600,
            second / 60 % 60,
            second % 60
        )
    }
}

/// The year, month and day `days` after 1970-01-01, by Howard Hinnant's `civil_from_days`
/// (<https://howardhinnant.github.io/date_algorithms.html#civil_from_days>), unsigned since `days` is never negative.
const fn civil(days: u64) -> (u64, u64, u64) {
    // Days since 0000-03-01, so that a leap day ends its year; an era is 400 years of 146 097 days.
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let of_era = shifted % 146_097;
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // Months from March, of 31, 30, 31, 30, 31 days and again: 153 days each five.
    let march_month = (5 * of_year + 2) / 153;
    let day = of_year - (153 * march_month + 2) / 5 + 1;
    let (month, year_after) = if march_month < 10 {
        (march_month + 3, 0)
    } else {
        (march_month - 9, 1)
    };
    (era * 400 + year_of_era + year_after, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn at(secs: u64) -> String {
        rfc3339(UNIX_EPOCH + Duration::from_secs(secs)).to_string()
    }

    #[test]
    fn times_print_as_rfc_3339_in_utc() {
        for (secs, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (86_399, "1970-01-01T23:59:59Z"),
            (951_782_400, "2000-02-29T00:00:00Z"),
            (951_868_800, "2000-03-01T00:00:00Z"),
            (1_709_164_800, "2024-02-29T00:00:00Z"),
            (1_709_251_199, "2024-02-29T23:59:59Z"),
            (1_735_689_599, "2024-12-31T23:59:59Z"),
            (4_107_542_400, "2100-03-01T00:00:00Z"),
            (LAST, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(at(secs), text);
        }
    }

    #[test]
    fn times_print_whole_seconds() {
        let time = UNIX_EPOCH + Duration::from_millis(1_709_164_800_999);
        assert_eq!(rfc3339(time).to_string(), "2024-02-29T00:00:00Z");
    }

    #[test]
    fn times_past_rfc_3339_print_its_ends() {
        assert_eq!(at(LAST + 1), "9999-12-31T23:59:59Z");
        assert_eq!(at(u64::MAX / 2), "9999-12-31T23:59:59Z");
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(rfc3339(before).to_string(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn every_day_follows_the_one_before_in_the_gregorian_calendar() {
        let last_day = |year: u64, month| match month {
            2 if year.is_multiple_of(4)
                && (!year.is_multiple_of(100) || year.is_multiple_of(400)) =>
            {
                29
            }
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        let mut previous = civil(0);
        assert_eq!(previous, (1970, 1, 1));
        for days in 1..=LAST / 86_400 {
            let (year, month, day) = previous;
            let next = if day < last_day(year, month) {
                (year, month, day + 1)
            } else if month < 12 {
                (year, month + 1, 1)
            } else {
                (year + 1, 1, 1)
            };
            previous = civil(days);
            assert_eq!(previous, next, "{days} days");
        }
        assert_eq!(previous, (9999, 12, 31));
    }
}
