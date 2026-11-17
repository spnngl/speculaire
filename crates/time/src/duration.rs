//! Durations as the config and `speculaire-loadgen` write them: `300ms`, `10m`, `1h30m` (D135).

use std::fmt;
use std::time::Duration;

/// The units, largest first, with their length in nanoseconds.
const UNITS: [(&str, u128); 7] = [
    ("d", 86_400_000_000_000),
    ("h", 3_600_000_000_000),
    ("m", 60_000_000_000),
    ("s", 1_000_000_000),
    ("ms", 1_000_000),
    ("us", 1_000),
    ("ns", 1),
];

/// Why a text is not a duration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    /// A group does not start with a digit, or the text is empty.
    #[error("expected a whole number")]
    Number,
    /// A number is followed by no unit, or one not listed.
    #[error("expected a unit: d, h, m, s, ms, us or ns")]
    Unit,
    /// A unit is no smaller than the one before it.
    #[error("expected units from largest to smallest, each once")]
    Order,
    /// The total is longer than [`Duration::MAX`].
    #[error("longer than {} s", u64::MAX)]
    Overflow,
}

/// Reads `text` as one or more groups of a whole number and a unit, units decreasing, without spaces: `1h30m`.
///
/// # Errors
///
/// When `text` is not that, or its total overflows [`Duration`].
pub fn parse(text: &str) -> Result<Duration, Invalid> {
    let mut rest = text;
    let mut total: u128 = 0;
    // The units still allowed are `UNITS[smallest..]`.
    let mut smallest = 0;
    loop {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (number, after) = rest.split_at(digits);
        let units = after
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(after.len());
        let (unit, next) = after.split_at(units);
        if number.is_empty() {
            return Err(Invalid::Number);
        }
        let (at, (_, scale)) = UNITS
            .iter()
            .enumerate()
            .find(|(_, (name, _))| *name == unit)
            .ok_or(Invalid::Unit)?;
        if at < smallest {
            return Err(Invalid::Order);
        }
        smallest = at + 1;
        let group = number
            .bytes()
            .try_fold(0_u128, |n, digit| {
                n.checked_mul(10)?.checked_add(u128::from(digit - b'0'))
            })
            .and_then(|n| n.checked_mul(*scale))
            .ok_or(Invalid::Overflow)?;
        total = total.checked_add(group).ok_or(Invalid::Overflow)?;
        rest = next;
        if total > Duration::MAX.as_nanos() {
            return Err(Invalid::Overflow);
        }
        if rest.is_empty() {
            return Ok(Duration::from_nanos_u128(total));
        }
    }
}

/// Prints `duration` as [`parse`] reads it: a group per unit that is not zero, largest first, each below the next
/// unit (`90s` prints `1m30s`), or `0s`.
#[must_use]
pub fn display(duration: Duration) -> impl fmt::Display {
    Text(duration)
}

struct Text(Duration);

impl fmt::Display for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut left = self.0.as_nanos();
        if left == 0 {
            return f.write_str("0s");
        }
        for (unit, scale) in UNITS {
            let count = left / scale;
            if count > 0 {
                write!(f, "{count}{unit}")?;
                left %= scale;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_unit_reads_its_length() {
        for (text, duration) in [
            ("2d", Duration::from_hours(48)),
            ("2h", Duration::from_hours(2)),
            ("2m", Duration::from_mins(2)),
            ("2s", Duration::from_secs(2)),
            ("2ms", Duration::from_millis(2)),
            ("2us", Duration::from_micros(2)),
            ("2ns", Duration::from_nanos(2)),
        ] {
            assert_eq!(parse(text), Ok(duration), "{text}");
            assert_eq!(display(duration).to_string(), text);
        }
    }

    #[test]
    fn groups_add_up() {
        assert_eq!(parse("1h30m"), Ok(Duration::from_mins(90)));
        assert_eq!(
            parse("1d2h3m4s5ms6us7ns"),
            Ok(Duration::new(93_784, 5_006_007))
        );
        assert_eq!(parse("0s"), Ok(Duration::ZERO));
        assert_eq!(parse("007s"), Ok(Duration::from_secs(7)));
    }

    #[test]
    fn durations_print_in_their_largest_units() {
        for (text, printed) in [
            ("0s", "0s"),
            ("0ms", "0s"),
            ("1d2h3m4s5ms6us7ns", "1d2h3m4s5ms6us7ns"),
            ("90s", "1m30s"),
            ("24h", "1d"),
            ("1500ms", "1s500ms"),
            ("1h0m1s", "1h1s"),
            ("18446744073709551615s", "213503982334601d7h15s"),
        ] {
            let duration = parse(text).unwrap();
            assert_eq!(display(duration).to_string(), printed, "{text}");
            assert_eq!(parse(printed), Ok(duration), "{printed}");
        }
    }

    #[test]
    fn the_longest_duration_reads_and_prints() {
        let text = display(Duration::MAX).to_string();
        assert_eq!(text, "213503982334601d7h15s999ms999us999ns");
        assert_eq!(parse(&text), Ok(Duration::MAX));
    }

    #[test]
    fn other_texts_are_refused() {
        for (text, invalid) in [
            ("", Invalid::Number),
            ("s", Invalid::Number),
            ("1h m", Invalid::Unit),
            ("-1s", Invalid::Number),
            ("+1s", Invalid::Number),
            ("1.5s", Invalid::Unit),
            ("10", Invalid::Unit),
            ("1h30", Invalid::Unit),
            ("1 h", Invalid::Unit),
            ("1h 30m", Invalid::Unit),
            (" 1h", Invalid::Number),
            ("1h ", Invalid::Unit),
            ("1x", Invalid::Unit),
            ("1min", Invalid::Unit),
            ("1H", Invalid::Unit),
            ("1µs", Invalid::Unit),
            ("1y", Invalid::Unit),
            ("1m1h", Invalid::Order),
            ("1s1s", Invalid::Order),
            ("1ms1s", Invalid::Order),
            ("213503982334601d7h15s999ms999us1000ns", Invalid::Overflow),
            ("18446744073709551616s", Invalid::Overflow),
            ("213503982334602d", Invalid::Overflow),
            (
                "99999999999999999999999999999999999999999ns",
                Invalid::Overflow,
            ),
        ] {
            assert_eq!(parse(text), Err(invalid), "{text:?}");
        }
    }
}
