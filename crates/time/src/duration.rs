//! Durations as the config and `speculaire-loadgen` write them: a number of seconds to the millisecond, `10` or
//! `0.3` (D138).

use std::fmt;
use std::time::Duration;

/// Why a text is not a number of seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Invalid {
    /// Not ASCII digits with an optional `.` and more digits: empty, signed, an exponent, `NaN` or `inf`.
    #[error("expected a number of seconds, such as 10 or 0.3")]
    Number,
    /// More than three decimals.
    #[error("expected a number of seconds to the millisecond, at most 3 decimals")]
    Finer,
    /// More whole seconds than [`i64::MAX`], TOML's largest integer.
    #[error("expected a number of seconds up to {}", i64::MAX)]
    Overflow,
}

/// Reads `text` as whole seconds and up to three decimals: `10`, `0.3`, `1.25`.
///
/// # Errors
///
/// When `text` is not that, or its whole seconds exceed [`i64::MAX`].
pub fn parse(text: &str) -> Result<Duration, Invalid> {
    let (whole, decimals) = text.split_once('.').unwrap_or((text, "0"));
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !digits(whole) || !digits(decimals) {
        return Err(Invalid::Number);
    }
    if decimals.len() > 3 {
        return Err(Invalid::Finer);
    }
    // Digits only, so the one failure is overflow, and the number is not negative.
    let secs = whole.parse::<i64>().map_err(|_| Invalid::Overflow)?;
    let millis = decimals
        .bytes()
        .chain(std::iter::repeat(b'0'))
        .take(3)
        .fold(0, |n, digit| n * 10 + u32::from(digit - b'0'));
    Ok(Duration::new(secs.unsigned_abs(), millis * 1_000_000))
}

/// Prints `duration` as [`parse`] reads it, to the millisecond, with no trailing zero: `10`, `0.3`, `1.25`.
#[must_use]
pub fn display(duration: Duration) -> impl fmt::Display {
    Seconds(duration)
}

struct Seconds(Duration);

impl fmt::Display for Seconds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.as_secs())?;
        let (mut millis, mut width) = (self.0.subsec_millis(), 3);
        if millis == 0 {
            return Ok(());
        }
        while millis % 10 == 0 {
            millis /= 10;
            width -= 1;
        }
        write!(f, ".{millis:0width$}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_read_to_the_millisecond_and_print_as_written() {
        for (text, duration) in [
            ("0", Duration::ZERO),
            ("10", Duration::from_secs(10)),
            ("0.3", Duration::from_millis(300)),
            ("0.001", Duration::from_millis(1)),
            ("1.25", Duration::from_millis(1250)),
            ("3600", Duration::from_hours(1)),
            (
                "9223372036854775807.999",
                Duration::new(i64::MAX.unsigned_abs(), 999_000_000),
            ),
        ] {
            assert_eq!(parse(text), Ok(duration), "{text}");
            assert_eq!(display(duration).to_string(), text);
        }
    }

    #[test]
    fn other_spellings_print_in_the_shortest_form() {
        for (text, printed) in [
            ("007", "7"),
            ("0.300", "0.3"),
            ("1.0", "1"),
            ("2.050", "2.05"),
        ] {
            assert_eq!(display(parse(text).unwrap()).to_string(), printed, "{text}");
        }
    }

    #[test]
    fn printing_cuts_below_the_millisecond() {
        assert_eq!(display(Duration::from_micros(1_999)).to_string(), "0.001");
    }

    #[test]
    fn other_texts_are_refused() {
        for (text, invalid) in [
            ("", Invalid::Number),
            (".5", Invalid::Number),
            ("1.", Invalid::Number),
            ("-1", Invalid::Number),
            ("+1", Invalid::Number),
            ("1e3", Invalid::Number),
            ("NaN", Invalid::Number),
            ("inf", Invalid::Number),
            (" 1", Invalid::Number),
            ("1.2.3", Invalid::Number),
            ("10s", Invalid::Number),
            ("1_000", Invalid::Number),
            ("0.0001", Invalid::Finer),
            ("0.0015", Invalid::Finer),
            ("0.3000", Invalid::Finer),
            ("9223372036854775808", Invalid::Overflow),
            ("99999999999999999999999", Invalid::Overflow),
        ] {
            assert_eq!(parse(text), Err(invalid), "{text:?}");
        }
    }
}
