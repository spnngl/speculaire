//! The version a runtime reports about itself.

use std::fmt;

/// A runtime's `major.minor.patch`, from the text it reports: `v2.4.2`, `2.3.0-rc.1`, `1.37.2+build`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Release {
    /// The major version.
    pub major: u64,
    /// The minor version.
    pub minor: u64,
    /// The patch version.
    pub patch: u64,
}

impl Release {
    /// A release.
    #[must_use]
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// The release a version text names: an optional `v`, three numbers, and anything after them as a pre-release or
    /// build suffix, which starts with `-` or `+`.
    ///
    /// Returns `None` for any other text, such as `Unknown` or `1.37`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.strip_prefix('v').unwrap_or(text);
        let numbers = text.split(['-', '+']).next()?;
        let mut parts = numbers.split('.');
        let mut number = || {
            let part = parts.next()?;
            // `u64::from_str` accepts a leading `+`, which no version has.
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            part.parse::<u64>().ok()
        };
        let release = Self::new(number()?, number()?, number()?);
        parts.next().is_none().then_some(release)
    }
}

impl fmt::Display for Release {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::Release;

    #[test]
    fn the_releases_runtimes_report_parse() {
        for (text, want) in [
            ("v2.4.2", Release::new(2, 4, 2)),
            ("2.3.0", Release::new(2, 3, 0)),
            ("1.37.2", Release::new(1, 37, 2)),
            ("v2.3.0-rc.1", Release::new(2, 3, 0)),
            ("v2.4.2-3-gabcdef+dirty", Release::new(2, 4, 2)),
            ("1.35.10+build.5", Release::new(1, 35, 10)),
            ("v0.0.0", Release::new(0, 0, 0)),
        ] {
            assert_eq!(Release::parse(text), Some(want), "{text}");
        }
    }

    #[test]
    fn text_that_is_no_release_does_not() {
        for text in [
            "",
            "Unknown",
            "v",
            "1",
            "1.37",
            "1.2.x",
            "1.2.3.4",
            "1..3",
            "1.+2.3",
            "1.2.+3",
            "+1.2.3",
            "-1.2.3",
            "v v1.2.3",
            "1.2.3 ",
            "1. 2.3",
            "99999999999999999999.0.0",
            "١.٢.٣",
        ] {
            assert_eq!(Release::parse(text), None, "{text:?}");
        }
    }

    #[test]
    fn releases_order_by_major_then_minor_then_patch() {
        assert!(Release::new(2, 3, 0) > Release::new(2, 2, 99));
        assert!(Release::new(2, 4, 0) > Release::new(2, 3, 9));
        assert!(Release::new(3, 0, 0) > Release::new(2, 99, 99));
        assert!(Release::new(1, 35, 10) > Release::new(1, 35, 9));
        assert_eq!(Release::new(1, 2, 3).to_string(), "1.2.3");
    }
}
