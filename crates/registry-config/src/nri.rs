//! NRI's request timeout, as containerd and CRI-O read it (D41, D64).

use std::fmt;
use std::time::Duration;

use serde::Deserialize;

use crate::go::parse_duration;

/// The timeout NRI applies when the runtime sets none (nri v0.12.3 `pkg/api/timeouts.go:27`, the same in the v0.11.0
/// CRI-O 1.35 vendors).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// How long the runtime waits for an NRI plugin to answer a request: containerd's `plugin_request_timeout`, CRI-O's
/// `nri_plugin_request_timeout`.
///
/// Both read a TOML string with Go's `time.ParseDuration` and an integer as nanoseconds, and refuse any other type
/// (go-toml v2.4.3 `unmarshaler.go:1722-1828`; BurntSushi/toml v1.6.0 `decode.go:477-495`). Both keep NRI's
/// default for zero (containerd v2.4.2 `internal/nri/config.go:100-106`, CRI-O v1.37.2
/// `internal/config/nri/nri.go:159-161`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RequestTimeout {
    /// Unset, or zero: [`DEFAULT_REQUEST_TIMEOUT`].
    #[default]
    Default,
    /// This long, more than zero.
    Set(Duration),
    /// Negative: every request expires at once (Go's `context.WithTimeout`).
    Expired,
}

impl RequestTimeout {
    /// How long a request may take.
    #[must_use]
    pub const fn get(self) -> Duration {
        match self {
            Self::Default => DEFAULT_REQUEST_TIMEOUT,
            Self::Set(timeout) => timeout,
            Self::Expired => Duration::ZERO,
        }
    }

    const fn of(nanos: Option<Duration>) -> Self {
        match nanos {
            None => Self::Expired,
            Some(Duration::ZERO) => Self::Default,
            Some(timeout) => Self::Set(timeout),
        }
    }
}

/// As Go prints a duration for the common values (`2s`, `500ms`).
impl fmt::Display for RequestTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => write!(f, "{DEFAULT_REQUEST_TIMEOUT:?}"),
            Self::Set(timeout) => write!(f, "{timeout:?}"),
            Self::Expired => f.write_str("a negative duration"),
        }
    }
}

impl<'de> Deserialize<'de> for RequestTimeout {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Visitor)
    }
}

struct Visitor;

impl serde::de::Visitor<'_> for Visitor {
    type Value = RequestTimeout;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a duration such as \"2s\", or an integer of nanoseconds")
    }

    fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<RequestTimeout, E> {
        parse_duration(text)
            .map(RequestTimeout::of)
            .map_err(E::custom)
    }

    fn visit_i64<E: serde::de::Error>(self, nanos: i64) -> Result<RequestTimeout, E> {
        Ok(RequestTimeout::of(
            u64::try_from(nanos).ok().map(Duration::from_nanos),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(value: &str) -> Result<RequestTimeout, toml::de::Error> {
        #[derive(Deserialize)]
        struct Key {
            timeout: RequestTimeout,
        }
        toml::from_str::<Key>(&format!("timeout = {value}")).map(|key| key.timeout)
    }

    #[test]
    fn a_string_is_a_go_duration_and_an_integer_nanoseconds() {
        for (value, want) in [
            ("\"2s\"", RequestTimeout::Set(Duration::from_secs(2))),
            ("\"500ms\"", RequestTimeout::Set(Duration::from_millis(500))),
            ("\"1m30s\"", RequestTimeout::Set(Duration::from_secs(90))),
            ("7", RequestTimeout::Set(Duration::from_nanos(7))),
            ("2_000_000_000", RequestTimeout::Set(Duration::from_secs(2))),
            // Zero keeps NRI's default; below zero, every request expires.
            ("\"0s\"", RequestTimeout::Default),
            ("\"0\"", RequestTimeout::Default),
            ("0", RequestTimeout::Default),
            ("\"-1s\"", RequestTimeout::Expired),
            ("-1", RequestTimeout::Expired),
        ] {
            assert_eq!(read(value).unwrap(), want, "{value}");
        }
    }

    #[test]
    fn what_go_cannot_parse_as_a_duration_is_refused() {
        // A float or a boolean reaches `time.ParseDuration` as its text, which has no unit.
        for value in ["\"2\"", "\"2x\"", "\"\"", "2.5", "true", "[1]", "{}"] {
            assert!(read(value).is_err(), "{value} is accepted");
        }
        assert!(
            read("\"2\"")
                .unwrap_err()
                .to_string()
                .contains("time: missing unit in duration \"2\"")
        );
        assert!(
            read("true").unwrap_err().to_string().contains(
                "invalid type: boolean `true`, expected a duration such as \"2s\", or an integer of nanoseconds"
            )
        );
    }

    #[test]
    fn the_timeout_prints_as_go_does() {
        assert_eq!(RequestTimeout::Default.get(), Duration::from_secs(2));
        assert_eq!(RequestTimeout::Expired.get(), Duration::ZERO);
        for (timeout, text) in [
            (RequestTimeout::Set(Duration::from_secs(2)), "2s"),
            (RequestTimeout::Set(Duration::from_millis(500)), "500ms"),
            (RequestTimeout::Default, "2s"),
            (RequestTimeout::Expired, "a negative duration"),
        ] {
            assert_eq!(timeout.to_string(), text);
        }
    }
}
