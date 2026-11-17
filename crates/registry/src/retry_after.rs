//! A registry's refusal to serve more for now, and the `Retry-After` it gives (D38, RFC 9110 § 10.2.3).

use std::time::{Duration, SystemTime};

use http::header::RETRY_AFTER;
use http::{HeaderMap, StatusCode};

/// A registry's refusal to serve more for now (D38): a `429`, or a `503` with `Retry-After`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Refusal {
    /// How long the registry asks to wait; `None` when a `429` does not say.
    pub retry_after: Option<Duration>,
}

impl Refusal {
    /// The refusal an answer of `status` with `headers` makes, read at `now`; `None` for any other answer.
    ///
    /// A `503` limits only with a `Retry-After` that parses: without one it is an outage, not a limit.
    #[must_use]
    pub fn of(status: StatusCode, headers: &HeaderMap, now: SystemTime) -> Option<Self> {
        let retry_after = headers
            .get(RETRY_AFTER)
            .and_then(|value| parse(value.as_bytes(), now));
        match status {
            StatusCode::TOO_MANY_REQUESTS => Some(Self { retry_after }),
            StatusCode::SERVICE_UNAVAILABLE => retry_after.map(|retry_after| Self {
                retry_after: Some(retry_after),
            }),
            _ => None,
        }
    }
}

/// The delay a `Retry-After` value asks for, read at `now`: whole seconds, or an HTTP date, zero once it is past.
///
/// Seconds beyond `u64` saturate. `None` when the value is neither.
#[must_use]
pub fn parse(value: &[u8], now: SystemTime) -> Option<Duration> {
    let text = std::str::from_utf8(value).ok()?.trim();
    // `u64::from_str` takes a leading `+`, which delay-seconds (`1*DIGIT`) does not.
    if !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(Duration::from_secs(text.parse().unwrap_or(u64::MAX)));
    }
    let date = httpdate::parse_http_date(text).ok()?;
    Some(date.duration_since(now).unwrap_or(Duration::ZERO))
}

#[cfg(test)]
mod tests;
