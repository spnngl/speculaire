use std::time::{Duration, SystemTime};

use http::header::RETRY_AFTER;
use http::{HeaderMap, HeaderValue, StatusCode};

use super::{Refusal, parse};

/// Sun, 06 Nov 1994 08:49:37 GMT, the example of RFC 9110 § 5.6.7.
fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(784_111_777)
}

fn headers(retry_after: Option<&'static str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    if let Some(value) = retry_after {
        headers.insert(RETRY_AFTER, HeaderValue::from_static(value));
    }
    headers
}

#[test]
fn whole_seconds_are_the_delay() {
    assert_eq!(parse(b"120", now()), Some(Duration::from_secs(120)));
    assert_eq!(parse(b" 0 ", now()), Some(Duration::ZERO));
    assert_eq!(
        parse(b"99999999999999999999999", now()),
        Some(Duration::from_secs(u64::MAX))
    );
}

#[test]
fn an_http_date_is_the_time_until_it_in_each_of_its_three_formats() {
    let two_minutes = Some(Duration::from_secs(120));
    assert_eq!(parse(b"Sun, 06 Nov 1994 08:51:37 GMT", now()), two_minutes);
    assert_eq!(parse(b"Sunday, 06-Nov-94 08:51:37 GMT", now()), two_minutes);
    assert_eq!(parse(b"Sun Nov  6 08:51:37 1994", now()), two_minutes);
}

#[test]
fn a_past_date_asks_for_no_delay() {
    assert_eq!(
        parse(b"Sun, 06 Nov 1994 08:00:00 GMT", now()),
        Some(Duration::ZERO)
    );
}

#[test]
fn anything_else_is_no_delay_at_all() {
    for value in [&b""[..], b"+5", b"-5", b"1.5", b"5s", b"tomorrow", b"\xff"] {
        assert_eq!(parse(value, now()), None, "{value:?}");
    }
}

#[test]
fn a_429_refuses_with_or_without_retry_after() {
    assert_eq!(
        Refusal::of(StatusCode::TOO_MANY_REQUESTS, &headers(Some("7")), now()),
        Some(Refusal {
            retry_after: Some(Duration::from_secs(7))
        })
    );
    let none = Some(Refusal { retry_after: None });
    assert_eq!(
        Refusal::of(StatusCode::TOO_MANY_REQUESTS, &headers(None), now()),
        none
    );
    assert_eq!(
        Refusal::of(StatusCode::TOO_MANY_REQUESTS, &headers(Some("soon")), now()),
        none
    );
}

#[test]
fn a_503_refuses_only_with_a_retry_after_that_parses() {
    assert_eq!(
        Refusal::of(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers(Some("Sun, 06 Nov 1994 08:51:37 GMT")),
            now()
        ),
        Some(Refusal {
            retry_after: Some(Duration::from_secs(120))
        })
    );
    assert_eq!(
        Refusal::of(StatusCode::SERVICE_UNAVAILABLE, &headers(None), now()),
        None
    );
    assert_eq!(
        Refusal::of(
            StatusCode::SERVICE_UNAVAILABLE,
            &headers(Some("soon")),
            now()
        ),
        None
    );
}

#[test]
fn other_statuses_never_refuse() {
    for status in [
        StatusCode::OK,
        StatusCode::NOT_FOUND,
        StatusCode::BAD_GATEWAY,
    ] {
        assert_eq!(Refusal::of(status, &headers(Some("7")), now()), None);
    }
}
