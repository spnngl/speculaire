//! The metered body, alone.

use http_body_util::{BodyExt as _, Full};
use hyper::body::Body as _;

use super::*;

#[tokio::test]
async fn a_metered_body_tells_its_size_and_its_end_as_the_body_it_wraps() {
    let response = Response::new(
        Full::new(Bytes::from_static(b"abc")).map_err(|never| -> io::Error { match never {} }),
    );
    let mut body = Metered::wrap(
        response,
        Counter::noop(),
        Histogram::noop(),
        Instant::now(),
        |metered| metered,
    )
    .into_body();
    assert_eq!(body.size_hint().exact(), Some(3));
    assert!(!body.is_end_stream());
    body.frame().await.unwrap().unwrap();
    assert!(body.is_end_stream());
}
