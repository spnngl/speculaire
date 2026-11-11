//! The plain-HTTP listener on `metrics.address`: `/livez`, `/readyz` and `/metrics` (D42, D45).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use metrics_exporter_prometheus::PrometheusHandle;

/// The content type of the protobuf exposition, as the exporter's own listener sends it
/// (`metrics-exporter-prometheus` 0.18.3 `src/protobuf.rs:18-19`).
const PROTOBUF: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

/// What the listener reports.
pub struct Status {
    stopping: AtomicBool,
    metrics: PrometheusHandle,
}

impl Status {
    /// A status that is ready: the agent opens the listener once its config is loaded (D45).
    #[must_use]
    pub fn new(metrics: PrometheusHandle) -> Self {
        Self {
            stopping: AtomicBool::new(false),
            metrics,
        }
    }

    /// Makes `/readyz` answer 503 from now on (D39).
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Relaxed);
    }
}

/// The routes, served by `axum::serve`.
pub fn router(status: Arc<Status>) -> Router {
    Router::new()
        .route("/livez", get(|| async { StatusCode::OK }))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .with_state(status)
}

async fn readyz(State(status): State<Arc<Status>>) -> StatusCode {
    if status.stopping.load(Ordering::Relaxed) {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    }
}

/// Protobuf when `Accept` names it, text otherwise; native histograms exist only in protobuf (D34).
async fn metrics(State(status): State<Arc<Status>>, headers: HeaderMap) -> Response {
    let handle = status.metrics.clone();
    let rendered = if wants_protobuf(&headers) {
        tokio::task::spawn_blocking(move || (PROTOBUF, handle.render_protobuf())).await
    } else {
        tokio::task::spawn_blocking(move || ("text/plain", handle.render().into_bytes())).await
    };
    match rendered {
        Ok((content_type, body)) => ([(header::CONTENT_TYPE, content_type)], body).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// The exporter's negotiation (`metrics-exporter-prometheus` 0.18.3 `src/exporter/http_listener.rs:167-188`).
fn wants_protobuf(headers: &HeaderMap) -> bool {
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    mime::MimeIter::new(accept).flatten().any(|m| {
        m.type_() == "application"
            && (m.subtype() == "vnd.google.protobuf" || m.subtype() == "x-protobuf")
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tower::ServiceExt as _;

    use super::{Status, router, wants_protobuf};

    async fn get(status: &Arc<Status>, path: &str) -> StatusCode {
        let request = Request::get(path).body(Body::empty()).unwrap();
        router(Arc::clone(status))
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    #[test]
    fn only_an_accept_naming_protobuf_wants_protobuf() {
        let accepting = |accept: &'static str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::ACCEPT, HeaderValue::from_static(accept));
            wants_protobuf(&headers)
        };
        assert!(accepting("application/vnd.google.protobuf"));
        assert!(accepting("application/x-protobuf"));
        assert!(accepting("text/plain, application/x-protobuf;q=0.5"));
        assert!(!accepting("application/json"));
        assert!(!accepting("text/x-protobuf"));
        assert!(!accepting("text/plain"));
        assert!(!wants_protobuf(&HeaderMap::new()));
    }

    #[tokio::test]
    async fn readyz_turns_503_on_stop_while_livez_stays_200() {
        let status = Arc::new(Status::new(
            PrometheusBuilder::new().build_recorder().handle(),
        ));
        assert_eq!(get(&status, "/readyz").await, StatusCode::OK);
        status.stop();
        assert_eq!(
            get(&status, "/readyz").await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(get(&status, "/livez").await, StatusCode::OK);
    }
}
