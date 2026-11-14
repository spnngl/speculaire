//! The listener and the answers.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::TryStreamExt as _;
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{
    ACCEPT, ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, HeaderValue, RANGE,
};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use rustls::ServerConfig;
use serde::Deserialize;
use serde::de::IgnoredAny;
use speculaire_oci::reference::Digest;
use speculaire_runtime::content::{Blob, Error};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, warn};

use crate::metrics::{self, Outcome};
use crate::pulls::{Answer, Body, Pull, Pulls};
use crate::request::{Ranged, Route, Span, range, route};
use crate::tls::Tls;

/// The largest manifest the mirror reads, as containerd limits one (`core/remotes/docker/resolver.go`).
const MAX_MANIFEST: u64 = 4 * 1024 * 1024;

/// How long a client may take to finish the TLS handshake, and to send a request's headers.
const CLIENT_TIME: Duration = Duration::from_secs(10);

/// Serves the pull API on `listener` until `stop` completes, then until every connection has closed: an idle one at
/// once, a busy one once it has sent its response (D39, D103).
pub async fn serve<P: Pulls>(
    listener: TcpListener,
    tls: Arc<Tls>,
    pulls: Arc<P>,
    stop: impl Future<Output = ()>,
) {
    listen(listener, move || tls.config(), pulls, stop).await;
}

/// What answers the requests of a listener: the pull API, or the peer API.
pub(crate) trait Api: Send + Sync + 'static {
    /// The response to `request`.
    fn answer(&self, request: &Request<Incoming>) -> impl Future<Output = Response<Body>> + Send;
}

impl<P: Pulls> Api for P {
    fn answer(&self, request: &Request<Incoming>) -> impl Future<Output = Response<Body>> + Send {
        handle(self, request)
    }
}

/// Serves `api` over HTTP/1.1 on `listener`, each connection with the TLS config `tls` gives then, until `stop`
/// completes; then closes `listener`, and returns once every connection has closed.
///
/// Waiting for the connections, not only for their bodies, is what lets a body's last bytes leave: hyper drops a body
/// once it has buffered its end, and the process may exit before hyper sends it.
pub(crate) async fn listen<A: Api>(
    listener: TcpListener,
    tls: impl Fn() -> Arc<ServerConfig>,
    api: Arc<A>,
    stop: impl Future<Output = ()>,
) {
    // Each connection holds a receiver: a send tells them all to close, and `closed` waits until they have.
    let (closing, _) = watch::channel(());
    tokio::pin!(stop);
    loop {
        tokio::select! {
            () = &mut stop => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let acceptor = TlsAcceptor::from(tls());
                    let api = Arc::clone(&api);
                    let closing = closing.subscribe();
                    tokio::spawn(connection(stream, acceptor, api, closing));
                }
                // A connection that was reset before it was accepted, or no file descriptor left: log and go on.
                Err(err) => {
                    warn!(
                        address = ?listener.local_addr().ok(),
                        error = %err,
                        "could not accept a connection"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            },
        }
    }
    drop(listener);
    closing.send_replace(());
    closing.closed().await;
}

/// Serves one connection until it ends, or until `closing` changes or goes: then a request in flight is answered,
/// and the connection closes.
async fn connection<A: Api>(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    api: Arc<A>,
    mut closing: watch::Receiver<()>,
) {
    // A response's head is small: Nagle's algorithm would hold it for the client's delayed ACK.
    if let Err(err) = stream.set_nodelay(true) {
        debug!(error = %err, "a client's connection is gone");
        return;
    }
    let handshake = tokio::time::timeout(CLIENT_TIME, acceptor.accept(stream));
    let accepted = tokio::select! {
        accepted = handshake => accepted,
        // A client that has sent no request yet loses nothing.
        _ = closing.changed() => return,
    };
    let Ok(accepted) = accepted else {
        debug!("a client did not finish the TLS handshake in time");
        return;
    };
    let tls = match accepted {
        Ok(tls) => tls,
        // Most often a client without the expected certificate: the handshake fails, which is the point.
        Err(err) => {
            debug!(error = %err, "a client was refused");
            return;
        }
    };
    let service = service_fn(move |request: Request<Incoming>| {
        let api = Arc::clone(&api);
        async move { Ok::<_, Infallible>(api.answer(&request).await) }
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(CLIENT_TIME)
        .serve_connection(TokioIo::new(tls), service);
    tokio::pin!(connection);
    let served = tokio::select! {
        served = connection.as_mut() => served,
        _ = closing.changed() => {
            // hyper ends the response in flight, flushes it, and closes TLS and the socket's sending side.
            connection.as_mut().graceful_shutdown();
            connection.await
        }
    };
    if let Err(err) = served {
        debug!(error = %err, "a connection ended with an error");
    }
}

/// Why a pull is answered with a 404.
pub(crate) enum Miss {
    /// This node does not hold it, or the request names no digest.
    NotHeld,
    /// Looking failed.
    Failed(Error),
}

async fn handle<P: Pulls>(pulls: &P, request: &Request<Incoming>) -> Response<Body> {
    let started = Instant::now();
    let Some(route) = route(request.method(), request.uri().path()) else {
        return status(StatusCode::NOT_FOUND);
    };
    let (kind, name, reference, head) = match route {
        Route::Ping => return ping(),
        Route::Pull {
            kind,
            name,
            reference,
            head,
        } => (kind, name, reference, head),
    };
    let header = |name| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
    };
    // Go clients, CRI-O's among them, send one `Accept` header per media type.
    let accept = request
        .headers()
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    let answered = pulls
        .pull(Pull {
            kind,
            name,
            reference: reference.as_ref(),
            head,
            range: header(RANGE),
            accept: (!accept.is_empty()).then_some(accept.as_str()),
        })
        .await;
    let (response, outcome) = match answered {
        Answer::Served(response) => (response, Outcome::Served),
        Answer::Missing => (status(StatusCode::NOT_FOUND), Outcome::FallThrough),
        Answer::Failed(err) => {
            warn!(error = %err, kind = kind.label(), "the mirror could not read content it may hold");
            (status(StatusCode::NOT_FOUND), Outcome::Error)
        }
    };
    metrics::request(kind, outcome);
    metrics::first_byte(kind, started.elapsed().as_secs_f64());
    response
}

/// The manifest as it is, with the content type it names.
pub(crate) async fn manifest(
    blob: Blob,
    digest: &Digest,
    head: bool,
) -> Result<Response<Body>, Miss> {
    let bytes = blob.read_all(MAX_MANIFEST).await.map_err(Miss::Failed)?;
    let media_type = media_type(&bytes).ok_or(Miss::NotHeld)?;
    Ok(manifest_response(&bytes, digest, media_type, head))
}

/// The response that serves manifest `bytes` of `digest`.
pub(crate) fn manifest_response(
    bytes: &Bytes,
    digest: &Digest,
    media_type: HeaderValue,
    head: bool,
) -> Response<Body> {
    let mut response = Response::new(if head {
        empty()
    } else {
        Full::new(bytes.clone()).map_err(never).boxed_unsync()
    });
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, media_type);
    headers.insert(CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    insert_digest(headers, digest);
    response
}

/// The response that serves `blob`, or the span of it `range_header` asks for; `sent` counts the body's bytes.
pub(crate) async fn blob_response(
    blob: Blob,
    digest: &Digest,
    head: bool,
    range_header: Option<&str>,
    sent: fn(usize),
) -> Result<Response<Body>, Miss> {
    let size = blob.size();
    let ranged = if head {
        Ranged::Whole
    } else {
        range(range_header, size)
    };
    let mut response = Response::new(empty());
    let headers = response.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    insert_digest(headers, digest);
    let span = match ranged {
        Ranged::Whole => Span::whole(size),
        Ranged::Part(span) => {
            *response.status_mut() = StatusCode::PARTIAL_CONTENT;
            response.headers_mut().insert(
                CONTENT_RANGE,
                header(&format!("bytes {}-{}/{size}", span.first, span.last)),
            );
            Some(span)
        }
        Ranged::Unsatisfiable => {
            *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
            let headers = response.headers_mut();
            headers.insert(CONTENT_RANGE, header(&format!("bytes */{size}")));
            headers.insert(CONTENT_LENGTH, HeaderValue::from(0));
            return Ok(response);
        }
    };
    let length = span.map_or(0, Span::bytes);
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(length));
    if head {
        return Ok(response);
    }
    if let Some(span) = span {
        let chunks = blob
            .stream(span.first, span.bytes())
            .await
            .map_err(Miss::Failed)?;
        let frames = chunks
            .inspect_ok(move |chunk| sent(chunk.len()))
            .map_ok(Frame::data)
            .map_err(io::Error::other);
        *response.body_mut() = StreamBody::new(frames).boxed_unsync();
    }
    Ok(response)
}

pub(crate) fn insert_digest(headers: &mut hyper::HeaderMap, digest: &Digest) {
    headers.insert("Docker-Content-Digest", header(&digest.to_string()));
}

/// A header value from text that is known to be one: digests, numbers, media types the mirror checked.
pub(crate) fn header(text: &str) -> HeaderValue {
    HeaderValue::from_str(text).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn ping() -> Response<Body> {
    let mut response = Response::new(
        Full::new(Bytes::from_static(b"{}"))
            .map_err(never)
            .boxed_unsync(),
    );
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        "Docker-Distribution-Api-Version",
        HeaderValue::from_static("registry/2.0"),
    );
    response
}

pub(crate) fn status(code: StatusCode) -> Response<Body> {
    let mut response = Response::new(empty());
    *response.status_mut() = code;
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(0));
    response
}

pub(crate) fn empty() -> Body {
    http_body_util::Empty::new().map_err(never).boxed_unsync()
}

pub(crate) fn never(never: Infallible) -> io::Error {
    match never {}
}

/// The media type a manifest names, or the one its shape implies; `None` when the bytes are no manifest at all.
pub(crate) fn media_type(bytes: &[u8]) -> Option<HeaderValue> {
    #[derive(Deserialize)]
    struct Document {
        #[serde(rename = "mediaType")]
        media_type: Option<String>,
        manifests: Option<IgnoredAny>,
        layers: Option<IgnoredAny>,
        config: Option<IgnoredAny>,
    }
    let document: Document = serde_json::from_slice(bytes).ok()?;
    if let Some(media_type) = document.media_type.filter(|m| !m.is_empty()) {
        return HeaderValue::from_str(&media_type).ok();
    }
    let inferred = if document.manifests.is_some() {
        "application/vnd.oci.image.index.v1+json"
    } else if document.layers.is_some() || document.config.is_some() {
        "application/vnd.oci.image.manifest.v1+json"
    } else {
        return None;
    };
    Some(HeaderValue::from_static(inferred))
}

#[cfg(test)]
mod tests;
