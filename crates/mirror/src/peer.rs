//! The peer API (D14, D24, D39): what this node holds, by digest, to the agents of other nodes, over mutual TLS with
//! node identities (D16).
//!
//! It shares the mirror's request parser and answers: `GET` and `HEAD` of a manifest or a blob by digest, one `Range`
//! at most. Anything else, and anything the node no longer holds, is a 404.

use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::body::{Frame, Incoming};
use hyper::header::RANGE;
use hyper::{Request, Response, StatusCode};
use rustls::ServerConfig;
use speculaire_runtime::content::Content;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::warn;

use crate::metrics::{self, Uploaded};
use crate::pulls::{Answer, Body, from_content};
use crate::request::{Kind, Reference, Route, route};
use crate::serve::{Api, listen, status};

/// Serves the peer API on `listener`, from `content`, under `uploads`, until `stop` completes.
///
/// `tls` is the node identity's server side (`speculaire_pki::node::Credentials::server`). Once `stop` completes, it
/// returns when every connection has closed: an idle one at once, one with a body in flight once it has sent the body
/// (D39, D103).
pub async fn serve<C: Content>(
    listener: TcpListener,
    mut tls: ServerConfig,
    content: Arc<C>,
    uploads: Arc<Uploads>,
    stop: impl Future<Output = ()>,
) {
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let peer = Arc::new(Peer { content, uploads });
    listen(listener, move || Arc::clone(&tls), peer, stop).await;
}

/// The blob bodies the peer API sends at once, at most `peer.max_uploads` (D24), and whether it still takes requests
/// (D39).
#[derive(Debug)]
pub struct Uploads {
    limit: AtomicUsize,
    /// The bodies in flight.
    active: watch::Sender<usize>,
    stopping: AtomicBool,
}

impl Uploads {
    /// At most `limit` bodies at once.
    #[must_use]
    pub fn new(limit: NonZeroUsize) -> Self {
        Self {
            limit: AtomicUsize::new(limit.get()),
            active: watch::Sender::new(0),
            stopping: AtomicBool::new(false),
        }
    }

    /// The cap.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Relaxed)
    }

    /// Moves the cap to `limit`; the bodies in flight above it finish.
    pub fn set_limit(&self, limit: NonZeroUsize) {
        self.limit.store(limit.get(), Ordering::Relaxed);
    }

    /// Answers every new request with 503 from now on, while the bodies in flight go on (D39, step 2).
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Relaxed);
    }

    /// One more body, unless the cap is reached.
    fn start(self: &Arc<Self>) -> Option<Upload> {
        let limit = self.limit.load(Ordering::Relaxed);
        let started = self.active.send_if_modified(|active| {
            if *active >= limit {
                return false;
            }
            *active += 1;
            metrics::uploads_in_flight(*active);
            true
        });
        started.then(|| Upload(Arc::clone(self)))
    }
}

/// A body in flight, counted until it drops.
struct Upload(Arc<Uploads>);

impl Drop for Upload {
    fn drop(&mut self) {
        self.0.active.send_modify(|active| {
            *active -= 1;
            metrics::uploads_in_flight(*active);
        });
    }
}

/// A body that holds its upload until hyper drops it: at its end, or when the connection goes.
struct Uploading {
    body: Body,
    _upload: Upload,
}

impl hyper::body::Body for Uploading {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }
}

/// The peer API's answers.
struct Peer<C> {
    content: Arc<C>,
    uploads: Arc<Uploads>,
}

impl<C: Content> Api for Peer<C> {
    async fn answer(&self, request: &Request<Incoming>) -> Response<Body> {
        if self.uploads.stopping.load(Ordering::Relaxed) {
            return busy();
        }
        let Some(Route::Pull {
            kind: kind @ (Kind::Manifest | Kind::Blob),
            reference: Some(Reference::Digest(digest)),
            head,
            ..
        }) = route(request.method(), request.uri().path())
        else {
            return status(StatusCode::NOT_FOUND);
        };
        // Only a blob's body counts against the cap (D24): a manifest is at most 4 MiB, and a `HEAD` sends nothing.
        let upload = match (kind, head) {
            (Kind::Blob, false) => match self.uploads.start() {
                Some(upload) => Some(upload),
                None => return busy(),
            },
            _ => None,
        };
        let range = request
            .headers()
            .get(RANGE)
            .and_then(|value| value.to_str().ok());
        let answered = from_content(
            &*self.content,
            kind,
            &digest,
            head,
            range,
            metrics::upload_bytes,
        )
        .await;
        match answered {
            Answer::Served(response) => {
                metrics::upload(Uploaded::Served);
                match upload {
                    Some(upload) => response.map(|body| {
                        Uploading {
                            body,
                            _upload: upload,
                        }
                        .boxed_unsync()
                    }),
                    None => response,
                }
            }
            // Announced, then deleted or collected without an event: the fetching agent goes to the next peer.
            Answer::Missing => status(StatusCode::NOT_FOUND),
            Answer::Failed(err) => {
                warn!(error = %err, kind = kind.label(), "the peer API could not read content the node may hold");
                status(StatusCode::NOT_FOUND)
            }
        }
    }
}

fn busy() -> Response<Body> {
    metrics::upload(Uploaded::Busy);
    status(StatusCode::SERVICE_UNAVAILABLE)
}

#[cfg(test)]
mod tests;
