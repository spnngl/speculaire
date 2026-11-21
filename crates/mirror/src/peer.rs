//! The peer API (D14, D24, D39): what this node holds, by digest, to the agents of other nodes, over mutual TLS with
//! node identities (D16).
//!
//! It shares the mirror's request parser and answers: `GET` and `HEAD` of a manifest or a blob by digest, from the
//! runtime's content then the artifact store, one `Range` at most; of a manifest by a tag the runtime lists (D123); and
//! `GET` of the referrers of a manifest the artifact store holds artifacts about, in any repository, and a 400 for
//! referrers of anything but a digest (D124). Anything else, and anything the node no longer holds, is a 404.

use std::future::Future;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Instant;

use bytes::Bytes;
use http_body_util::BodyExt as _;
use hyper::body::{Frame, Incoming};
use hyper::header::{HeaderValue, RANGE};
use hyper::{Request, Response, StatusCode};
use rustls::ServerConfig;
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::reference::Digest;
use speculaire_oci::tagged::Tagged;
use speculaire_runtime::content::Content;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::warn;

use crate::listed::Listed;
use crate::metrics::{Metered, PeerSeries, Uploaded};
use crate::pulls::{Answer, Body, from_content};
use crate::referrers::{self, Referrers};
use crate::request::{Kind, Reference, Route, artifact_type, route};
use crate::serve::{Api, MAX_MANIFEST, listen, manifest_response, media_type, status};

/// Serves the peer API on `listener`, from `content`, the tags `listed` and the `artifacts` the node holds, under
/// `uploads`, until `stop` completes.
///
/// `tls` is the node identity's server side (`speculaire_pki::node::Credentials::server`). Once `stop` completes, it
/// returns when every connection open then has closed: an idle one at once, one with a body in flight once it has sent
/// the body (D39, D103); until then a new connection is answered as `uploads` says, 503 once stopped (D177).
pub async fn serve<C: Content, A: Referrers>(
    listener: TcpListener,
    mut tls: ServerConfig,
    content: Arc<C>,
    listed: Listed,
    artifacts: Arc<A>,
    uploads: Arc<Uploads>,
    stop: impl Future<Output = ()>,
) {
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let peer = Arc::new(Peer {
        content,
        listed,
        artifacts,
        uploads,
    });
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
    series: PeerSeries,
}

impl Uploads {
    /// At most `limit` bodies at once.
    #[must_use]
    pub fn new(limit: NonZeroUsize) -> Self {
        Self {
            limit: AtomicUsize::new(limit.get()),
            active: watch::Sender::new(0),
            stopping: AtomicBool::new(false),
            series: PeerSeries::new(),
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
            self.series.in_flight(*active);
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
            self.0.series.in_flight(*active);
        });
    }
}

/// A body that holds its upload until hyper drops it: at its end, or when the connection goes.
struct Uploading {
    body: Metered<Body>,
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
struct Peer<C, A> {
    content: Arc<C>,
    listed: Listed,
    artifacts: Arc<A>,
    uploads: Arc<Uploads>,
}

impl<C: Content, A: Referrers> Api for Peer<C, A> {
    async fn answer(&self, request: &Request<Incoming>) -> Response<Body> {
        let started = Instant::now();
        if self.uploads.stopping.load(Ordering::Relaxed) {
            return self.busy();
        }
        let (kind, digest, head) = match route(request.method(), request.uri().path()) {
            Some(Route::Pull {
                kind: kind @ (Kind::Manifest | Kind::Blob),
                reference: Some(Reference::Digest(digest)),
                head,
                ..
            }) => (kind, digest, head),
            Some(Route::Pull {
                kind: Kind::Manifest,
                name,
                reference: Some(Reference::Tag(tag)),
                head,
            }) => return self.tag(name, tag, head).await,
            Some(Route::Pull {
                kind: Kind::Referrers,
                reference: Some(Reference::Digest(target)),
                head: false,
                ..
            }) => {
                self.uploads.series.upload(Uploaded::Served);
                let wanted = artifact_type(request.uri().query());
                return referrers::index(&*self.artifacts, &target, wanted.as_deref()).await;
            }
            // A referrers API never answers 404, and a `<digest>` of invalid syntax is a 400 (distribution-spec
            // v1.1.1-57-g9727462 `spec.md:626-627`).
            Some(Route::Pull {
                kind: Kind::Referrers,
                head: false,
                ..
            }) => return status(StatusCode::BAD_REQUEST),
            _ => return status(StatusCode::NOT_FOUND),
        };
        // Only a blob's body counts against the cap (D24): a manifest is at most 4 MiB, and a `HEAD` sends nothing.
        let upload = match (kind, head) {
            (Kind::Blob, false) => match self.uploads.start() {
                Some(upload) => Some(upload),
                None => return self.busy(),
            },
            _ => None,
        };
        let range = request
            .headers()
            .get(RANGE)
            .and_then(|value| value.to_str().ok());
        let mut answered = from_content(&*self.content, kind, &digest, head, range).await;
        if matches!(answered, Answer::Missing) {
            answered = from_content(&*self.artifacts, kind, &digest, head, range).await;
        }
        let series = &self.uploads.series;
        match answered {
            Answer::Served(_, response) => {
                series.upload(Uploaded::Served);
                match upload {
                    Some(upload) => series.measure(started, response, |body| {
                        Uploading {
                            body,
                            _upload: upload,
                        }
                        .boxed_unsync()
                    }),
                    None => response,
                }
            }
            // Announced, then deleted or collected without an event: the fetching agent goes to the next peer. The
            // node's own content refuses nothing: only the relay does.
            Answer::Missing | Answer::Refused(_) => status(StatusCode::NOT_FOUND),
            Answer::Failed(err) => {
                warn!(error = %err, kind = kind.label(), "the peer API could not read content the node may hold");
                status(StatusCode::NOT_FOUND)
            }
        }
    }
}

impl<C: Content, A> Peer<C, A> {
    /// The manifest the runtime pulled the tag `name:tag` by, an index before a platform's manifest: the asking node
    /// picks its own platform from an index.
    async fn tag(&self, name: &str, tag: &str, head: bool) -> Response<Body> {
        let Some(tagged) = Tagged::parse(&format!("{name}:{tag}")) else {
            return status(StatusCode::NOT_FOUND);
        };
        let mut found = None;
        for digest in self.listed.digests(&tagged) {
            let Some((bytes, media_type)) = self.manifest(&digest).await else {
                continue;
            };
            let index = matches!(manifest::children(&bytes), Ok(Children::Index { .. }));
            if index || found.is_none() {
                found = Some((digest, bytes, media_type));
            }
            if index {
                break;
            }
        }
        let Some((digest, bytes, media_type)) = found else {
            return status(StatusCode::NOT_FOUND);
        };
        self.uploads.series.upload(Uploaded::Served);
        manifest_response(&bytes, &digest, media_type, head)
    }

    /// The manifest `digest`, when the node holds it.
    async fn manifest(&self, digest: &Digest) -> Option<(Bytes, HeaderValue)> {
        let blob = match self.content.open(digest).await {
            Ok(blob) => blob?,
            Err(err) => {
                warn!(error = %err, "the peer API could not read a manifest the node may hold");
                return None;
            }
        };
        let bytes = blob.read_all(MAX_MANIFEST).await.ok()?;
        let media_type = media_type(&bytes)?;
        Some((bytes, media_type))
    }
}

impl<C, A> Peer<C, A> {
    fn busy(&self) -> Response<Body> {
        self.uploads.series.upload(Uploaded::Busy);
        status(StatusCode::SERVICE_UNAVAILABLE)
    }
}

#[cfg(test)]
mod tests;
