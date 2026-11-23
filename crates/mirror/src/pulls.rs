//! What answers a pull: this node's own content on containerd, the relay on CRI-O (D66).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Stream, StreamExt as _, TryStreamExt as _};
use http::header::RETRY_AFTER;
use http::{HeaderValue, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use hyper::Response;
use speculaire_oci::reference::Digest;
use speculaire_oci::tagged::Tagged;
use speculaire_runtime::content::{Blob, Content, Error};
use tokio::time::Instant;
use tracing::warn;

use crate::fetch::{Fetcher, Staging};
use crate::metrics::Source;
use crate::request::{Kind, Reference};
use crate::serve::status;

/// The body of an answer.
pub type Body = UnsyncBoxBody<Bytes, io::Error>;

/// A pull the runtime asks for.
#[derive(Clone, Debug)]
pub struct Pull<'a> {
    /// A manifest, a blob or referrers.
    pub kind: Kind,
    /// The repository name as the runtime wrote it, the registry first on CRI-O.
    pub name: &'a str,
    /// The registry of the name, which containerd sends apart (`ns`); `None` on CRI-O.
    pub namespace: Option<&'a str>,
    /// Its digest or tag; `None` when the text is neither.
    pub reference: Option<&'a Reference<'a>>,
    /// Only the head of the answer is wanted.
    pub head: bool,
    /// The `Range` header.
    pub range: Option<&'a str>,
    /// The `Accept` headers, joined.
    pub accept: Option<&'a str>,
}

impl Pull<'_> {
    /// The tag pulled, named in full: `None` for a digest, or a name that is no image reference.
    #[must_use]
    pub fn tagged(&self) -> Option<Tagged> {
        let Some(Reference::Tag(tag)) = self.reference else {
            return None;
        };
        Tagged::parse(&match self.namespace {
            Some(namespace) => format!("{namespace}/{}:{tag}", self.name),
            None => format!("{}:{tag}", self.name),
        })
    }
}

/// What became of a pull.
pub enum Answer {
    /// The response to send, and where its bytes come from.
    Served(Source, Response<Body>),
    /// This node does not have it and will not fetch it: the runtime goes on (a 404).
    Missing,
    /// Looking or fetching failed: a 404 too, and the error is logged and counted.
    Failed(Error),
    /// Upstream refused the relay, or failed it: the runtime gets the refusal rather than a 404 (D129).
    Refused(Refusal),
}

/// Upstream's refusal of a relayed pull, which the runtime gets (D129).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Upstream limits the node: a `429`, with upstream's `Retry-After` when it gave one.
    Limited(Option<HeaderValue>),
    /// Upstream failed, or answered a status that serves nothing and denies nothing: a `502`.
    Failed,
}

impl Refusal {
    /// The response the runtime gets.
    pub(crate) fn response(self) -> Response<Body> {
        match self {
            Self::Limited(retry_after) => {
                let mut response = status(StatusCode::TOO_MANY_REQUESTS);
                if let Some(retry_after) = retry_after {
                    response.headers_mut().insert(RETRY_AFTER, retry_after);
                }
                response
            }
            Self::Failed => status(StatusCode::BAD_GATEWAY),
        }
    }
}

/// Something that answers pulls.
pub trait Pulls: Send + Sync + 'static {
    /// The answer to `pull`.
    fn pull(&self, pull: Pull<'_>) -> impl Future<Output = Answer> + Send;
}

/// containerd: what the node holds, by digest, whatever the name, else what peers hold; a tag, what its holders
/// resolve it to (D123).
pub struct Local<C> {
    content: C,
    fetcher: Fetcher,
    broken: Broken,
}

impl<C: Content> Local<C> {
    /// Answers from `content`, and fetches a digest it lacks with `fetcher`.
    pub fn new(content: C, fetcher: Fetcher) -> Self {
        Self {
            content,
            fetcher,
            broken: Broken::default(),
        }
    }
}

/// How long a blob whose body failed falls through, so that containerd's next try of it goes upstream.
const BROKEN_FOR: Duration = Duration::from_secs(60);

/// The blobs whose body failed after their head went out, until when each falls through (D205).
#[derive(Clone, Default)]
struct Broken(Arc<Mutex<HashMap<Digest, Instant>>>);

impl Broken {
    fn holds(&self, digest: &Digest) -> bool {
        let now = Instant::now();
        let mut broken = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        broken.retain(|_, until| *until > now);
        broken.contains_key(digest)
    }

    fn mark(&self, digest: Digest) {
        let until = Instant::now() + BROKEN_FOR;
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(digest, until);
    }
}

/// A blob whose head is out and whose body is not: dropped so, it marks its digest broken.
struct Unsent {
    digest: Digest,
    broken: Broken,
    sent: bool,
}

impl Unsent {
    const fn sent(&mut self) {
        self.sent = true;
    }
}

impl Drop for Unsent {
    fn drop(&mut self) {
        if !self.sent {
            self.broken.mark(self.digest.clone());
        }
    }
}

/// The body of a blob from peers whose head said `size` bytes: nothing until it is whole and checked, then its bytes.
/// When no peer sends it right, or the blob is another size, the body fails before its first byte, so containerd keeps
/// none of it. That, or containerd giving up first, marks `digest` broken.
fn held(
    staging: Staging,
    digest: Digest,
    size: u64,
    broken: Broken,
) -> impl Stream<Item = io::Result<Bytes>> + Send {
    let mut unsent = Unsent {
        digest,
        broken,
        sent: false,
    };
    futures_util::stream::once(async move {
        let Some(staged) = staging.finish().await.filter(|staged| staged.blob.size() == size) else {
            warn!(digest = %unsent.digest, "no peer sent the blob right after its head was sent: the pull goes upstream");
            return Err(io::Error::other("no peer sent the blob right"));
        };
        unsent.sent();
        let chunks = staged.blob.stream(0, size).await.map_err(io::Error::other)?;
        let claim = staged.claim;
        // The staging file stays claimed of the space until its last byte is sent.
        Ok(chunks.map(move |chunk| {
            let _ = &claim;
            chunk.map_err(io::Error::other)
        }))
    })
    .try_flatten()
}

impl<C: Content> Pulls for Local<C> {
    async fn pull(&self, pull: Pull<'_>) -> Answer {
        let digest = match (pull.kind, pull.reference) {
            (Kind::Manifest | Kind::Blob, Some(Reference::Digest(digest))) => digest,
            (Kind::Manifest, Some(Reference::Tag(_))) => {
                let resolved = match pull.tagged() {
                    Some(tagged) => self.fetcher.tag(&tagged).await,
                    None => None,
                };
                return resolved.map_or(Answer::Missing, |resolved| {
                    Answer::Served(Source::Peer, resolved.response(pull.head))
                });
            }
            _ => return Answer::Missing,
        };
        let answer = from_content(&self.content, pull.kind, digest, pull.head, pull.range).await;
        // A peer's content is served once it is whole and checked, which a head or a range would not wait for: those
        // fall through (D102).
        if !matches!(answer, Answer::Missing) || pull.head || pull.range.is_some() {
            return answer;
        }
        // containerd waits 30 s for the head of an answer, and five minutes for the next byte of its body: a blob's
        // head goes out as soon as a peer answers, and its body once it is whole and checked (D205).
        if pull.kind == Kind::Blob {
            if self.broken.holds(digest) {
                return Answer::Missing;
            }
            let Some(staging) = self.fetcher.stage(pull.kind, digest, u64::MAX).await else {
                return Answer::Missing;
            };
            let size = staging.size();
            let body = held(staging, digest.clone(), size, self.broken.clone());
            return Answer::Served(
                Source::Peer,
                crate::serve::held_response(digest, size, body),
            );
        }
        match self.fetcher.whole(pull.kind, digest).await {
            Some(blob) => from_blob(blob, Source::Peer, pull.kind, digest, false, None).await,
            None => Answer::Missing,
        }
    }
}

/// The answer of a pull of `digest` from `content`, this node's own.
pub(crate) async fn from_content<C: Content>(
    content: &C,
    kind: Kind,
    digest: &Digest,
    head: bool,
    range: Option<&str>,
) -> Answer {
    match content.open(digest).await {
        Ok(Some(blob)) => from_blob(blob, Source::Local, kind, digest, head, range).await,
        Ok(None) => Answer::Missing,
        Err(err) => Answer::Failed(err),
    }
}

/// The answer of a pull of `digest`, whose content is `blob`, from `source`.
async fn from_blob(
    blob: Blob,
    source: Source,
    kind: Kind,
    digest: &Digest,
    head: bool,
    range: Option<&str>,
) -> Answer {
    let served = match kind {
        Kind::Manifest => crate::serve::manifest(blob, digest, head).await,
        _ => crate::serve::blob_response(blob, digest, head, range).await,
    };
    match served {
        Ok(response) => Answer::Served(source, response),
        Err(crate::serve::Miss::NotHeld) => Answer::Missing,
        Err(crate::serve::Miss::Failed(err)) => Answer::Failed(err),
    }
}

#[cfg(test)]
mod tests;
