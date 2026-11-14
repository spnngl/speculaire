//! What answers a pull: this node's own content on containerd, the relay on CRI-O (D66).

use std::future::Future;
use std::io;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::Response;
use speculaire_oci::reference::Digest;
use speculaire_runtime::content::{Blob, Content, Error};

use crate::fetch::Fetcher;
use crate::metrics;
use crate::request::{Kind, Reference};

/// The body of an answer.
pub type Body = UnsyncBoxBody<Bytes, io::Error>;

/// A pull the runtime asks for.
#[derive(Clone, Debug)]
pub struct Pull<'a> {
    /// A manifest, a blob or referrers.
    pub kind: Kind,
    /// The repository name as the runtime wrote it, the registry first on CRI-O.
    pub name: &'a str,
    /// Its digest or tag; `None` when the text is neither.
    pub reference: Option<&'a Reference>,
    /// Only the head of the answer is wanted.
    pub head: bool,
    /// The `Range` header.
    pub range: Option<&'a str>,
    /// The `Accept` headers, joined.
    pub accept: Option<&'a str>,
}

/// What became of a pull.
pub enum Answer {
    /// The response to send.
    Served(Response<Body>),
    /// This node does not have it and will not fetch it: the runtime goes on (a 404).
    Missing,
    /// Looking or fetching failed: a 404 too, and the error is logged and counted.
    Failed(Error),
}

/// Something that answers pulls.
pub trait Pulls: Send + Sync + 'static {
    /// The answer to `pull`.
    fn pull(&self, pull: Pull<'_>) -> impl Future<Output = Answer> + Send;
}

/// containerd: what the node holds, by digest, whatever the name, else what peers hold. A tag is a miss (D6).
pub struct Local<C> {
    content: C,
    fetcher: Fetcher,
}

impl<C: Content> Local<C> {
    /// Answers from `content`, and fetches a digest it lacks with `fetcher`.
    pub const fn new(content: C, fetcher: Fetcher) -> Self {
        Self { content, fetcher }
    }
}

impl<C: Content> Pulls for Local<C> {
    async fn pull(&self, pull: Pull<'_>) -> Answer {
        let (Kind::Manifest | Kind::Blob, Some(Reference::Digest(digest))) =
            (pull.kind, pull.reference)
        else {
            return Answer::Missing;
        };
        let answer = from_content(
            &self.content,
            pull.kind,
            digest,
            pull.head,
            pull.range,
            metrics::local_bytes,
        )
        .await;
        // A peer's content is served once it is whole and checked, which a head or a range would not wait for: those
        // fall through (D102).
        if !matches!(answer, Answer::Missing) || pull.head || pull.range.is_some() {
            return answer;
        }
        match self.fetcher.whole(pull.kind, digest).await {
            Some(blob) => {
                from_blob(blob, pull.kind, digest, false, None, metrics::peer_bytes).await
            }
            None => Answer::Missing,
        }
    }
}

/// The answer of a pull of `digest` from `content`; `sent` counts the bytes of a blob's body as they go.
pub(crate) async fn from_content<C: Content>(
    content: &C,
    kind: Kind,
    digest: &Digest,
    head: bool,
    range: Option<&str>,
    sent: fn(usize),
) -> Answer {
    match content.open(digest).await {
        Ok(Some(blob)) => from_blob(blob, kind, digest, head, range, sent).await,
        Ok(None) => Answer::Missing,
        Err(err) => Answer::Failed(err),
    }
}

/// The answer of a pull of `digest`, whose content is `blob`.
async fn from_blob(
    blob: Blob,
    kind: Kind,
    digest: &Digest,
    head: bool,
    range: Option<&str>,
    sent: fn(usize),
) -> Answer {
    let served = match kind {
        Kind::Manifest => crate::serve::manifest(blob, digest, head).await,
        _ => crate::serve::blob_response(blob, digest, head, range, sent).await,
    };
    match served {
        Ok(response) => Answer::Served(response),
        Err(crate::serve::Miss::NotHeld) => Answer::Missing,
        Err(crate::serve::Miss::Failed(err)) => Answer::Failed(err),
    }
}
