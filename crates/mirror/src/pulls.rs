//! What answers a pull: this node's own content on containerd, the relay on CRI-O (D66).

use std::future::Future;
use std::io;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::Response;
use speculaire_oci::reference::Digest;
use speculaire_oci::tagged::Tagged;
use speculaire_runtime::content::{Blob, Content, Error};

use crate::fetch::Fetcher;
use crate::metrics::Source;
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
}

impl<C: Content> Local<C> {
    /// Answers from `content`, and fetches a digest it lacks with `fetcher`.
    pub const fn new(content: C, fetcher: Fetcher) -> Self {
        Self { content, fetcher }
    }
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
