//! On CRI-O the mirror sits in every pull's path and relays it (D66, D67, D88).
//!
//! A manifest by tag is resolved at upstream, never from a peer (D6); a manifest by digest and the blobs below a
//! manifest the relay served come from the *blob cache* or, once, from upstream, streamed to CRI-O and to a temporary
//! file while they are hashed, with the last chunk held back until the digest matches (D7, D67).

use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};

use aws_lc_rs::digest::{self, Context as Hasher};
use bytes::Bytes;
use futures_util::TryStreamExt as _;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, RANGE};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt as _, Limited, StreamBody};
use hyper::Response;
use hyper::body::{Frame, Incoming};
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::reference::Digest;
use speculaire_registry::{Client, Request, Response as Upstreamed};
use speculaire_runtime::registries::{self, Registries, Source};
use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::cache::{Cache, Writer};
use crate::content::{Content as _, Error};
use crate::metrics;
use crate::pulls::{Answer, Body, Pull, Pulls, from_content};
use crate::request::{Kind, Reference};
use crate::serve::{insert_digest, manifest_response, media_type};

/// The largest manifest the relay reads.
const MAX_MANIFEST: usize = 4 * 1024 * 1024;

/// What a manifest request carries when CRI-O sent no `Accept`.
const DEFAULT_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

/// How many digests the relay remembers having served below a manifest.
const KNOWN_LIMIT: usize = 200_000;

/// The images the runtime lists, whose blobs the cache evicts last (D67).
pub trait Images: Send + Sync + 'static {
    /// The digests of the listed images: their IDs and the digests of their names.
    fn listed(&self) -> impl std::future::Future<Output = Vec<Digest>> + Send;
}

/// No listed image: nothing is protected.
pub struct NoImages;

impl Images for NoImages {
    fn listed(&self) -> impl std::future::Future<Output = Vec<Digest>> + Send {
        std::future::ready(Vec::new())
    }
}

/// The image list of CRI-O (D65, D67).
pub struct CrioImages {
    socket: std::path::PathBuf,
}

impl CrioImages {
    /// The list `ListImages` gives on `socket`.
    #[must_use]
    pub fn new(socket: impl Into<std::path::PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }
}

impl Images for CrioImages {
    async fn listed(&self) -> Vec<Digest> {
        let images = match speculaire_runtime::cri::list_images(&self.socket).await {
            Ok(images) => images,
            Err(err) => {
                warn!(error = %err, "the image list of CRI-O cannot be read: the blob cache evicts without it");
                return Vec::new();
            }
        };
        let mut digests = Vec::new();
        for image in images {
            // CRI-O's image ID is the hex of the image's config digest.
            digests.extend(Digest::parse(&format!("sha256:{}", image.id)).ok());
            digests.extend(
                image
                    .repo_digests
                    .iter()
                    .filter_map(|name| Digest::parse(name.rsplit_once('@')?.1).ok()),
            );
        }
        digests
    }
}

/// The names under which each digest was served: a blob or a manifest is served only for a name that a manifest
/// served earlier pointed it out for (D66).
#[derive(Default)]
struct Known {
    names: Mutex<HashMap<Digest, HashSet<String>>>,
}

impl Known {
    fn insert(&self, digest: &Digest, name: &str) {
        let mut names = self
            .names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if names.len() >= KNOWN_LIMIT && !names.contains_key(digest) {
            // Pulls in flight fail and are retried, which re-teaches the names: bounded memory over exactness.
            names.clear();
        }
        names
            .entry(digest.clone())
            .or_default()
            .insert(name.to_owned());
    }

    fn has(&self, digest: &Digest, name: &str) -> bool {
        self.names
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(digest)
            .is_some_and(|names| names.contains(name))
    }
}

/// The relay.
pub struct Relay<I> {
    cache: Arc<Cache>,
    client: Client,
    registries: Arc<dyn Registries>,
    known: Known,
    images: I,
    over: Arc<Notify>,
}

impl<I: Images> Relay<I> {
    /// A relay that keeps what it serves in `cache`, and fetches where `registries` say.
    #[must_use]
    pub fn new(cache: Cache, registries: Arc<dyn Registries>, images: I) -> Self {
        Self {
            cache: Arc::new(cache),
            client: Client::new(),
            registries,
            known: Known::default(),
            images,
            over: Arc::new(Notify::new()),
        }
    }

    /// The blob cache.
    #[must_use]
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// Evicts what is over the cache's bound now, protecting the images the runtime lists.
    pub async fn evict(&self) {
        if !self.cache.over() {
            return;
        }
        let protected = self.protected().await;
        self.cache.evict(&protected);
    }

    /// Evicts whenever a blob kept makes the cache exceed its bound; never returns.
    pub async fn evict_when_over(&self) {
        loop {
            self.over.notified().await;
            self.evict().await;
        }
    }

    /// The digests of the listed images and of everything below them, as far as the cache holds the manifests.
    async fn protected(&self) -> HashSet<Digest> {
        let mut protected = HashSet::new();
        let mut pending = self.images.listed().await;
        while let Some(digest) = pending.pop() {
            if !protected.insert(digest.clone()) {
                continue;
            }
            let Ok(Some(blob)) = self.cache.open(&digest).await else {
                continue;
            };
            // A blob that is no manifest, or too large to be one, has nothing below it.
            let Ok(bytes) = blob.read_all(MAX_MANIFEST as u64).await else {
                continue;
            };
            if let Ok(children) = manifest::children(&bytes) {
                pending.extend(children.digests().into_iter().cloned());
            }
        }
        protected
    }

    async fn manifest(&self, pull: &Pull<'_>, reference: &Reference) -> Answer {
        let text = match reference {
            Reference::Digest(digest) => digest.to_string(),
            Reference::Tag(tag) => tag.clone(),
        };
        let asked = match reference {
            Reference::Digest(_) => registries::Reference::Digest(&text),
            Reference::Tag(_) => registries::Reference::Tag(&text),
        };
        let sources = match self.registries.sources(pull.name, asked) {
            Ok(sources) => sources,
            Err(err) => return Answer::Failed(Error::Relay(err.to_string())),
        };
        // A manifest by digest that this relay served for this name is its own to serve again.
        if let Reference::Digest(digest) = reference
            && self.known.has(digest, pull.name)
            && self.cache.contains(digest)
        {
            return from_content(&*self.cache, Kind::Manifest, digest, pull.head, None).await;
        }
        for source in &sources {
            if let Some(answer) = self.relay_manifest(source, pull, reference).await {
                return answer;
            }
        }
        Answer::Missing
    }

    /// The manifest from one source, or `None` when it does not give one: the next source is tried.
    async fn relay_manifest(
        &self,
        source: &Source,
        pull: &Pull<'_>,
        reference: &Reference,
    ) -> Option<Answer> {
        let text = match reference {
            Reference::Digest(digest) => digest.to_string(),
            Reference::Tag(tag) => tag.clone(),
        };
        // The head of a tag is asked as a head: it costs no pull, and the body is not read.
        let head = pull.head && matches!(reference, Reference::Tag(_));
        let request = Request {
            method: if head { Method::HEAD } else { Method::GET },
            path: format!("/{}/manifests/{text}", source.repository),
            repository: source.repository.clone(),
            headers: vec![(ACCEPT, header_value(pull.accept.unwrap_or(DEFAULT_ACCEPT))?)],
        };
        let response = self.send(source, &request).await?;
        if response.status != StatusCode::OK {
            debug!(status = %response.status, name = pull.name, "upstream has no such manifest for the relay");
            return None;
        }
        if head {
            return Some(Answer::Served(head_response(&response)?));
        }
        let content_type = response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = Limited::new(response.body, MAX_MANIFEST)
            .collect()
            .await
            .map_err(|err| debug!(error = %err, "reading a manifest from upstream failed"))
            .ok()?
            .to_bytes();
        let digest = match reference {
            Reference::Digest(digest) => digest.clone(),
            Reference::Tag(_) => hash_of("sha256", &bytes)?,
        };
        if hash_of(digest.algorithm(), &bytes).as_ref() != Some(&digest) {
            warn!(name = pull.name, digest = %digest, "upstream sent a manifest that is not the digest asked for");
            return None;
        }
        let children = manifest::children(&bytes)
            .map_err(|err| debug!(error = %err, name = pull.name, "the manifest is of a kind the relay does not read"))
            .ok()?;
        let media_type = content_type
            .as_deref()
            .and_then(|text| text.split(';').next())
            .map(str::trim)
            .and_then(header_value)
            .or_else(|| media_type(&bytes))?;
        self.learn(pull.name, &digest, &children);
        match self.keep(&digest, &bytes).await {
            Ok(()) => {}
            Err(err) => {
                warn!(error = %err, digest = %digest, "the blob cache could not keep a manifest");
            }
        }
        metrics::upstream_bytes(bytes.len());
        Some(Answer::Served(manifest_response(
            &bytes, &digest, media_type, false,
        )))
    }

    /// Remembers that `digest` and what is below it may be served for `name`.
    fn learn(&self, name: &str, digest: &Digest, children: &Children) {
        self.known.insert(digest, name);
        for child in children.digests() {
            self.known.insert(child, name);
        }
    }

    async fn keep(&self, digest: &Digest, bytes: &[u8]) -> io::Result<()> {
        let mut writer = self.cache.writer().await?;
        writer.write(bytes).await?;
        writer.commit(&self.cache, digest).await?;
        if self.cache.over() {
            self.over.notify_one();
        }
        Ok(())
    }

    async fn blob(&self, pull: &Pull<'_>, digest: &Digest) -> Answer {
        if !self.known.has(digest, pull.name) {
            return Answer::Missing;
        }
        if self.cache.contains(digest) {
            return from_content(&*self.cache, Kind::Blob, digest, pull.head, pull.range).await;
        }
        let digest_text = digest.to_string();
        let sources = match self
            .registries
            .sources(pull.name, registries::Reference::Digest(&digest_text))
        {
            Ok(sources) => sources,
            Err(err) => return Answer::Failed(Error::Relay(err.to_string())),
        };
        for source in &sources {
            let mut headers = Vec::new();
            if let Some(range) = pull.range.and_then(header_value) {
                headers.push((RANGE, range));
            }
            let request = Request {
                method: if pull.head { Method::HEAD } else { Method::GET },
                path: format!("/{}/blobs/{digest}", source.repository),
                repository: source.repository.clone(),
                headers,
            };
            let Some(response) = self.send(source, &request).await else {
                continue;
            };
            let answer = match (response.status, pull.head, pull.range) {
                (StatusCode::OK, true, _) => head_response(&response).map(Answer::Served),
                (StatusCode::OK, false, None) => {
                    Some(self.relay_blob(response, digest, pull.name).await)
                }
                // A range, answered as upstream answers it: unhashed, not kept (D7's limit).
                (
                    StatusCode::OK
                    | StatusCode::PARTIAL_CONTENT
                    | StatusCode::RANGE_NOT_SATISFIABLE,
                    false,
                    Some(_),
                ) => Some(Answer::Served(passthrough(response, digest))),
                (status, ..) => {
                    debug!(%status, name = pull.name, "upstream has no such blob for the relay");
                    None
                }
            };
            if let Some(answer) = answer {
                return answer;
            }
        }
        Answer::Missing
    }

    /// A blob whole: hashed as it streams, kept when the digest matches, and never sent to its end when it does not.
    async fn relay_blob(&self, response: Upstreamed, digest: &Digest, name: &str) -> Answer {
        let Some(algorithm) = algorithm(digest.algorithm()) else {
            return Answer::Failed(Error::Relay(format!(
                "{digest}: the relay hashes only sha256, sha384 and sha512"
            )));
        };
        let length = response.headers.get(CONTENT_LENGTH).cloned();
        let writer = self
            .cache
            .writer()
            .await
            .map_err(|err| warn!(error = %err, "the blob cache cannot write: this blob is relayed without being kept"))
            .ok();
        let relaying = Relaying {
            body: response.body,
            hasher: Hasher::new(algorithm),
            expected: digest.clone(),
            writer,
            cache: Arc::clone(&self.cache),
            over: Arc::clone(&self.over),
            held: None,
            done: false,
            name: name.to_owned(),
        };
        let mut out = Response::new(
            StreamBody::new(relaying.into_stream().map_ok(Frame::data)).boxed_unsync(),
        );
        let headers = out.headers_mut();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
        insert_digest(headers, digest);
        if let Some(length) = length {
            headers.insert(CONTENT_LENGTH, length);
        }
        Answer::Served(out)
    }

    /// Sends to the first candidate of `source` that answers.
    async fn send(&self, source: &Source, request: &Request) -> Option<Upstreamed> {
        let mut last = None;
        for endpoint in &source.candidates {
            match self
                .client
                .send(endpoint, &source.credentials, request)
                .await
            {
                Ok(response) => return Some(response),
                Err(err) => last = Some(err),
            }
        }
        if let Some(err) = last {
            warn!(error = %err, "a registry does not answer the relay");
        }
        None
    }
}

impl<I: Images> Pulls for Relay<I> {
    async fn pull(&self, pull: Pull<'_>) -> Answer {
        let Some(reference) = pull.reference else {
            return Answer::Missing;
        };
        match (pull.kind, reference) {
            (Kind::Manifest, _) => self.manifest(&pull, reference).await,
            (Kind::Blob, Reference::Digest(digest)) => self.blob(&pull, digest).await,
            _ => Answer::Missing,
        }
    }
}

fn header_value(text: &str) -> Option<HeaderValue> {
    HeaderValue::from_str(text).ok()
}

fn algorithm(name: &str) -> Option<&'static digest::Algorithm> {
    match name {
        "sha256" => Some(&digest::SHA256),
        "sha384" => Some(&digest::SHA384),
        "sha512" => Some(&digest::SHA512),
        _ => None,
    }
}

/// The digest of `bytes` under `algorithm`.
fn hash_of(algorithm_name: &str, bytes: &[u8]) -> Option<Digest> {
    let algorithm = algorithm(algorithm_name)?;
    let mut hasher = Hasher::new(algorithm);
    hasher.update(bytes);
    to_digest(algorithm_name, &hasher.finish())
}

fn to_digest(algorithm_name: &str, hashed: &digest::Digest) -> Option<Digest> {
    use std::fmt::Write as _;
    let hex = hashed.as_ref().iter().fold(String::new(), |mut out, byte| {
        // Writing to a string cannot fail.
        let _ = write!(out, "{byte:02x}");
        out
    });
    Digest::parse(&format!("{algorithm_name}:{hex}")).ok()
}

/// A response with the headers of upstream's answer to a HEAD, and no body.
fn head_response(response: &Upstreamed) -> Option<Response<Body>> {
    let mut out = Response::new(crate::serve::empty());
    for name in [
        CONTENT_TYPE,
        CONTENT_LENGTH,
        HeaderName::from_static("docker-content-digest"),
        HeaderName::from_static("accept-ranges"),
    ] {
        if let Some(value) = response.headers.get(&name) {
            out.headers_mut().insert(name, value.clone());
        }
    }
    // A head without a length is no use to the runtime: the mirror does not guess.
    out.headers().contains_key(CONTENT_LENGTH).then_some(out)
}

/// A range answer as upstream gave it: status, `Content-Range`, `Content-Length`, and the body unhashed.
fn passthrough(response: Upstreamed, digest: &Digest) -> Response<Body> {
    let mut out = Response::new(
        response
            .body
            .map_frame(|frame| {
                if let Some(data) = frame.data_ref() {
                    metrics::upstream_bytes(data.len());
                }
                frame
            })
            .map_err(io::Error::other)
            .boxed_unsync(),
    );
    *out.status_mut() = response.status;
    let headers = out.headers_mut();
    for name in [CONTENT_LENGTH, HeaderName::from_static("content-range")] {
        if let Some(value) = response.headers.get(&name) {
            headers.insert(name, value.clone());
        }
    }
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert("accept-ranges", HeaderValue::from_static("bytes"));
    insert_digest(headers, digest);
    out
}

/// A blob being relayed: what has been hashed, and the last chunk, held back.
struct Relaying {
    body: Incoming,
    hasher: Hasher,
    expected: Digest,
    writer: Option<Writer>,
    cache: Arc<Cache>,
    over: Arc<Notify>,
    held: Option<Bytes>,
    done: bool,
    name: String,
}

impl Relaying {
    fn into_stream(self) -> impl futures_util::Stream<Item = Result<Bytes, io::Error>> {
        futures_util::stream::try_unfold(self, Self::step)
    }

    /// The next chunk to send. A chunk is sent when the next one has arrived, so the last waits for the digest: on a
    /// match it is sent and the file is kept, on a mismatch the stream fails, the connection closes without it and the
    /// file is deleted (D67).
    async fn step(mut self) -> Result<Option<(Bytes, Self)>, io::Error> {
        if self.done {
            return Ok(None);
        }
        loop {
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    if data.is_empty() {
                        continue;
                    }
                    self.hasher.update(&data);
                    if let Some(writer) = &mut self.writer
                        && let Err(err) = writer.write(&data).await
                    {
                        warn!(error = %err, "the blob cache cannot write: this blob is relayed without being kept");
                        self.writer = None;
                    }
                    metrics::upstream_bytes(data.len());
                    if let Some(previous) = self.held.replace(data) {
                        return Ok(Some((previous, self)));
                    }
                }
                Some(Err(err)) => {
                    debug!(error = %err, name = %self.name, "upstream broke off a blob");
                    return Err(io::Error::other(err));
                }
                None => return self.finish().await,
            }
        }
    }

    async fn finish(mut self) -> Result<Option<(Bytes, Self)>, io::Error> {
        let name = self.expected.algorithm().to_owned();
        let actual = to_digest(&name, &self.hasher.clone().finish());
        if actual.as_ref() != Some(&self.expected) {
            warn!(expected = %self.expected, name = %self.name, "upstream sent a blob that is not its digest: nothing is kept, and the last chunk is not sent");
            return Err(io::Error::other("the blob does not match its digest"));
        }
        if let Some(writer) = self.writer.take() {
            match writer.commit(&self.cache, &self.expected).await {
                Ok(()) => {
                    if self.cache.over() {
                        self.over.notify_one();
                    }
                }
                Err(err) => {
                    warn!(error = %err, digest = %self.expected, "the blob cache could not keep a blob");
                }
            }
        }
        self.done = true;
        Ok(self.held.take().map(|last| (last, self)))
    }
}

#[cfg(test)]
mod tests;
