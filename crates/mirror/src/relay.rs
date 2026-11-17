//! On CRI-O the mirror sits in every pull's path and relays it (D66, D67, D88).
//!
//! A manifest by tag is resolved by the peers that hold the tag, else at upstream (D123); a manifest by digest and the
//! blobs below a manifest the relay served come from the *blob cache*, else from peers, else, once, from upstream,
//! streamed to CRI-O and to a temporary file while they are hashed, with the last chunk held back until the digest
//! matches (D7, D67, D102).
//!
//! When no source serves, CRI-O gets upstream's refusal: a 429 with its `Retry-After`, or a 502 when upstream failed. A
//! 404 means upstream has no such content, or denies it to the node, and CRI-O pulls it itself (D129).

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::TryStreamExt as _;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, RANGE, RETRY_AFTER};
use http::{HeaderName, HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt as _, Limited, StreamBody};
use hyper::Response;
use hyper::body::{Frame, Incoming};
use speculaire_oci::hash::{self, Hash};
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::reference::Digest;
use speculaire_registry::{Client, Request, Response as Upstreamed};
use speculaire_runtime::content::Error;
use speculaire_runtime::images::Images;
use speculaire_runtime::registries::{self, Registries, Source};
use tokio::sync::Notify;
use tracing::{debug, warn};

use crate::cache::{Cache, Writer};
use crate::fetch::{Download, Fetcher};
use crate::listed::Listed;
use crate::metrics;
use crate::pulls::{Answer, Body, Pull, Pulls, Refusal, from_content};
use crate::request::{Kind, Reference};
use crate::serve::{insert_digest, manifest_response, media_type};

/// The largest manifest the relay reads.
const MAX_MANIFEST: usize = 4 * 1024 * 1024;

/// What a manifest request carries when CRI-O sent no `Accept`.
const DEFAULT_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

/// How many digests the relay remembers having served below a manifest.
const KNOWN_LIMIT: usize = 200_000;

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
pub struct Relay {
    cache: Arc<Cache>,
    fetcher: Fetcher,
    client: Client,
    registries: Arc<dyn Registries>,
    known: Known,
    /// The runtime's image list, whose blobs the cache evicts last (D67); `None` until it is first read.
    listed: Listed,
    over: Arc<Notify>,
}

impl Relay {
    /// A relay that keeps what it serves in `cache`, and fetches a blob from peers with `fetcher`, else where
    /// `registries` say. It follows `images` on a task of its own, which ends with the relay.
    #[must_use]
    pub fn new(
        cache: Cache,
        fetcher: Fetcher,
        registries: Arc<dyn Registries>,
        images: Arc<dyn Images>,
    ) -> Self {
        Self {
            cache: Arc::new(cache),
            fetcher,
            client: Client::new(),
            registries,
            known: Known::default(),
            listed: Listed::follow(images),
            over: Arc::new(Notify::new()),
        }
    }

    /// The blob cache.
    #[must_use]
    pub const fn cache(&self) -> &Arc<Cache> {
        &self.cache
    }

    /// Evicts what is over the cache's bound now, protecting the images the runtime lists.
    pub async fn evict(&self) {
        if !self.cache.over() {
            return;
        }
        let protected = self.protected().await;
        let cache = Arc::clone(&self.cache);
        // Deleting files blocks.
        if let Err(err) = tokio::task::spawn_blocking(move || cache.evict(&protected)).await {
            warn!(error = %err, "the blob cache could not evict");
        }
    }

    /// The runtime's image list it follows.
    #[must_use]
    pub const fn listed(&self) -> &Listed {
        &self.listed
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
        let listed: Option<Vec<Digest>> = self.listed.borrow().as_ref().map(|list| {
            list.images()
                .flat_map(|image| {
                    std::iter::once(&image.id)
                        .chain(image.repo_digests.iter().map(|repo| &repo.digest))
                })
                .cloned()
                .collect()
        });
        let mut pending = listed.unwrap_or_else(|| {
            warn!("the runtime's image list is not read yet: the blob cache evicts without it");
            Vec::new()
        });
        while let Some(digest) = pending.pop() {
            if !protected.insert(digest.clone()) {
                continue;
            }
            // Looking is no serving: the blobs it protects keep their place in the eviction order (D67).
            let Some(blob) = self.cache.peek(&digest).await else {
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

    async fn manifest(&self, pull: &Pull<'_>, reference: &Reference<'_>) -> Answer {
        let text: Cow<'_, str> = match reference {
            Reference::Digest(digest) => digest.to_string().into(),
            Reference::Tag(tag) => (*tag).into(),
        };
        let asked = match reference {
            Reference::Digest(_) => registries::Reference::Digest(&text),
            Reference::Tag(_) => registries::Reference::Tag(&text),
        };
        let sources = match self.registries.sources(pull.name, asked) {
            Ok(sources) => sources,
            Err(err) => return Answer::Failed(Error::Relay(err.to_string())),
        };
        if sources.is_empty() {
            return Answer::Missing;
        }
        // A manifest by digest that this relay served for this name, or that one it served points to, is its own to
        // serve again, else the peers' (D123).
        if let Reference::Digest(digest) = reference
            && self.known.has(digest, pull.name)
        {
            if self.cache.contains(digest) {
                return from_content(&*self.cache, Kind::Manifest, digest, pull.head, None).await;
            }
            if let Some(blob) = self.fetcher.whole(Kind::Manifest, digest).await
                && let Ok(bytes) = blob.read_all(MAX_MANIFEST as u64).await
                && let Some(media_type) = media_type(&bytes)
                && let Some(answer) = self.peer_manifest(pull, digest, &bytes, media_type).await
            {
                return answer;
            }
        }
        if let Some(tagged) = pull.tagged()
            && let Some(resolved) = self.fetcher.tag(&tagged).await
            && let Some(answer) = self
                .peer_manifest(pull, &resolved.digest, &resolved.bytes, resolved.media_type)
                .await
        {
            return answer;
        }
        let mut miss = Miss::Absent;
        for source in &sources {
            match self.relay_manifest(source, pull, reference, &text).await {
                Ok(answer) => return answer,
                Err(met) => miss = miss.or(met),
            }
        }
        miss.answer()
    }

    /// The manifest from one source, or why it gives none: the next source is tried. `text` is `reference` as the path
    /// names it.
    async fn relay_manifest(
        &self,
        source: &Source,
        pull: &Pull<'_>,
        reference: &Reference<'_>,
        text: &str,
    ) -> Result<Answer, Miss> {
        // The head of a tag is asked as a head: it costs no pull, and the body is not read.
        let head = pull.head && matches!(reference, Reference::Tag(_));
        let accept = header_value(pull.accept.unwrap_or(DEFAULT_ACCEPT)).ok_or(Miss::Absent)?;
        let request = Request {
            method: if head { Method::HEAD } else { Method::GET },
            path: format!("/{}/manifests/{text}", source.repository),
            repository: source.repository.clone(),
            headers: vec![(ACCEPT, accept)],
        };
        let (response, host) = self.send(source, &request).await?;
        if response.status != StatusCode::OK {
            return Err(missed(&response, host, pull.name, text));
        }
        let failed = |why: &str| failed(host, pull.name, text, why);
        if head {
            let head = head_response(&response).ok_or_else(|| failed("a head without a length"))?;
            return Ok(Answer::Served(metrics::Source::Upstream, head));
        }
        let content_type = response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let bytes = Limited::new(response.body, MAX_MANIFEST)
            .collect()
            .await
            .map_err(|err| failed(&format!("the manifest cannot be read: {err}")))?
            .to_bytes();
        // A manifest by tag is named by its sha256; one by digest has to hash to it.
        let digest = match reference {
            Reference::Tag(_) => {
                hash::of("sha256", &bytes).expect("sha256 is an algorithm the relay hashes")
            }
            Reference::Digest(digest) => {
                if hash::of(digest.algorithm(), &bytes).as_ref() != Some(digest) {
                    return Err(failed("a manifest that is not the digest asked for"));
                }
                (*digest).clone()
            }
        };
        // A kind the relay does not read is CRI-O's to pull itself.
        let children = manifest::children(&bytes)
            .map_err(|err| debug!(error = %err, name = pull.name, "the manifest is of a kind the relay does not read"))
            .map_err(|()| Miss::Absent)?;
        let media_type = content_type
            .as_deref()
            .and_then(|text| text.split(';').next())
            .map(str::trim)
            .and_then(header_value)
            .or_else(|| media_type(&bytes))
            .ok_or(Miss::Absent)?;
        self.hold(pull.name, &digest, &bytes, &children).await;
        Ok(Answer::Served(
            metrics::Source::Upstream,
            manifest_response(&bytes, &digest, media_type, false),
        ))
    }

    /// Serves manifest `bytes`, which peers sent, as the relay serves one from upstream; `None` when it is of a kind
    /// the relay does not read.
    async fn peer_manifest(
        &self,
        pull: &Pull<'_>,
        digest: &Digest,
        bytes: &Bytes,
        media_type: HeaderValue,
    ) -> Option<Answer> {
        let children = manifest::children(bytes)
            .map_err(|err| debug!(error = %err, name = pull.name, "a peer's manifest is of a kind the relay does not read"))
            .ok()?;
        self.hold(pull.name, digest, bytes, &children).await;
        Some(Answer::Served(
            metrics::Source::Peer,
            manifest_response(bytes, digest, media_type, pull.head),
        ))
    }

    /// Learns what is below a manifest served for `name`, and keeps it in the cache.
    async fn hold(&self, name: &str, digest: &Digest, bytes: &[u8], children: &Children) {
        self.learn(name, digest, children);
        if let Err(err) = self.keep(digest, bytes).await {
            warn!(error = %err, digest = %digest, "the blob cache could not keep a manifest");
        }
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
        // A whole blob comes from a peer that holds it before upstream (D67); a head or a range does not.
        if !pull.head
            && pull.range.is_none()
            && let Some(download) = self.fetcher.download(Kind::Blob, digest).await
        {
            let length = download.size();
            return self
                .relay_blob(
                    Feed::Peers(Box::new(download)),
                    Some(length.into()),
                    digest,
                    pull.name,
                )
                .await;
        }
        let digest_text = digest.to_string();
        let sources = match self
            .registries
            .sources(pull.name, registries::Reference::Digest(&digest_text))
        {
            Ok(sources) => sources,
            Err(err) => return Answer::Failed(Error::Relay(err.to_string())),
        };
        let mut miss = Miss::Absent;
        for source in &sources {
            match self
                .relay_upstream_blob(source, pull, digest, &digest_text)
                .await
            {
                Ok(answer) => return answer,
                Err(met) => miss = miss.or(met),
            }
        }
        miss.answer()
    }

    /// The blob from one source, or why it gives none: the next source is tried. `text` is `digest` as text.
    async fn relay_upstream_blob(
        &self,
        source: &Source,
        pull: &Pull<'_>,
        digest: &Digest,
        text: &str,
    ) -> Result<Answer, Miss> {
        let mut headers = Vec::new();
        if let Some(range) = pull.range.and_then(header_value) {
            headers.push((RANGE, range));
        }
        let request = Request {
            method: if pull.head { Method::HEAD } else { Method::GET },
            path: format!("/{}/blobs/{text}", source.repository),
            repository: source.repository.clone(),
            headers,
        };
        let (response, host) = self.send(source, &request).await?;
        match (response.status, pull.head, pull.range) {
            (StatusCode::OK, true, _) => head_response(&response)
                .map(|head| Answer::Served(metrics::Source::Upstream, head))
                .ok_or_else(|| failed(host, pull.name, text, "a head without a length")),
            (StatusCode::OK, false, None) => {
                let length = response.headers.get(CONTENT_LENGTH).cloned();
                let feed = Feed::Upstream(response.body);
                Ok(self.relay_blob(feed, length, digest, pull.name).await)
            }
            // A range, answered as upstream answers it: unhashed, not kept (D7's limit).
            (
                StatusCode::OK | StatusCode::PARTIAL_CONTENT | StatusCode::RANGE_NOT_SATISFIABLE,
                false,
                Some(_),
            ) => Ok(Answer::Served(
                metrics::Source::Upstream,
                passthrough(response, digest),
            )),
            _ => Err(missed(&response, host, pull.name, text)),
        }
    }

    /// A blob whole, of `length`: hashed as it streams, kept when the digest matches, and never sent to its end when it
    /// does not.
    async fn relay_blob(
        &self,
        feed: Feed,
        length: Option<HeaderValue>,
        digest: &Digest,
        name: &str,
    ) -> Answer {
        let Some(hash) = Hash::new(digest) else {
            return Answer::Failed(Error::Relay(format!(
                "{digest}: the relay hashes only sha256, sha384 and sha512"
            )));
        };
        let writer = self
            .cache
            .writer()
            .await
            .map_err(|err| warn!(error = %err, "the blob cache cannot write: this blob is relayed without being kept"))
            .ok();
        let source = match feed {
            Feed::Upstream(_) => metrics::Source::Upstream,
            Feed::Peers(_) => metrics::Source::Peer,
        };
        let relaying = Relaying {
            feed: Some(feed),
            hash,
            expected: digest.clone(),
            writer,
            cache: Arc::clone(&self.cache),
            over: Arc::clone(&self.over),
            held: None,
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
        Answer::Served(source, out)
    }

    /// Sends to the first candidate of `source` that answers: its answer and its host, else a failure.
    async fn send<'s>(
        &self,
        source: &'s Source,
        request: &Request,
    ) -> Result<(Upstreamed, &'s str), Miss> {
        let mut last = None;
        for endpoint in &source.candidates {
            match self
                .client
                .send(endpoint, &source.credentials, request)
                .await
            {
                Ok(response) => return Ok((response, &endpoint.authority)),
                Err(err) => last = Some(err),
            }
        }
        if let Some(err) = last {
            warn!(error = %err, "a registry does not answer the relay");
        }
        Err(Miss::Refused(Refusal::Failed))
    }
}

/// Why a source served nothing. Of all sources', the runtime gets the worst.
enum Miss {
    /// Upstream has no such content, or denies it to the node (D66): a 404, and CRI-O pulls it itself.
    Absent,
    /// Upstream refused, or failed.
    Refused(Refusal),
}

impl Miss {
    /// Of `self` and `other`, met later, the one the runtime gets: a limit over a failure over a 404, the first of
    /// equals.
    fn or(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    const fn rank(&self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::Refused(Refusal::Failed) => 1,
            Self::Refused(Refusal::Limited(_)) => 2,
        }
    }

    fn answer(self) -> Answer {
        match self {
            Self::Absent => Answer::Missing,
            Self::Refused(refusal) => Answer::Refused(refusal),
        }
    }
}

/// What `response`, which serves nothing, tells the runtime of `name`'s `reference`, from `host` (D129).
fn missed(response: &Upstreamed, host: &str, name: &str, reference: &str) -> Miss {
    let status = response.status;
    if matches!(
        status,
        StatusCode::NOT_FOUND | StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        debug!(%status, host, name, reference, "upstream does not serve the relay");
        return Miss::Absent;
    }
    if response.refusal().is_none() {
        return failed(
            host,
            name,
            reference,
            &format!("upstream answered {status}"),
        );
    }
    warn!(%status, host, name, reference, "upstream limits the relay: CRI-O gets a 429");
    Miss::Refused(Refusal::Limited(response.headers.get(RETRY_AFTER).cloned()))
}

/// Upstream at `host` failed `name`'s `reference`, for `why`: CRI-O gets a 502 (D129).
fn failed(host: &str, name: &str, reference: &str, why: &str) -> Miss {
    warn!(
        host,
        name, reference, why, "upstream failed the relay: CRI-O gets a 502"
    );
    Miss::Refused(Refusal::Failed)
}

impl Pulls for Relay {
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
    let mut out = Response::new(response.body.map_err(io::Error::other).boxed_unsync());
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

/// Where a relayed blob comes from.
enum Feed {
    Upstream(Incoming),
    Peers(Box<Download>),
}

impl Feed {
    /// The next chunk, or `None` at the end.
    async fn next(&mut self, name: &str) -> Result<Option<Bytes>, io::Error> {
        match self {
            Self::Upstream(body) => loop {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data()
                            && !data.is_empty()
                        {
                            return Ok(Some(data));
                        }
                    }
                    Some(Err(err)) => {
                        debug!(error = %err, name, "upstream broke off a blob");
                        return Err(io::Error::other(err));
                    }
                    None => return Ok(None),
                }
            },
            Self::Peers(download) => download.next().await.ok_or_else(|| {
                debug!(name, "no peer is left to finish a blob");
                io::Error::other("no peer is left to finish the blob")
            }),
        }
    }
}

/// A blob being relayed: what has been hashed, and the last chunk, held back.
struct Relaying {
    /// Where the blob comes from, until it ends.
    feed: Option<Feed>,
    hash: Hash,
    expected: Digest,
    writer: Option<Writer>,
    cache: Arc<Cache>,
    over: Arc<Notify>,
    held: Option<Bytes>,
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
        loop {
            let Some(feed) = &mut self.feed else {
                return Ok(None);
            };
            let Some(data) = feed.next(&self.name).await? else {
                return self.finish().await;
            };
            self.hash.update(&data);
            if let Some(writer) = &mut self.writer
                && let Err(err) = writer.write(&data).await
            {
                warn!(error = %err, "the blob cache cannot write: this blob is relayed without being kept");
                self.writer = None;
            }
            if let Some(previous) = self.held.replace(data) {
                return Ok(Some((previous, self)));
            }
        }
    }

    async fn finish(mut self) -> Result<Option<(Bytes, Self)>, io::Error> {
        let matched = self.hash.matches();
        let feed = self.feed.take();
        if !matched {
            // A peer's part in a wrong blob denies it (D52); upstream is only warned about.
            match feed {
                Some(Feed::Peers(download)) => download.finish(false),
                _ => {
                    warn!(expected = %self.expected, name = %self.name, "upstream sent a blob that is not its digest: nothing is kept, and the last chunk is not sent");
                }
            }
            return Err(io::Error::other("the blob does not match its digest"));
        }
        if let Some(Feed::Peers(download)) = feed {
            download.finish(true);
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
        Ok(self.held.take().map(|last| (last, self)))
    }
}

#[cfg(test)]
mod tests;
