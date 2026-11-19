//! Discovery: the artifacts of a root, found in the store and at peers, else upstream through the node's registry config
//! (D17, D43, D49, D126).
//!
//! The root's manifest comes from the node's content, else the store or peers, and an index is kept in the store. The
//! artifacts come from peers first; upstream is asked only when they give none. There, the root's manifest is asked
//! of each source of each repository the image list names it in, in order, the node's own mirror skipped; the first source that serves it is the upstream of the root's artifacts. The targets are the
//! root and, when it is an index, its manifest of the node's platform and that manifest's attestation manifests. Per
//! target, in order: the referrers API, the referrers fallback tag when the API answers 404, then the legacy `.sig`
//! tag. A tag is asked by `HEAD` first and fetched only when it exists (D38).
//!
//! A host that refuses to serve more for now is paused, for every root, and the discovery it refused ends
//! [`Reason::RateLimited`] (D38, D128).

use std::sync::Arc;
use std::time::Duration;

use http::header::{ACCEPT, CONTENT_TYPE, LINK};
use http::{HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt as _, Limited};
use hyper::body::Incoming;
use speculaire_mirror::fetch::Fetcher;
use speculaire_mirror::request::Kind as Wanted;
use speculaire_oci::index::Index;
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::{self, Descriptor, Referrer};
use speculaire_registry::{Client, Request, Response, link};
use speculaire_runtime::registries::{Reference, Registries, Source};
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::metrics::{self, OTHER, Outcome};
use crate::store::{self, Artifact, Discovering, Kind, Store};

mod pauses;
mod peers;

use pauses::Pauses;
pub use peers::Local;

/// How long a root whose artifacts are unreachable, or not kept, waits before it is discovered again (D121).
pub const RETRY: Duration = Duration::from_secs(600);

/// What a manifest request accepts.
const MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

/// The media types of an index: OCI's and Docker's.
const INDEXES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// How much discovery fetches (D121).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Referrers fetched per target; the rest are dropped.
    pub referrers: usize,
    /// Pages of the referrers API read per target.
    pub pages: usize,
    /// Bytes of a manifest or referrers index (D85).
    pub manifest: u64,
    /// Bytes of any other blob: `sbom.max_size` (D12).
    pub blob: u64,
}

impl Limits {
    /// The limits of D121, with blobs up to `blob` bytes.
    #[must_use]
    pub const fn new(blob: u64) -> Self {
        Self {
            referrers: 64,
            pages: 10,
            manifest: 4 * 1024 * 1024,
            blob,
        }
    }
}

/// Why a root's artifacts were not discovered.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Discovery could not end, and is tried again at `retry_at`: D20's `Unverifiable`, which M5's verdict takes as is.
    #[error("unverifiable: {reason}")]
    Unverifiable {
        /// Why.
        reason: Reason,
        /// When to discover the root again.
        retry_at: Instant,
    },
    /// The artifact store failed.
    #[error(transparent)]
    Store(#[from] store::Error),
}

/// Why discovery could not end.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reason {
    /// No source of any of the root's repositories served its manifest (D17).
    #[error("artifacts unreachable")]
    Unreachable,
    /// The registry host refused to serve more for now (D38).
    #[error("upstream rate limited: {host}")]
    RateLimited {
        /// The endpoint's authority.
        host: String,
    },
}

/// Discovers artifacts at peers, else upstream, and keeps them in the artifact store.
pub struct Discovery {
    store: Arc<Store>,
    local: Arc<dyn Local>,
    peers: Fetcher,
    client: Client,
    registries: Arc<dyn Registries>,
    mirror: String,
    platform: Host,
    limits: Limits,
    pauses: Pauses,
}

/// The source a root's manifest came from, and the `upstream` label of its requests.
struct Upstream {
    source: Source,
    label: String,
}

/// Where the blobs of an artifact come from.
#[derive(Clone, Copy)]
enum Origin<'a> {
    Upstream(&'a Upstream),
    Peers,
}

/// What one request came to.
enum Fetched<T> {
    Got(T),
    Missing,
    Failed,
}

impl Discovery {
    /// Discovery into `store`, reading root manifests from `local`, from `peers`, and upstream through `registries`,
    /// which never asks the node's own mirror at `mirror`, the authority of `mirror.address`.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        local: Arc<dyn Local>,
        peers: Fetcher,
        registries: Arc<dyn Registries>,
        mirror: String,
        platform: Host,
        limits: Limits,
    ) -> Self {
        Self {
            store,
            local,
            peers,
            client: Client::new(),
            registries,
            mirror,
            platform,
            limits,
            pauses: Pauses::default(),
        }
    }

    /// The store artifacts are kept in.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The manifests the index `root` names, from the store else the node; none when `root` is no index, `None` when
    /// neither holds it.
    pub async fn children(&self, root: &Digest) -> Option<Vec<Digest>> {
        let bytes = match self.store.read(root).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) | Err(_) => self.local.manifest(root, self.limits.manifest).await?,
        };
        let index = Index::parse(&bytes).ok();
        Some(index.map_or_else(Vec::new, |index| index.manifests().cloned().collect()))
    }

    /// Discovers the artifacts of `root`, which the image list names in each of `names`
    /// (`docker.io/library/busybox`), keeps them, and records them as the root's.
    ///
    /// # Errors
    ///
    /// When peers give no artifact and no source serves the root's manifest, a host refuses to serve more for now, or
    /// the store fails.
    pub async fn discover(&self, root: &Digest, names: &[String]) -> Result<Vec<Artifact>, Error> {
        self.run(root, names, false).await
    }

    /// Asks upstream for the artifacts of `root` once more, whatever peers give, and records them beside those
    /// recorded: what a verdict about to be `Rejected` asks first (D126).
    ///
    /// # Errors
    ///
    /// As [`Discovery::discover`], when no source serves the root's manifest.
    pub async fn again(&self, root: &Digest, names: &[String]) -> Result<Vec<Artifact>, Error> {
        self.run(root, names, true).await
    }

    /// Discovers `root`, upstream alone and beside its record when `again`, else peers first.
    async fn run(
        &self,
        root: &Digest,
        names: &[String],
        again: bool,
    ) -> Result<Vec<Artifact>, Error> {
        let discovering = self.store.discovering(root);
        let mut index = self.held(root).await?;
        let mut artifacts = if again {
            Vec::new()
        } else {
            self.nearby(&discovering, root, index.as_deref()).await?
        };
        if artifacts.is_empty() {
            let (upstream, fetched) = self.root(root, names, index.as_deref()).await?;
            index = fetched;
            artifacts = self
                .upstream(&discovering, &upstream, root, index.as_deref())
                .await?;
        }
        if let Some(bytes) = &index
            && Index::parse(bytes).is_ok()
        {
            discovering.keep(root, bytes).await?;
        }
        if again {
            for artifact in self.store.recorded(root).await?.unwrap_or_default() {
                if !artifacts.contains(&artifact) {
                    artifacts.push(artifact);
                }
            }
        }
        self.store.record(root, &artifacts).await?;
        Ok(artifacts)
    }

    /// The artifacts of `root` from `upstream`, `index` being its manifest when it is an index.
    async fn upstream(
        &self,
        discovering: &Discovering<'_>,
        upstream: &Upstream,
        root: &Digest,
        index: Option<&[u8]>,
    ) -> Result<Vec<Artifact>, Error> {
        let mut targets = vec![root.clone()];
        let mut artifacts = Vec::new();
        if let Some((platform, attestations)) = self.platform(index) {
            targets.push(platform.clone());
            for attestation in attestations {
                if let Some(artifact) = self
                    .attestation(discovering, upstream, &platform, &attestation)
                    .await?
                {
                    artifacts.push(artifact);
                    targets.push(attestation);
                }
            }
        }
        for target in &targets {
            self.bundles(discovering, upstream, target, &mut artifacts)
                .await?;
            if let Some(artifact) = self.signature(discovering, upstream, target).await? {
                artifacts.push(artifact);
            }
        }
        Ok(artifacts)
    }

    /// The manifest of the node's platform that `index` names, and that manifest's attestation manifests (D49).
    fn platform(&self, index: Option<&[u8]>) -> Option<(Digest, Vec<Digest>)> {
        let index = Index::parse(index?).ok()?;
        let platform = index.platform_manifest(&self.platform)?;
        let attestations = index.attestations(platform).into_iter().cloned().collect();
        Some((platform.clone(), attestations))
    }

    /// The first source, of each name in order, that serves the root's manifest, and the manifest when it is an index:
    /// `held` when given.
    ///
    /// The root is asked by `HEAD`, and fetched only when its media type is an index's and it is not held: Docker Hub
    /// counts each `GET` of a manifest against its pull limit, and an image manifest names no target (D49). A source
    /// whose hosts are all paused is passed; when no source serves, the earliest pause met is the error.
    async fn root(
        &self,
        root: &Digest,
        names: &[String],
        held: Option<&[u8]>,
    ) -> Result<(Upstream, Option<Vec<u8>>), Error> {
        let text = root.to_string();
        let mut limited: Option<Paused> = None;
        for name in names {
            let sources = match self.registries.sources(name, Reference::Digest(&text)) {
                Ok(sources) => sources,
                Err(e) => {
                    warn!(name, error = %e, "the registry config has no source of the name");
                    continue;
                }
            };
            let host = name.split_once('/').map_or(name.as_str(), |(host, _)| host);
            let label = if self.registries.configured(host) {
                host.to_owned()
            } else {
                OTHER.to_owned()
            };
            for mut source in sources {
                source
                    .candidates
                    .retain(|endpoint| endpoint.authority != self.mirror);
                if source.candidates.is_empty() {
                    continue;
                }
                let upstream = Upstream {
                    source,
                    label: label.clone(),
                };
                let path = format!("/{}/manifests/{text}", upstream.source.repository);
                let fetched = match self.index(&upstream, path, root, held).await {
                    Ok(fetched) => fetched,
                    Err(met) => {
                        limited = Some(met.earliest(limited));
                        continue;
                    }
                };
                if let Fetched::Got(index) = fetched {
                    return Ok((upstream, index));
                }
            }
        }
        Err(limited.map_or_else(
            || Error::Unverifiable {
                reason: Reason::Unreachable,
                retry_at: Instant::now() + RETRY,
            },
            Error::from,
        ))
    }

    /// Whether `upstream` serves the root's manifest at `path`, and the manifest when it is an index: `held` when given.
    async fn index(
        &self,
        upstream: &Upstream,
        path: String,
        root: &Digest,
        held: Option<&[u8]>,
    ) -> Result<Fetched<Option<Vec<u8>>>, Paused> {
        let Some(response) = self.send(upstream, Method::HEAD, &path, MANIFESTS).await? else {
            return Ok(Fetched::Failed);
        };
        let result = outcome(response.status);
        metrics::fetched(&upstream.label, result);
        if result != Outcome::Ok {
            return Ok(Fetched::Failed);
        }
        let index = response
            .headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media_type| INDEXES.contains(&media_type.trim()));
        if !index {
            return Ok(Fetched::Got(None));
        }
        if let Some(bytes) = held {
            return Ok(Fetched::Got(Some(bytes.to_vec())));
        }
        Ok(match self.manifest(upstream, path, Some(root)).await? {
            Fetched::Got(bytes) => Fetched::Got(Some(bytes)),
            Fetched::Missing => Fetched::Missing,
            Fetched::Failed => Fetched::Failed,
        })
    }

    /// The attestation manifest `digest` of `target`, kept with its blobs.
    async fn attestation(
        &self,
        discovering: &Discovering<'_>,
        upstream: &Upstream,
        target: &Digest,
        digest: &Digest,
    ) -> Result<Option<Artifact>, Error> {
        let path = format!("/{}/manifests/{digest}", upstream.source.repository);
        let Fetched::Got(bytes) = self.manifest(upstream, path, Some(digest)).await? else {
            return Ok(None);
        };
        let Ok(Children::Image { config, layers }) = manifest::children(&bytes) else {
            debug!(%digest, "an attestation manifest that is no image manifest is dropped");
            return Ok(None);
        };
        let artifact = Artifact {
            target: target.clone(),
            manifest: digest.clone(),
            kind: Kind::Attestation,
            blobs: std::iter::once(config).chain(layers).collect(),
        };
        self.keep(discovering, Origin::Upstream(upstream), &bytes, artifact)
            .await
    }

    /// The Sigstore bundle referrers of `target`, kept with their blobs.
    async fn bundles(
        &self,
        discovering: &Discovering<'_>,
        upstream: &Upstream,
        target: &Digest,
        artifacts: &mut Vec<Artifact>,
    ) -> Result<(), Error> {
        let mut descriptors = self.referrers(upstream, target).await?;
        descriptors.retain(|d| d.may_be_bundle() && d.size <= self.limits.manifest);
        if descriptors.len() > self.limits.referrers {
            warn!(%target, referrers = descriptors.len(), kept = self.limits.referrers, "a target has too many referrers");
            descriptors.truncate(self.limits.referrers);
        }
        for descriptor in descriptors {
            let path = format!(
                "/{}/manifests/{}",
                upstream.source.repository, descriptor.digest
            );
            let Fetched::Got(bytes) = self
                .manifest(upstream, path, Some(&descriptor.digest))
                .await?
            else {
                continue;
            };
            // The index is a hint: a manifest refers to the target only when its own subject says so.
            let referrer = match Referrer::parse(&bytes) {
                Ok(referrer)
                    if referrer.subject.as_ref() == Some(target) && referrer.is_bundle() =>
                {
                    referrer
                }
                _ => {
                    debug!(%target, referrer = %descriptor.digest, "a referrer that is no bundle of the target is dropped");
                    continue;
                }
            };
            let artifact = Artifact {
                target: target.clone(),
                manifest: descriptor.digest,
                kind: Kind::Bundle,
                blobs: referrer.blobs().map(|blob| blob.digest.clone()).collect(),
            };
            if let Some(artifact) = self
                .keep(discovering, Origin::Upstream(upstream), &bytes, artifact)
                .await?
            {
                artifacts.push(artifact);
            }
        }
        Ok(())
    }

    /// The descriptors the referrers API lists for `target`, page by page, or the fallback tag's when it answers 404.
    async fn referrers(
        &self,
        upstream: &Upstream,
        target: &Digest,
    ) -> Result<Vec<Descriptor>, Paused> {
        let repository = &upstream.source.repository;
        let root = &upstream.source.candidates[0].root;
        let mut descriptors = Vec::new();
        let mut path = format!("/{repository}/referrers/{target}");
        for page in 0..self.limits.pages {
            let Some(response) = self
                .send(upstream, Method::GET, &path, referrers::INDEX)
                .await?
            else {
                return Ok(descriptors);
            };
            if page == 0 && response.status == StatusCode::NOT_FOUND {
                metrics::fetched(&upstream.label, Outcome::NotFound);
                return self.fallback(upstream, target).await;
            }
            let next = response
                .headers
                .get_all(LINK)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .find_map(link::next)
                .and_then(|next| below(next, root));
            let Some(bytes) = self.body(upstream, response, None).await else {
                return Ok(descriptors);
            };
            match referrers::index(&bytes) {
                Ok(listed) => descriptors.extend(listed),
                Err(e) => {
                    warn!(%target, error = %e, "a referrers answer that is no index is dropped");
                    return Ok(descriptors);
                }
            }
            match next {
                Some(next) => path = next,
                None => return Ok(descriptors),
            }
        }
        warn!(%target, pages = self.limits.pages, "a target has more pages of referrers than are read");
        Ok(descriptors)
    }

    /// The descriptors the referrers fallback tag of `target` lists, if it exists.
    async fn fallback(
        &self,
        upstream: &Upstream,
        target: &Digest,
    ) -> Result<Vec<Descriptor>, Paused> {
        let path = format!(
            "/{}/manifests/{}",
            upstream.source.repository,
            referrers::fallback_tag(target)
        );
        let Fetched::Got(bytes) = self.tag(upstream, path).await? else {
            return Ok(Vec::new());
        };
        Ok(referrers::index(&bytes).unwrap_or_else(|e| {
            warn!(%target, error = %e, "a referrers fallback tag that is no index is dropped");
            Vec::new()
        }))
    }

    /// The manifest of the legacy `.sig` tag of `target`, kept with its blobs, if it exists.
    async fn signature(
        &self,
        discovering: &Discovering<'_>,
        upstream: &Upstream,
        target: &Digest,
    ) -> Result<Option<Artifact>, Error> {
        let path = format!(
            "/{}/manifests/{}",
            upstream.source.repository,
            referrers::signature_tag(target)
        );
        let Fetched::Got(bytes) = self.tag(upstream, path).await? else {
            return Ok(None);
        };
        let digest = speculaire_oci::hash::of("sha256", &bytes)
            .expect("sha256 is an algorithm the agent hashes");
        let Ok(manifest) = Referrer::parse(&bytes) else {
            debug!(%target, "a .sig tag that is no image manifest is dropped");
            return Ok(None);
        };
        let artifact = Artifact {
            target: target.clone(),
            manifest: digest,
            kind: Kind::Signature,
            blobs: manifest.blobs().map(|blob| blob.digest.clone()).collect(),
        };
        self.keep(discovering, Origin::Upstream(upstream), &bytes, artifact)
            .await
    }

    /// Keeps `artifact`, `bytes` being its manifest, with its blobs: `None` when a blob cannot be had, which drops the
    /// artifact. A blob its manifest lists above `sbom.max_size` is left out unfetched, its artifact kept, for the
    /// verifier to reject by that size (D150).
    async fn keep(
        &self,
        discovering: &Discovering<'_>,
        origin: Origin<'_>,
        bytes: &[u8],
        artifact: Artifact,
    ) -> Result<Option<Artifact>, Error> {
        let above: Vec<Digest> = Referrer::parse(bytes)
            .map(|manifest| {
                manifest
                    .blobs()
                    .filter(|blob| blob.size > self.limits.blob)
                    .map(|blob| blob.digest.clone())
                    .collect()
            })
            .unwrap_or_default();
        for blob in &artifact.blobs {
            if above.contains(blob) {
                warn!(%blob, max = self.limits.blob, "an artifact blob listed larger than sbom.max_size is left out");
                continue;
            }
            if discovering.hold(blob) {
                continue;
            }
            let kept = match origin {
                Origin::Upstream(upstream) => self.blob(discovering, upstream, blob).await?,
                Origin::Peers => match self
                    .nearby_bytes(Wanted::Blob, blob, self.limits.blob)
                    .await?
                {
                    Some(content) => {
                        discovering.keep(blob, &content).await?;
                        true
                    }
                    None => false,
                },
            };
            if !kept {
                return Ok(None);
            }
        }
        discovering.keep(&artifact.manifest, bytes).await?;
        Ok(Some(artifact))
    }

    /// Fetches the blob `digest` into the store, checking it in flight: whether it is kept.
    async fn blob(
        &self,
        discovering: &Discovering<'_>,
        upstream: &Upstream,
        digest: &Digest,
    ) -> Result<bool, Error> {
        let path = format!("/{}/blobs/{digest}", upstream.source.repository);
        let Some(response) = self.send(upstream, Method::GET, &path, "*/*").await? else {
            return Ok(false);
        };
        if response.status != StatusCode::OK {
            metrics::fetched(&upstream.label, outcome(response.status));
            return Ok(false);
        }
        let mut writer = self.store.writer(digest).await?;
        let mut body = response.body;
        while let Some(frame) = body.frame().await {
            let Ok(frame) = frame else {
                metrics::fetched(&upstream.label, Outcome::Error);
                return Ok(false);
            };
            if let Ok(data) = frame.into_data() {
                writer.write(&data).await?;
                if writer.written() > self.limits.blob {
                    warn!(%digest, max = self.limits.blob, "an artifact blob is larger than sbom.max_size");
                    metrics::fetched(&upstream.label, Outcome::Error);
                    return Ok(false);
                }
            }
        }
        match discovering.commit(writer).await {
            Ok(()) => {
                metrics::fetched(&upstream.label, Outcome::Ok);
                Ok(true)
            }
            Err(store::Error::Mismatch(_)) => {
                warn!(%digest, "an artifact blob does not match its digest");
                metrics::fetched(&upstream.label, Outcome::DigestMismatch);
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The tag at `path`, asked by `HEAD` and fetched only when it exists (D38).
    async fn tag(&self, upstream: &Upstream, path: String) -> Result<Fetched<Vec<u8>>, Paused> {
        let Some(response) = self.send(upstream, Method::HEAD, &path, MANIFESTS).await? else {
            return Ok(Fetched::Failed);
        };
        let result = outcome(response.status);
        metrics::fetched(&upstream.label, result);
        match result {
            Outcome::Ok => self.manifest(upstream, path, None).await,
            Outcome::NotFound => Ok(Fetched::Missing),
            Outcome::DigestMismatch | Outcome::RateLimited | Outcome::Error => Ok(Fetched::Failed),
        }
    }

    /// The manifest at `path`, checked against `digest` when the path names one.
    async fn manifest(
        &self,
        upstream: &Upstream,
        path: String,
        digest: Option<&Digest>,
    ) -> Result<Fetched<Vec<u8>>, Paused> {
        let Some(response) = self.send(upstream, Method::GET, &path, MANIFESTS).await? else {
            return Ok(Fetched::Failed);
        };
        Ok(match outcome(response.status) {
            Outcome::Ok => match self.body(upstream, response, digest).await {
                Some(bytes) => Fetched::Got(bytes),
                None => Fetched::Failed,
            },
            Outcome::NotFound => {
                metrics::fetched(&upstream.label, Outcome::NotFound);
                Fetched::Missing
            }
            other => {
                debug!(path, status = %response.status, "upstream refused a manifest");
                metrics::fetched(&upstream.label, other);
                Fetched::Failed
            }
        })
    }

    /// The body of a 200, up to the manifest limit and checked against `digest`, counted.
    async fn body(
        &self,
        upstream: &Upstream,
        response: Response,
        digest: Option<&Digest>,
    ) -> Option<Vec<u8>> {
        if response.status != StatusCode::OK {
            metrics::fetched(&upstream.label, outcome(response.status));
            return None;
        }
        let Some(bytes) = read(response.body, self.limits.manifest).await else {
            metrics::fetched(&upstream.label, Outcome::Error);
            return None;
        };
        if let Some(digest) = digest
            && speculaire_oci::hash::of(digest.algorithm(), &bytes).as_ref() != Some(digest)
        {
            warn!(%digest, "an artifact manifest does not match its digest");
            metrics::fetched(&upstream.label, Outcome::DigestMismatch);
            return None;
        }
        metrics::fetched(&upstream.label, Outcome::Ok);
        Some(bytes)
    }

    /// Asks each candidate of the upstream's source in turn, its paused hosts passed: the first answer that is no
    /// refusal, whatever its status, else `None`.
    ///
    /// # Errors
    ///
    /// When a host refused, or was paused, and no other answered.
    async fn send(
        &self,
        upstream: &Upstream,
        method: Method,
        path: &str,
        accept: &'static str,
    ) -> Result<Option<Response>, Paused> {
        let request = Request {
            method,
            path: path.to_owned(),
            repository: upstream.source.repository.clone(),
            headers: vec![(ACCEPT, HeaderValue::from_static(accept))],
        };
        let mut last = None;
        let mut limited = None;
        for endpoint in &upstream.source.candidates {
            let host = &endpoint.authority;
            if let Some(until) = self.pauses.until(host, Instant::now()) {
                limited = Some(Paused::new(host, until).earliest(limited));
                continue;
            }
            match self
                .client
                .send(endpoint, &upstream.source.credentials, &request)
                .await
            {
                Ok(response) => {
                    let Some(refusal) = response.refusal() else {
                        self.pauses.answered(host);
                        return Ok(Some(response));
                    };
                    metrics::fetched(&upstream.label, Outcome::RateLimited);
                    let until = self.pauses.refused(host, refusal, Instant::now());
                    limited = Some(Paused::new(host, until).earliest(limited));
                }
                Err(e) => last = Some(e),
            }
        }
        if let Some(limited) = limited {
            return Err(limited);
        }
        if let Some(e) = last {
            warn!(path, error = %e, "upstream does not answer for artifacts");
        }
        metrics::fetched(&upstream.label, Outcome::Error);
        Ok(None)
    }
}

/// A host refused to serve more for now, or was paused, and no other answered (D38).
struct Paused {
    host: String,
    until: Instant,
}

impl Paused {
    fn new(host: &str, until: Instant) -> Self {
        Self {
            host: host.to_owned(),
            until,
        }
    }

    /// Of `self` and the limit met before, `kept`, the one that ends first.
    fn earliest(self, kept: Option<Self>) -> Self {
        match kept {
            Some(kept) if kept.until <= self.until => kept,
            _ => self,
        }
    }
}

impl From<Paused> for Error {
    fn from(paused: Paused) -> Self {
        Self::Unverifiable {
            reason: Reason::RateLimited { host: paused.host },
            retry_at: paused.until,
        }
    }
}

fn outcome(status: StatusCode) -> Outcome {
    match status {
        StatusCode::OK => Outcome::Ok,
        StatusCode::NOT_FOUND => Outcome::NotFound,
        _ => Outcome::Error,
    }
}

async fn read(body: Incoming, max: u64) -> Option<Vec<u8>> {
    let max = usize::try_from(max).unwrap_or(usize::MAX);
    let collected = Limited::new(body, max).collect().await.ok()?;
    Some(collected.to_bytes().to_vec())
}

/// The path below the API root `root` of a link to the next page, relative or absolute.
fn below(link: &str, root: &str) -> Option<String> {
    let path = match link.split_once("://") {
        Some((_, rest)) => &rest[rest.find('/')?..],
        None => link,
    };
    path.strip_prefix(root)
        .filter(|path| path.starts_with('/'))
        .map(str::to_owned)
}

#[cfg(test)]
mod tests;
