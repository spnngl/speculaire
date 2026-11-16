//! Discovery: the artifacts of a root, found upstream through the node's registry config (D17, D43, D49).
//!
//! The root's manifest is asked of each source of each repository the image list names it in, in order, the node's
//! own mirror skipped; the first source that serves it is the upstream of the root's artifacts. The targets are the
//! root and, when it is an index, its manifest of the node's platform and that manifest's attestation manifests. Per
//! target, in order: the referrers API, the referrers fallback tag when the API answers 404, then the legacy `.sig`
//! tag. A tag is asked by `HEAD` first and fetched only when it exists (D38).

use std::sync::Arc;

use http::header::{ACCEPT, CONTENT_TYPE, LINK};
use http::{HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt as _, Limited};
use hyper::body::Incoming;
use speculaire_oci::index::Index;
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::{self, Descriptor, Referrer};
use speculaire_registry::{Client, Request, Response, link};
use speculaire_runtime::registries::{Reference, Registries, Source};
use tracing::{debug, warn};

use crate::metrics::{self, OTHER, Outcome};
use crate::store::{self, Artifact, Kind, Store};

/// What a manifest request accepts.
const MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";

/// The media types of an index: OCI's and Docker's.
const INDEXES: [&str; 2] = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

/// How much discovery fetches (D119).
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
    /// The limits of D119, with blobs up to `blob` bytes.
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
    /// No source of any of the root's repositories served its manifest (D17).
    #[error("artifacts unreachable")]
    Unreachable,
    /// The artifact store failed.
    #[error(transparent)]
    Store(#[from] store::Error),
}

/// Discovers artifacts upstream and keeps them in the artifact store.
pub struct Discovery {
    store: Arc<Store>,
    client: Client,
    registries: Arc<dyn Registries>,
    mirror: String,
    platform: Host,
    limits: Limits,
}

/// The source a root's manifest came from, and the `upstream` label of its requests.
struct Upstream {
    source: Source,
    label: String,
}

/// What one request came to.
enum Fetched<T> {
    Got(T),
    Missing,
    Failed,
}

impl Discovery {
    /// Discovery into `store` through `registries`, which never asks the node's own mirror at `mirror`, the
    /// authority of `mirror.address`.
    #[must_use]
    pub fn new(
        store: Arc<Store>,
        registries: Arc<dyn Registries>,
        mirror: String,
        platform: Host,
        limits: Limits,
    ) -> Self {
        Self {
            store,
            client: Client::new(),
            registries,
            mirror,
            platform,
            limits,
        }
    }

    /// The store artifacts are kept in.
    #[must_use]
    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Discovers the artifacts of `root`, which the image list names in each of `names`
    /// (`docker.io/library/busybox`), keeps them, and records them as the root's.
    ///
    /// # Errors
    ///
    /// When no source serves the root's manifest, or the store fails.
    pub async fn discover(&self, root: &Digest, names: &[String]) -> Result<Vec<Artifact>, Error> {
        let (upstream, index) = self.root(root, names).await.ok_or(Error::Unreachable)?;
        let mut targets = vec![root.clone()];
        let mut artifacts = Vec::new();
        if let Some(bytes) = index
            && let Ok(index) = Index::parse(&bytes)
            && let Some(platform) = index.platform_manifest(&self.platform)
        {
            targets.push(platform.clone());
            for attestation in index.attestations(platform) {
                if let Some(artifact) = self.attestation(&upstream, platform, attestation).await? {
                    artifacts.push(artifact);
                    targets.push(attestation.clone());
                }
            }
        }
        for target in &targets {
            self.bundles(&upstream, target, &mut artifacts).await?;
            if let Some(artifact) = self.signature(&upstream, target).await? {
                artifacts.push(artifact);
            }
        }
        self.store.record(root, &artifacts).await?;
        Ok(artifacts)
    }

    /// The first source, of each name in order, that serves the root's manifest, and the manifest when it is an index.
    ///
    /// The root is asked by `HEAD`, and fetched only when its media type is an index's: Docker Hub counts each `GET` of
    /// a manifest against its pull limit, and an image manifest names no target (D49).
    async fn root(&self, root: &Digest, names: &[String]) -> Option<(Upstream, Option<Vec<u8>>)> {
        let text = root.to_string();
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
                let Some(response) = self.send(&upstream, Method::HEAD, &path, MANIFESTS).await
                else {
                    continue;
                };
                let result = outcome(response.status);
                metrics::fetched(&upstream.label, result);
                if result != Outcome::Ok {
                    continue;
                }
                let index = response
                    .headers
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.split(';').next())
                    .is_some_and(|media_type| INDEXES.contains(&media_type.trim()));
                if !index {
                    return Some((upstream, None));
                }
                if let Fetched::Got(bytes) = self.manifest(&upstream, path, Some(root)).await {
                    return Some((upstream, Some(bytes)));
                }
            }
        }
        None
    }

    /// The attestation manifest `digest` of `target`, kept with its blobs.
    async fn attestation(
        &self,
        upstream: &Upstream,
        target: &Digest,
        digest: &Digest,
    ) -> Result<Option<Artifact>, Error> {
        let path = format!("/{}/manifests/{digest}", upstream.source.repository);
        let Fetched::Got(bytes) = self.manifest(upstream, path, Some(digest)).await else {
            return Ok(None);
        };
        let Ok(Children::Image { config, layers }) = manifest::children(&bytes) else {
            debug!(%digest, "an attestation manifest that is no image manifest is dropped");
            return Ok(None);
        };
        let blobs: Vec<Digest> = std::iter::once(config).chain(layers).collect();
        self.keep(upstream, digest, &bytes, &blobs, Kind::Attestation, target)
            .await
    }

    /// The Sigstore bundle referrers of `target`, kept with their blobs.
    async fn bundles(
        &self,
        upstream: &Upstream,
        target: &Digest,
        artifacts: &mut Vec<Artifact>,
    ) -> Result<(), Error> {
        let mut descriptors = self.referrers(upstream, target).await;
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
                .await
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
            let blobs: Vec<Digest> = referrer.blobs().map(|blob| blob.digest.clone()).collect();
            if let Some(artifact) = self
                .keep(
                    upstream,
                    &descriptor.digest,
                    &bytes,
                    &blobs,
                    Kind::Bundle,
                    target,
                )
                .await?
            {
                artifacts.push(artifact);
            }
        }
        Ok(())
    }

    /// The descriptors the referrers API lists for `target`, page by page, or the fallback tag's when it answers 404.
    async fn referrers(&self, upstream: &Upstream, target: &Digest) -> Vec<Descriptor> {
        let repository = &upstream.source.repository;
        let root = &upstream.source.candidates[0].root;
        let mut descriptors = Vec::new();
        let mut path = format!("/{repository}/referrers/{target}");
        for page in 0..self.limits.pages {
            let Some(response) = self
                .send(upstream, Method::GET, &path, referrers::INDEX)
                .await
            else {
                return descriptors;
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
                return descriptors;
            };
            match referrers::index(&bytes) {
                Ok(listed) => descriptors.extend(listed),
                Err(e) => {
                    warn!(%target, error = %e, "a referrers answer that is no index is dropped");
                    return descriptors;
                }
            }
            match next {
                Some(next) => path = next,
                None => return descriptors,
            }
        }
        warn!(%target, pages = self.limits.pages, "a target has more pages of referrers than are read");
        descriptors
    }

    /// The descriptors the referrers fallback tag of `target` lists, if it exists.
    async fn fallback(&self, upstream: &Upstream, target: &Digest) -> Vec<Descriptor> {
        let path = format!(
            "/{}/manifests/{}",
            upstream.source.repository,
            referrers::fallback_tag(target)
        );
        let Fetched::Got(bytes) = self.tag(upstream, path).await else {
            return Vec::new();
        };
        referrers::index(&bytes).unwrap_or_else(|e| {
            warn!(%target, error = %e, "a referrers fallback tag that is no index is dropped");
            Vec::new()
        })
    }

    /// The manifest of the legacy `.sig` tag of `target`, kept with its blobs, if it exists.
    async fn signature(
        &self,
        upstream: &Upstream,
        target: &Digest,
    ) -> Result<Option<Artifact>, Error> {
        let path = format!(
            "/{}/manifests/{}",
            upstream.source.repository,
            referrers::signature_tag(target)
        );
        let Fetched::Got(bytes) = self.tag(upstream, path).await else {
            return Ok(None);
        };
        let digest = speculaire_oci::hash::of("sha256", &bytes)
            .expect("sha256 is an algorithm the agent hashes");
        let Ok(manifest) = Referrer::parse(&bytes) else {
            debug!(%target, "a .sig tag that is no image manifest is dropped");
            return Ok(None);
        };
        let blobs: Vec<Digest> = manifest.blobs().map(|blob| blob.digest.clone()).collect();
        self.keep(upstream, &digest, &bytes, &blobs, Kind::Signature, target)
            .await
    }

    /// Keeps the manifest `bytes` and the `blobs` it names as an artifact of `target`: `None` when a blob cannot be
    /// had, which drops the artifact.
    async fn keep(
        &self,
        upstream: &Upstream,
        digest: &Digest,
        bytes: &[u8],
        blobs: &[Digest],
        kind: Kind,
        target: &Digest,
    ) -> Result<Option<Artifact>, Error> {
        for blob in blobs {
            if !self.store.contains(blob) && !self.blob(upstream, blob).await? {
                return Ok(None);
            }
        }
        self.store.keep(digest, bytes).await?;
        Ok(Some(Artifact {
            target: target.clone(),
            manifest: digest.clone(),
            kind,
            blobs: blobs.to_vec(),
        }))
    }

    /// Fetches the blob `digest` into the store, checking it in flight: whether it is kept.
    async fn blob(&self, upstream: &Upstream, digest: &Digest) -> Result<bool, Error> {
        let path = format!("/{}/blobs/{digest}", upstream.source.repository);
        let Some(response) = self.send(upstream, Method::GET, &path, "*/*").await else {
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
        match writer.commit(&self.store).await {
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
    async fn tag(&self, upstream: &Upstream, path: String) -> Fetched<Vec<u8>> {
        let Some(response) = self.send(upstream, Method::HEAD, &path, MANIFESTS).await else {
            return Fetched::Failed;
        };
        let result = outcome(response.status);
        metrics::fetched(&upstream.label, result);
        match result {
            Outcome::Ok => self.manifest(upstream, path, None).await,
            Outcome::NotFound => Fetched::Missing,
            Outcome::DigestMismatch | Outcome::RateLimited | Outcome::Error => Fetched::Failed,
        }
    }

    /// The manifest at `path`, checked against `digest` when the path names one.
    async fn manifest(
        &self,
        upstream: &Upstream,
        path: String,
        digest: Option<&Digest>,
    ) -> Fetched<Vec<u8>> {
        let Some(response) = self.send(upstream, Method::GET, &path, MANIFESTS).await else {
            return Fetched::Failed;
        };
        match outcome(response.status) {
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
        }
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

    /// Asks each candidate of the upstream's source in turn: the first answer, whatever its status.
    async fn send(
        &self,
        upstream: &Upstream,
        method: Method,
        path: &str,
        accept: &'static str,
    ) -> Option<Response> {
        let request = Request {
            method,
            path: path.to_owned(),
            repository: upstream.source.repository.clone(),
            headers: vec![(ACCEPT, HeaderValue::from_static(accept))],
        };
        let mut last = None;
        for endpoint in &upstream.source.candidates {
            match self
                .client
                .send(endpoint, &upstream.source.credentials, &request)
                .await
            {
                Ok(response) => return Some(response),
                Err(e) => last = Some(e),
            }
        }
        if let Some(e) = last {
            warn!(path, error = %e, "upstream does not answer for artifacts");
        }
        metrics::fetched(&upstream.label, Outcome::Error);
        None
    }
}

fn outcome(status: StatusCode) -> Outcome {
    match status {
        StatusCode::OK => Outcome::Ok,
        StatusCode::NOT_FOUND => Outcome::NotFound,
        StatusCode::TOO_MANY_REQUESTS => Outcome::RateLimited,
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
