//! The layers of a prewarmed image the node held without a blob, fetched once its pull went through (D195).
//!
//! A runtime pulls no blob of a layer it holds unpacked: containerd keeps the snapshots of an image removed while its
//! containers run, and CRI-O's storage reuses a layer it holds for another image. The node would then never announce
//! such a layer, and the seed's round would wait for `prewarm.seed_timeout` (D185). Each layer of the pulled platform
//! manifest the node holds no blob of is fetched, peers first (D102), where the node announces from: on containerd,
//! into its content store, from peers else upstream with the node's own mirror left out; on CRI-O, through the relay,
//! which keeps it in the blob cache.

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;

use http::{Method, StatusCode};
use http_body_util::BodyExt as _;
use metrics::counter;
use speculaire_mirror::fetch::Fetcher;
use speculaire_mirror::relay::Relay;
use speculaire_mirror::request::{self, Kind};
use speculaire_mirror::{Answer, Pull, Pulls as _};
use speculaire_oci::index::Index;
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::{Digest, Reference};
use speculaire_registry::{Client, Request, Response};
use speculaire_runtime::containerd::Containerd;
use speculaire_runtime::content::{self, Content};
use speculaire_runtime::cri;
use speculaire_runtime::images::Image;
use speculaire_runtime::registries::{self, Registries};
use tracing::{debug, warn};

use crate::telemetry::PREWARM_REFETCHED;

/// The largest manifest read, as the mirror's.
const MAX_MANIFEST: u64 = 4 << 20;

/// Fetches the layers a prewarmed image left the node holding without a blob.
pub(crate) struct Refetch {
    /// The runtime's CRI socket, whose image list names what a tag was pulled by.
    socket: PathBuf,
    host: Host,
    destination: Destination,
}

/// Where a layer is fetched into.
enum Destination {
    /// containerd's content store: from peers, else upstream.
    Store(Box<Store>),
    /// The relay's blob cache: the relay asks peers before upstream.
    Relay(Arc<Relay>),
}

/// containerd's content store, and where it fetches from.
struct Store {
    containerd: Containerd,
    fetcher: Fetcher,
    upstream: Upstream,
}

/// The node's registry config, its own mirror left out, as the reflector's resolver reads it (D185).
struct Upstream {
    registries: Arc<dyn Registries>,
    client: Client,
    /// The authority of the node's own mirror, which the registry config lists first.
    mirror: String,
}

/// Why a layer was not fetched.
#[derive(Debug, thiserror::Error)]
enum Unfetched {
    #[error(transparent)]
    Content(#[from] content::Error),
    #[error(transparent)]
    Registries(#[from] registries::Error),
    #[error("no peer and no source besides the mirror served it")]
    Nowhere,
    #[error("the relay answered no blob")]
    Unanswered,
}

/// Why the layers of an image were not read.
#[derive(Debug, thiserror::Error)]
enum Unread {
    #[error(transparent)]
    Content(#[from] content::Error),
    #[error("the manifest {0} is not held")]
    Absent(String),
    #[error(transparent)]
    Manifest(#[from] manifest::Error),
    #[error(transparent)]
    Index(#[from] speculaire_oci::referrers::Error),
    #[error("the index {0} has no manifest for this node's platform")]
    NoPlatform(String),
    #[error("the image manifest {0} is an index")]
    Nested(String),
}

impl Refetch {
    /// On containerd: into its content store, from peers with `fetcher`, else where `registries` say but the mirror at
    /// `mirror`.
    pub(crate) fn store(
        containerd: Containerd,
        fetcher: Fetcher,
        registries: Arc<dyn Registries>,
        mirror: String,
    ) -> Self {
        Self {
            socket: containerd.socket().to_owned(),
            host: Host::current(),
            destination: Destination::Store(Box::new(Store {
                containerd,
                fetcher,
                upstream: Upstream {
                    registries,
                    client: Client::new(),
                    mirror,
                },
            })),
        }
    }

    /// On CRI-O, whose CRI socket is `socket`: through `relay`.
    pub(crate) fn relay(socket: PathBuf, relay: Arc<Relay>) -> Self {
        Self {
            socket,
            host: Host::current(),
            destination: Destination::Relay(relay),
        }
    }

    /// Fetches each layer of the platform manifest of `image`, just pulled, that the node holds no blob of, and counts
    /// each fetched.
    pub(crate) async fn run(&self, image: &Reference) {
        let root = match image.digest() {
            Some(digest) => Some(digest.clone()),
            None => match cri::list_images(&self.socket).await {
                Ok(listed) => {
                    let listed: Vec<Image> = listed.iter().filter_map(Image::from_listed).collect();
                    root(&listed, image)
                }
                Err(err) => {
                    warn!(%image, error = %err, "the layers of a prewarmed image are not checked for blobs");
                    return;
                }
            },
        };
        let Some(root) = root else {
            debug!(%image, "the runtime lists no digest of a prewarmed image: its layers are not checked for blobs");
            return;
        };
        let missing = match &self.destination {
            Destination::Store(store) => missing(&store.containerd, &root, &self.host).await,
            Destination::Relay(relay) => missing(&**relay.cache(), &root, &self.host).await,
        };
        let missing = match missing {
            Ok(missing) => missing,
            Err(err) => {
                warn!(%image, error = %err, "the layers of a prewarmed image are not checked for blobs");
                return;
            }
        };
        let fetched = fetch_each(image, missing, |layer| async move {
            self.fetch(image.name(), &layer).await
        })
        .await;
        counter!(PREWARM_REFETCHED).increment(fetched);
    }

    /// Fetches the blob `layer` of the repository `name`.
    async fn fetch(&self, name: &str, layer: &Digest) -> Result<(), Unfetched> {
        match &self.destination {
            Destination::Store(store) => {
                if let Some(blob) = store.fetcher.whole(Kind::Blob, layer).await {
                    let size = blob.size();
                    return Ok(store
                        .containerd
                        .write(layer, blob.stream(0, size).await?)
                        .await?);
                }
                let body = store.upstream.blob(name, layer).await?.body;
                let chunks = body
                    .map_err(|err| content::Error::Io(std::io::Error::other(err)))
                    .into_data_stream();
                Ok(store.containerd.write(layer, Box::pin(chunks)).await?)
            }
            Destination::Relay(relay) => {
                let reference = request::Reference::Digest(layer.clone());
                let pull = Pull {
                    kind: Kind::Blob,
                    name,
                    namespace: None,
                    reference: Some(&reference),
                    head: false,
                    range: None,
                    accept: None,
                };
                // The relay serves a blob for the name of an image whose manifest it served: the prewarm pull's.
                let Answer::Served(_, response) = relay.pull(pull).await else {
                    return Err(Unfetched::Unanswered);
                };
                // The relay keeps the blob once its body was read to the end and matched the digest.
                let mut body = response.into_body();
                while let Some(frame) = body.frame().await {
                    frame.map_err(content::Error::Io)?;
                }
                Ok(())
            }
        }
    }
}

impl Upstream {
    /// The answer with the blob `digest` of the repository `name`, from the first source besides the mirror that has it.
    async fn blob(&self, name: &str, digest: &Digest) -> Result<Response, Unfetched> {
        let text = digest.to_string();
        for source in self
            .registries
            .sources(name, registries::Reference::Digest(&text))?
        {
            let request = Request {
                method: Method::GET,
                path: format!("/{}/blobs/{text}", source.repository),
                repository: source.repository.clone(),
                headers: Vec::new(),
            };
            let candidates = source
                .candidates
                .iter()
                .filter(|endpoint| endpoint.authority != self.mirror);
            for endpoint in candidates {
                match self
                    .client
                    .send(endpoint, &source.credentials, &request)
                    .await
                {
                    Ok(response) if response.status == StatusCode::OK => return Ok(response),
                    Ok(response) => {
                        debug!(host = endpoint.authority, status = %response.status, "a source has no blob to refetch");
                    }
                    Err(err) => {
                        debug!(host = endpoint.authority, error = %err, "a source does not answer");
                    }
                }
            }
        }
        Err(Unfetched::Nowhere)
    }
}

/// Fetches each of `layers` of `image` with `fetch`, and returns how many it fetched; a layer it could not fetch is
/// logged, as the node does not announce it.
async fn fetch_each<F>(image: &Reference, layers: Vec<Digest>, fetch: impl Fn(Digest) -> F) -> u64
where
    F: Future<Output = Result<(), Unfetched>>,
{
    let mut fetched = 0;
    for layer in layers {
        match fetch(layer.clone()).await {
            Ok(()) => {
                fetched += 1;
                debug!(%image, %layer, "fetched a layer held without its blob");
            }
            Err(err) => warn!(
                %image,
                %layer,
                error = %err,
                "a layer held without its blob was not fetched: the node does not announce it"
            ),
        }
    }
    fetched
}

/// The manifest `image` was pulled by, as `listed` names it: the repository digest, in its repository, of the image
/// listed under its tag.
fn root(listed: &[Image], image: &Reference) -> Option<Digest> {
    let tag = image.tag()?;
    listed
        .iter()
        .filter(|held| {
            held.tags
                .iter()
                .any(|tagged| tagged.name() == image.name() && tagged.tag() == tag)
        })
        .flat_map(|held| &held.repo_digests)
        .find(|repo| repo.repository == image.name())
        .map(|repo| repo.digest.clone())
}

/// The layers of the image manifest `root` leads to on `host`, that `content` holds no blob of, in order and once each.
async fn missing(
    content: &impl Content,
    root: &Digest,
    host: &Host,
) -> Result<Vec<Digest>, Unread> {
    let mut digest = root.clone();
    let mut bytes = read(content, &digest).await?;
    if let Children::Index { .. } = manifest::children(&bytes)? {
        digest = Index::parse(&bytes)?
            .platform_manifest(host)
            .ok_or_else(|| Unread::NoPlatform(root.to_string()))?
            .clone();
        bytes = read(content, &digest).await?;
    }
    let Children::Image { layers, .. } = manifest::children(&bytes)? else {
        return Err(Unread::Nested(digest.to_string()));
    };
    let mut missing = Vec::new();
    for layer in layers {
        if !missing.contains(&layer) && content.open(&layer).await?.is_none() {
            missing.push(layer);
        }
    }
    Ok(missing)
}

/// The manifest `digest`, which `content` holds.
async fn read(content: &impl Content, digest: &Digest) -> Result<axum::body::Bytes, Unread> {
    let blob = content
        .open(digest)
        .await?
        .ok_or_else(|| Unread::Absent(digest.to_string()))?;
    Ok(blob.read_all(MAX_MANIFEST).await?)
}

#[cfg(test)]
mod tests;
