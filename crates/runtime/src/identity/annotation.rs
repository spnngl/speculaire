//! containerd 2.3's path, `annotation`: the image name containerd annotates the container with, resolved in its image
//! store, and checked against the container's snapshot (D15, D170).
//!
//! containerd 2.3 sends NRI v0.12.0, whose `Container` names no image. It annotates the container with the name the pod
//! asked for, after any annotation the pod passes through (v2.3.7 `internal/cri/server/container_create.go:921-929`,
//! `:986`), and creates the container's snapshot on its image's chain ID before NRI's `CreateContainer` (`:378`,
//! `:450`), in the snapshotter of the pod's runtime handler (D171). The name resolves to the image's target digest in
//! the store; the target's manifest for the node's platform gives its chain ID; the snapshot must rest on it. A retag between the pull and the create, to an image with other
//! layers, is a mismatch. One with the same layers and another config is not: the gap D15 accepts.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use arc_swap::ArcSwap;
use bytes::Bytes;
use speculaire_nri::api::{Container, PodSandbox};
use speculaire_oci::index::Index;
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::{Digest, Reference};
use speculaire_oci::{chain, referrers};
use speculaire_registry_config::containerd::config::{self as containerd_config, Snapshotters};
use tracing::{debug, warn};

use super::{Identified, MISSING};
use crate::containerd::Containerd;
use crate::containerd::store::Store;
use crate::content::{self, Content as _};

/// The annotation containerd puts the pod's image name in (v2.3.7 `internal/cri/annotations/annotations.go:79`).
pub const IMAGE_NAME: &str = "io.kubernetes.cri.image-name";

/// Why a name has no identity: containerd's image store, as the agent last read it, has no image of that name; an
/// `Unverifiable` reason.
pub const NOT_STORED: &str = "image name not in containerd's image store";

/// Why an image has no identity: its manifest for the node, or its config, cannot be read; an `Unverifiable` reason.
pub const NO_CHAIN: &str = "image layers cannot be read";

/// Why a container has no identity: containerd's snapshot service does not say what its snapshot rests on; an
/// `Unverifiable` reason.
pub const NO_SNAPSHOT: &str = "container snapshot cannot be read";

/// The pod annotation that runs a pod on [`UNTRUSTED_RUNTIME`] (v2.3.7 `internal/cri/annotations/annotations.go:62`).
const UNTRUSTED_WORKLOAD: &str = "io.kubernetes.cri.untrusted-workload";

/// The runtime handler of an untrusted workload (v2.3.7 `internal/cri/config/config.go:499`).
const UNTRUSTED_RUNTIME: &str = "untrusted";

/// The largest manifest or config read: the mirror's limit (D52).
const MAX_DOCUMENT: u64 = 4 << 20;

/// The chain IDs kept, by target digest; past it, all are dropped. An image's chain ID never changes.
const CHAINS: usize = 4096;

/// The `annotation` path of one containerd.
#[derive(Debug)]
pub struct Annotation {
    containerd: Containerd,
    store: Store,
    host: Host,
    /// The image and runtime services' snapshotters, read again at each `Configure`.
    snapshotters: ArcSwap<Snapshotters>,
    /// The chain ID of each target digest resolved so far.
    chains: Mutex<HashMap<Digest, Digest>>,
}

impl Annotation {
    /// The path of `containerd`, on a node of platform `host`.
    #[must_use]
    pub fn new(containerd: Containerd, host: Host) -> Self {
        Self {
            containerd,
            store: Store::default(),
            host,
            snapshotters: ArcSwap::from_pointee(Snapshotters::default()),
            chains: Mutex::new(HashMap::new()),
        }
    }

    /// Reads the snapshotters from containerd's `config.toml` again: the defaults when the file does not exist, the
    /// ones read before when it cannot be read, as containerd keeps running on the config it read.
    pub fn configure(&self) {
        let config = self.containerd.config();
        let snapshotters = match containerd_config::load_snapshotters(&config) {
            Ok(snapshotters) => snapshotters,
            Err(err) if crate::containerd::config_missing(&err, &config) => Snapshotters::default(),
            Err(err) => {
                warn!(config = %config.display(), %err, "containerd's config cannot be read: the gate keeps looking for container snapshots in the snapshotters it read before");
                return;
            }
        };
        self.snapshotters.store(Arc::new(snapshotters));
    }

    /// Keeps the image store until the agent stops.
    pub async fn follow(&self) {
        self.containerd.keep(&self.store).await;
    }

    /// The identity of `container`, created in `pod`: its image's target digest and the name it was asked by, when its
    /// snapshot rests on the image's chain ID.
    pub async fn identify<'a>(&self, pod: &PodSandbox, container: &'a Container) -> Identified<'a> {
        let Some(name) = container.annotations.get(IMAGE_NAME) else {
            return Identified::Unknown(MISSING);
        };
        let Ok(reference) = Reference::parse_docker_ref(name) else {
            return Identified::Unknown(MISSING);
        };
        let Some(target) = self.store.get(&reference.to_string()) else {
            return Identified::Unknown(NOT_STORED);
        };
        let Some(chain) = self.chain(&target).await else {
            return Identified::Unknown(NO_CHAIN);
        };
        // An untrusted workload names no handler or this one (v2.3.7 `internal/cri/config/config.go:731-748`).
        let handler = if pod
            .annotations
            .get(UNTRUSTED_WORKLOAD)
            .is_some_and(|value| value == "true")
        {
            UNTRUSTED_RUNTIME
        } else {
            &pod.runtime_handler
        };
        let snapshotters = self.snapshotters.load_full();
        let snapshotter = snapshotters.of(handler);
        match self
            .containerd
            .snapshot_base(snapshotter, &container.id, &chain)
            .await
        {
            Ok(base) if Digest::parse(&base).is_ok_and(|base| base == chain) => {
                Identified::Listed {
                    digest: target,
                    name,
                }
            }
            Ok(base) => {
                debug!(container = container.id, %name, %chain, base, "the container's snapshot is not its image's");
                Identified::Mismatched
            }
            Err(err) => {
                debug!(container = container.id, snapshotter, %err, "no snapshot base");
                Identified::Unknown(NO_SNAPSHOT)
            }
        }
    }

    /// The chain ID of the image `target` names on this node, kept once read.
    async fn chain(&self, target: &Digest) -> Option<Digest> {
        if let Some(chain) = self.chains().get(target) {
            return Some(chain.clone());
        }
        let chain = match self.read_chain(target).await {
            Ok(chain) => chain,
            Err(err) => {
                debug!(%target, %err, "no chain ID");
                return None;
            }
        };
        let mut chains = self.chains();
        if chains.len() >= CHAINS {
            chains.clear();
        }
        chains.insert(target.clone(), chain.clone());
        Some(chain)
    }

    fn chains(&self) -> std::sync::MutexGuard<'_, HashMap<Digest, Digest>> {
        self.chains.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The chain ID of `target`'s config, through its manifest for the node's platform when it is an index.
    async fn read_chain(&self, target: &Digest) -> Result<Digest, ChainError> {
        let bytes = self.read(target).await?;
        let config = match manifest::children(&bytes)? {
            Children::Image { config, .. } => config,
            Children::Index { .. } => {
                let index = Index::parse(&bytes)?;
                let manifest = index
                    .platform_manifest(&self.host)
                    .ok_or(ChainError::NoPlatform)?;
                match manifest::children(&self.read(manifest).await?)? {
                    Children::Image { config, .. } => config,
                    Children::Index { .. } => return Err(ChainError::Nested),
                }
            }
        };
        Ok(chain::of_config(&self.read(&config).await?)?)
    }

    async fn read(&self, digest: &Digest) -> Result<Bytes, ChainError> {
        let blob = self
            .containerd
            .open(digest)
            .await?
            .ok_or_else(|| ChainError::Absent(Box::new(digest.clone())))?;
        Ok(blob.read_all(MAX_DOCUMENT).await?)
    }
}

/// Why an image has no chain ID.
#[derive(Debug, thiserror::Error)]
enum ChainError {
    #[error(transparent)]
    Content(#[from] content::Error),
    #[error("{0} is not in containerd's content store")]
    Absent(Box<Digest>),
    #[error(transparent)]
    Manifest(#[from] manifest::Error),
    #[error(transparent)]
    Index(#[from] referrers::Error),
    #[error("no image manifest for the node's platform")]
    NoPlatform,
    #[error("the node's manifest is an index")]
    Nested,
    #[error(transparent)]
    Config(#[from] chain::Error),
}

#[cfg(test)]
mod tests;
