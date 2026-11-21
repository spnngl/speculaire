//! The runtime of this node, chosen once at startup, and what it hands out (D90).
//!
//! [`Node`] is built from the [`Runtime`] that [`detect`](crate::detect) found, and gives each concern as a trait:
//! [`Wiring`], [`Settings`], [`Registries`], [`Content`], [`Inventory`] and [`Images`]. Nothing outside this crate matches on the runtime to do
//! a runtime's job; the one thing a trait does not hide is [`Fallback`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;

use crate::containerd::Containerd;
use crate::content::{self, Blob, Content};
use crate::crio::CriO;
use crate::detect::{Runtime, Sockets};
use crate::identity::NodeIdentity;
use crate::identity::annotation::Annotation;
use crate::images::Images;
use crate::inventory::Inventory;
use crate::paths::Paths;
use crate::registries::{ContainerdRegistries, CrioRegistries, Registries};
use crate::settings::Settings;
use crate::wiring::Wiring;

/// What the mirror does for a blob its node does not hold, which is the node's, not the runtime's, to say (D66).
///
/// No trait hides it: the two differ in what the mirror is. Per blob, the mirror answers from the node's own content
/// and the runtime goes upstream for the rest, so the mirror never talks to a registry. With the relay, the runtime
/// asks the mirror for every manifest and blob, and the mirror fetches, verifies and caches them itself: it holds
/// credentials, answers for the digests it checked, and has its own metrics and cache. A trait would make the same
/// call mean two security models; the agent matches on this and starts the one it means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /// The mirror serves what the node holds, and answers 404 for the rest.
    PerBlob,
    /// The mirror pulls through an upstream client and a blob cache.
    Relay,
}

#[derive(Clone, Debug)]
enum Kind {
    Containerd(Containerd),
    CriO(CriO),
}

/// The runtime of this node and the node's files.
#[derive(Clone, Debug)]
pub struct Node {
    kind: Kind,
}

impl Node {
    /// The node whose runtime is `runtime`, with its socket among `sockets` and its files below `paths`.
    ///
    /// `containerd_config` is containerd's `config.toml` when it is not the default one (D87); `systemctl` is what
    /// reloads CRI-O.
    #[must_use]
    pub fn new(
        runtime: Runtime,
        sockets: &Sockets,
        paths: Paths,
        containerd_config: Option<PathBuf>,
        systemctl: impl Into<PathBuf>,
    ) -> Self {
        let kind = match runtime {
            Runtime::Containerd => Kind::Containerd(Containerd::new(
                paths,
                sockets.containerd.clone(),
                containerd_config,
            )),
            Runtime::CriO => Kind::CriO(CriO::new(paths, sockets.crio.clone(), systemctl)),
        };
        Self { kind }
    }

    /// The runtime's name, as errors and logs say it.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.runtime().name()
    }

    /// The runtime.
    #[must_use]
    pub fn runtime(&self) -> Runtime {
        match self.kind {
            Kind::Containerd(_) => Runtime::Containerd,
            Kind::CriO(_) => Runtime::CriO,
        }
    }

    /// The runtime's CRI socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        match &self.kind {
            Kind::Containerd(containerd) => containerd.socket(),
            Kind::CriO(crio) => crio.socket(),
        }
    }

    /// What the mirror does for a blob the node does not hold.
    #[must_use]
    pub fn fallback(&self) -> Fallback {
        match self.kind {
            Kind::Containerd(_) => Fallback::PerBlob,
            Kind::CriO(_) => Fallback::Relay,
        }
    }

    /// How the runtime is pointed at the mirror.
    #[must_use]
    pub fn wiring(&self) -> &dyn Wiring {
        match &self.kind {
            Kind::Containerd(containerd) => containerd,
            Kind::CriO(crio) => crio,
        }
    }

    /// The runtime's settings the agent depends on.
    #[must_use]
    pub fn settings(&self) -> &dyn Settings {
        match &self.kind {
            Kind::Containerd(containerd) => containerd,
            Kind::CriO(crio) => crio,
        }
    }

    /// The runtime's registry config.
    #[must_use]
    pub fn registries(&self) -> Arc<dyn Registries> {
        match &self.kind {
            Kind::Containerd(containerd) => {
                Arc::new(ContainerdRegistries::new(containerd.config()))
            }
            Kind::CriO(crio) => Arc::new(CrioRegistries::new(
                crio.context(),
                crio.socket(),
                crio.dropin(),
            )),
        }
    }

    /// What the runtime holds that peers can read: on containerd, its content in `k8s.io`; on CRI-O, nothing, since
    /// there the blob cache is what peers read (D67, D99).
    #[must_use]
    pub fn inventory(&self) -> Arc<dyn Inventory> {
        match &self.kind {
            Kind::Containerd(containerd) => Arc::new(containerd.clone()),
            Kind::CriO(crio) => Arc::new(crio.clone()),
        }
    }

    /// The runtime's image list, followed: read over the CRI, again at each of the runtime's hints (D121).
    #[must_use]
    pub fn images(&self) -> Arc<dyn Images> {
        match &self.kind {
            Kind::Containerd(containerd) => Arc::new(containerd.clone()),
            Kind::CriO(crio) => Arc::new(crio.clone()),
        }
    }

    /// The image identity the gate reads from NRI's `CreateContainer` (D169, D170).
    #[must_use]
    pub fn identity(&self) -> NodeIdentity {
        match &self.kind {
            Kind::Containerd(containerd) => {
                NodeIdentity::containerd(Annotation::new(containerd.clone(), Host::current()))
            }
            Kind::CriO(_) => NodeIdentity::crio(),
        }
    }

    /// The content the node holds.
    #[must_use]
    pub fn content(&self) -> NodeContent {
        match &self.kind {
            Kind::Containerd(containerd) => NodeContent::Containerd(containerd.clone()),
            Kind::CriO(crio) => NodeContent::CriO(crio.clone()),
        }
    }

    /// The agent stops: a follower of [`images`](Self::images) or [`inventory`](Self::inventory) that loses the
    /// runtime from now on ends, and says nothing, since the agent's own teardown is what cut it.
    pub fn stop(&self) {
        match &self.kind {
            Kind::Containerd(containerd) => containerd.stopping().stop(),
            Kind::CriO(crio) => crio.stopping().stop(),
        }
    }
}

/// Whether the agent stops, shared by the clones of a runtime and so by every follower it handed out.
#[derive(Clone, Debug, Default)]
pub(crate) struct Stopping(Arc<AtomicBool>);

impl Stopping {
    fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Whether [`Node::stop`] was called.
    pub(crate) fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// The [`Content`] of a [`Node`]: its runtime's, behind one type, because `Content` has no `dyn` form.
#[derive(Clone, Debug)]
pub enum NodeContent {
    /// containerd's content directory and service.
    Containerd(Containerd),
    /// CRI-O's: nothing the mirror can read.
    CriO(CriO),
}

impl Content for NodeContent {
    async fn open(&self, digest: &Digest) -> Result<Option<Blob>, content::Error> {
        match self {
            Self::Containerd(containerd) => containerd.open(digest).await,
            Self::CriO(crio) => crio.open(digest).await,
        }
    }
}

#[cfg(test)]
mod tests;
