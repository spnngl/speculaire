//! The snapshot a container's root filesystem rests on: the chain ID of its image's layers (D15).
//!
//! containerd prepares a container's snapshot, keyed by the container ID, on the chain ID of the image's diff IDs
//! (v2.3.7 `client/container_opts.go:259`). A user-namespaced container on a snapshotter that cannot remap IDs rests
//! instead on a remapped copy whose parent is that chain ID; the container's snapshot then carries the ID mapping
//! labels (v2.3.7 `client/snapshotter_opts_unix.go:62-136`).
//!
//! Each prepare is an event, published before the CRI asks NRI's plugins (v2.3.7 `core/metadata/snapshot.go:282`;
//! `internal/cri/server/container_create.go:378`, `:450`): [`Prepared`] keeps the parents it names, so that the gate
//! asks `Stat` only when it reads first (D189).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use containerd_client::events::{SnapshotCommit, SnapshotPrepare, SnapshotRemove};
use containerd_client::services::v1::SubscribeRequest;
use containerd_client::services::v1::events_client::EventsClient;
use containerd_client::services::v1::snapshots::snapshots_client::SnapshotsClient;
use containerd_client::services::v1::snapshots::{Info, StatSnapshotRequest};
use containerd_client::tonic::{Request, Status};
use containerd_client::types::Envelope;
use prost::Message as _;
use speculaire_oci::reference::Digest;
use tracing::debug;

use super::{Containerd, NAMESPACE, with_namespace};

const PREPARE: &str = "/snapshot/prepare";
const COMMIT: &str = "/snapshot/commit";
const REMOVE: &str = "/snapshot/remove";

/// The snapshots kept in [`Prepared`]; past it, all are dropped. A node runs far fewer containers.
const PREPARED: usize = 4096;

/// How long to wait before following again, after containerd went away.
const RETRY: Duration = Duration::from_secs(1);

/// The labels a container's snapshot carries when its user namespace maps IDs (v2.3.7 `core/snapshots/snapshotter.go:39-41`).
const ID_MAPPINGS: [&str; 2] = [
    "containerd.io/snapshot/uidmapping",
    "containerd.io/snapshot/gidmapping",
];

/// Why the base of a snapshot is unknown.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No containerd to connect to.
    #[error("no containerd to ask for snapshots")]
    Unreachable,
    /// `Stat` failed.
    #[error("containerd's snapshot service: {0}")]
    Stat(#[from] Status),
    /// The snapshot rests on nothing.
    #[error("snapshot {0:?} has no parent")]
    NoParent(String),
}

impl Containerd {
    /// The snapshot that snapshot `key` of `snapshotter` rests on: its parent, or the parent of a remapped parent when it
    /// maps IDs and its parent is not `chain`. Takes one `Stat`, two under a remap.
    ///
    /// # Errors
    ///
    /// When containerd is unreachable, a `Stat` fails, or a snapshot has no parent.
    pub async fn snapshot_base(
        &self,
        snapshotter: &str,
        key: &str,
        chain: &Digest,
    ) -> Result<String, Error> {
        let info = self.stat(snapshotter, key).await?;
        let remapped = ID_MAPPINGS
            .iter()
            .any(|label| info.labels.contains_key(*label));
        if !remapped || Digest::parse(&info.parent).is_ok_and(|parent| parent == *chain) {
            return parent(info);
        }
        parent(self.stat(snapshotter, &info.parent).await?)
    }

    /// containerd's `Stat` of snapshot `key` of `snapshotter`.
    async fn stat(&self, snapshotter: &str, key: &str) -> Result<Info, Error> {
        let channel = self.channel().await.ok_or(Error::Unreachable)?;
        let mut request = Request::new(StatSnapshotRequest {
            snapshotter: snapshotter.to_owned(),
            key: key.to_owned(),
        });
        with_namespace(&mut request);
        // A containerd that restarted fails this call, and the channel connects again for the next one.
        let response = SnapshotsClient::new(channel).stat(request).await?;
        Ok(response.into_inner().info.unwrap_or_default())
    }
}

/// The active snapshots of `k8s.io` prepared since the snapshot events were last followed without a break, by key:
/// their snapshotter and the chain ID they rest on. A parent that is no digest, such as a remapped copy, is left out.
#[derive(Debug, Default)]
pub struct Prepared(Mutex<HashMap<String, (String, Digest)>>);

impl Prepared {
    /// Whether snapshot `key` of `snapshotter` was prepared on `chain`. False when no event said: `Stat` tells.
    #[must_use]
    pub fn rests_on(&self, snapshotter: &str, key: &str, chain: &Digest) -> bool {
        self.lock()
            .get(key)
            .is_some_and(|(prepared, parent)| prepared == snapshotter && parent == chain)
    }

    /// Changes the snapshots as the event `envelope` says.
    fn apply(&self, envelope: &Envelope) {
        let Some(event) = envelope.event.as_ref().map(|any| any.value.as_slice()) else {
            return;
        };
        if envelope.namespace != NAMESPACE {
            return;
        }
        let mut snapshots = self.lock();
        match envelope.topic.as_str() {
            PREPARE => {
                let Ok(prepared) = SnapshotPrepare::decode(event) else {
                    return;
                };
                let Ok(parent) = Digest::parse(&prepared.parent) else {
                    snapshots.remove(&prepared.key);
                    return;
                };
                if snapshots.len() >= PREPARED {
                    snapshots.clear();
                }
                snapshots.insert(prepared.key, (prepared.snapshotter, parent));
            }
            // A committed snapshot is no longer active under its key.
            COMMIT => {
                if let Ok(committed) = SnapshotCommit::decode(event) {
                    snapshots.remove(&committed.key);
                }
            }
            REMOVE => {
                if let Ok(removed) = SnapshotRemove::decode(event) {
                    snapshots.remove(&removed.key);
                }
            }
            _ => {}
        }
    }

    fn clear(&self) {
        self.lock().clear();
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, (String, Digest)>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Containerd {
    /// Keeps `prepared` from containerd's snapshot events until the agent stops; dropping the future stops it sooner.
    /// Between two subscriptions, events may be lost: `prepared` is emptied, and fills again from the next.
    pub async fn keep_prepared(&self, prepared: &Prepared) {
        loop {
            let followed = self.follow_snapshots(prepared).await;
            prepared.clear();
            if self.stopping().is_set() {
                return;
            }
            if let Err(status) = followed {
                // containerd may have restarted: the next call connects again.
                self.forget_channel().await;
                debug!(error = %status, "containerd's snapshot events cannot be followed: the gate asks `Stat`");
            }
            tokio::time::sleep(RETRY).await;
        }
    }

    /// Applies each snapshot event of one subscription to `prepared`, emptied once subscribed, until the stream ends.
    async fn follow_snapshots(&self, prepared: &Prepared) -> Result<(), Status> {
        let Some(channel) = self.channel().await else {
            return Ok(());
        };
        let filters = [PREPARE, COMMIT, REMOVE]
            .map(|topic| format!("namespace=={NAMESPACE:?},topic=={topic:?}"))
            .to_vec();
        let mut stream = EventsClient::new(channel)
            .subscribe(SubscribeRequest { filters })
            .await?
            .into_inner();
        prepared.clear();
        while let Some(envelope) = stream.message().await? {
            prepared.apply(&envelope);
        }
        Ok(())
    }
}

/// The parent of `info`, if it has one.
fn parent(info: Info) -> Result<String, Error> {
    if info.parent.is_empty() {
        return Err(Error::NoParent(info.name));
    }
    Ok(info.parent)
}

#[cfg(test)]
mod tests;
