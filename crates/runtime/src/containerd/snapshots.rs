//! The snapshot a container's root filesystem rests on: the chain ID of its image's layers (D15).
//!
//! containerd prepares a container's snapshot, keyed by the container ID, on the chain ID of the image's diff IDs
//! (v2.3.7 `client/container_opts.go:259`). A user-namespaced container on a snapshotter that cannot remap IDs rests
//! instead on a remapped copy whose parent is that chain ID; the container's snapshot then carries the ID mapping
//! labels (v2.3.7 `client/snapshotter_opts_unix.go:62-136`).

use containerd_client::services::v1::snapshots::snapshots_client::SnapshotsClient;
use containerd_client::services::v1::snapshots::{Info, StatSnapshotRequest};
use containerd_client::tonic::{Request, Status};
use speculaire_oci::reference::Digest;

use super::{Containerd, with_namespace};

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

/// The parent of `info`, if it has one.
fn parent(info: Info) -> Result<String, Error> {
    if info.parent.is_empty() {
        return Err(Error::NoParent(info.name));
    }
    Ok(info.parent)
}

#[cfg(test)]
mod tests;
