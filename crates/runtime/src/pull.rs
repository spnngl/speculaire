//! Pulling an image as the kubelet does, and how full the filesystem it lands on is: the same CRI calls on containerd
//! and CRI-O, behind [`Pull`] so the agent's prewarm worker can be tested without a runtime (D90, D188).

use std::io;
use std::path::{Path, PathBuf};

use futures_util::future::BoxFuture;
use speculaire_oci::reference::Reference;
use tokio::sync::OnceCell;

use crate::cri;

/// Pulls images into the runtime, where the kubelet looks for them.
pub trait Pull: Send + Sync {
    /// `ImageService.PullImage` of `image`, through the runtime's registry config and so through the mirror, with no
    /// credentials: the registry config holds them (D17).
    fn pull<'a>(&'a self, image: &'a Reference) -> BoxFuture<'a, Result<(), cri::Error>>;

    /// How full the filesystem images land on is, in percent from 0 to 100, as the kubelet counts it.
    fn usage(&self) -> BoxFuture<'_, Result<u8, UsageError>>;
}

/// Why the image filesystem's usage is unknown.
#[derive(Debug, thiserror::Error)]
pub enum UsageError {
    /// `ImageFsInfo` failed.
    #[error(transparent)]
    Cri(#[from] cri::Error),
    /// `ImageFsInfo` named no filesystem.
    #[error("{} names no image filesystem", socket.display())]
    Unnamed {
        /// The runtime's socket.
        socket: PathBuf,
    },
    /// `statvfs` failed on the mount point.
    #[error("cannot read the usage of {}: {source}", mountpoint.display())]
    Statvfs {
        /// The mount point `ImageFsInfo` named.
        mountpoint: PathBuf,
        /// Why.
        source: io::Error,
    },
}

/// [`Pull`] over a runtime's CRI socket.
#[derive(Debug)]
pub(crate) struct CriPull {
    socket: PathBuf,
    /// The image filesystem's mount point, asked once: CRI-O walks its whole image store to answer.
    mountpoint: OnceCell<PathBuf>,
}

impl CriPull {
    pub(crate) fn new(socket: &Path) -> Self {
        Self {
            socket: socket.to_owned(),
            mountpoint: OnceCell::new(),
        }
    }

    async fn mountpoint(&self) -> Result<&Path, UsageError> {
        let mountpoint = self
            .mountpoint
            .get_or_try_init(|| async {
                cri::image_filesystem(&self.socket)
                    .await?
                    .ok_or_else(|| UsageError::Unnamed {
                        socket: self.socket.clone(),
                    })
            })
            .await?;
        Ok(mountpoint)
    }
}

impl Pull for CriPull {
    fn pull<'a>(&'a self, image: &'a Reference) -> BoxFuture<'a, Result<(), cri::Error>> {
        Box::pin(async move { cri::pull_image(&self.socket, &image.to_string()).await })
    }

    fn usage(&self) -> BoxFuture<'_, Result<u8, UsageError>> {
        Box::pin(async {
            let mountpoint = self.mountpoint().await?.to_owned();
            tokio::task::spawn_blocking(move || {
                rustix::fs::statvfs(&mountpoint)
                    .map(|stat| percent_used(stat.f_blocks, stat.f_bavail))
                    .map_err(|errno| UsageError::Statvfs {
                        mountpoint,
                        source: errno.into(),
                    })
            })
            .await
            .expect("statvfs does not panic")
        })
    }
}

/// The share of a filesystem in use as the kubelet's image garbage collection counts it: what is not available to
/// an unprivileged user, over every block, rounded down for the available share (kubernetes v1.37.0
/// `pkg/kubelet/images/image_gc_manager.go:392`).
fn percent_used(blocks: u64, available: u64) -> u8 {
    if blocks == 0 {
        return 0;
    }
    let available = u128::from(available.min(blocks)) * 100 / u128::from(blocks);
    100 - u8::try_from(available)
        .expect("available is at most every block, so its share is at most 100")
}

#[cfg(test)]
mod tests {
    use super::percent_used;

    #[test]
    fn usage_is_counted_as_the_kubelet_does() {
        assert_eq!(percent_used(0, 0), 0);
        assert_eq!(percent_used(100, 100), 0);
        assert_eq!(percent_used(100, 45), 55);
        assert_eq!(percent_used(1000, 999), 1);
        assert_eq!(percent_used(1000, 1), 100);
        assert_eq!(percent_used(100, 0), 100);
        assert_eq!(percent_used(100, 200), 0);
        assert_eq!(percent_used(u64::MAX, u64::MAX / 2), 51);
    }
}
