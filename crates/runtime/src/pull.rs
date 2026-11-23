//! Pulling an image as the kubelet does, how full the filesystem it lands on is, and pinning it: the same CRI calls on
//! containerd and CRI-O but the pin, behind [`Pull`] so the agent's prewarm worker can be tested without a runtime
//! (D90, D188, D191).

use std::io;
use std::path::{Path, PathBuf};

use futures_util::future::BoxFuture;
use speculaire_oci::reference::Reference;
use tokio::sync::OnceCell;
use tracing::debug;

use crate::{containerd, cri};

/// Pulls images into the runtime, where the kubelet looks for them.
pub trait Pull: Send + Sync {
    /// `ImageService.PullImage` of `image`, through the runtime's registry config and so through the mirror, with no
    /// credentials: the registry config holds them (D17).
    fn pull<'a>(&'a self, image: &'a Reference) -> BoxFuture<'a, Result<(), cri::Error>>;

    /// How full the filesystem images land on is, in percent from 0 to 100, as the kubelet counts it.
    fn usage(&self) -> BoxFuture<'_, Result<u8, UsageError>>;

    /// Pins `image`, so the kubelet's image garbage collection keeps it, and marks the pin as the agent's; answers
    /// whether `image` carries the agent's pin. An image pinned already, by the runtime's config or an operator, is
    /// left alone.
    fn pin<'a>(&'a self, image: &'a Reference) -> BoxFuture<'a, Result<bool, cri::Error>>;

    /// Takes the pin off `image` if the agent marked it.
    fn unpin<'a>(&'a self, image: &'a Reference) -> BoxFuture<'a, Result<(), cri::Error>>;

    /// The images whose pin the agent marked.
    fn marked(&self) -> BoxFuture<'_, Result<Vec<Reference>, cri::Error>>;
}

/// Whether the runtime can pin an image from the CRI's side.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Pinning {
    /// containerd: by a label on the image's name.
    Label,
    /// CRI-O pins only the images of its config's `pinned_images`, so the agent does not pin there (D65).
    None,
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
    pinning: Pinning,
    /// The image filesystem's mount point, asked once: CRI-O walks its whole image store to answer.
    mountpoint: OnceCell<PathBuf>,
}

impl CriPull {
    pub(crate) fn new(socket: &Path, pinning: Pinning) -> Self {
        Self {
            socket: socket.to_owned(),
            pinning,
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

    fn pin<'a>(&'a self, image: &'a Reference) -> BoxFuture<'a, Result<bool, cri::Error>> {
        Box::pin(async move {
            match self.pinning {
                Pinning::Label => containerd::pins::pin(&self.socket, image).await,
                Pinning::None => {
                    debug!(%image, "left unpinned: the runtime has no pin the agent may set");
                    Ok(false)
                }
            }
        })
    }

    fn unpin<'a>(&'a self, image: &'a Reference) -> BoxFuture<'a, Result<(), cri::Error>> {
        Box::pin(async move {
            match self.pinning {
                Pinning::Label => containerd::pins::unpin(&self.socket, image).await,
                Pinning::None => Ok(()),
            }
        })
    }

    fn marked(&self) -> BoxFuture<'_, Result<Vec<Reference>, cri::Error>> {
        Box::pin(async {
            match self.pinning {
                Pinning::Label => containerd::pins::marked(&self.socket).await,
                Pinning::None => Ok(Vec::new()),
            }
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
