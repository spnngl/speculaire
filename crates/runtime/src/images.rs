//! The runtime's image list, and how it changes (D116).
//!
//! Both runtimes answer CRI `ListImages`, and neither streams image changes over the CRI. Each follows a hint of its
//! own that the list may have changed: containerd's image events, CRI-O's `images.json` directory. At each hint the
//! list is read again and compared; the whole list is sent at the start, every [`RELIST`], and whenever the hints
//! stopped, so a hint missed costs one interval at most.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use speculaire_oci::reference::Digest;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::warn;

use crate::cri::{self, ListedImage};

/// How often the image list is read again, whatever the hints said (D116).
pub const RELIST: Duration = Duration::from_secs(60);

/// How long to wait before following again, after the runtime went away.
const RETRY: Duration = Duration::from_secs(1);

/// A repository digest the runtime lists for an image: the repository, and the digest it was pulled by.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RepoDigest {
    /// The repository, with its registry: `docker.io/library/busybox`.
    pub repository: String,
    /// The manifest or index digest.
    pub digest: Digest,
}

impl RepoDigest {
    /// Reads `<repository>@<digest>`, as the CRI lists it.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let (repository, digest) = text.rsplit_once('@')?;
        Some(Self {
            repository: repository.to_owned(),
            digest: Digest::parse(digest).ok()?,
        })
    }
}

/// An image the runtime lists.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Image {
    /// The image ID: the config digest of the manifest it was pulled by, on both runtimes.
    pub id: Digest,
    /// Its repository digests, in the runtime's order. On CRI-O they pair each repository with each digest the image
    /// was pulled by, so a registry may never have served some of them (D65).
    pub repo_digests: Vec<RepoDigest>,
}

impl Image {
    /// The image of a CRI answer; `None` when its ID is no digest. containerd lists the ID with its algorithm, CRI-O
    /// with the hex alone; a repository digest that does not parse is left out.
    #[must_use]
    pub fn from_listed(listed: &ListedImage) -> Option<Self> {
        let id = if listed.id.contains(':') {
            Digest::parse(&listed.id)
        } else {
            Digest::parse(&format!("sha256:{}", listed.id))
        }
        .ok()?;
        Some(Self {
            id,
            repo_digests: listed
                .repo_digests
                .iter()
                .filter_map(|text| RepoDigest::parse(text))
                .collect(),
        })
    }
}

/// What a follower of the image list learns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Update {
    /// The whole list: an image it lacks is gone.
    Listing(Vec<Image>),
    /// An image appeared, or its repository digests changed.
    Listed(Image),
    /// The image with this ID is gone.
    Removed(Digest),
}

/// The image list as the updates of a follower left it.
#[derive(Clone, Debug, Default)]
pub struct List {
    images: HashMap<Digest, Image>,
}

impl List {
    /// Applies `update`.
    pub fn apply(&mut self, update: Update) {
        match update {
            Update::Listing(images) => {
                self.images = images
                    .into_iter()
                    .map(|image| (image.id.clone(), image))
                    .collect();
            }
            Update::Listed(image) => {
                self.images.insert(image.id.clone(), image);
            }
            Update::Removed(id) => {
                self.images.remove(&id);
            }
        }
    }

    /// The images listed, in no order.
    pub fn images(&self) -> impl Iterator<Item = &Image> {
        self.images.values()
    }
}

/// The runtime's image list, followed (D116).
pub trait Images: Send + Sync {
    /// Sends the image list, then each change, until `updates` closes. The list comes again every [`RELIST`] and when
    /// the runtime's hints stopped; while the runtime cannot be reached, nothing is sent.
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()>;
}

/// Why a watch stopped.
#[derive(Debug)]
pub(crate) enum Lost {
    /// The runtime cannot be asked, or its hints cannot be followed; the reason is logged.
    Unreachable(String),
    /// The hints stopped.
    Ended,
    /// Nobody reads the updates any more.
    Closed,
}

/// Follows the list on `socket` until `updates` closes: `watch` runs a source of hints into the sender it is given, and
/// returns why it stopped; it is run again after [`RETRY`].
pub(crate) async fn follow<W, F>(
    socket: &Path,
    updates: &mpsc::Sender<Update>,
    every: Duration,
    runtime: &str,
    mut watch: W,
) where
    W: FnMut(mpsc::Sender<()>) -> F,
    F: Future<Output = Lost>,
{
    loop {
        let (hint, hints) = mpsc::channel(1);
        let lost = tokio::select! {
            () = updates.closed() => return,
            lost = relist(socket, updates, every, hints, watch(hint)) => lost,
        };
        match lost {
            Lost::Closed => return,
            Lost::Unreachable(error) => {
                warn!(%error, "{runtime}'s image list cannot be followed: reading it again");
            }
            Lost::Ended => warn!("{runtime}'s image hints stopped: reading its image list again"),
        }
        tokio::select! {
            () = updates.closed() => return,
            () = tokio::time::sleep(RETRY) => {}
        }
    }
}

/// Reads the list at the start, every `every` and at each hint, and sends it or what changed, until `watching` ends.
async fn relist(
    socket: &Path,
    updates: &mpsc::Sender<Update>,
    every: Duration,
    mut hints: mpsc::Receiver<()>,
    watching: impl Future<Output = Lost>,
) -> Lost {
    let mut watching = std::pin::pin!(watching);
    let mut tick = tokio::time::interval(every);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut known: HashMap<Digest, Image> = HashMap::new();
    loop {
        let whole = tokio::select! {
            lost = &mut watching => return lost,
            _ = tick.tick() => true,
            Some(()) = hints.recv() => false,
        };
        let listed = match cri::list_images(socket).await {
            Ok(listed) => listed,
            Err(e) => return Lost::Unreachable(e.to_string()),
        };
        let images: Vec<Image> = listed.iter().filter_map(Image::from_listed).collect();
        let sent = if whole {
            known = images
                .iter()
                .map(|image| (image.id.clone(), image.clone()))
                .collect();
            vec![Update::Listing(images)]
        } else {
            changes(&mut known, images)
        };
        for update in sent {
            if updates.send(update).await.is_err() {
                return Lost::Closed;
            }
        }
    }
}

/// What changed from `known` to `images`; `known` becomes `images`.
fn changes(known: &mut HashMap<Digest, Image>, images: Vec<Image>) -> Vec<Update> {
    let mut now: HashMap<Digest, Image> = images
        .into_iter()
        .map(|image| (image.id.clone(), image))
        .collect();
    let mut updates: Vec<Update> = known
        .keys()
        .filter(|id| !now.contains_key(*id))
        .map(|id| Update::Removed(id.clone()))
        .collect();
    updates.extend(
        now.values()
            .filter(|image| known.get(&image.id) != Some(*image))
            .map(|image| Update::Listed(image.clone())),
    );
    std::mem::swap(known, &mut now);
    updates
}

#[cfg(test)]
mod tests;
