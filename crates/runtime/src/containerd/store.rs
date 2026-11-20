//! An in-memory copy of containerd's image store in `k8s.io`: each image name and the digest it targets (D15).
//!
//! The gate looks an image up while it holds the runtime's NRI call, so a lookup reads a snapshot that the follower
//! swaps and takes no lock. The store is filled by one images `List`, then kept by the `/images/*` events, and listed
//! again whenever the event stream ends and every [`RECONCILE`] in between. The events name the image and carry no
//! digest (v2.3.7 `core/metadata/images.go:169,270,337`), so each create or update is followed by a `Get`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use containerd_client::services::v1::events_client::EventsClient;
use containerd_client::services::v1::images_client::ImagesClient;
use containerd_client::services::v1::{
    GetImageRequest, Image, ImageCreate, ImageDelete, ImageUpdate, ListImagesRequest,
    SubscribeRequest,
};
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Code, Request, Status};
use containerd_client::types::Envelope;
use prost::Message as _;
use speculaire_oci::reference::Digest;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

use super::{Containerd, NAMESPACE, with_namespace};

/// How often the images are listed again, for a change whose event was lost.
pub const RECONCILE: Duration = Duration::from_secs(60);

/// How long after subscribing the images are listed once more: containerd answers a subscription only with its first
/// event, so an image created while the first listing ran may have no event.
const SETTLE: Duration = Duration::from_secs(1);

/// How long to wait before following again, after containerd went away.
const RETRY: Duration = Duration::from_secs(1);

const CREATE: &str = "/images/create";
const UPDATE: &str = "/images/update";
const DELETE: &str = "/images/delete";

/// Events the subscription may hold while a listing runs.
const BACKLOG: usize = 1024;

/// What an event of containerd says about an image of `k8s.io`.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    /// The image was created, or its target or labels changed: its name.
    Changed(String),
    /// The image was deleted: its name.
    Deleted(String),
}

/// The image event `envelope` stands for, if it is one of `k8s.io`.
#[must_use]
pub fn event(envelope: &Envelope) -> Option<Event> {
    if envelope.namespace != NAMESPACE {
        return None;
    }
    let event = envelope.event.as_ref()?.value.as_slice();
    match envelope.topic.as_str() {
        CREATE => Some(Event::Changed(ImageCreate::decode(event).ok()?.name)),
        UPDATE => Some(Event::Changed(ImageUpdate::decode(event).ok()?.name)),
        DELETE => Some(Event::Deleted(ImageDelete::decode(event).ok()?.name)),
        _ => None,
    }
}

/// The images of `k8s.io` by name, each with the digest of its target: an index or a manifest.
#[derive(Debug, Default)]
pub struct Store {
    images: ArcSwap<HashMap<String, Digest>>,
}

impl Store {
    /// The target of the image named `name`, a reference the CRI normalised, such as
    /// `docker.io/library/busybox:1.37`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<Digest> {
        self.images.load().get(name).cloned()
    }

    /// Every image name, for a comparison with what containerd lists.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        self.images.load().keys().cloned().collect()
    }
}

/// A store holding the images given, as a test or a benchmark fills it.
impl FromIterator<(String, Digest)> for Store {
    fn from_iter<I: IntoIterator<Item = (String, Digest)>>(images: I) -> Self {
        Self {
            images: ArcSwap::from_pointee(images.into_iter().collect()),
        }
    }
}

/// Why following stopped.
enum Lost {
    /// No containerd to connect to.
    Unreachable,
    /// A call failed.
    Call(Status),
    /// The event stream ended.
    Ended,
}

impl Containerd {
    /// Keeps `store` equal to containerd's image store in `k8s.io` until the agent stops; dropping the future stops it
    /// sooner.
    pub async fn keep(&self, store: &Store) {
        self.keep_every(store, RECONCILE).await;
    }

    /// [`Containerd::keep`], listing every `every`.
    async fn keep_every(&self, store: &Store, every: Duration) {
        loop {
            let lost = self.watch_images(store, every).await;
            // The agent's own teardown cut the connection: that is no failure to report.
            if self.stopping().is_set() {
                return;
            }
            match lost {
                Lost::Unreachable => debug!("no containerd to list images from"),
                Lost::Call(status) => {
                    // containerd may have restarted: the next call connects again.
                    self.forget_channel().await;
                    warn!(error = %status, "containerd's image store cannot be followed: listing it again");
                }
                Lost::Ended => warn!("containerd's image events stopped: listing the images again"),
            }
            tokio::time::sleep(RETRY).await;
        }
    }

    /// Subscribes to the image events, then lists every `every`, and once [`SETTLE`] after subscribing, and applies
    /// each event in between.
    async fn watch_images(&self, store: &Store, every: Duration) -> Lost {
        let Some(channel) = self.channel().await else {
            return Lost::Unreachable;
        };
        let (sender, mut events) = mpsc::channel(BACKLOG);
        let mut subscription = std::pin::pin!(subscribe(channel.clone(), sender));
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut settle = std::pin::pin!(tokio::time::sleep(SETTLE));
        let mut settled = false;
        // The one writer's copy: each change is published as a new snapshot.
        let mut images = HashMap::new();
        loop {
            let applied = tokio::select! {
                ended = &mut subscription => {
                    return match ended {
                        Ok(()) => Lost::Ended,
                        Err(status) => Lost::Call(status),
                    };
                }
                _ = tick.tick() => list(channel.clone()).await.map(|listing| images = listing),
                () = &mut settle, if !settled => {
                    settled = true;
                    list(channel.clone()).await.map(|listing| images = listing)
                }
                // The subscription holds the sender: `events` stays open while it runs.
                Some(envelope) = events.recv() => match event(&envelope) {
                    Some(event) => apply(channel.clone(), &mut images, event).await,
                    None => continue,
                },
            };
            if let Err(status) = applied {
                return Lost::Call(status);
            }
            store.images.store(Arc::new(images.clone()));
        }
    }
}

/// Every image of [`NAMESPACE`] with a target digest that parses.
async fn list(channel: Channel) -> Result<HashMap<String, Digest>, Status> {
    let mut request = Request::new(ListImagesRequest {
        filters: Vec::new(),
    });
    with_namespace(&mut request);
    let images = ImagesClient::new(channel)
        .list(request)
        .await?
        .into_inner()
        .images;
    Ok(images.into_iter().filter_map(target).collect())
}

/// Changes `images` as `event` says, reading a changed image again.
async fn apply(
    channel: Channel,
    images: &mut HashMap<String, Digest>,
    event: Event,
) -> Result<(), Status> {
    let name = match event {
        Event::Deleted(name) => {
            images.remove(&name);
            return Ok(());
        }
        Event::Changed(name) => name,
    };
    let mut request = Request::new(GetImageRequest { name: name.clone() });
    with_namespace(&mut request);
    let found = match ImagesClient::new(channel).get(request).await {
        Ok(response) => response.into_inner().image.and_then(target),
        // Deleted since: its delete event follows.
        Err(status) if status.code() == Code::NotFound => None,
        Err(status) => return Err(status),
    };
    match found {
        Some((name, digest)) => images.insert(name, digest),
        None => images.remove(&name),
    };
    Ok(())
}

/// The name and target digest of `image`, if the digest parses.
fn target(image: Image) -> Option<(String, Digest)> {
    let digest = Digest::parse(&image.target?.digest).ok()?;
    Some((image.name, digest))
}

/// Sends the image events of `k8s.io` to `events` until the stream ends, or `events` closes.
async fn subscribe(channel: Channel, events: mpsc::Sender<Envelope>) -> Result<(), Status> {
    let filters = [CREATE, UPDATE, DELETE]
        .map(|topic| format!("namespace=={NAMESPACE:?},topic=={topic:?}"))
        .to_vec();
    let mut stream = EventsClient::new(channel)
        .subscribe(SubscribeRequest { filters })
        .await?
        .into_inner();
    while let Some(envelope) = stream.message().await? {
        if events.send(envelope).await.is_err() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
