//! containerd's content in `k8s.io`, the CRI's namespace, as an [`Inventory`]: `List`, then the content events (D99).
//!
//! containerd publishes `/content/create` when a writer commits (v2.4.2 and v2.3.7 `core/metadata/content.go:632`)
//! and `/content/delete` on an explicit delete (`:236`). Its garbage collector deletes content and publishes neither:
//! it names only image deletes and snapshot removals (v2.4.2 `core/metadata/db.go:348-365`). So the content is listed
//! again every [`RECONCILE`], and whenever the event stream ends.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use containerd_client::events::{ContentCreate, ContentDelete};
use containerd_client::services::v1::content_client::ContentClient;
use containerd_client::services::v1::events_client::EventsClient;
use containerd_client::services::v1::{ListContentRequest, SubscribeRequest};
use containerd_client::tonic::transport::Channel;
use containerd_client::tonic::{Request, Status};
use containerd_client::types::Envelope;
use futures_util::future::BoxFuture;
use prost::Message as _;
use speculaire_oci::reference::Digest;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

use super::{Containerd, NAMESPACE, with_namespace};
use crate::inventory::{Change, Inventory, Update};

/// How often the content is listed again, for what the garbage collector deleted (D99).
pub const RECONCILE: Duration = Duration::from_secs(60);

/// How long to wait before following again, after containerd went away.
const RETRY: Duration = Duration::from_secs(1);

const CREATE: &str = "/content/create";
const DELETE: &str = "/content/delete";

/// Events the subscription may hold while the listing runs.
const BACKLOG: usize = 1024;

/// The change an event of containerd stands for: content created or deleted in `k8s.io`, with a digest that
/// parses. Every other event is none.
#[must_use]
pub fn change(envelope: &Envelope) -> Option<Change> {
    if envelope.namespace != NAMESPACE {
        return None;
    }
    let event = envelope.event.as_ref()?.value.as_slice();
    let (digest, change): (String, fn(Digest) -> Change) = match envelope.topic.as_str() {
        CREATE => (ContentCreate::decode(event).ok()?.digest, Change::Added),
        DELETE => (ContentDelete::decode(event).ok()?.digest, Change::Removed),
        _ => return None,
    };
    Digest::parse(&digest).ok().map(change)
}

/// Why following stopped.
enum Lost {
    /// No containerd to connect to.
    Unreachable,
    /// A call failed.
    Call(Status),
    /// The event stream ended.
    Ended,
    /// Nobody reads the updates any more.
    Closed,
}

impl Inventory for Containerd {
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
        Box::pin(async move { self.follow_every(&updates, RECONCILE).await })
    }
}

impl Containerd {
    /// Follows the content, listing it every `every`, until `updates` closes.
    async fn follow_every(&self, updates: &mpsc::Sender<Update>, every: Duration) {
        loop {
            let lost = tokio::select! {
                () = updates.closed() => return,
                lost = self.watch(updates, every) => lost,
            };
            match lost {
                Lost::Closed => return,
                Lost::Unreachable => debug!("no containerd to list content from"),
                Lost::Call(status) => {
                    // containerd may have restarted: the next call connects again.
                    self.forget_channel().await;
                    warn!(error = %status, "containerd's content cannot be followed: listing it again");
                }
                Lost::Ended => warn!("containerd's content events stopped: listing it again"),
            }
            tokio::select! {
                () = updates.closed() => return,
                () = tokio::time::sleep(RETRY) => {}
            }
        }
    }

    /// Subscribes to the content events, then lists every `every` and forwards each event in between.
    ///
    /// containerd answers a subscription only with its first event, so the subscription is polled beside the listings.
    /// A change between the subscription and the first listing can wait for the next listing.
    async fn watch(&self, updates: &mpsc::Sender<Update>, every: Duration) -> Lost {
        let Some(channel) = self.channel().await else {
            return Lost::Unreachable;
        };
        let (sender, mut events) = mpsc::channel(BACKLOG);
        let mut subscription = std::pin::pin!(subscribe(channel.clone(), sender));
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            let update = tokio::select! {
                ended = &mut subscription => {
                    return match ended {
                        Ok(()) => Lost::Ended,
                        Err(status) => Lost::Call(status),
                    };
                }
                _ = tick.tick() => match list(channel.clone()).await {
                    Ok(listing) => Update::Listing(listing),
                    Err(status) => return Lost::Call(status),
                },
                // The subscription holds the sender: `events` stays open while it runs.
                Some(envelope) = events.recv() => match change(&envelope) {
                    Some(change) => Update::Change(change),
                    None => continue,
                },
            };
            if updates.send(update).await.is_err() {
                return Lost::Closed;
            }
        }
    }
}

/// Every digest in [`NAMESPACE`] that parses.
async fn list(channel: Channel) -> Result<HashSet<Digest>, Status> {
    let mut request = Request::new(ListContentRequest {
        filters: Vec::new(),
    });
    with_namespace(&mut request);
    let mut stream = ContentClient::new(channel)
        .list(request)
        .await?
        .into_inner();
    let mut listing = HashSet::new();
    while let Some(response) = stream.message().await? {
        listing.extend(
            response
                .info
                .into_iter()
                .filter_map(|info| Digest::parse(&info.digest).ok()),
        );
    }
    Ok(listing)
}

/// Sends the content events of `k8s.io` to `events` until the stream ends, or `events` closes.
async fn subscribe(channel: Channel, events: mpsc::Sender<Envelope>) -> Result<(), Status> {
    let filters = [CREATE, DELETE]
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
