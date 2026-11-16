//! containerd's images in `k8s.io`, the CRI's namespace, as [`Images`]: CRI `ListImages`, read again at each image
//! event (D118).
//!
//! containerd publishes `/images/create`, `/images/update` and `/images/delete` for every image name it stores
//! (v2.4.2 `core/metadata/images.go:169,270,337`), with the name and no digest: the list itself says what changed. Its
//! garbage collector publishes the images it deletes too (`core/metadata/db.go:355-356`), so the events miss nothing
//! while the stream lasts.

use std::sync::Arc;
use std::time::Duration;

use containerd_client::services::v1::SubscribeRequest;
use containerd_client::services::v1::events_client::EventsClient;
use containerd_client::types::Envelope;
use futures_util::future::BoxFuture;
use tokio::sync::mpsc;

use super::{Containerd, NAMESPACE};
use crate::images::{self, Images, Lost, RELIST, Update};

const TOPICS: [&str; 3] = ["/images/create", "/images/update", "/images/delete"];

/// Whether an event of containerd may change the CRI's image list: an image event in `k8s.io`.
#[must_use]
pub fn hints(envelope: &Envelope) -> bool {
    envelope.namespace == NAMESPACE && TOPICS.contains(&envelope.topic.as_str())
}

impl Images for Containerd {
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
        Box::pin(async move { self.follow_images(&updates, RELIST).await })
    }
}

impl Containerd {
    /// Follows the image list, reading it every `every`, until `updates` closes.
    pub(crate) async fn follow_images(&self, updates: &mpsc::Sender<Update>, every: Duration) {
        images::follow(self.socket(), updates, every, "containerd", |hint| {
            self.image_events(hint)
        })
        .await;
    }

    /// Sends a hint for each image event until the stream ends.
    async fn image_events(&self, hint: mpsc::Sender<()>) -> Lost {
        let Some(channel) = self.channel().await else {
            return Lost::Unreachable("no containerd to subscribe to".to_owned());
        };
        let filters = TOPICS
            .map(|topic| format!("namespace=={NAMESPACE:?},topic=={topic:?}"))
            .to_vec();
        let subscribed = EventsClient::new(channel)
            .subscribe(SubscribeRequest { filters })
            .await;
        let mut stream = match subscribed {
            Ok(response) => response.into_inner(),
            Err(status) => {
                // containerd may have restarted: the next call connects again.
                self.forget_channel().await;
                return Lost::Unreachable(status.to_string());
            }
        };
        loop {
            match stream.message().await {
                Ok(Some(envelope)) => {
                    if hints(&envelope) {
                        // A full channel holds a hint already: the list is read once for both.
                        let _ = hint.try_send(());
                    }
                }
                Ok(None) => return Lost::Ended,
                Err(status) => {
                    self.forget_channel().await;
                    return Lost::Unreachable(status.to_string());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
