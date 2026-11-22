//! What a reflector sends a stream unasked, queued until the stream's loop writes it between answers (D183).

use std::collections::HashMap;
use std::sync::{Arc, PoisonError};

use speculaire_oci::reference::Reference;
use tokio::sync::Notify;

use crate::metrics::{self, Stage};
use crate::push::{LIST_CAP, PrewarmList};
use crate::sync::{Mutex, MutexGuard};

/// Why a push was not queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PushError {
    /// The node has no stream that takes pushes: none, or one whose `Hello` says protocol version 1 (D184).
    #[error("the node has no stream that takes pushes")]
    NoStream,
    /// The stream already waits to send [`LIST_CAP`] other images.
    #[error("the stream already waits to send {LIST_CAP} other images")]
    Full,
}

/// Queues pushes for the agents streaming to this reflector, one stream at a time (D183).
#[derive(Clone, Debug, Default)]
pub struct Pushes(Arc<Streams>);

impl Pushes {
    /// Queues a `Prewarm` of `image` for `node`'s stream, unless it waits already.
    ///
    /// # Errors
    ///
    /// When the node has no stream that takes pushes, or its stream waits to send [`LIST_CAP`] other images.
    pub fn prewarm(&self, node: &str, image: &Reference) -> Result<(), PushError> {
        self.0.prewarm(node, image)
    }

    /// Queues `list` for `node`'s stream, in place of any list that waits.
    ///
    /// # Errors
    ///
    /// When the node has no stream that takes pushes.
    pub fn list(&self, node: &str, list: &Arc<PrewarmList>) -> Result<(), PushError> {
        let outbox = self.0.lock().outboxes.get(node).cloned();
        outbox.ok_or(PushError::NoStream)?.list(Arc::clone(list));
        Ok(())
    }

    pub(crate) fn streams(&self) -> &Arc<Streams> {
        &self.0
    }
}

/// The outbox of each node's stream that takes pushes, its latest, and what each new stream is sent at its `Hello`.
#[derive(Debug, Default)]
pub(crate) struct Streams(Mutex<Open>);

#[derive(Debug, Default)]
struct Open {
    outboxes: HashMap<Arc<str>, Arc<Outbox>>,
    /// The member's `prewarm.images` (D186).
    list: Option<Arc<PrewarmList>>,
    /// The images whose wave ended (D186).
    released: Vec<Reference>,
}

impl Streams {
    /// A new outbox for `node`'s stream, which replaces that of its earlier stream. It holds the list and the released
    /// images, sent after the `Hello`'s answer (D186).
    pub(crate) fn open(&self, node: &Arc<str>) -> Arc<Outbox> {
        let mut open = self.lock();
        let outbox = Arc::new(Outbox {
            pending: Mutex::new(Pending {
                list: open.list.clone(),
                images: open.released.clone(),
            }),
            queued: Notify::new(),
        });
        open.outboxes.insert(Arc::clone(node), Arc::clone(&outbox));
        let released = open.released.len() as u64;
        drop(open);
        metrics::sent(Stage::Release, released);
        outbox
    }

    /// Forgets `outbox`, unless a later stream of `node` replaced it.
    pub(crate) fn close(&self, node: &str, outbox: &Arc<Outbox>) {
        let mut open = self.lock();
        if open
            .outboxes
            .get(node)
            .is_some_and(|stream| Arc::ptr_eq(stream, outbox))
        {
            open.outboxes.remove(node);
        }
    }

    /// The nodes with a stream that takes pushes.
    pub(crate) fn nodes(&self) -> Vec<Arc<str>> {
        self.lock().outboxes.keys().cloned().collect()
    }

    /// Queues a `Prewarm` of `image` for `node`'s stream, as [`Pushes::prewarm`].
    pub(crate) fn prewarm(&self, node: &str, image: &Reference) -> Result<(), PushError> {
        let outbox = self.lock().outboxes.get(node).cloned();
        outbox.ok_or(PushError::NoStream)?.prewarm(image)
    }

    /// Queues `list` for every stream, and for each that opens later.
    pub(crate) fn set_list(&self, list: &Arc<PrewarmList>) {
        let mut open = self.lock();
        open.list = Some(Arc::clone(list));
        let outboxes: Vec<_> = open.outboxes.values().cloned().collect();
        drop(open);
        for outbox in outboxes {
            outbox.list(Arc::clone(list));
        }
    }

    /// Marks `image` released: each stream that opens from now on is sent it. Returns the nodes streaming now, which
    /// the caller sends it to.
    pub(crate) fn release(&self, image: &Reference) -> Vec<Arc<str>> {
        let mut open = self.lock();
        if !open.released.contains(image) {
            open.released.push(image.clone());
        }
        open.outboxes.keys().cloned().collect()
    }

    /// Takes `image` back from the released: a new wave of it starts, or it left the list.
    pub(crate) fn withdraw(&self, image: &Reference) {
        self.lock().released.retain(|released| released != image);
    }

    fn lock(&self) -> MutexGuard<'_, Open> {
        // Each change is one map or list operation: a panic leaves no change halfway.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One stream's pushes not written yet. Nothing in it is ever dropped: a newer list replaces the older, and an image
/// waits once however often it is queued, so it holds at most one list and [`LIST_CAP`] images (D183).
#[derive(Debug, Default)]
pub(crate) struct Outbox {
    pending: Mutex<Pending>,
    /// Woken when something is queued; a wake with nobody waiting is kept for the next wait.
    queued: Notify,
}

/// What an [`Outbox`] holds.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    /// The latest list.
    pub(crate) list: Option<Arc<PrewarmList>>,
    /// The images, in the order queued, each once.
    pub(crate) images: Vec<Reference>,
}

impl Outbox {
    fn prewarm(&self, image: &Reference) -> Result<(), PushError> {
        let mut pending = self.lock();
        if !pending.images.contains(image) {
            if pending.images.len() >= LIST_CAP {
                return Err(PushError::Full);
            }
            pending.images.push(image.clone());
        }
        drop(pending);
        self.queued.notify_one();
        Ok(())
    }

    fn list(&self, list: Arc<PrewarmList>) {
        self.lock().list = Some(list);
        self.queued.notify_one();
    }

    /// Waits until something is queued since the last wait ended.
    pub(crate) async fn queued(&self) {
        self.queued.notified().await;
    }

    /// Takes everything queued.
    pub(crate) fn take(&self) -> Pending {
        std::mem::take(&mut *self.lock())
    }

    fn lock(&self) -> MutexGuard<'_, Pending> {
        // Each change is one assignment or push: a panic leaves no change halfway.
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty(pending: &Pending) -> bool {
        pending.list.is_none() && pending.images.is_empty()
    }

    fn image(n: usize) -> Reference {
        Reference::parse_docker_ref(&format!("registry.example/image-{n}")).unwrap()
    }

    #[test]
    fn an_outbox_keeps_each_image_once_up_to_the_cap_and_the_latest_list() {
        let pushes = Pushes::default();
        let node: Arc<str> = Arc::from("a");
        assert_eq!(pushes.prewarm("a", &image(0)), Err(PushError::NoStream));
        let outbox = pushes.streams().open(&node);
        for n in 0..LIST_CAP {
            pushes.prewarm("a", &image(n)).unwrap();
        }
        pushes.prewarm("a", &image(0)).unwrap();
        assert_eq!(pushes.prewarm("a", &image(LIST_CAP)), Err(PushError::Full));
        let first = Arc::new(PrewarmList::new(vec![image(1)]).unwrap());
        let second = Arc::new(PrewarmList::default());
        pushes.list("a", &first).unwrap();
        pushes.list("a", &second).unwrap();
        let taken = outbox.take();
        assert!(taken.list.is_some_and(|list| Arc::ptr_eq(&list, &second)));
        assert_eq!(taken.images, (0..LIST_CAP).map(image).collect::<Vec<_>>());
        assert!(empty(&outbox.take()));
        // Taken, the images make room again.
        pushes.prewarm("a", &image(LIST_CAP)).unwrap();
    }

    #[test]
    fn a_later_stream_of_the_node_takes_its_pushes_over() {
        let pushes = Pushes::default();
        let node: Arc<str> = Arc::from("a");
        let earlier = pushes.streams().open(&node);
        let later = pushes.streams().open(&node);
        pushes.prewarm("a", &image(0)).unwrap();
        assert!(empty(&earlier.take()));
        // The earlier stream's end leaves the later one's outbox.
        pushes.streams().close("a", &earlier);
        pushes.prewarm("a", &image(1)).unwrap();
        assert_eq!(later.take().images, [image(0), image(1)]);
        pushes.streams().close("a", &later);
        assert_eq!(pushes.prewarm("a", &image(2)), Err(PushError::NoStream));
    }
}
