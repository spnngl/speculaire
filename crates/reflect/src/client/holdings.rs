//! What the node holds, as the agent announces it: every stream starts from it, then follows its changes (D2, D98).
//! Tags are announced beside digests, each under its tag key (D123).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use speculaire_oci::reference::Digest;
use tokio::sync::broadcast;

use crate::Key;

/// How many changes a stream may fall behind before it sends a snapshot again.
const BACKLOG: usize = 1024;

/// The digests and tags the node can serve; the agent feeds it from the runtime's inventory and image list.
#[derive(Debug)]
pub struct Holdings {
    held: Mutex<Held>,
    changes: broadcast::Sender<Arc<Batch>>,
}

/// The keys held, kept apart so that a listing of either replaces only its own.
#[derive(Debug, Default)]
struct Held {
    digests: HashSet<Key>,
    tags: HashSet<Key>,
}

/// One change of [`Holdings`]: digests that came and went, never the same in both.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Batch {
    pub(crate) added: Vec<Key>,
    pub(crate) removed: Vec<Key>,
}

impl Default for Holdings {
    fn default() -> Self {
        Self {
            held: Mutex::default(),
            changes: broadcast::channel(BACKLOG).0,
        }
    }
}

impl Holdings {
    /// Replaces the digests with a full listing: the streams get what differs.
    pub fn replace<'a>(&self, listing: impl IntoIterator<Item = &'a Digest>) {
        let mut held = self.held();
        self.swap(&mut held.digests, listing);
    }

    /// Replaces the tag keys with a full listing (D123): the streams get what differs.
    pub fn replace_tags<'a>(&self, listing: impl IntoIterator<Item = &'a Digest>) {
        let mut held = self.held();
        self.swap(&mut held.tags, listing);
    }

    fn swap<'a>(&self, keys: &mut HashSet<Key>, listing: impl IntoIterator<Item = &'a Digest>) {
        let listing: HashSet<Key> = listing.into_iter().map(Key::from).collect();
        let batch = Batch {
            added: listing.difference(keys).copied().collect(),
            removed: keys.difference(&listing).copied().collect(),
        };
        *keys = listing;
        self.send(batch);
    }

    /// The node holds `digest`.
    pub fn add(&self, digest: &Digest) {
        let key = Key::from(digest);
        let mut held = self.held();
        if held.digests.insert(key) {
            self.send(Batch {
                added: vec![key],
                removed: Vec::new(),
            });
        }
    }

    /// The node no longer holds `digest`.
    pub fn remove(&self, digest: &Digest) {
        let key = Key::from(digest);
        let mut held = self.held();
        if held.digests.remove(&key) {
            self.send(Batch {
                added: Vec::new(),
                removed: vec![key],
            });
        }
    }

    /// Every key held now, and the changes after it.
    pub(crate) fn subscribe(&self) -> (Vec<Key>, broadcast::Receiver<Arc<Batch>>) {
        let held = self.held();
        let keys = held.digests.iter().chain(&held.tags).copied().collect();
        (keys, self.changes.subscribe())
    }

    /// Sends under the lock, so that a subscriber's snapshot and its changes follow each other without a gap. With no
    /// stream up, the change is dropped: the next stream starts with a snapshot (D98).
    fn send(&self, batch: Batch) {
        if !batch.added.is_empty() || !batch.removed.is_empty() {
            let _ = self.changes.send(Arc::new(batch));
        }
    }

    fn held(&self) -> MutexGuard<'_, Held> {
        self.held.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    fn key(n: u8) -> Key {
        Key::from(&digest(n))
    }

    #[test]
    fn a_subscriber_gets_the_digests_then_what_changes() {
        let holdings = Holdings::default();
        holdings.add(&digest(1));
        let (digests, mut changes) = holdings.subscribe();
        assert_eq!(digests, [key(1)]);
        // Adding what is held, or removing what is not, is no change.
        holdings.add(&digest(1));
        holdings.remove(&digest(9));
        holdings.add(&digest(2));
        holdings.replace(&[digest(2), digest(3)]);
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: vec![key(2)],
                removed: Vec::new()
            }
        );
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: vec![key(3)],
                removed: vec![key(1)]
            }
        );
        // A listing equal to what is held is no change.
        holdings.replace(&[digest(2), digest(3)]);
        assert!(changes.try_recv().is_err());
    }

    #[test]
    fn tags_and_digests_are_listed_apart_and_streamed_together() {
        let holdings = Holdings::default();
        holdings.replace(&[digest(1)]);
        holdings.replace_tags(&[digest(7)]);
        let (mut keys, mut changes) = holdings.subscribe();
        keys.sort_by_key(ToString::to_string);
        assert_eq!(keys, [key(1), key(7)]);
        holdings.replace_tags(&[digest(8)]);
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: vec![key(8)],
                removed: vec![key(7)]
            }
        );
        // A digest listing leaves the tags alone.
        holdings.replace(&[]);
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: Vec::new(),
                removed: vec![key(1)]
            }
        );
        assert_eq!(holdings.subscribe().0, [key(8)]);
    }
}
