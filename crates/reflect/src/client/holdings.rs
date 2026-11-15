//! What the node holds, as the agent announces it: every stream starts from it, then follows its changes (D2, D98).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use speculaire_oci::reference::Digest;
use tokio::sync::broadcast;

use crate::Key;

/// How many changes a stream may fall behind before it sends a snapshot again.
const BACKLOG: usize = 1024;

/// The digests the node can serve; the agent feeds it from the runtime's inventory.
#[derive(Debug)]
pub struct Holdings {
    digests: Mutex<HashSet<Key>>,
    changes: broadcast::Sender<Arc<Batch>>,
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
            digests: Mutex::default(),
            changes: broadcast::channel(BACKLOG).0,
        }
    }
}

impl Holdings {
    /// Replaces the digests with a full listing: the streams get what differs.
    pub fn replace<'a>(&self, listing: impl IntoIterator<Item = &'a Digest>) {
        let listing: HashSet<Key> = listing.into_iter().map(Key::from).collect();
        let mut digests = self.digests();
        let batch = Batch {
            added: listing.difference(&digests).copied().collect(),
            removed: digests.difference(&listing).copied().collect(),
        };
        *digests = listing;
        self.send(batch);
    }

    /// The node holds `digest`.
    pub fn add(&self, digest: &Digest) {
        let key = Key::from(digest);
        let mut digests = self.digests();
        if digests.insert(key) {
            self.send(Batch {
                added: vec![key],
                removed: Vec::new(),
            });
        }
    }

    /// The node no longer holds `digest`.
    pub fn remove(&self, digest: &Digest) {
        let key = Key::from(digest);
        let mut digests = self.digests();
        if digests.remove(&key) {
            self.send(Batch {
                added: Vec::new(),
                removed: vec![key],
            });
        }
    }

    /// Every digest held now, and the changes after it.
    pub(crate) fn subscribe(&self) -> (Vec<Key>, broadcast::Receiver<Arc<Batch>>) {
        let digests = self.digests();
        (digests.iter().copied().collect(), self.changes.subscribe())
    }

    /// Sends under the lock, so that a subscriber's snapshot and its changes follow each other without a gap. With no
    /// stream up, the change is dropped: the next stream starts with a snapshot (D98).
    fn send(&self, batch: Batch) {
        if !batch.added.is_empty() || !batch.removed.is_empty() {
            let _ = self.changes.send(Arc::new(batch));
        }
    }

    fn digests(&self) -> MutexGuard<'_, HashSet<Key>> {
        self.digests.lock().unwrap_or_else(PoisonError::into_inner)
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
}
