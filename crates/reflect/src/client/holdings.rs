//! What the node holds, as the agent announces it: every stream starts from it, then follows its changes (D2, D98).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use speculaire_oci::reference::Digest;
use tokio::sync::broadcast;

/// How many changes a stream may fall behind before it sends a snapshot again.
const BACKLOG: usize = 1024;

/// The digests the node can serve; the agent feeds it from the runtime's inventory.
#[derive(Debug)]
pub struct Holdings {
    digests: Mutex<HashSet<Digest>>,
    changes: broadcast::Sender<Arc<Batch>>,
}

/// One change of [`Holdings`]: digests that came and went, never the same in both.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Batch {
    pub(crate) added: Vec<Digest>,
    pub(crate) removed: Vec<Digest>,
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
    pub fn replace(&self, listing: HashSet<Digest>) {
        let mut digests = self.digests();
        let batch = Batch {
            added: listing.difference(&digests).cloned().collect(),
            removed: digests.difference(&listing).cloned().collect(),
        };
        *digests = listing;
        self.send(batch);
    }

    /// The node holds `digest`.
    pub fn add(&self, digest: Digest) {
        let mut digests = self.digests();
        if digests.insert(digest.clone()) {
            self.send(Batch {
                added: vec![digest],
                removed: Vec::new(),
            });
        }
    }

    /// The node no longer holds `digest`.
    pub fn remove(&self, digest: &Digest) {
        let mut digests = self.digests();
        if digests.remove(digest) {
            self.send(Batch {
                added: Vec::new(),
                removed: vec![digest.clone()],
            });
        }
    }

    /// Every digest held now, and the changes after it.
    pub(crate) fn subscribe(&self) -> (Vec<Digest>, broadcast::Receiver<Arc<Batch>>) {
        let digests = self.digests();
        (digests.iter().cloned().collect(), self.changes.subscribe())
    }

    /// Sends under the lock, so that a subscriber's snapshot and its changes follow each other without a gap. With no
    /// stream up, the change is dropped: the next stream starts with a snapshot (D98).
    fn send(&self, batch: Batch) {
        if !batch.added.is_empty() || !batch.removed.is_empty() {
            let _ = self.changes.send(Arc::new(batch));
        }
    }

    fn digests(&self) -> MutexGuard<'_, HashSet<Digest>> {
        self.digests.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    #[test]
    fn a_subscriber_gets_the_digests_then_what_changes() {
        let holdings = Holdings::default();
        holdings.add(digest(1));
        let (digests, mut changes) = holdings.subscribe();
        assert_eq!(digests, [digest(1)]);
        // Adding what is held, or removing what is not, is no change.
        holdings.add(digest(1));
        holdings.remove(&digest(9));
        holdings.add(digest(2));
        holdings.replace(HashSet::from([digest(2), digest(3)]));
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: vec![digest(2)],
                removed: Vec::new()
            }
        );
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: vec![digest(3)],
                removed: vec![digest(1)]
            }
        );
        // A listing equal to what is held is no change.
        holdings.replace(HashSet::from([digest(2), digest(3)]));
        assert!(changes.try_recv().is_err());
    }
}
