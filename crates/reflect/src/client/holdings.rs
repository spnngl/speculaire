//! What the node holds, as the agent announces it: every stream starts from it, then follows its changes (D2, D98).
//! Each source of keys lists its own: the runtime's content, the artifact store, and the tags under their tag keys
//! (D123). A key is announced while any source holds it (D124).

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use speculaire_oci::reference::Digest;
use tokio::sync::broadcast;

use crate::Key;

/// How many changes a stream may fall behind before it sends a snapshot again.
const BACKLOG: usize = 1024;

/// The digests and tags the node can serve; the agent feeds it from each [`Source`].
#[derive(Debug)]
pub struct Holdings {
    held: Mutex<Held>,
    changes: broadcast::Sender<Arc<Batch>>,
}

/// What lists keys into [`Holdings`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// The runtime's content, or the blob cache where the node relays (D99).
    Content,
    /// The artifact store: the artifacts' manifests and blobs (D121, D124).
    Artifacts,
    /// The tags the runtime lists, each under its tag key (D123).
    Tags,
}

/// The keys of each source, kept apart so that a listing of one replaces only its own.
#[derive(Debug, Default)]
struct Held {
    content: HashSet<Key>,
    artifacts: HashSet<Key>,
    tags: HashSet<Key>,
}

impl Held {
    fn of(&mut self, source: Source) -> &mut HashSet<Key> {
        match source {
            Source::Content => &mut self.content,
            Source::Artifacts => &mut self.artifacts,
            Source::Tags => &mut self.tags,
        }
    }

    /// Whether any source holds `key`: whether it is announced.
    fn holds(&self, key: &Key) -> bool {
        self.content.contains(key) || self.artifacts.contains(key) || self.tags.contains(key)
    }
}

/// One change of [`Holdings`]: keys that came and went, never the same in both.
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
    /// Replaces the keys of `source` with a full listing: the streams get what the node gains or no longer holds.
    pub fn replace<'a>(&self, source: Source, listing: impl IntoIterator<Item = &'a Digest>) {
        let listing: HashSet<Key> = listing.into_iter().map(Key::from).collect();
        let mut held = self.held();
        let before = std::mem::take(held.of(source));
        let added = listing
            .difference(&before)
            .filter(|key| !held.holds(key))
            .copied()
            .collect();
        let gone: Vec<Key> = before.difference(&listing).copied().collect();
        *held.of(source) = listing;
        let removed = gone.into_iter().filter(|key| !held.holds(key)).collect();
        self.send(Batch { added, removed });
    }

    /// `source` holds `digest`.
    pub fn add(&self, source: Source, digest: &Digest) {
        let key = Key::from(digest);
        let mut held = self.held();
        let announced = held.holds(&key);
        if held.of(source).insert(key) && !announced {
            self.send(Batch {
                added: vec![key],
                removed: Vec::new(),
            });
        }
    }

    /// `source` no longer holds `digest`.
    pub fn remove(&self, source: Source, digest: &Digest) {
        let key = Key::from(digest);
        let mut held = self.held();
        if held.of(source).remove(&key) && !held.holds(&key) {
            self.send(Batch {
                added: Vec::new(),
                removed: vec![key],
            });
        }
    }

    /// Every key held now, and the changes after it.
    pub(crate) fn subscribe(&self) -> (Vec<Key>, broadcast::Receiver<Arc<Batch>>) {
        let held = self.held();
        let keys: HashSet<Key> = held
            .content
            .iter()
            .chain(&held.artifacts)
            .chain(&held.tags)
            .copied()
            .collect();
        (keys.into_iter().collect(), self.changes.subscribe())
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
        holdings.add(Source::Content, &digest(1));
        let (digests, mut changes) = holdings.subscribe();
        assert_eq!(digests, [key(1)]);
        // Adding what is held, or removing what is not, is no change.
        holdings.add(Source::Content, &digest(1));
        holdings.remove(Source::Content, &digest(9));
        holdings.add(Source::Content, &digest(2));
        holdings.replace(Source::Content, &[digest(2), digest(3)]);
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
        holdings.replace(Source::Content, &[digest(2), digest(3)]);
        assert!(changes.try_recv().is_err());
    }

    #[test]
    fn each_source_lists_apart_and_the_streams_get_them_together() {
        let holdings = Holdings::default();
        holdings.replace(Source::Content, &[digest(1)]);
        holdings.replace(Source::Tags, &[digest(7)]);
        let (mut keys, mut changes) = holdings.subscribe();
        keys.sort_by_key(ToString::to_string);
        assert_eq!(keys, [key(1), key(7)]);
        holdings.replace(Source::Tags, &[digest(8)]);
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: vec![key(8)],
                removed: vec![key(7)]
            }
        );
        // A listing of the content leaves the tags alone.
        holdings.replace(Source::Content, &[]);
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: Vec::new(),
                removed: vec![key(1)]
            }
        );
        assert_eq!(holdings.subscribe().0, [key(8)]);
    }

    #[test]
    fn a_digest_two_sources_hold_is_announced_once_and_withdrawn_when_both_drop_it() {
        let holdings = Holdings::default();
        let (_, mut changes) = holdings.subscribe();
        holdings.add(Source::Content, &digest(1));
        holdings.replace(Source::Artifacts, &[digest(1), digest(2)]);
        holdings.add(Source::Artifacts, &digest(1));
        let (mut keys, _) = holdings.subscribe();
        keys.sort_by_key(ToString::to_string);
        assert_eq!(keys, [key(1), key(2)]);
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: vec![key(1)],
                removed: Vec::new()
            }
        );
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: vec![key(2)],
                removed: Vec::new()
            }
        );
        assert!(changes.try_recv().is_err());
        // The store still holds it: no change.
        holdings.remove(Source::Content, &digest(1));
        holdings.replace(Source::Content, &[]);
        assert!(changes.try_recv().is_err());
        holdings.add(Source::Content, &digest(1));
        holdings.replace(Source::Artifacts, &[digest(2)]);
        assert!(changes.try_recv().is_err());
        holdings.replace(Source::Content, &[]);
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: Vec::new(),
                removed: vec![key(1)]
            }
        );
        holdings.remove(Source::Artifacts, &digest(2));
        assert_eq!(
            *changes.try_recv().unwrap(),
            Batch {
                added: Vec::new(),
                removed: vec![key(2)]
            }
        );
        assert_eq!(holdings.subscribe().0, []);
    }
}
