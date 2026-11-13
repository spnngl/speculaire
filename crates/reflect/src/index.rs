//! Which agents hold which digests: soft state, as the agents' streams announce it (D2).
//!
//! Each node and each digest gets a small integer, so that a digest's holders and a node's digests are roaring
//! bitmaps: D2 sizes 20 million pairs this way.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, PoisonError};

use roaring::RoaringBitmap;
use speculaire_oci::reference::Digest;

use crate::sync::{Mutex, MutexGuard};

/// The index, shared by every stream and lookup.
#[derive(Debug, Default)]
pub(crate) struct Index {
    inner: Mutex<Inner>,
}

/// One `Announce` stream's hold on its node's entry: a later stream for the node takes it over.
#[derive(Debug)]
pub(crate) struct Stream {
    node: Arc<str>,
    id: u64,
}

/// Why a change to the index was not made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refused {
    /// A later stream of the same node took the entry over.
    Superseded,
    /// The node would hold more digests than the limit.
    Limit,
}

/// An agent another may fetch from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Holder {
    pub(crate) node: Arc<str>,
    pub(crate) peer: SocketAddr,
}

#[derive(Debug, Default)]
struct Inner {
    /// The last stream number given.
    streams: u64,
    nodes: HashMap<Arc<str>, u32>,
    /// By node number; `None` is free for the next node.
    agents: Vec<Option<Agent>>,
    free_agents: Vec<u32>,
    digests: HashMap<Digest, u32>,
    /// By digest number; `None` is free for the next digest.
    holders: Vec<Option<Holders>>,
    free_holders: Vec<u32>,
    pairs: u64,
}

#[derive(Debug)]
struct Agent {
    node: Arc<str>,
    peer: SocketAddr,
    stream: u64,
    digests: RoaringBitmap,
}

#[derive(Debug)]
struct Holders {
    digest: Digest,
    nodes: RoaringBitmap,
}

impl Index {
    /// Opens a stream for `node`, whose peer API is at `peer`: it takes over the node's entry and empties it.
    pub(crate) fn join(&self, node: &str, peer: SocketAddr) -> Stream {
        let mut inner = self.lock();
        inner.streams += 1;
        let id = inner.streams;
        let node = if let Some(&slot) = inner.nodes.get(node) {
            inner.empty(slot);
            let agent = inner.agent(slot);
            agent.peer = peer;
            agent.stream = id;
            Arc::clone(&agent.node)
        } else {
            let name: Arc<str> = Arc::from(node);
            let agent = Agent {
                node: Arc::clone(&name),
                peer,
                stream: id,
                digests: RoaringBitmap::new(),
            };
            let inner = &mut *inner;
            let slot = allocate(&mut inner.agents, &mut inner.free_agents, agent);
            inner.nodes.insert(Arc::clone(&name), slot);
            name
        };
        inner.publish();
        Stream { node, id }
    }

    /// Replaces what the stream's node holds with `digests`, a whole snapshot.
    pub(crate) fn replace(&self, stream: &Stream, digests: HashSet<Digest>) -> Result<(), Refused> {
        let mut inner = self.lock();
        let slot = inner.owned(stream)?;
        let kept: RoaringBitmap = digests
            .iter()
            .filter_map(|digest| inner.digests.get(digest).copied())
            .collect();
        let gone = &inner.agent(slot).digests - &kept;
        for digest in &gone {
            inner.release(slot, digest);
        }
        for digest in digests {
            inner.hold(slot, digest);
        }
        inner.publish();
        Ok(())
    }

    /// Removes `removed`, then adds `added`, to what the stream's node holds, if it then holds at most `limit` digests.
    pub(crate) fn apply(
        &self,
        stream: &Stream,
        added: Vec<Digest>,
        removed: &[Digest],
        limit: usize,
    ) -> Result<(), Refused> {
        let mut inner = self.lock();
        let slot = inner.owned(stream)?;
        let mut next = inner.agent(slot).digests.clone();
        for digest in removed {
            if let Some(&number) = inner.digests.get(digest) {
                next.remove(number);
            }
        }
        let fresh: HashSet<&Digest> = added
            .iter()
            .filter(|digest| {
                inner
                    .digests
                    .get(*digest)
                    .is_none_or(|&number| !next.contains(number))
            })
            .collect();
        if usize::try_from(next.len()).map_or(true, |held| held + fresh.len() > limit) {
            return Err(Refused::Limit);
        }
        for digest in removed {
            if let Some(&number) = inner.digests.get(digest) {
                inner.release(slot, number);
            }
        }
        for digest in added {
            inner.hold(slot, digest);
        }
        inner.publish();
        Ok(())
    }

    /// Ends the stream: if it still holds its node's entry, the node and all it held leave the index.
    pub(crate) fn leave(&self, stream: &Stream) {
        let mut inner = self.lock();
        let Ok(slot) = inner.owned(stream) else {
            return;
        };
        inner.empty(slot);
        inner.nodes.remove(&stream.node);
        inner.agents[at(slot)] = None;
        inner.free_agents.push(slot);
        inner.publish();
    }

    /// Up to `limit` holders of `digest`, from a random one on and never `asking`: lookups spread over the holders.
    pub(crate) fn lookup(&self, digest: &Digest, asking: &str, limit: usize) -> Vec<Holder> {
        let inner = self.lock();
        let Some(holders) = inner
            .digests
            .get(digest)
            .and_then(|&number| inner.holders[at(number)].as_ref())
        else {
            return Vec::new();
        };
        let nodes = &holders.nodes;
        let asking = inner.nodes.get(asking).copied();
        let start = u32::try_from(nodes.len())
            .ok()
            .and_then(|len| nodes.select(fastrand::u32(..len)))
            .unwrap_or_default();
        nodes
            .range(start..)
            .chain(nodes.range(..start))
            .filter(|&slot| Some(slot) != asking)
            .take(limit)
            .filter_map(|slot| inner.agents[at(slot)].as_ref())
            .map(|agent| Holder {
                node: Arc::clone(&agent.node),
                peer: agent.peer,
            })
            .collect()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        // The index holds no invariant a panic can break halfway that a later stream cannot repair.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Inner {
    /// The node number of the entry `stream` holds.
    fn owned(&self, stream: &Stream) -> Result<u32, Refused> {
        self.nodes
            .get(&stream.node)
            .copied()
            .filter(|&slot| {
                self.agents[at(slot)]
                    .as_ref()
                    .is_some_and(|agent| agent.stream == stream.id)
            })
            .ok_or(Refused::Superseded)
    }

    fn agent(&mut self, slot: u32) -> &mut Agent {
        self.agents[at(slot)]
            .as_mut()
            .expect("a node number of the map has an agent")
    }

    /// Marks `slot` as a holder of `digest`, numbering the digest if new.
    fn hold(&mut self, slot: u32, digest: Digest) {
        let number = if let Some(&number) = self.digests.get(&digest) {
            number
        } else {
            let holders = Holders {
                digest: digest.clone(),
                nodes: RoaringBitmap::new(),
            };
            let number = allocate(&mut self.holders, &mut self.free_holders, holders);
            self.digests.insert(digest, number);
            number
        };
        if self.agent(slot).digests.insert(number) {
            self.holders_of(number).nodes.insert(slot);
            self.pairs += 1;
        }
    }

    /// Removes digest `number` from what `slot` holds.
    fn release(&mut self, slot: u32, number: u32) {
        if self.agent(slot).digests.remove(number) {
            self.unhold(slot, number);
        }
    }

    /// Removes `slot` from the holders of digest `number`, forgetting the digest when none is left.
    fn unhold(&mut self, slot: u32, number: u32) {
        self.pairs -= 1;
        let holders = self.holders_of(number);
        holders.nodes.remove(slot);
        if holders.nodes.is_empty()
            && let Some(holders) = self.holders[at(number)].take()
        {
            self.digests.remove(&holders.digest);
            self.free_holders.push(number);
        }
    }

    fn empty(&mut self, slot: u32) {
        let held = std::mem::take(&mut self.agent(slot).digests);
        for number in &held {
            self.unhold(slot, number);
        }
    }

    fn holders_of(&mut self, number: u32) -> &mut Holders {
        self.holders[at(number)]
            .as_mut()
            .expect("a digest number an agent holds has holders")
    }

    fn publish(&self) {
        crate::metrics::index(self.nodes.len(), self.digests.len(), self.pairs);
    }
}

fn at(number: u32) -> usize {
    usize::try_from(number).expect("a u32 fits a usize")
}

/// Puts `value` in a free slot, or a new one; its number.
fn allocate<T>(slots: &mut Vec<Option<T>>, free: &mut Vec<u32>, value: T) -> u32 {
    let number = free.pop().unwrap_or_else(|| {
        slots.push(None);
        u32::try_from(slots.len() - 1).expect("fewer than 2^32 nodes and digests")
    });
    slots[at(number)] = Some(value);
    number
}

#[cfg(test)]
impl Index {
    /// What each node holds, after checking that both directions of the index and its counts agree.
    fn held(&self) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
        let inner = self.lock();
        let mut held = std::collections::BTreeMap::new();
        let mut pairs = 0;
        for (node, &slot) in &inner.nodes {
            let agent = inner.agents[at(slot)].as_ref().expect("an agent");
            assert_eq!(agent.node, *node);
            let digests = held
                .entry(node.to_string())
                .or_insert_with(std::collections::BTreeSet::new);
            for number in &agent.digests {
                let holders = inner.holders[at(number)].as_ref().expect("holders");
                assert!(holders.nodes.contains(slot));
                assert_eq!(inner.digests.get(&holders.digest), Some(&number));
                digests.insert(holders.digest.to_string());
                pairs += 1;
            }
        }
        let holding: u64 = inner
            .holders
            .iter()
            .flatten()
            .map(|holders| holders.nodes.len())
            .sum();
        assert_eq!(holding, pairs);
        assert_eq!(inner.pairs, pairs);
        assert_eq!(inner.digests.len(), inner.holders.iter().flatten().count());
        assert_eq!(inner.nodes.len(), inner.agents.iter().flatten().count());
        held
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    pub(super) fn digest(n: u32) -> Digest {
        Digest::parse(&format!("sha256:{n:064x}")).unwrap()
    }

    pub(super) fn peer(n: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, n], 7484))
    }

    fn set(numbers: &[u32]) -> HashSet<Digest> {
        numbers.iter().copied().map(digest).collect()
    }

    fn held(pairs: &[(&str, &[u32])]) -> BTreeMap<String, BTreeSet<String>> {
        pairs
            .iter()
            .map(|(node, numbers)| {
                let digests = numbers.iter().map(|&n| digest(n).to_string()).collect();
                ((*node).to_owned(), digests)
            })
            .collect()
    }

    #[test]
    fn a_snapshot_replaces_and_a_delta_changes_what_a_node_holds() {
        let index = Index::default();
        let a = index.join("a", peer(1));
        index.replace(&a, set(&[1, 2])).unwrap();
        let b = index.join("b", peer(2));
        index.replace(&b, set(&[2, 3])).unwrap();
        index.replace(&a, set(&[2, 4])).unwrap();
        assert_eq!(index.held(), held(&[("a", &[2, 4]), ("b", &[2, 3])]));
        index
            .apply(&b, vec![digest(5), digest(3)], &[digest(3), digest(2)], 2)
            .unwrap();
        assert_eq!(index.held(), held(&[("a", &[2, 4]), ("b", &[3, 5])]));
        assert_eq!(
            index.apply(&b, vec![digest(6)], &[], 2),
            Err(Refused::Limit)
        );
        assert_eq!(index.held(), held(&[("a", &[2, 4]), ("b", &[3, 5])]));
        index.leave(&a);
        assert_eq!(index.held(), held(&[("b", &[3, 5])]));
    }

    #[test]
    fn a_later_stream_empties_the_entry_and_the_earlier_one_changes_nothing() {
        let index = Index::default();
        let first = index.join("a", peer(1));
        index.replace(&first, set(&[1])).unwrap();
        let second = index.join("a", peer(2));
        assert_eq!(index.held(), held(&[("a", &[])]));
        index.replace(&second, set(&[2])).unwrap();
        assert_eq!(index.replace(&first, set(&[3])), Err(Refused::Superseded));
        assert_eq!(
            index.apply(&first, vec![digest(3)], &[], 9),
            Err(Refused::Superseded)
        );
        index.leave(&first);
        assert_eq!(index.held(), held(&[("a", &[2])]));
        let holders = index.lookup(&digest(2), "b", 8);
        assert_eq!(
            holders,
            [Holder {
                node: Arc::from("a"),
                peer: peer(2)
            }]
        );
    }

    #[test]
    fn freed_numbers_are_reused() {
        let index = Index::default();
        for round in 0..3 {
            let a = index.join("a", peer(1));
            index.replace(&a, set(&[round, round + 1])).unwrap();
            index.leave(&a);
        }
        let inner = index.lock();
        assert_eq!((inner.agents.len(), inner.holders.len()), (1, 2));
    }
}

/// Concurrent streams under Shuttle's schedules (D97): `just shuttle`.
#[cfg(all(test, shuttle))]
mod schedules {
    use std::collections::{BTreeMap, BTreeSet};

    use super::tests::{digest, peer};
    use super::*;

    #[test]
    fn concurrent_streams_never_leave_a_pair_of_a_closed_one() {
        shuttle::check_random(
            || {
                let index = Arc::new(Index::default());
                // Two streams of `a` race, one of them closing; `b` closes; `c` stays open.
                let streams = [
                    ("a", 1, false),
                    ("a", 2, true),
                    ("b", 3, false),
                    ("c", 4, true),
                ];
                let threads = streams.map(|(node, n, open)| {
                    let index = Arc::clone(&index);
                    shuttle::thread::spawn(move || {
                        let stream = index.join(node, peer(n));
                        let _ = index.replace(&stream, [digest(n.into()), digest(0)].into());
                        let _ =
                            index.apply(&stream, vec![digest(u32::from(n) + 10)], &[digest(0)], 10);
                        if !open {
                            index.leave(&stream);
                        }
                        (stream, n, open)
                    })
                });
                let ended = threads.map(|thread| thread.join().expect("a stream thread"));
                // A node's entry is its last stream's, while that stream is open: the index numbers streams as
                // they join.
                let mut last: BTreeMap<&str, &(Stream, u8, bool)> = BTreeMap::new();
                for ended in &ended {
                    let node = &*ended.0.node;
                    if last.get(node).is_none_or(|other| other.0.id < ended.0.id) {
                        last.insert(node, ended);
                    }
                }
                let expected: BTreeMap<String, BTreeSet<String>> = last
                    .into_iter()
                    .filter(|(_, (_, _, open))| *open)
                    .map(|(node, (_, n, _))| {
                        let digests = [digest((*n).into()), digest(u32::from(*n) + 10)];
                        (
                            node.to_owned(),
                            digests.map(|digest| digest.to_string()).into(),
                        )
                    })
                    .collect();
                assert_eq!(index.held(), expected);
                for (stream, _, _) in &ended {
                    index.leave(stream);
                }
                assert!(index.held().is_empty());
            },
            2_000,
        );
    }
}
