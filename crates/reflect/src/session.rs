//! One `Announce` stream, from its `Hello` to its end, which withdraws what it announced (D2).

use std::collections::HashSet;
use std::sync::Arc;

use speculaire_oci::reference::Digest;

use crate::index::{Index, Refused, Stream};
use crate::message::{Announcement, Delta, Hello, Snapshot};
use crate::metrics::Reason;
use crate::server::Settings;

/// Why a stream ends early.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Rejection {
    /// The agent broke a rule; the reflector counts it.
    Refused(Reason, String),
    /// A later stream of the same node took over.
    Superseded,
}

/// What the reflector answers a message with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    /// Send a new snapshot.
    Resync,
}

/// A stream's state: the TLS peer's node, and from its `Hello` on, its entry in the index.
#[derive(Debug)]
pub(crate) struct Session {
    index: Arc<Index>,
    settings: Arc<Settings>,
    /// The node of the TLS peer's certificate.
    peer: Arc<str>,
    open: Option<Open>,
}

#[derive(Debug)]
struct Open {
    stream: Stream,
    /// The chunks of a snapshot not yet ended.
    staged: HashSet<Digest>,
    /// The sequence number of the next delta; `None` until a snapshot ends.
    next: Option<u64>,
}

impl Session {
    pub(crate) const fn new(index: Arc<Index>, settings: Arc<Settings>, peer: Arc<str>) -> Self {
        Self {
            index,
            settings,
            peer,
            open: None,
        }
    }

    /// The node of the TLS peer.
    pub(crate) fn node(&self) -> &str {
        &self.peer
    }

    /// Takes in one message.
    pub(crate) fn handle(&mut self, message: Announcement) -> Result<Option<Reply>, Rejection> {
        let limit = self.settings.limits.digests;
        match (message, &mut self.open) {
            (Announcement::Hello(hello), None) => {
                self.open = Some(self.hello(&hello)?);
                Ok(None)
            }
            (Announcement::Hello(_), Some(_)) => Err(refused(Reason::Malformed, "a second Hello")),
            (_, None) => Err(refused(Reason::Malformed, "no Hello first")),
            (Announcement::Snapshot(snapshot), Some(open)) => {
                open.snapshot(&self.index, snapshot, limit)?;
                Ok(None)
            }
            (Announcement::Delta(delta), Some(open)) => open.delta(&self.index, delta, limit),
        }
    }

    fn hello(&self, hello: &Hello) -> Result<Open, Rejection> {
        if hello.node != *self.peer {
            return Err(refused(
                Reason::Identity,
                &format!(
                    "Hello for node {:?} on a link of node {:?}",
                    hello.node, self.peer
                ),
            ));
        }
        if !self.settings.versions.contains(&hello.version) {
            return Err(refused(
                Reason::Version,
                &format!(
                    "protocol version {} is not in {:?}",
                    hello.version, self.settings.versions
                ),
            ));
        }
        Ok(Open {
            stream: self.index.join(&self.peer, hello.peer),
            staged: HashSet::new(),
            next: None,
        })
    }
}

impl Open {
    fn snapshot(
        &mut self,
        index: &Index,
        snapshot: Snapshot,
        limit: usize,
    ) -> Result<(), Rejection> {
        self.staged.extend(snapshot.digests);
        if self.staged.len() > limit {
            return Err(too_many(limit));
        }
        if snapshot.last {
            index
                .replace(&self.stream, std::mem::take(&mut self.staged))
                .map_err(|_| Rejection::Superseded)?;
            self.next = Some(snapshot.seq);
        }
        Ok(())
    }

    fn delta(
        &mut self,
        index: &Index,
        delta: Delta,
        limit: usize,
    ) -> Result<Option<Reply>, Rejection> {
        match self.next {
            Some(next) if next == delta.seq => {
                index
                    .apply(&self.stream, delta.added, &delta.removed, limit)
                    .map_err(|refused| match refused {
                        Refused::Superseded => Rejection::Superseded,
                        Refused::Limit => too_many(limit),
                    })?;
                self.next = Some(next.wrapping_add(1));
                Ok(None)
            }
            // Deltas after a gap are of no use until the next snapshot: one resync asks for it.
            Some(_) => {
                self.next = None;
                Ok(Some(Reply::Resync))
            }
            None => Ok(None),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(open) = &self.open {
            self.index.leave(&open.stream);
        }
    }
}

fn refused(reason: Reason, why: &str) -> Rejection {
    Rejection::Refused(reason, why.to_owned())
}

fn too_many(limit: usize) -> Rejection {
    refused(Reason::Digests, &format!("more than {limit} digests"))
}
