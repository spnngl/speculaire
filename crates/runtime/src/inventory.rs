//! What a node can serve to its peers: a listing, then the changes to it (D90, D99).

use std::collections::HashSet;
use std::sync::Arc;

use futures_util::future::BoxFuture;
use speculaire_oci::reference::Digest;
use tokio::sync::mpsc;

/// A change to what the node holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// The node holds the digest now.
    Added(Digest),
    /// The node no longer holds it.
    Removed(Digest),
}

/// What [`Inventory::follow`] sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Update {
    /// Every digest the node holds now; it replaces whatever came before.
    Listing(HashSet<Digest>),
    /// A change since the last listing.
    Change(Change),
}

/// The digests a node can serve.
pub trait Inventory: Send + Sync {
    /// Sends a listing to `updates`, then each change, and a listing again whenever changes may have been missed.
    ///
    /// The future runs until `updates` closes; it retries whatever fails meanwhile.
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()>;
}
