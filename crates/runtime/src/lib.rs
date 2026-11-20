//! containerd and CRI-O: which of them runs on the node (D64), what they say about themselves, and every job that
//! differs between them, behind traits (D90).
//!
//! [`Node`] is the one place that knows which runtime it is. [`Wiring`](wiring::Wiring) points it at the mirror,
//! [`Settings`](settings::Settings) says what it is set to, [`Registries`](registries::Registries) says where images
//! are, [`Content`](content::Content) says what the node holds, [`Inventory`](inventory::Inventory) follows it, and
//! [`Images`](images::Images) follows the runtime's image list, and [`Identity`](identity::Identity) reads a container's
//! image identity.

pub mod certificates;
pub mod containerd;
pub mod content;
pub mod cri;
pub mod crio;
pub mod detect;
pub mod files;
#[cfg(test)]
mod fixture;
pub mod identity;
pub mod images;
pub mod inventory;
mod node;
pub mod paths;
pub mod registries;
pub mod settings;
pub mod version;
pub mod watch;
pub mod wiring;

pub use node::{Fallback, Node, NodeContent};
