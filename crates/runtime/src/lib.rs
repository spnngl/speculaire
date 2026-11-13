//! containerd and CRI-O: which of them runs on the node (D64), what they say about themselves, and every job that
//! differs between them, behind traits (D90).
//!
//! [`Node`] is the one place that knows which runtime it is. [`Wiring`](wiring::Wiring) points it at the mirror,
//! [`Settings`](settings::Settings) says what it is set to, [`Registries`](registries::Registries) says where images
//! are, [`Content`](content::Content) says what the node holds, and [`Inventory`](inventory::Inventory) follows it.

pub mod certificates;
pub mod containerd;
pub mod content;
pub mod cri;
pub mod crio;
pub mod detect;
pub mod files;
#[cfg(test)]
mod fixture;
pub mod inventory;
mod node;
pub mod paths;
pub mod registries;
pub mod settings;
pub mod version;
pub mod watch;
pub mod wiring;

pub use node::{Fallback, Node, NodeContent};
