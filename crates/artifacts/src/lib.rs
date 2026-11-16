//! The artifact store and discovery (D121): the agent finds the artifacts of each image the runtime lists upstream,
//! through the node's registry config, and keeps them in its own content-addressed store. The runtime never pulls
//! them. What is kept is untrusted until verification (M5) checks it.
//!
//! [`follow()`] turns the image list into roots, [`Discovery`] finds a root's artifacts, and [`Store`] keeps them.

pub mod discover;
pub mod follow;
pub mod metrics;
pub mod store;

pub use discover::{Discovery, Limits};
pub use follow::follow;
pub use store::{Artifact, Kind, Store};
