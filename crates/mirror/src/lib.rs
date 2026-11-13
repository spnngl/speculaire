//! The local registry mirror (D5, D14): the pull half of the distribution API, over TLS 1.3 with a client certificate,
//! from the runtime's own content.
//!
//! What this node does not hold, the mirror answers with a fast 404, so that the runtime falls through to the next
//! host or to upstream; it never answers 401, 408 or 429 (ARCHITECTURE.md § Vocabulary, *fall through*).
//!
//! The peer API, [`peer`], serves the same content to the agents of other nodes.

pub mod cache;
pub mod metrics;
pub mod peer;
mod pulls;
pub mod relay;
pub mod request;
mod serve;
pub mod tls;

pub use pulls::{Answer, Body, Local, Pull, Pulls};
pub use serve::serve;
