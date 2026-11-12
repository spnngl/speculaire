//! The local registry mirror (D5, D14): the pull half of the distribution API, over TLS 1.3 with a client certificate,
//! from the runtime's own content.
//!
//! What this node does not hold, the mirror answers with a fast 404, so that the runtime falls through to the next
//! host or to upstream; it never answers 401, 408 or 429 (ARCHITECTURE.md § Vocabulary, *fall through*).

pub mod content;
pub mod metrics;
pub mod request;
mod serve;
pub mod tls;

pub use serve::serve;
