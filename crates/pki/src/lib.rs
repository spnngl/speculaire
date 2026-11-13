//! The certificates the agent and the runtime use between themselves, and those of peer links (D14, D16).
//!
//! [`mirror`] is the mirror's local CA; [`node`] is the kubelet identity that nodes present to each other.

pub mod mirror;
pub mod node;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
