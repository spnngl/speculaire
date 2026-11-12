//! The certificates the agent and the runtime use between themselves (D14, D16).
//!
//! Today that is the mirror's local CA, [`mirror`]; the kubelet identity of the peer API joins it later.

pub mod mirror;
