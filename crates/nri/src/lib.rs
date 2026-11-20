//! NRI's protocol, without any runtime: the multiplexer that carries two ttrpc connections over the one socket between
//! a runtime and a plugin (D9, D163).

mod frame;
mod mux;
mod queue;
mod sync;

pub use frame::{MAX_PAYLOAD, Oversize};
pub use mux::{ConnId, Connection, Connections, Mux, MuxError};
