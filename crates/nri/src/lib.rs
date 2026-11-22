//! An NRI plugin without any runtime (D9, D163, D166): the multiplexer that carries two ttrpc connections over the one
//! socket between a runtime and a plugin, ttrpc's unary calls, and NRI's plugin protocol, answered by a [`Handler`].

pub mod create;
mod frame;
mod mux;
mod plugin;
mod queue;
mod sync;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod ttrpc;
pub mod version;
mod wire;

/// NRI's messages, generated from the subset of `pkg/api/api.proto` the plugin uses (D166).
#[expect(
    missing_docs,
    clippy::pedantic,
    reason = "generated: the protobuf comments are the documentation"
)]
pub mod api {
    include!(concat!(env!("OUT_DIR"), "/nri.pkg.api.v1alpha1.rs"));
}

pub use frame::{MAX_PAYLOAD, Oversize};
pub use mux::{ConnId, Connection, Connections, Mux, MuxError};
pub use plugin::{
    Answer, Configuration, End, Handler, INDEX, MAX_IN_FLIGHT, NAME, NriVersion,
    REGISTRATION_TIMEOUT, RegistrationError, serve,
};
