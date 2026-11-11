//! The registry config of the container runtimes, read as each runtime reads it (D17, D66).
//!
//! The agent reaches registries with the TLS settings and credentials the runtime already has, and `configure` edits
//! the same files. Parsers are ports of the runtimes' own code and are tested against it (D29, D70), so the agent
//! and the runtime agree on every file. Credentials and header values are [`secrecy::SecretString`]s (D37).

pub mod containerd;
mod error;
mod fold;
mod go;
mod header;

pub use error::ParseError;
pub use header::Headers;
