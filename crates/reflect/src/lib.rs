//! The reflector: which agents hold which digests, as each announces for itself over mutual TLS (D2, D16, D97, D105).
//!
//! An agent with `role = "reflector"` serves its API, [`Reflector`]; every agent calls it with its [`client::Client`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

#[cfg(feature = "bench")]
pub mod bench;
pub mod client;
pub mod frame;
pub mod message;
pub mod metrics;
pub use key::Key;
pub use server::{
    LOOKUP_PEERS, Limits, Member, PROTOCOL_VERSION, Reflector, SNAPSHOT_CHUNK, Settings,
};

mod index;
mod key;
mod server;
mod session;
mod sync;

/// The reflector API's messages, generated from `proto/`.
#[expect(
    missing_docs,
    clippy::pedantic,
    reason = "generated: the protobuf comments are the documentation"
)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/speculaire.reflect.v1.rs"));
}

/// A connection to the reflector at `address`, over the TLS of `tls` (`Credentials::client` of the member's node) and
/// [`frame::ALPN`]; it then carries [`frame`]s.
///
/// # Errors
///
/// When the connection or its TLS handshake fails. In TLS 1.3 the server checks the client's certificate after the
/// handshake: its refusal arrives with the first read.
pub async fn connect(
    address: SocketAddr,
    mut tls: ClientConfig,
) -> io::Result<TlsStream<TcpStream>> {
    tls.alpn_protocols = vec![frame::ALPN.to_vec()];
    let tcp = TcpStream::connect(address).await?;
    // A lookup is small: Nagle's algorithm would hold it for the reflector's delayed ACK.
    tcp.set_nodelay(true)?;
    TlsConnector::from(Arc::new(tls))
        .connect(ServerName::IpAddress(address.ip().into()), tcp)
        .await
}
