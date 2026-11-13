//! The reflector: which agents hold which digests, as each announces for itself over mutual TLS (D2, D16, D97).
//!
//! An agent with `role = "reflector"` serves its API, [`Reflector`]; every agent calls it with its [`client::Client`].

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};

pub mod client;
pub mod message;
pub mod metrics;
pub use server::{
    LOOKUP_PEERS, Limits, Member, PROTOCOL_VERSION, Reflector, SNAPSHOT_CHUNK, Settings,
};

mod index;
mod server;
mod session;
mod sync;

/// The reflector API's messages, server and client, generated from `proto/`.
#[expect(
    missing_docs,
    clippy::pedantic,
    clippy::allow_attributes_without_reason,
    clippy::clone_on_ref_ptr,
    reason = "generated: the protobuf comments are the documentation"
)]
pub mod proto {
    tonic::include_proto!("speculaire.reflect.v1");
}

/// A channel to the reflector at `address`, over the TLS of `tls`: `Credentials::client` of the member's node. Wrap it
/// in [`proto::reflector_client::ReflectorClient`].
///
/// # Errors
///
/// When the connection or its TLS handshake fails. In TLS 1.3 the server checks the client's certificate after the
/// handshake: its refusal arrives with the first call.
pub async fn connect(
    address: SocketAddr,
    mut tls: ClientConfig,
) -> Result<Channel, tonic::transport::Error> {
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));
    // The URI only names the authority of requests: the connector dials `address`.
    Endpoint::from_shared(format!("http://{address}"))?
        .connect_with_connector(tower::service_fn(move |_| {
            let connector = connector.clone();
            async move {
                let tcp = TcpStream::connect(address).await?;
                let tls = connector
                    .connect(ServerName::IpAddress(address.ip().into()), tcp)
                    .await?;
                Ok::<_, io::Error>(TokioIo::new(tls))
            }
        }))
        .await
}
