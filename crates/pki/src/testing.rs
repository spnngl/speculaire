//! A cluster CA that issues certificates as kubelet's, and a handshake in memory, for tests of the node identity (D16).
#![expect(
    clippy::missing_panics_doc,
    reason = "test support: a key or certificate that cannot be made fails the test"
)]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};
use time::OffsetDateTime;

/// A cluster CA, as kubeadm makes it.
pub struct Cluster {
    ca: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Cluster {
    /// A new CA whose subject common name is `name`.
    #[must_use]
    pub fn new(name: &str) -> Self {
        let key = KeyPair::generate().expect("a CA key");
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = params.self_signed(&key).expect("a CA certificate").pem();
        Self {
            ca,
            issuer: Issuer::new(params, key),
        }
    }

    /// The CA certificate, as PEM.
    #[must_use]
    pub fn ca(&self) -> &str {
        &self.ca
    }

    /// kubelet's PEM file for `node`, as [`kubelet`] asks for it.
    #[must_use]
    pub fn kubelet(&self, node: &str) -> String {
        self.issue(&kubelet(node))
    }

    /// A certificate from `params` with a new key, in one PEM file as kubelet writes it: the certificate, then the key.
    #[must_use]
    pub fn issue(&self, params: &CertificateParams) -> String {
        let key = KeyPair::generate().expect("a key");
        let cert = params.signed_by(&key, &self.issuer).expect("a certificate");
        format!("{}{}", cert.pem(), key.serialize_pem())
    }
}

/// What kubelet's certificate manager asks for: `O=system:nodes, CN=system:node:<node>`, `clientAuth`, valid for a day
/// from an hour ago.
#[must_use]
pub fn kubelet(node: &str) -> CertificateParams {
    let now = SystemTime::now();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::OrganizationName, crate::node::ORGANIZATION);
    params.distinguished_name.push(
        DnType::CommonName,
        format!("{}{node}", crate::node::COMMON_NAME_PREFIX),
    );
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.not_before = OffsetDateTime::from(now - Duration::from_hours(1));
    params.not_after = OffsetDateTime::from(now + Duration::from_hours(24));
    params
}

/// The first certificate in `pem`.
#[must_use]
pub fn der(pem: &str) -> CertificateDer<'static> {
    CertificateDer::from_pem_slice(pem.as_bytes()).expect("a PEM certificate")
}

/// The certificate each side presented in a finished handshake.
#[derive(Debug)]
pub struct Handshake {
    /// The server's, as the client saw it.
    pub server: CertificateDer<'static>,
    /// The client's, as the server saw it.
    pub client: CertificateDer<'static>,
}

/// Runs a handshake between `client` and `server` in memory, to its end.
///
/// # Errors
///
/// The first error of either side: in TLS 1.3, the server refuses the client's certificate after the client finished.
pub fn handshake(server: ServerConfig, client: ClientConfig) -> Result<Handshake, rustls::Error> {
    let name = ServerName::try_from("peer.speculaire.invalid").expect("a valid server name");
    let mut client = Connection::Client(ClientConnection::new(Arc::new(client), name)?);
    let mut server = Connection::Server(ServerConnection::new(Arc::new(server))?);
    // Both directions every round: `|` does not stop at the first that moved bytes.
    while transfer(&mut client, &mut server)? | transfer(&mut server, &mut client)? {}
    let presented = |by: &Connection| {
        by.peer_certificates()
            .and_then(<[CertificateDer<'_>]>::first)
            .map(|cert| cert.clone().into_owned())
    };
    match (presented(&client), presented(&server)) {
        (Some(server), Some(client)) => Ok(Handshake { server, client }),
        _ => Err(rustls::Error::General(
            "the handshake ended without both certificates".to_owned(),
        )),
    }
}

/// Moves what `from` has to send to `to`; whether there was anything.
fn transfer(from: &mut Connection, to: &mut Connection) -> Result<bool, rustls::Error> {
    let mut bytes = Vec::new();
    while from.wants_write() {
        from.write_tls(&mut bytes).expect("writing to memory");
    }
    let mut rest = bytes.as_slice();
    while !rest.is_empty() {
        to.read_tls(&mut rest).expect("reading from memory");
        to.process_new_packets()?;
    }
    Ok(!bytes.is_empty())
}
