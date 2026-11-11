//! Spike 03: a kubelet client certificate as mTLS identity on both sides of a peer connection.
//!
//! `tls-spike serve` and `tls-spike connect <host:port> <node-name>`.
//! Env: TLS_CERT (cert + key PEM, default kubelet's current file), TLS_CA (default cluster CA).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use rustls::client::ResolvesClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::ResolvesServerCert;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsError, RootCertStore, ServerConfig,
    SignatureScheme,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use webpki::KeyUsage;
use x509_parser::prelude::{FromDer, X509Certificate};

const DEFAULT_PORT: u16 = 7481;

fn port() -> u16 {
    std::env::var("TLS_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(DEFAULT_PORT)
}
const KUBELET_CERT: &str = "/var/lib/kubelet/pki/kubelet-client-current.pem";
const CLUSTER_CA: &str = "/etc/kubernetes/pki/ca.crt";

/// What the certificate says about its holder.
struct Identity {
    node: String,
    serial: String,
}

fn identity(der: &CertificateDer<'_>) -> Result<Identity, TlsError> {
    let other = |m: String| TlsError::General(m);
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| other(format!("parse certificate: {e}")))?;
    let orgs: Vec<_> = cert.subject().iter_organization().filter_map(|a| a.as_str().ok()).collect();
    if orgs != ["system:nodes"] {
        return Err(other(format!("subject O={orgs:?} is not system:nodes")));
    }
    let cn = cert.subject().iter_common_name().next().and_then(|a| a.as_str().ok()).unwrap_or_default();
    let Some(node) = cn.strip_prefix("system:node:") else {
        return Err(other(format!("subject CN={cn:?} is not system:node:<name>")));
    };
    Ok(Identity { node: node.to_owned(), serial: cert.raw_serial_as_string() })
}

/// The one verifier, used on both sides: chain to the cluster CA, `clientAuth`, node subject, no hostname.
#[derive(Debug)]
struct NodeVerifier {
    roots: RootCertStore,
    algs: WebPkiSupportedAlgorithms,
    expect: Option<String>,
}

impl NodeVerifier {
    fn check(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: UnixTime) -> Result<Identity, TlsError> {
        let cert = webpki::EndEntityCert::try_from(end_entity).map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
        cert.verify_for_usage(self.algs.all, &self.roots.roots, intermediates, now, KeyUsage::client_auth(), None, None)
            .map_err(|e| TlsError::InvalidCertificate(CertificateError::Other(rustls::OtherError(Arc::new(e)))))?;
        let id = identity(end_entity)?;
        if let Some(expect) = &self.expect
            && *expect != id.node
        {
            return Err(TlsError::General(format!("expected node {expect}, certificate is for node {}", id.node)));
        }
        Ok(id)
    }
}

impl ServerCertVerifier for NodeVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.check(end_entity, intermediates, now).map(|_| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.algs)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

impl ClientCertVerifier for NodeVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, end_entity: &CertificateDer<'_>, intermediates: &[CertificateDer<'_>], now: UnixTime) -> Result<ClientCertVerified, TlsError> {
        self.check(end_entity, intermediates, now).map(|_| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.algs)
    }

    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Serves the certificate in `path`, reloading it when the symlink's target changes (kubelet rotation).
#[derive(Debug)]
struct Reloading {
    path: PathBuf,
    state: Mutex<Option<(PathBuf, Arc<CertifiedKey>)>>,
}

impl Reloading {
    fn new(path: PathBuf) -> Self {
        Self { path, state: Mutex::new(None) }
    }

    fn current(&self) -> Option<Arc<CertifiedKey>> {
        let target = fs::canonicalize(&self.path).ok()?;
        let mut state = self.state.lock().expect("state lock");
        if state.as_ref().is_none_or(|(t, _)| *t != target) {
            let key = load(&target).inspect_err(|e| eprintln!("tls-spike: reload {}: {e:#}", target.display())).ok()?;
            eprintln!("tls-spike: loaded {}", target.display());
            *state = Some((target, Arc::new(key)));
        }
        state.as_ref().map(|(_, k)| Arc::clone(k))
    }
}

impl ResolvesServerCert for Reloading {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current()
    }
}

impl ResolvesClientCert for Reloading {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.current()
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn load(path: &Path) -> Result<CertifiedKey> {
    let certs = CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(path)?;
    Ok(CertifiedKey::new(certs, aws_lc_rs::sign::any_supported_type(&key)?))
}

fn roots(ca: &Path) -> Result<RootCertStore> {
    let mut store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca)? {
        store.add(cert?)?;
    }
    Ok(store)
}

fn verifier(provider: &CryptoProvider, expect: Option<String>) -> Result<Arc<NodeVerifier>> {
    let ca = std::env::var("TLS_CA").unwrap_or_else(|_| CLUSTER_CA.into());
    Ok(Arc::new(NodeVerifier { roots: roots(Path::new(&ca))?, algs: provider.signature_verification_algorithms, expect }))
}

fn cert_path() -> PathBuf {
    PathBuf::from(std::env::var("TLS_CERT").unwrap_or_else(|_| KUBELET_CERT.into()))
}

fn own_serial(resolver: &Reloading) -> String {
    resolver.current().and_then(|k| identity(&k.cert[0]).ok()).map(|i| i.serial).unwrap_or_default()
}

fn peer(conn: &rustls::CommonState) -> String {
    match conn.peer_certificates().and_then(|c| c.first()).map(identity) {
        Some(Ok(id)) => format!("system:node:{} serial={}", id.node, id.serial),
        other => format!("unknown ({other:?})", other = other.map(|r| r.err())),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let provider = Arc::new(aws_lc_rs::default_provider());
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("serve") => serve(provider).await,
        Some("connect") => {
            let addr = args.next().context("connect <host[:port]> <node-name>")?;
            let node = args.next().context("connect <host[:port]> <node-name>")?;
            connect(provider, &addr, &node).await
        }
        _ => bail!("usage: tls-spike serve | connect <host[:port]> <node-name>"),
    }
}

async fn serve(provider: Arc<CryptoProvider>) -> Result<()> {
    let resolver = Arc::new(Reloading::new(cert_path()));
    let config = ServerConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier(&provider, None)?)
        .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind(("::", port())).await?;
    eprintln!("tls-spike: serving on [::]:{}", port());
    loop {
        let (tcp, from) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let resolver = Arc::clone(&resolver);
        tokio::spawn(async move {
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let who = peer(tls.get_ref().1);
                    println!("accepted {from} peer={who} my_serial={}", own_serial(&resolver));
                    let mut line = String::new();
                    let _ = BufReader::new(&mut tls).read_line(&mut line).await;
                    let _ = tls.write_all(b"ok\n").await;
                    let _ = tls.shutdown().await;
                }
                Err(e) => println!("rejected {from}: {e}"),
            }
        });
    }
}

async fn connect(provider: Arc<CryptoProvider>, addr: &str, node: &str) -> Result<()> {
    let resolver = Arc::new(Reloading::new(cert_path()));
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier(&provider, Some(node.to_owned()))?)
        .with_client_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesClientCert>);
    let addr = if addr.contains(':') { addr.to_owned() } else { format!("{addr}:{}", port()) };
    let tcp = TcpStream::connect(&addr).await?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("peer.speculaire.invalid")?, tcp)
        .await
        .map_err(|e| anyhow::anyhow!("handshake failed: {e}"))?;
    println!("connected {addr} server={} my_serial={}", peer(tls.get_ref().1), own_serial(&resolver));
    tls.write_all(b"hello\n").await?;
    let mut reply = String::new();
    BufReader::new(&mut tls).read_line(&mut reply).await?;
    println!("reply {}", reply.trim());
    Ok(())
}
