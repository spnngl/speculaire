//! The node identity (D16, D95): the kubelet client certificate this node presents on both sides of a peer link, the
//! cluster CA it checks other nodes' certificates against, and the one verifier that checks them.
//!
//! [`Credentials`] holds what was last loaded, and a handshake reads only that. Loading a file again swaps it in whole
//! or, when it cannot be used, leaves the one in use; the agent decides when to load (D95).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use std::{fmt, io};

use arc_swap::ArcSwapOption;
use rustls::client::ResolvesClientCert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{self, CryptoProvider, WebPkiSupportedAlgorithms, aws_lc_rs};
use rustls::pki_types::pem::{self, PemObject as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert, VerifierBuilderError, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, OtherError,
    RootCertStore, ServerConfig, SignatureScheme,
};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;

/// The subject organization of every node certificate.
pub const ORGANIZATION: &str = "system:nodes";

/// What the subject common name of a node certificate starts with; the node's name follows it.
pub const COMMON_NAME_PREFIX: &str = "system:node:";

/// Why a peer certificate is refused beyond its chain, whose refusals are rustls' own [`CertificateError`]s.
///
/// A verifier reports it as [`CertificateError::Other`].
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// The bytes are not an X.509 certificate.
    #[error("not a certificate: {0}")]
    Encoding(String),
    /// The subject's organizations are not exactly `system:nodes`.
    #[error("subject O={0:?} is not system:nodes")]
    Organization(Vec<String>),
    /// The subject's common names are not exactly one `system:node:<name>`, with a name.
    #[error("subject CN={0:?} is not system:node:<name>")]
    CommonName(Vec<String>),
    /// The certificate is another node's than the one the client asked for.
    #[error("expected node {expected}, certificate is for node {presented}")]
    OtherNode {
        /// The node the client asked for.
        expected: String,
        /// The node the certificate names.
        presented: String,
    },
    /// No cluster CA is loaded, so no certificate can be checked.
    #[error("no cluster CA is loaded")]
    NoAuthority,
}

// rustls shows `CertificateError::Other` with `Debug`: this is what a log of a refused handshake reads.
impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl From<Refusal> for rustls::Error {
    fn from(refusal: Refusal) -> Self {
        CertificateError::Other(OtherError(Arc::new(refusal))).into()
    }
}

/// Why the contents of a certificate or CA file cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum Problem {
    /// The file holds no certificate.
    #[error("no certificate in it")]
    NoCertificate,
    /// A PEM section cannot be read.
    #[error("unreadable PEM: {0}")]
    Pem(pem::Error),
    /// The certificate file holds no private key that rustls reads.
    #[error("no usable private key in it: {0}")]
    Key(pem::Error),
    /// The private key is not the certificate's.
    #[error("the private key does not match the certificate")]
    Mismatch,
    /// The certificate is not a node's.
    #[error(transparent)]
    Subject(#[from] Refusal),
    /// rustls refuses the key or a CA certificate.
    #[error(transparent)]
    Tls(rustls::Error),
    /// rustls cannot check peer certificates against the CA.
    #[error("the CA cannot be used: {0}")]
    Authority(VerifierBuilderError),
}

/// Why a file was not loaded; each names the file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The file does not exist: on a node that is joining, kubelet has not written it yet (D16).
    #[error("{} does not exist", path.display())]
    Absent {
        /// The file.
        path: PathBuf,
    },
    /// The file exists and cannot be read.
    #[error("cannot read {}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        source: io::Error,
    },
    /// The file was read and its contents cannot be used.
    #[error("{}: {problem}", path.display())]
    Invalid {
        /// The file.
        path: PathBuf,
        /// Why.
        problem: Problem,
    },
}

/// The node a certificate names: `<name>` of the subject `O=system:nodes, CN=system:node:<name>` (D16).
///
/// # Errors
///
/// When `der` is not a certificate, or its subject is not a node's.
pub fn node_subject(der: &[u8]) -> Result<String, Refusal> {
    node_of(&certificate(der)?)
}

fn certificate(der: &[u8]) -> Result<X509Certificate<'_>, Refusal> {
    X509Certificate::from_der(der)
        .map(|(_, cert)| cert)
        .map_err(|err| Refusal::Encoding(err.to_string()))
}

fn node_of(cert: &X509Certificate<'_>) -> Result<String, Refusal> {
    // An attribute that is not a string still counts, so that it cannot hide among the strings.
    let text = |value: &x509_parser::x509::AttributeTypeAndValue<'_>| {
        value
            .as_str()
            .map_or_else(|_| "<not a string>".to_owned(), str::to_owned)
    };
    let subject = cert.subject();
    let organizations: Vec<String> = subject.iter_organization().map(text).collect();
    if organizations != [ORGANIZATION] {
        return Err(Refusal::Organization(organizations));
    }
    let names: Vec<String> = subject.iter_common_name().map(text).collect();
    if let [name] = names.as_slice()
        && let Some(node) = name.strip_prefix(COMMON_NAME_PREFIX)
        && !node.is_empty()
    {
        return Ok(node.to_owned());
    }
    Err(Refusal::CommonName(names))
}

/// A node certificate with its key, as this node presents it.
#[derive(Debug)]
pub struct Identity {
    node: String,
    expiry: SystemTime,
    key: Arc<CertifiedKey>,
}

impl Identity {
    /// Reads kubelet's PEM file: the certificate, the chain above it if any, and the private key.
    fn parse(pem: &[u8], provider: &CryptoProvider) -> Result<Self, Problem> {
        let chain = CertificateDer::pem_slice_iter(pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Problem::Pem)?;
        let leaf = chain.first().ok_or(Problem::NoCertificate)?;
        let cert = certificate(leaf)?;
        let node = node_of(&cert)?;
        let expiry = SystemTime::from(cert.validity().not_after.to_datetime());
        let key = PrivateKeyDer::from_pem_slice(pem).map_err(Problem::Key)?;
        let key = CertifiedKey::from_der(chain, key, provider).map_err(|err| match err {
            rustls::Error::InconsistentKeys(_) => Problem::Mismatch,
            other => Problem::Tls(other),
        })?;
        Ok(Self {
            node,
            expiry,
            key: Arc::new(key),
        })
    }

    /// The node the certificate names.
    #[must_use]
    pub fn node(&self) -> &str {
        &self.node
    }

    /// When the certificate expires: kubelet replaces it well before then.
    #[must_use]
    pub const fn expiry(&self) -> SystemTime {
        self.expiry
    }
}

/// The cluster CA, as the chain check of every peer certificate: to it, with `clientAuth`, valid now.
#[derive(Debug)]
struct Authority {
    chain: Arc<dyn ClientCertVerifier>,
}

impl Authority {
    fn parse(pem: &[u8], provider: &Arc<CryptoProvider>) -> Result<Self, Problem> {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(pem) {
            roots
                .add(cert.map_err(Problem::Pem)?)
                .map_err(Problem::Tls)?;
        }
        if roots.is_empty() {
            return Err(Problem::NoCertificate);
        }
        let chain =
            WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(provider))
                .build()
                .map_err(Problem::Authority)?;
        Ok(Self { chain })
    }
}

/// This node's identity and the cluster CA, as both sides of a peer link use them; either is absent until loaded.
///
/// It resolves the certificate a handshake presents, on either side, without touching a file.
#[derive(Debug)]
pub struct Credentials {
    provider: Arc<CryptoProvider>,
    identity: ArcSwapOption<Identity>,
    authority: ArcSwapOption<Authority>,
}

impl Default for Credentials {
    /// Neither identity nor CA yet, on the aws-lc-rs provider (D13).
    fn default() -> Self {
        Self {
            provider: Arc::new(aws_lc_rs::default_provider()),
            identity: ArcSwapOption::empty(),
            authority: ArcSwapOption::empty(),
        }
    }
}

impl Credentials {
    /// Loads kubelet's certificate and key from `path`, one PEM file, and swaps them in; returns them.
    ///
    /// The path is read once, through its symlink: kubelet repoints the link on rotation and deletes older files.
    ///
    /// # Errors
    ///
    /// When the file is absent or unreadable, the key does not match the certificate, or the certificate is not a node's;
    /// the identity in use stays.
    pub fn load_identity(&self, path: &Path) -> Result<Arc<Identity>, Error> {
        let identity = Arc::new(Identity::parse(&read(path)?, &self.provider).map_err(
            |problem| Error::Invalid {
                path: path.to_owned(),
                problem,
            },
        )?);
        self.identity.store(Some(Arc::clone(&identity)));
        Ok(identity)
    }

    /// Loads the cluster CA from `path`, one or more PEM certificates, and swaps it in.
    ///
    /// # Errors
    ///
    /// When the file is absent or unreadable, or holds no certificate rustls accepts as a root; the CA in use stays.
    pub fn load_authority(&self, path: &Path) -> Result<(), Error> {
        let authority =
            Authority::parse(&read(path)?, &self.provider).map_err(|problem| Error::Invalid {
                path: path.to_owned(),
                problem,
            })?;
        self.authority.store(Some(Arc::new(authority)));
        Ok(())
    }

    /// The identity in use, if one was loaded.
    #[must_use]
    pub fn identity(&self) -> Option<Arc<Identity>> {
        self.identity.load_full()
    }

    /// Whether both the identity and the CA are loaded: a peer link can be made only then (D16).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.identity.load().is_some() && self.authority.load().is_some()
    }

    /// The server side of a peer link: TLS 1.3, presenting this node's identity, requiring a node certificate.
    ///
    /// # Panics
    ///
    /// Never: aws-lc-rs supports TLS 1.3.
    #[must_use]
    pub fn server(self: &Arc<Self>) -> ServerConfig {
        ServerConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("aws-lc-rs supports TLS 1.3")
            .with_client_cert_verifier(Arc::new(self.verifier(None)))
            .with_cert_resolver(Arc::<Self>::clone(self))
    }

    /// The client side of a peer link to `node`: TLS 1.3, presenting this node's identity, requiring `node`'s
    /// certificate. The server name a connection gives is not checked: the node name is.
    ///
    /// # Panics
    ///
    /// Never: aws-lc-rs supports TLS 1.3.
    #[must_use]
    pub fn client(self: &Arc<Self>, node: &str) -> ClientConfig {
        self.client_of(Some(node.to_owned()))
    }

    /// The client side of a link to any node of the cluster, such as a load balancer's backend: the caller reads which
    /// node answered from the handshake (D2).
    ///
    /// # Panics
    ///
    /// Never: aws-lc-rs supports TLS 1.3.
    #[must_use]
    pub fn client_any(self: &Arc<Self>) -> ClientConfig {
        self.client_of(None)
    }

    fn client_of(self: &Arc<Self>, node: Option<String>) -> ClientConfig {
        ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("aws-lc-rs supports TLS 1.3")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(self.verifier(node)))
            .with_client_cert_resolver(Arc::<Self>::clone(self))
    }

    fn verifier(self: &Arc<Self>, expected: Option<String>) -> Verifier {
        Verifier {
            credentials: Arc::clone(self),
            expected,
        }
    }

    fn key(&self) -> Option<Arc<CertifiedKey>> {
        self.identity
            .load()
            .as_ref()
            .map(|identity| Arc::clone(&identity.key))
    }
}

fn read(path: &Path) -> Result<Vec<u8>, Error> {
    std::fs::read(path).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => Error::Absent {
            path: path.to_owned(),
        },
        _ => Error::Read {
            path: path.to_owned(),
            source,
        },
    })
}

impl ResolvesServerCert for Credentials {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.key()
    }
}

impl ResolvesClientCert for Credentials {
    fn resolve(&self, _: &[&[u8]], _: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        self.key()
    }

    fn has_certs(&self) -> bool {
        self.identity.load().is_some()
    }
}

/// The one check of a peer certificate, on both sides (D16): its chain to the cluster CA in use, `clientAuth`, a node
/// subject, and, on the client side, the node asked for. No hostname: kubelet client certificates have no SAN.
#[derive(Debug)]
struct Verifier {
    credentials: Arc<Credentials>,
    expected: Option<String>,
}

impl Verifier {
    fn check(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        let authority = self.credentials.authority.load();
        let authority = authority.as_ref().ok_or(Refusal::NoAuthority)?;
        authority
            .chain
            .verify_client_cert(end_entity, intermediates, now)?;
        let presented = node_subject(end_entity)?;
        match &self.expected {
            Some(expected) if *expected != presented => Err(Refusal::OtherNode {
                expected: expected.clone(),
                presented,
            }
            .into()),
            _ => Ok(()),
        }
    }

    fn algorithms(&self) -> &WebPkiSupportedAlgorithms {
        &self.credentials.provider.signature_verification_algorithms
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity, intermediates, now)
            .map(|()| ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls12_signature(message, cert, signature, self.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(message, cert, signature, self.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms().supported_schemes()
    }
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        // kubelet's certificate is the only one a node has; a hint would not change which it presents.
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check(end_entity, intermediates, now)
            .map(|()| ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls12_signature(message, cert, signature, self.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        crypto::verify_tls13_signature(message, cert, signature, self.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms().supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose};
    use time::OffsetDateTime;

    use super::*;
    use crate::testing::{Cluster, der, handshake, kubelet};

    /// A node of `cluster`, its files in a directory of its own: kubelet's file, and the cluster's CA.
    struct Node {
        dir: tempfile::TempDir,
        credentials: Arc<Credentials>,
    }

    impl Node {
        fn new(cluster: &Cluster, pem: &str) -> Self {
            let node = Self {
                dir: tempfile::tempdir().unwrap(),
                credentials: Arc::new(Credentials::default()),
            };
            fs::write(node.ca(), cluster.ca()).unwrap();
            node.credentials.load_authority(&node.ca()).unwrap();
            node.rotate(pem).unwrap();
            node
        }

        fn certificate(&self) -> PathBuf {
            self.dir.path().join("kubelet-client-current.pem")
        }

        fn ca(&self) -> PathBuf {
            self.dir.path().join("ca.crt")
        }

        /// Writes `pem` as kubelet's file and loads it.
        fn rotate(&self, pem: &str) -> Result<Arc<Identity>, Error> {
            fs::write(self.certificate(), pem).unwrap();
            self.credentials.load_identity(&self.certificate())
        }
    }

    /// Where the private key starts in a PEM file of [`Cluster::issue`].
    fn key_at(pem: &str) -> usize {
        pem.find("-----BEGIN PRIVATE KEY").unwrap()
    }

    /// What the server side, and the client side asking for `expected`, say of the certificate in `pem`.
    fn verdicts(
        checker: &Arc<Credentials>,
        pem: &str,
        expected: &str,
    ) -> [Result<(), rustls::Error>; 2] {
        let cert = der(pem);
        let now = UnixTime::now();
        let name = ServerName::try_from("peer.speculaire.invalid").unwrap();
        [
            checker
                .verifier(None)
                .verify_client_cert(&cert, &[], now)
                .map(|_| ()),
            checker
                .verifier(Some(expected.to_owned()))
                .verify_server_cert(&cert, &[], &name, &[], now)
                .map(|_| ()),
        ]
    }

    /// What a node of a cluster says, on both sides, of a certificate of node `b` of that cluster, edited by `edit`.
    fn verdicts_of(edit: impl FnOnce(&mut CertificateParams)) -> [Result<(), rustls::Error>; 2] {
        let cluster = Cluster::new("kubernetes");
        let node = Node::new(&cluster, &cluster.kubelet("a"));
        let mut params = kubelet("b");
        edit(&mut params);
        verdicts(&node.credentials, &cluster.issue(&params), "b")
    }

    fn refusal(result: &Result<(), rustls::Error>) -> Option<&Refusal> {
        match result {
            Err(rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(err)))) => {
                err.downcast_ref::<Refusal>()
            }
            _ => None,
        }
    }

    #[test]
    fn a_node_of_the_cluster_is_accepted_on_both_sides() {
        for verdict in verdicts_of(|_| ()) {
            assert!(verdict.is_ok(), "{verdict:?}");
        }
    }

    #[test]
    fn a_node_of_another_cluster_is_refused_on_both_sides() {
        let cluster = Cluster::new("kubernetes");
        let node = Node::new(&cluster, &cluster.kubelet("a"));
        let other = Cluster::new("other").kubelet("b");
        for verdict in verdicts(&node.credentials, &other, "b") {
            assert_eq!(verdict, Err(CertificateError::UnknownIssuer.into()));
        }
        // kubeadm names every cluster CA `kubernetes`: the chain finds the issuer by name, and its signature fails.
        let other = Cluster::new("kubernetes").kubelet("b");
        for verdict in verdicts(&node.credentials, &other, "b") {
            assert_eq!(verdict, Err(CertificateError::BadSignature.into()));
        }
    }

    #[test]
    fn a_subject_without_the_nodes_organization_is_refused_on_both_sides() {
        let verdicts = verdicts_of(|params| {
            params.distinguished_name.remove(DnType::OrganizationName);
        });
        for verdict in verdicts {
            assert_eq!(refusal(&verdict), Some(&Refusal::Organization(Vec::new())));
            assert_eq!(
                verdict.unwrap_err().to_string(),
                "invalid peer certificate: Other(OtherError(subject O=[] is not system:nodes))"
            );
        }
    }

    #[test]
    fn a_common_name_without_the_node_prefix_is_refused_on_both_sides() {
        let verdicts = verdicts_of(|params| {
            params
                .distinguished_name
                .push(DnType::CommonName, "system:nodes:b");
        });
        for verdict in verdicts {
            assert_eq!(
                refusal(&verdict),
                Some(&Refusal::CommonName(vec!["system:nodes:b".to_owned()]))
            );
        }
    }

    #[test]
    fn another_node_than_the_one_asked_for_is_refused_by_the_client() {
        let cluster = Cluster::new("kubernetes");
        let node = Node::new(&cluster, &cluster.kubelet("a"));
        let [server, client] = verdicts(&node.credentials, &cluster.kubelet("c"), "b");
        assert!(server.is_ok(), "the server asks for no node: {server:?}");
        assert_eq!(
            client.unwrap_err().to_string(),
            "invalid peer certificate: Other(OtherError(expected node b, certificate is for node c))"
        );
    }

    #[test]
    fn a_server_only_certificate_is_refused_for_its_purpose_on_both_sides() {
        let verdicts = verdicts_of(|params| {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        });
        for verdict in verdicts {
            assert!(
                matches!(
                    verdict,
                    Err(rustls::Error::InvalidCertificate(
                        CertificateError::InvalidPurposeContext { .. }
                    ))
                ),
                "{verdict:?}"
            );
        }
    }

    #[test]
    fn an_expired_certificate_is_refused_on_both_sides() {
        let verdicts = verdicts_of(|params| {
            params.not_before = OffsetDateTime::now_utc() - time::Duration::days(2);
            params.not_after = OffsetDateTime::now_utc() - time::Duration::days(1);
        });
        for verdict in verdicts {
            assert!(
                matches!(
                    verdict,
                    Err(rustls::Error::InvalidCertificate(
                        CertificateError::ExpiredContext { .. }
                    ))
                ),
                "{verdict:?}"
            );
        }
    }

    #[test]
    fn nothing_is_accepted_before_a_ca_is_loaded() {
        let cluster = Cluster::new("kubernetes");
        let credentials = Arc::new(Credentials::default());
        for verdict in verdicts(&credentials, &cluster.kubelet("b"), "b") {
            assert_eq!(refusal(&verdict), Some(&Refusal::NoAuthority));
        }
    }

    #[test]
    fn a_subject_is_a_node_only_with_the_nodes_organization_and_a_named_node() {
        let cluster = Cluster::new("kubernetes");
        let subject = |edit: fn(&mut CertificateParams)| {
            let mut params = kubelet("b");
            edit(&mut params);
            node_subject(&der(&cluster.issue(&params)))
        };
        assert_eq!(subject(|_| ()), Ok("b".to_owned()));
        // rcgen keeps one value per attribute type: each push replaces the kubelet's.
        assert_eq!(
            subject(|params| params
                .distinguished_name
                .push(DnType::CommonName, "system:node:")),
            Err(Refusal::CommonName(vec!["system:node:".to_owned()]))
        );
        assert_eq!(
            subject(|params| {
                params.distinguished_name.remove(DnType::CommonName);
            }),
            Err(Refusal::CommonName(Vec::new()))
        );
        assert_eq!(
            subject(|params| params
                .distinguished_name
                .push(DnType::OrganizationName, "system:masters")),
            Err(Refusal::Organization(vec!["system:masters".to_owned()]))
        );
        assert!(matches!(
            node_subject(b"not a certificate"),
            Err(Refusal::Encoding(_))
        ));
    }

    #[test]
    fn a_handshake_checks_both_nodes_and_presents_each_ones_certificate() {
        let cluster = Cluster::new("kubernetes");
        let a = Node::new(&cluster, &cluster.kubelet("a"));
        let b = Node::new(&cluster, &cluster.kubelet("b"));
        let seen = handshake(a.credentials.server(), b.credentials.client("a")).unwrap();
        assert_eq!(node_subject(&seen.server), Ok("a".to_owned()));
        assert_eq!(node_subject(&seen.client), Ok("b".to_owned()));

        let err = handshake(a.credentials.server(), b.credentials.client("c")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid peer certificate: Other(OtherError(expected node c, certificate is for node a))"
        );
        let stranger = Cluster::new("other");
        let stranger = Node::new(&stranger, &stranger.kubelet("b"));
        let err = handshake(a.credentials.server(), stranger.credentials.client("a")).unwrap_err();
        assert_eq!(
            err,
            CertificateError::UnknownIssuer.into(),
            "the server refuses"
        );
    }

    #[test]
    fn a_client_of_any_node_accepts_every_node_of_the_cluster_and_no_stranger() {
        let cluster = Cluster::new("kubernetes");
        let a = Node::new(&cluster, &cluster.kubelet("a"));
        let b = Node::new(&cluster, &cluster.kubelet("b"));
        handshake(b.credentials.server(), a.credentials.client_any()).unwrap();
        let stranger = Cluster::new("other");
        let stranger = Node::new(&stranger, &stranger.kubelet("b"));
        let err = handshake(stranger.credentials.server(), a.credentials.client_any()).unwrap_err();
        assert_eq!(err, CertificateError::UnknownIssuer.into());
    }

    #[test]
    fn a_handshake_after_the_files_are_deleted_uses_the_loaded_pair() {
        let cluster = Cluster::new("kubernetes");
        let a = Node::new(&cluster, &cluster.kubelet("a"));
        let b = Node::new(&cluster, &cluster.kubelet("b"));
        let Node { dir, credentials } = a;
        dir.close().unwrap();
        handshake(credentials.server(), b.credentials.client("a")).unwrap();
    }

    #[test]
    fn a_new_pair_is_what_the_next_handshake_presents() {
        let cluster = Cluster::new("kubernetes");
        let a = Node::new(&cluster, &cluster.kubelet("a"));
        let b = Node::new(&cluster, &cluster.kubelet("b"));
        let fresh = cluster.kubelet("a");
        assert_eq!(a.rotate(&fresh).unwrap().node(), "a");
        let seen = handshake(a.credentials.server(), b.credentials.client("a")).unwrap();
        assert_eq!(seen.server, der(&fresh));
    }

    #[test]
    fn a_key_that_is_not_the_certificates_is_refused_naming_the_file_and_the_pair_in_use_stays() {
        let cluster = Cluster::new("kubernetes");
        let first = cluster.kubelet("a");
        let a = Node::new(&cluster, &first);
        let b = Node::new(&cluster, &cluster.kubelet("b"));
        let other = cluster.kubelet("a");
        let mismatched = format!("{}{}", &other[..key_at(&other)], &first[key_at(&first)..]);
        let err = a.rotate(&mismatched).unwrap_err();
        assert!(
            matches!(
                err,
                Error::Invalid {
                    problem: Problem::Mismatch,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(
            err.to_string(),
            format!(
                "{}: the private key does not match the certificate",
                a.certificate().display()
            )
        );
        let seen = handshake(a.credentials.server(), b.credentials.client("a")).unwrap();
        assert_eq!(seen.server, der(&first));
    }

    #[test]
    fn a_file_that_cannot_be_used_says_why_and_names_itself() {
        let cluster = Cluster::new("kubernetes");
        let a = Node::new(&cluster, &cluster.kubelet("a"));
        let missing = a.dir.path().join("missing.pem");
        assert!(matches!(
            a.credentials.load_identity(&missing),
            Err(Error::Absent { path }) if path == missing
        ));
        assert!(matches!(
            a.credentials.load_authority(a.dir.path()),
            Err(Error::Read { .. })
        ));
        for (text, problem) in [
            ("", "no certificate in it"),
            (
                "-----BEGIN CERTIFICATE-----\n!\n-----END CERTIFICATE-----\n",
                "unreadable PEM",
            ),
        ] {
            fs::write(a.certificate(), text).unwrap();
            let err = a.credentials.load_identity(&a.certificate()).unwrap_err();
            assert!(err.to_string().contains(problem), "{err}");
            fs::write(a.ca(), text).unwrap();
            let err = a.credentials.load_authority(&a.ca()).unwrap_err();
            assert!(err.to_string().contains(problem), "{err}");
        }
        let pem = cluster.kubelet("a");
        let err = a.rotate(&pem[..key_at(&pem)]).unwrap_err();
        assert!(err.to_string().contains("no usable private key"), "{err}");
        let mut params = kubelet("a");
        params.distinguished_name.remove(DnType::OrganizationName);
        let err = a.rotate(&cluster.issue(&params)).unwrap_err();
        assert!(
            err.to_string()
                .ends_with("subject O=[] is not system:nodes"),
            "{err}"
        );
        assert_eq!(a.credentials.identity().unwrap().node(), "a");
        assert!(a.credentials.is_ready(), "the CA in use stays too");
    }

    #[test]
    fn credentials_are_ready_with_both_an_identity_and_a_ca() {
        let cluster = Cluster::new("kubernetes");
        let a = Node::new(&cluster, &cluster.kubelet("a"));
        assert!(a.credentials.is_ready());
        let credentials = Credentials::default();
        assert!(!credentials.is_ready());
        assert!(!credentials.has_certs());
        credentials.load_identity(&a.certificate()).unwrap();
        assert!(!credentials.is_ready());
        assert!(credentials.has_certs());
        let credentials = Credentials::default();
        credentials.load_authority(&a.ca()).unwrap();
        assert!(!credentials.is_ready());
    }

    #[test]
    fn the_expiry_is_the_certificates() {
        let cluster = Cluster::new("kubernetes");
        let params = kubelet("a");
        let a = Node::new(&cluster, &cluster.issue(&params));
        assert_eq!(
            a.credentials.identity().unwrap().expiry(),
            SystemTime::from(params.not_after.replace_nanosecond(0).unwrap())
        );
    }

    #[test]
    fn both_sides_offer_the_providers_schemes_and_no_hint() {
        let cluster = Cluster::new("kubernetes");
        let a = Node::new(&cluster, &cluster.kubelet("a"));
        let verifier = a.credentials.verifier(None);
        let schemes = ServerCertVerifier::supported_verify_schemes(&verifier);
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
        assert_eq!(
            schemes,
            ClientCertVerifier::supported_verify_schemes(&verifier)
        );
        assert!(ClientCertVerifier::root_hint_subjects(&verifier).is_empty());
    }
}
