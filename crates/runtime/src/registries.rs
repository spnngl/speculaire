//! Where an image is, how to trust it and who to be there: the *registry config* of a runtime, behind one trait (D17,
//! D66, D89).
//!
//! The upstream client asks a [`Registries`] for the [`Source`]s of a name, and never reads a runtime's files itself.
//! One implementation reads containerd's (`config.toml`, `hosts.toml`), another CRI-O's (`registries.conf`, `certs.d`,
//! the auth file).
//!
//! A config is read at [`Registries::reload`], files of certificates and keys with it; nothing a request does reads a
//! file (D91, D92).

pub mod containerd;
pub mod crio;
mod live;

pub use containerd::ContainerdRegistries;
pub use crio::CrioRegistries;
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use secrecy::SecretString;
use secrecy::zeroize::Zeroizing;

/// A certificate to present to an endpoint that asks for one, and its key (PEM).
#[derive(Clone, Debug)]
pub struct ClientCert {
    /// The certificate chain.
    pub certificate: Vec<u8>,
    /// The private key.
    pub key: SecretString,
}

/// How an endpoint is trusted.
#[derive(Clone, Debug, Default)]
pub struct Tls {
    /// CA certificates (PEM) to trust besides the system's.
    pub roots: Vec<Vec<u8>>,
    /// A certificate to present.
    pub client: Option<ClientCert>,
    /// The server's certificate is not checked at all (`insecure`, `skip_verify`).
    pub skip_verify: bool,
}

/// A registry to ask, and how to trust it.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// Whether it speaks TLS; plain HTTP is for `insecure` registries.
    pub https: bool,
    /// `host` or `host:port`.
    pub authority: String,
    /// The path of its API: `/v2`, or more for a registry that serves its API below a prefix.
    pub root: String,
    /// The registry the image is named for, when this endpoint stands in for it (`?ns=` on containerd's mirrors).
    pub namespace: Option<String>,
    /// How to trust it.
    pub tls: Tls,
    /// Headers to add to every request to it, such as `hosts.toml`'s `header`; their values are secrets (D37).
    pub headers: Vec<(String, SecretString)>,
}

impl Endpoint {
    /// An endpoint at `authority` with nothing special: the API at `/v2`, the system's trust, no header.
    #[must_use]
    pub fn new(https: bool, authority: impl Into<String>) -> Self {
        Self {
            https,
            authority: authority.into(),
            root: "/v2".to_owned(),
            namespace: None,
            tls: Tls::default(),
            headers: Vec::new(),
        }
    }
}

/// A login for an endpoint.
#[derive(Clone, Debug)]
pub enum Credentials {
    /// None: the registry is asked as anyone.
    Anonymous,
    /// A user name and password, for Basic authentication and for a token endpoint; with an identity token, the
    /// token endpoint is asked for access tokens in exchange for it, as go.podman.io/image does.
    Login {
        /// The user name.
        username: String,
        /// The password.
        password: SecretString,
        /// The identity token of an `OAuth2` login.
        identity_token: Option<SecretString>,
    },
}

/// A registry the upstream client may ask for an image: the endpoints to try in order, the repository there, and the
/// login.
#[derive(Clone, Debug)]
pub struct Source {
    /// One endpoint, or for an `insecure` registry HTTPS without verification and then plain HTTP.
    pub candidates: Vec<Endpoint>,
    /// The repository at that registry: `library/busybox`.
    pub repository: String,
    /// Who to ask as.
    pub credentials: Credentials,
}

/// What an image is pulled by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reference<'a> {
    /// A tag.
    Tag(&'a str),
    /// A digest, `sha256:<hex>`.
    Digest(&'a str),
}

/// Why no source could be made.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The registry config cannot be read.
    #[error("registry config: {0}")]
    Config(String),
    /// The name has no registry in it.
    #[error("{0:?} names no registry and repository")]
    Name(String),
}

/// The registry config of a node: where each image may be had, and as whom.
pub trait Registries: Send + Sync {
    /// The sources to ask for the image `name` (`docker.io/library/busybox`) by `reference`, in the order the runtime
    /// tries them. A registry the config blocks has none.
    ///
    /// # Errors
    ///
    /// When the registry config cannot be read, or `name` has no registry and repository in it.
    fn sources(&self, name: &str, reference: Reference<'_>) -> Result<Vec<Source>, Error>;

    /// Reads the registry config again. `sources` never reads the registry config from disk: what it answers is what the
    /// last successful `reload` read (D91).
    ///
    /// With `since`, only when a file of the config was modified at or after it; without, always, whatever the
    /// modification times say.
    ///
    /// # Errors
    ///
    /// When the registry config cannot be read or is not valid, naming the file and the place in it. The config held
    /// stays in use, if there is one. A credential, certificate or key file that cannot be used is no error: see
    /// [`Reloaded::problems`].
    fn reload(&self, since: Option<std::time::SystemTime>) -> Result<Reloaded, Error>;
}

/// What a [`Registries::reload`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reloaded {
    /// Whether the registry config held was replaced.
    pub changed: bool,
    /// What the new config does without, one text each: a credential, certificate or key file that cannot be used
    /// leaves only the hosts it is for anonymous, or without it (D92). Empty when nothing was read.
    pub problems: Vec<String>,
}

/// `name` split into its registry and its repository.
pub(crate) fn split_name(name: &str) -> Result<(&str, &str), Error> {
    name.split_once('/')
        .filter(|(host, repository)| !host.is_empty() && !repository.is_empty())
        .ok_or_else(|| Error::Name(name.to_owned()))
}

/// The CA certificates (PEM) of `path`, or `why` they cannot be used.
fn read_chain(path: &std::path::Path) -> Result<Vec<u8>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let chain = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate in it", path.display()));
    }
    Ok(pem)
}

/// A CA file (D92): read and checked now, so that no request reads it. One that cannot be used is noted in `problems`
/// and left out.
pub(crate) fn read_ca(path: &std::path::Path, problems: &mut Vec<String>) -> Option<Vec<u8>> {
    read_chain(path)
        .map_err(|why| problems.push(format!("a CA file is not used: {why}")))
        .ok()
}

/// A client certificate and its key (D92): read and checked now, so that no request reads them, the key into memory
/// that is wiped. A pair that cannot be used is noted in `problems` and left out.
pub(crate) fn read_client(
    cert: &std::path::Path,
    key: &std::path::Path,
    problems: &mut Vec<String>,
) -> Option<ClientCert> {
    let read = || -> Result<ClientCert, String> {
        let certificate = read_chain(cert)?;
        let pem =
            Zeroizing::new(std::fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?);
        PrivateKeyDer::from_pem_slice(&pem).map_err(|e| format!("{}: {e}", key.display()))?;
        let text = std::str::from_utf8(&pem).map_err(|e| format!("{}: {e}", key.display()))?;
        Ok(ClientCert {
            certificate,
            key: SecretString::from(text),
        })
    };
    read()
        .map_err(|why| problems.push(format!("a client certificate is not used: {why}")))
        .ok()
}
