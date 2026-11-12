//! Where an image is, how to trust it and who to be there: the *registry config* of a runtime, behind one trait (D17,
//! D66, D89).
//!
//! The upstream client asks a [`Registries`] for the [`Source`]s of a name, and never reads a runtime's files itself.
//! One implementation reads containerd's (`config.toml`, `hosts.toml`), another CRI-O's (`registries.conf`, `certs.d`,
//! the auth file).

pub mod containerd;
pub mod crio;
mod live;

pub use containerd::ContainerdRegistries;
pub use crio::CrioRegistries;
use secrecy::SecretString;

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

    /// Reads the registry config again, and returns whether it changed. `sources` never reads the registry config
    /// from disk: what it answers is what the last successful `reload` read (D91).
    ///
    /// With `since`, only when a file of the config was modified at or after it; without, always, whatever the
    /// modification times say.
    ///
    /// # Errors
    ///
    /// When the registry config cannot be read or is not valid, naming the file and the place in it. The config held
    /// stays in use, if there is one.
    fn reload(&self, since: Option<std::time::SystemTime>) -> Result<bool, Error>;
}

/// `name` split into its registry and its repository.
pub(crate) fn split_name(name: &str) -> Result<(&str, &str), Error> {
    name.split_once('/')
        .filter(|(host, repository)| !host.is_empty() && !repository.is_empty())
        .ok_or_else(|| Error::Name(name.to_owned()))
}

/// The trust of a host from its CA and client certificate files.
pub(crate) fn read_tls(
    authority: &str,
    ca: &[std::path::PathBuf],
    client: Option<(&std::path::Path, &std::path::Path)>,
) -> Tls {
    let read = |path: &std::path::Path| {
        std::fs::read(path)
            .map_err(|err| tracing::warn!(authority, path = %path.display(), error = %err, "a certificate file cannot be read"))
            .ok()
    };
    Tls {
        roots: ca.iter().filter_map(|path| read(path)).collect(),
        client: client.and_then(|(cert, key)| {
            let certificate = read(cert)?;
            let key = String::from_utf8(read(key)?).ok()?;
            Some(ClientCert {
                certificate,
                key: SecretString::from(key),
            })
        }),
        skip_verify: false,
    }
}
