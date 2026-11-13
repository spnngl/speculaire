//! What CRI-O says about itself: its merged config, from `GET /config` on its socket (D64).
//!
//! CRI-O serves the inspect API on `crio.sock` next to the CRI (v1.37.2 `server/inspect.go:140,153`), and answers the
//! merged TOML of `crio.conf` and `crio.conf.d/` (what `crio status config` prints).

pub mod dropin;
mod settings;
mod wiring;

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::future::BoxFuture;
use serde::Deserialize;
pub use settings::MINIMUM;
use speculaire_registry_config::crio::Context;
use tokio::sync::mpsc;

use crate::content::{Blob, Content};
use crate::inventory::{Inventory, Update};
use crate::paths::Paths;

/// A node that runs CRI-O: the files it reads, its socket and `systemctl` (D90).
#[derive(Clone, Debug)]
pub struct CriO {
    paths: Paths,
    socket: PathBuf,
    systemctl: PathBuf,
}

impl CriO {
    /// The CRI-O of the node at `paths`, answering on `socket`; `systemctl` reloads it.
    #[must_use]
    pub fn new(paths: Paths, socket: impl Into<PathBuf>, systemctl: impl Into<PathBuf>) -> Self {
        Self {
            paths,
            socket: socket.into(),
            systemctl: systemctl.into(),
        }
    }

    /// Its socket: the CRI, and the inspect API.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The drop-in `configure` writes (D66).
    #[must_use]
    pub fn dropin(&self) -> PathBuf {
        self.paths
            .at("/etc/containers/registries.conf.d/99-speculaire.conf")
    }

    /// CRI-O's per-registry certificate directories.
    fn certs(&self) -> PathBuf {
        self.paths.at("/etc/containers/certs.d")
    }

    /// The context CRI-O's files are read in.
    #[must_use]
    pub fn context(&self) -> Context {
        Context {
            root: self.paths.root().to_owned(),
            // root's home, below the stand-in root too: the user's own files are read.
            home: self.paths.at("/root"),
            ..Context::root()
        }
    }
}

/// CRI-O keeps its layers where the mirror cannot read them: what it serves is its blob cache's (D67).
impl Content for CriO {
    fn open(
        &self,
        _digest: &speculaire_oci::reference::Digest,
    ) -> impl Future<Output = Result<Option<Blob>, crate::content::Error>> + Send {
        std::future::ready(Ok(None))
    }
}

/// CRI-O keeps no blob a peer can read: under [`Fallback::Relay`](crate::Fallback::Relay) the blob cache is what the
/// node serves, and it follows itself (D67).
impl Inventory for CriO {
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            if updates.send(Update::Listing(HashSet::new())).await.is_ok() {
                updates.closed().await;
            }
        })
    }
}

/// How long CRI-O may take to connect, read or write.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The longest response read: CRI-O's whole config is a few tens of KiB.
const MAX_RESPONSE: u64 = 4_194_304;

/// The settings of CRI-O's NRI that the agent depends on (D54, D64), under `[crio.nri]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nri {
    /// `enable_nri`.
    pub enabled: bool,
    /// `nri_disable_connections`.
    pub disable_connections: bool,
    /// `nri_validator_required_plugins`, under `[crio.nri.default_validator]`: the plugins CRI-O refuses containers
    /// without.
    pub required_plugins: Vec<String>,
}

/// Why CRI-O's config could not be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The socket could not be reached or read.
    #[error("{path}: {source}")]
    Socket {
        /// The socket.
        path: String,
        /// What failed.
        source: io::Error,
    },
    /// The response is not a plain HTTP response with status 200.
    #[error("CRI-O's inspect API answered {0}")]
    Response(String),
    /// The body is not CRI-O's TOML.
    #[error("CRI-O's config is not valid: {0}")]
    Config(#[from] toml::de::Error),
}

/// `GET /config` on CRI-O's socket: the response's body.
///
/// # Errors
///
/// When the socket cannot be reached or read, or CRI-O does not answer 200.
pub fn config(socket: &Path) -> Result<String, Error> {
    let at = |source| Error::Socket {
        path: socket.display().to_string(),
        source,
    };
    let mut stream = UnixStream::connect(socket).map_err(at)?;
    stream.set_read_timeout(Some(TIMEOUT)).map_err(at)?;
    stream.set_write_timeout(Some(TIMEOUT)).map_err(at)?;
    // HTTP/1.0: the server closes the connection after the body, and sends it without chunking.
    stream
        .write_all(b"GET /config HTTP/1.0\r\nHost: crio\r\nAccept: application/toml\r\n\r\n")
        .map_err(at)?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE)
        .read_to_end(&mut response)
        .map_err(at)?;
    body(&response).map(str::to_owned)
}

/// The body of an HTTP/1.x response with status 200 and no transfer coding.
///
/// # Errors
///
/// When the response has another status, a transfer coding or no UTF-8 text, or is cut short.
pub fn body(response: &[u8]) -> Result<&str, Error> {
    let bad = |what: &str| Error::Response(what.to_owned());
    let end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| bad("no end of headers"))?;
    let head =
        std::str::from_utf8(&response[..end]).map_err(|_| bad("headers that are not text"))?;
    let (status_line, headers) = head.split_once("\r\n").unwrap_or((head, ""));
    let mut status = status_line.split(' ');
    if !status.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(bad(&format!("{status_line:?}")));
    }
    if status.next() != Some("200") {
        return Err(bad(&format!("{status_line:?}")));
    }
    let mut length = None;
    for header in headers.lines() {
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad("a transfer coding"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| bad("a bad Content-Length"))?,
            );
        }
    }
    let body = &response[end + 4..];
    let body = match length {
        Some(length) if body.len() < length => return Err(bad("a body shorter than its length")),
        Some(length) => &body[..length],
        None => body,
    };
    std::str::from_utf8(body).map_err(|_| bad("a body that is not text"))
}

impl Nri {
    /// The NRI settings in the text of CRI-O's config; a missing key has CRI-O's default (NRI on, connections open, no
    /// required plugin).
    ///
    /// # Errors
    ///
    /// When the text is not TOML or a key has the wrong type.
    pub fn parse(config: &str) -> Result<Self, Error> {
        #[derive(Default, Deserialize)]
        struct Root {
            #[serde(default)]
            crio: Crio,
        }
        #[derive(Default, Deserialize)]
        struct Crio {
            #[serde(default)]
            nri: Section,
        }
        #[derive(Deserialize)]
        #[serde(default)]
        struct Section {
            enable_nri: bool,
            nri_disable_connections: bool,
            default_validator: Validator,
        }
        impl Default for Section {
            fn default() -> Self {
                Self {
                    enable_nri: true,
                    nri_disable_connections: false,
                    default_validator: Validator::default(),
                }
            }
        }
        #[derive(Default, Deserialize)]
        struct Validator {
            #[serde(default)]
            nri_validator_required_plugins: Vec<String>,
        }
        let Root { crio: Crio { nri } } = toml::from_str(config)?;
        Ok(Self {
            enabled: nri.enable_nri,
            disable_connections: nri.nri_disable_connections,
            required_plugins: nri.default_validator.nri_validator_required_plugins,
        })
    }
}

/// The credential file CRI-O reads, `[crio.image] global_auth_file` in the text of its config (v1.37.0
/// `pkg/config/config.go:717`, handed to the image library as `AuthFilePath` at `server/server.go:448`); `None` when
/// unset, and the library's default search applies (D89).
///
/// # Errors
///
/// When the text is not TOML or the key is not a string.
pub fn global_auth_file(config: &str) -> Result<Option<PathBuf>, Error> {
    #[derive(Default, Deserialize)]
    struct Root {
        #[serde(default)]
        crio: Crio,
    }
    #[derive(Default, Deserialize)]
    struct Crio {
        #[serde(default)]
        image: Image,
    }
    #[derive(Default, Deserialize)]
    struct Image {
        #[serde(default)]
        global_auth_file: String,
    }
    let Root {
        crio: Crio { image },
    } = toml::from_str(config)?;
    Ok((!image.global_auth_file.is_empty()).then(|| PathBuf::from(image.global_auth_file)))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    #[test]
    fn the_global_auth_file_is_under_crio_image_and_empty_means_none() {
        let set = "[crio.image]\nglobal_auth_file = \"/var/lib/kubelet/config.json\"\n";
        assert_eq!(
            super::global_auth_file(set).unwrap(),
            Some(PathBuf::from("/var/lib/kubelet/config.json"))
        );
        for text in ["", "[crio]\n", "[crio.image]\nglobal_auth_file = \"\"\n"] {
            assert_eq!(super::global_auth_file(text).unwrap(), None, "{text:?}");
        }
        assert!(super::global_auth_file("[crio.image]\nglobal_auth_file = 1\n").is_err());
    }

    use super::*;

    const CONFIG: &str = "[crio]\nroot = \"/var/lib/containers/storage\"\n\n[crio.nri]\nenable_nri = true\nnri_disable_connections = false\n\n[crio.nri.default_validator]\nnri_enable_default_validator = true\nnri_validator_required_plugins = [\"speculaire\", \"other\"]\n";

    fn response(status: &str, headers: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.0 {status}\r\n{headers}\r\n{body}").into_bytes()
    }

    #[test]
    fn the_nri_settings_come_from_crio_nri_and_its_default_validator() {
        assert_eq!(
            Nri::parse(CONFIG).unwrap(),
            Nri {
                enabled: true,
                disable_connections: false,
                required_plugins: vec!["speculaire".to_owned(), "other".to_owned()],
            }
        );
        let off = "[crio.nri]\nenable_nri = false\nnri_disable_connections = true\n";
        let nri = Nri::parse(off).unwrap();
        assert!(!nri.enabled && nri.disable_connections && nri.required_plugins.is_empty());
    }

    #[test]
    fn missing_keys_have_crios_defaults() {
        for text in ["", "[crio]\n", "[crio.nri]\n"] {
            assert_eq!(
                Nri::parse(text).unwrap(),
                Nri {
                    enabled: true,
                    disable_connections: false,
                    required_plugins: Vec::new(),
                },
                "{text:?}"
            );
        }
        assert!(Nri::parse("[crio.nri]\nenable_nri = \"yes\"\n").is_err());
        assert!(Nri::parse("[crio.nri\n").is_err());
    }

    #[test]
    fn a_response_is_its_body_when_the_status_is_200() {
        let ok = response("200 OK", "Content-Type: application/toml\r\n", "a = 1\n");
        assert_eq!(body(&ok).unwrap(), "a = 1\n");
        let sized = response("200 OK", "content-length: 3\r\n", "a = 1\n");
        assert_eq!(body(&sized).unwrap(), "a =");
        let exact = response("200 OK", "Content-Length: 6\r\n", "a = 1\n");
        assert_eq!(body(&exact).unwrap(), "a = 1\n");
        let short = response("200 OK", "Content-Length: 30\r\n", "a = 1\n");
        assert!(body(&short).is_err());
        assert!(body(&response("200 OK", "Content-Length: x\r\n", "")).is_err());
    }

    #[test]
    fn anything_else_is_an_error_naming_what_came() {
        for (bad, want) in [
            (response("404 Not Found", "", "no"), "404 Not Found"),
            (response("500 Oops", "", ""), "500"),
            (
                response(
                    "200 OK",
                    "Transfer-Encoding: chunked\r\n",
                    "6\r\na = 1\n\r\n0\r\n\r\n",
                ),
                "transfer coding",
            ),
            (b"SSH-2.0-OpenSSH\r\n\r\n".to_vec(), "SSH"),
            (b"HTTP/1.0 200 OK\r\nno end".to_vec(), "end of headers"),
            (b"HTTP/1.0 200 OK\r\n\r\n\xff".to_vec(), "not text"),
            (b"HTTP/1.0 200 OK\xff\r\n\r\n".to_vec(), "not text"),
            (Vec::new(), "end of headers"),
        ] {
            let err = body(&bad).unwrap_err().to_string();
            assert!(err.contains(want), "{err}");
        }
    }

    #[test]
    fn the_config_is_fetched_from_the_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crio.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 512];
            let n = stream.read(&mut request).unwrap();
            stream.write_all(&response("200 OK", "", CONFIG)).unwrap();
            String::from_utf8(request[..n].to_vec()).unwrap()
        });
        assert_eq!(config(&path).unwrap(), CONFIG);
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /config HTTP/1.0\r\n"), "{request}");
        let missing = config(&dir.path().join("gone.sock")).unwrap_err();
        assert!(missing.to_string().contains("gone.sock"), "{missing}");
    }
}
