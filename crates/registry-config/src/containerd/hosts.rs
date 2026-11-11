//! `hosts.toml`, the per-registry config of containerd (D17).
//!
//! Ported from containerd's `core/remotes/docker/config/hosts.go` at v2.4.2 (`hostConfig`, `parseHostsFile`,
//! `loadHostDir`, `loadCertFiles`, `HostDirFromRoot` and the host defaults of `ConfigureHosts`). The `hosts` tests
//! run it against containerd's own code on the same files.
//!
//! A file holds a default `server`, hosts that are tried first, and the keys they share: `capabilities`, `ca`,
//! `client`, `skip_verify`, `header`, `override_path` and `dial_timeout`. [`parse_hosts_file`] turns the text into
//! [`HostConfig`]s in containerd's order; [`resolve`] adds what a registry host defaults to.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use toml::de::DeTable;

use crate::ParseError;
use crate::error::from_toml;
use crate::fold::{fold_fields, table_at, tables_in};
use crate::go::{clean_path, is_localhost, parse_duration, parse_url, split_host_port};
use crate::header::{HeaderValue, Headers};

/// The query argument that names the registry a mirror stands in for (`resolver.go:645`): `?ns=docker.io`.
pub const NAMESPACE_QUERY_ARG: &str = "ns";

/// What a host may do (`registry.go:36`): the capabilities of `hosts.toml`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities(u8);

impl Capabilities {
    /// Fetch manifests and blobs by digest.
    pub const PULL: Self = Self(1);
    /// Fetch manifests by name.
    pub const RESOLVE: Self = Self(2);
    /// Push blobs and manifests.
    pub const PUSH: Self = Self(4);
    /// List referrers through the OCI referrers endpoint.
    pub const REFERRERS: Self = Self(8);
    /// Every capability: what a host without `capabilities` has.
    pub const ALL: Self = Self(15);
    /// No capability.
    pub const NONE: Self = Self(0);

    /// Whether every capability of `other` is in `self`.
    #[must_use]
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// The names of the capabilities, in the order of `hosts.toml`'s documentation.
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        [
            (Self::PULL, "pull"),
            (Self::RESOLVE, "resolve"),
            (Self::PUSH, "push"),
            (Self::REFERRERS, "referrers"),
        ]
        .into_iter()
        .filter(|(capability, _)| self.contains(*capability))
        .map(|(_, name)| name)
        .collect()
    }

    fn named(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "pull" => Some(Self::PULL),
            "resolve" => Some(Self::RESOLVE),
            "push" => Some(Self::PUSH),
            "referrers" => Some(Self::REFERRERS),
            _ => None,
        }
    }
}

impl std::ops::BitOr for Capabilities {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// A client certificate and, when it is not in the same file, its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientPair {
    /// The certificate file.
    pub cert: PathBuf,
    /// The key file; `None` when the certificate file holds the key.
    pub key: Option<PathBuf>,
}

/// One endpoint of a registry as `hosts.toml` configures it, before the defaults of [`resolve`].
#[derive(Clone, Debug, Default)]
pub struct HostConfig {
    /// `http` or `https`, from the server URL; empty for the root of a file without `server`.
    pub scheme: String,
    /// The host and port; empty for the root of a file without `server`.
    pub host: String,
    /// The API root, such as `/v2`; empty with `override_path` and no path in the URL.
    pub path: String,
    /// What the host may be used for.
    pub capabilities: Capabilities,
    ca: Option<Vec<PathBuf>>,
    client: Option<Vec<ClientPair>>,
    /// `skip_verify`; `None` when the file does not say.
    pub skip_verify: Option<bool>,
    /// `dial_timeout`.
    pub dial_timeout: Option<Duration>,
    /// Headers added to every request to the host.
    pub header: Headers,
}

impl Default for Capabilities {
    fn default() -> Self {
        Self::NONE
    }
}

impl HostConfig {
    /// The CA certificate files to trust, as an absolute path or relative to the file's directory.
    #[must_use]
    pub fn ca(&self) -> &[PathBuf] {
        self.ca.as_deref().unwrap_or_default()
    }

    /// The client certificates to present.
    #[must_use]
    pub fn client(&self) -> &[ClientPair] {
        self.client.as_deref().unwrap_or_default()
    }

    /// Whether the host names TLS settings: `ca`, `client` or `skip_verify`, even an empty `ca = []`.
    #[must_use]
    pub fn has_tls(&self) -> bool {
        self.ca.is_some() || self.client.is_some() || self.skip_verify.is_some()
    }
}

/// A host or a file of the host directory that cannot be used.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HostsError {
    /// A file or directory could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file or directory.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A `hosts.toml` is not valid.
    #[error("invalid {}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// What is wrong, and where.
        source: ParseError,
    },
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Paths {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientItem {
    Cert(String),
    Pair(Vec<String>),
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Client {
    One(String),
    Many(Vec<ClientItem>),
}

/// The keys a host table and the root of the file share (`hostFileConfig`).
#[derive(Deserialize, Default)]
struct Entry {
    #[serde(default)]
    capabilities: Vec<String>,
    ca: Option<Paths>,
    client: Option<Client>,
    skip_verify: Option<bool>,
    header: Option<BTreeMap<String, HeaderValue>>,
    #[serde(default)]
    override_path: bool,
    #[serde(default)]
    dial_timeout: String,
}

#[derive(Deserialize, Default)]
struct File {
    #[serde(default)]
    server: String,
    #[serde(default)]
    host: BTreeMap<String, Entry>,
}

/// Parses the text of a `hosts.toml` that lives in `base_dir`: the hosts in file order, then the file's own `server`
/// (`parseHostsFile`, `hosts.go:380`).
///
/// # Errors
///
/// When the text is not TOML, a key has the wrong type, or a host is not valid: an unknown capability, a `server`
/// that is not a URL, a `client` pair that is not two files, a `dial_timeout` that is not a duration.
pub fn parse_hosts_file(base_dir: &Path, text: &str) -> Result<Vec<HostConfig>, ParseError> {
    let order = host_order(text);
    let file: File = from_toml(text, fold_file)?;
    let root: Entry = from_toml(text, fold_file)?;
    let mut hosts = Vec::with_capacity(order.len() + 1);
    for name in order {
        // A host table is in `file.host` unless it was not a table (`host = 1` fails above).
        let entry = file.host.get(&name).ok_or_else(|| {
            ParseError::new(format!("host.{name:?}"), "is not a table of settings")
        })?;
        hosts.push(host_config(
            &name,
            base_dir,
            entry,
            &format!("host.{name:?}"),
        )?);
    }
    hosts.push(host_config(&file.server, base_dir, &root, "")?);
    if hosts.len() > 2 {
        hosts.swap(0, 1);
    }
    Ok(hosts)
}

/// The keys of a file and of a host table, matched in any case as go-toml does.
const FIELDS: &[&str] = &[
    "server",
    "host",
    "capabilities",
    "ca",
    "client",
    "skip_verify",
    "header",
    "override_path",
    "dial_timeout",
];

fn fold_file(table: &mut DeTable<'_>) {
    fold_fields(table, FIELDS);
    if let Some(hosts) = table_at(table, "host") {
        for host in tables_in(hosts) {
            fold_fields(host, FIELDS);
        }
    }
}

/// The hosts, in the order their tables first open (`getSortedHosts`, `hosts.go:551`): `[host."a"]` and
/// `[host."a".header]` both name `a`, a name is listed again when another came between, and a host declared by dotted
/// keys or an inline table is not listed, as in containerd.
fn host_order(text: &str) -> Vec<String> {
    use toml_parser::decoder::Encoding;
    use toml_parser::parser::EventReceiver;
    use toml_parser::{ErrorSink, Raw, Source, Span};

    struct Tables<'s> {
        source: &'s Source<'s>,
        in_header: bool,
        parts: Vec<String>,
        order: Vec<String>,
    }
    impl EventReceiver for Tables<'_> {
        fn std_table_open(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
            self.in_header = true;
            self.parts.clear();
        }
        fn array_table_open(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
            self.in_header = false;
        }
        fn simple_key(
            &mut self,
            span: Span,
            encoding: Option<Encoding>,
            _error: &mut dyn ErrorSink,
        ) {
            if !self.in_header {
                return;
            }
            let mut key = std::borrow::Cow::Borrowed("");
            if let Some(raw) = self.source.get(span) {
                Raw::new_unchecked(raw.as_str(), encoding, span).decode_key(&mut key, &mut ());
            }
            self.parts.push(key.into_owned());
        }
        fn std_table_close(&mut self, _span: Span, _error: &mut dyn ErrorSink) {
            if !self.in_header {
                return;
            }
            self.in_header = false;
            // Go compares with the last name it listed, which starts empty: `[host.""]` is skipped.
            let last = self.order.last().map_or("", String::as_str);
            if self.parts.len() >= 2 && self.parts[0] == "host" && self.parts[1] != last {
                self.order.push(self.parts[1].clone());
            }
        }
    }
    let source = Source::new(text);
    let tokens = source.lex().into_vec();
    let mut tables = Tables {
        source: &source,
        in_header: false,
        parts: Vec::new(),
        order: Vec::new(),
    };
    toml_parser::parser::parse_document(&tokens, &mut tables, &mut ());
    tables.order
}

/// `parseHostConfig` (`hosts.go:424`): one host from its `server` and its settings. `key` names the table in errors.
fn host_config(
    server: &str,
    base_dir: &Path,
    entry: &Entry,
    key: &str,
) -> Result<HostConfig, ParseError> {
    let at = |name: &str| {
        if key.is_empty() {
            name.to_owned()
        } else {
            format!("{key}.{name}")
        }
    };
    let mut host = HostConfig::default();
    if !server.is_empty() {
        let url = if server.starts_with("http") {
            server.to_owned()
        } else {
            format!("https://{server}")
        };
        let url = parse_url(&url).map_err(|e| {
            ParseError::new(at("server"), format!("unable to parse server {url}: {e}"))
        })?;
        host.scheme = url.scheme;
        host.host = url.host;
        host.path = if url.path.is_empty() {
            if entry.override_path {
                String::new()
            } else {
                "/v2".to_owned()
            }
        } else {
            let mut path = clean_path(&url.path);
            if !path.ends_with("/v2") && !entry.override_path {
                path.push_str("/v2");
            }
            path
        };
    }
    host.skip_verify = entry.skip_verify;
    host.capabilities = if entry.capabilities.is_empty() {
        Capabilities::ALL
    } else {
        entry
            .capabilities
            .iter()
            .try_fold(Capabilities::NONE, |all, name| {
                Capabilities::named(name)
                    .map(|one| all | one)
                    .ok_or_else(|| {
                        ParseError::new(at("capabilities"), format!("unknown capability {name}"))
                    })
            })?
    };
    let absolute = |path: &str| PathBuf::from(join(base_dir, path));
    host.ca = entry.ca.as_ref().map(|ca| match ca {
        Paths::One(path) => vec![absolute(path)],
        Paths::Many(paths) => paths.iter().map(|p| absolute(p)).collect(),
    });
    host.client = match &entry.client {
        None => None,
        Some(Client::One(cert)) => Some(vec![ClientPair {
            cert: absolute(cert),
            key: None,
        }]),
        Some(Client::Many(items)) => Some(
            items
                .iter()
                .map(|item| match item {
                    ClientItem::Cert(cert) => Ok(ClientPair {
                        cert: absolute(cert),
                        key: None,
                    }),
                    ClientItem::Pair(files) => match files.as_slice() {
                        [cert, key] => Ok(ClientPair {
                            cert: absolute(cert),
                            // Go joins an empty key with the directory, so that one is the directory.
                            key: Some(absolute(key)).filter(|key| !key.as_os_str().is_empty()),
                        }),
                        _ => Err(ParseError::new(
                            at("client"),
                            format!("invalid pair {files:?}"),
                        )),
                    },
                })
                .collect::<Result<_, _>>()?,
        ),
    };
    if let Some(header) = &entry.header {
        host.header = header
            .iter()
            .map(|(name, value)| (name.clone(), value.values()))
            .collect();
    }
    if !entry.dial_timeout.is_empty() {
        host.dial_timeout = Some(
            parse_duration(&entry.dial_timeout)
                .map_err(|e| ParseError::new(at("dial_timeout"), e.to_string()))?,
        );
    }
    Ok(host)
}

/// `makeAbsPath`: `path` itself when absolute, else joined to `base` (cleaned, as Go's `filepath.Join`).
fn join(base: &Path, path: &str) -> String {
    if path.starts_with('/') {
        return path.to_owned();
    }
    join_clean(&base.to_string_lossy(), path)
}

/// Go's `filepath.Join` of two elements: empty ones are ignored, the result is cleaned.
fn join_clean(first: &str, second: &str) -> String {
    match (first.is_empty(), second.is_empty()) {
        (true, true) => String::new(),
        (true, false) => clean_path(second),
        (false, true) => clean_path(first),
        (false, false) => clean_path(&format!("{first}/{second}")),
    }
}

/// The `hosts.toml` of `dir`, parsed: `None` when it is missing or empty, where containerd reads certificate files.
///
/// # Errors
///
/// When the file cannot be read, or [`parse_hosts_file`] refuses it.
pub fn read_hosts_toml(dir: &Path) -> Result<Option<Vec<HostConfig>>, HostsError> {
    let path = dir.join("hosts.toml");
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(HostsError::Read { path, source }),
    };
    if bytes.is_empty() {
        return Ok(None);
    }
    let parsed = String::from_utf8(bytes)
        .map_err(|e| ParseError::new("", e.to_string()))
        .and_then(|text| parse_hosts_file(dir, &text));
    parsed
        .map(Some)
        .map_err(|source| HostsError::Parse { path, source })
}

/// The hosts of a host directory (`loadHostDir`, `hosts.go:315`): its `hosts.toml`, or, when it has none or containerd
/// cannot decode it (it logs the failure and goes on), the certificate files of Docker's layout.
///
/// # Errors
///
/// When a file or the directory cannot be read.
pub fn load_host_dir(dir: &Path) -> Result<Vec<HostConfig>, HostsError> {
    match read_hosts_toml(dir) {
        Ok(Some(hosts)) => Ok(hosts),
        Ok(None) => load_cert_files(dir),
        Err(HostsError::Parse { path, source }) => {
            tracing::error!(path = %path.display(), error = %source, "failed to decode hosts.toml");
            load_cert_files(dir)
        }
        Err(e) => Err(e),
    }
}

/// `loadCertFiles` (`hosts.go:622`): `*.crt` are CA certificates, `*.cert` client certificates with the `*.key` next
/// to them. One host, with no name.
#[expect(
    clippy::case_sensitive_file_extension_comparisons,
    reason = "Go compares the suffix as bytes: `CA.CRT` is not a CA certificate"
)]
fn load_cert_files(dir: &Path) -> Result<Vec<HostConfig>, HostsError> {
    let read = |source| HostsError::Read {
        path: dir.to_owned(),
        source,
    };
    let mut names = Vec::new();
    match std::fs::read_dir(dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(read)?;
                if !entry.file_type().map_err(read)?.is_dir() {
                    names.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(read(e)),
    }
    names.sort();
    let mut host = HostConfig::default();
    for name in names {
        if name.ends_with(".crt") {
            host.ca.get_or_insert_default().push(dir.join(&name));
        }
        if let Some(stem) = name.strip_suffix(".cert") {
            let key = dir.join(format!("{stem}.key"));
            let key = match std::fs::metadata(&key) {
                Ok(_) => Some(key),
                Err(e) if e.kind() == ErrorKind::NotFound => None,
                Err(source) => return Err(HostsError::Read { path: key, source }),
            };
            host.client.get_or_insert_default().push(ClientPair {
                cert: dir.join(&name),
                key,
            });
        }
    }
    host.capabilities = Capabilities::NONE;
    Ok(vec![host])
}

/// `hostPaths` (`config_unix.go`): where `root` keeps the config of `host`. A port is written `_port_` in the first.
fn host_paths(root: &Path, host: &str) -> Vec<PathBuf> {
    let root = root.to_string_lossy();
    let mut paths = Vec::new();
    if let Some(i) = host.rfind(':').filter(|i| *i > 0) {
        paths.push(join_clean(&root, &format!("{}_{}_", &host[..i], &host[i + 1..])).into());
    }
    paths.push(join_clean(&root, host).into());
    paths.push(join_clean(&root, "_default").into());
    paths
}

/// The directory of `host` in the first of `roots` that has one (`HostDirFromRoot`, `hostDirFromRoots`): `root/host`
/// with a port as `_port_`, else `root/_default`.
///
/// # Errors
///
/// When looking for a directory fails other than by its absence.
pub fn host_dir(roots: &[PathBuf], host: &str) -> Result<Option<PathBuf>, HostsError> {
    for root in roots {
        for path in host_paths(root, host) {
            match std::fs::metadata(&path) {
                Ok(_) => return Ok(Some(path)),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(source) => return Err(HostsError::Read { path, source }),
            }
        }
    }
    Ok(None)
}

/// An endpoint a runtime tries for a registry host, with everything containerd's `ConfigureHosts` settles.
#[derive(Clone, Debug)]
pub struct RegistryHost {
    /// `http` or `https`.
    pub scheme: String,
    /// The host and port.
    pub host: String,
    /// The API root.
    pub path: String,
    /// What the host may be used for.
    pub capabilities: Capabilities,
    /// Headers added to every request to the host.
    pub header: Headers,
    /// The TLS settings the file names, or the defaults of a local registry.
    pub tls: Tls,
    /// How long to wait for a connection.
    pub dial_timeout: Option<Duration>,
    /// Whether a TLS failure retries on plain HTTP (`NewHTTPFallback`): an `http` host with TLS settings.
    pub http_fallback: bool,
}

/// The TLS settings of a [`RegistryHost`].
#[derive(Clone, Debug, Default)]
pub struct Tls {
    /// `skip_verify`, `None` when nothing says.
    pub skip_verify: Option<bool>,
    /// CA certificate files, besides the system's.
    pub ca: Vec<PathBuf>,
    /// Client certificates.
    pub client: Vec<ClientPair>,
}

impl RegistryHost {
    /// Whether the host stands in for `ref_host`, the registry of the image (`isProxy`, `registry.go`): a mirror. A
    /// request to it carries `?ns=<ref_host>` ([`NAMESPACE_QUERY_ARG`]).
    #[must_use]
    pub fn is_proxy(&self, ref_host: &str) -> bool {
        self.host != ref_host && !(ref_host == "docker.io" && self.host == "registry-1.docker.io")
    }
}

/// The endpoints of `host`, as `ConfigureHosts` (`hosts.go:78`) lists them for a runtime whose `config_path` is
/// `roots`: those of its host directory in order, the default `server` last, with the defaults of a registry that
/// names none: `docker.io` is `registry-1.docker.io`, a local registry is tried on HTTPS then HTTP, any other is
/// HTTPS. `default_scheme` replaces the scheme of those defaults.
///
/// # Errors
///
/// When the host directory or its files cannot be read.
pub fn resolve(
    roots: &[PathBuf],
    host: &str,
    default_scheme: Option<&str>,
) -> Result<Vec<RegistryHost>, HostsError> {
    let mut hosts = match host_dir(roots, host)? {
        Some(dir) => load_host_dir(&dir)?,
        None => vec![HostConfig::default()],
    };
    if let Some(last) = hosts.last_mut().filter(|last| last.host.is_empty()) {
        apply_defaults(last, host, default_scheme);
    }
    Ok(hosts.into_iter().map(registry_host).collect())
}

fn apply_defaults(last: &mut HostConfig, host: &str, default_scheme: Option<&str>) {
    if host == "docker.io" {
        "https".clone_into(&mut last.scheme);
        "registry-1.docker.io".clone_into(&mut last.host);
    } else if is_localhost(host) {
        host.clone_into(&mut last.host);
        if let Some(scheme) = default_scheme {
            scheme.clone_into(&mut last.scheme);
        } else {
            let port = split_host_port(host).map_or("", |(_, port)| port);
            // On the default port only HTTPS makes sense; elsewhere the scheme is ambiguous and HTTP follows HTTPS.
            let scheme = if port.is_empty() || port == "443" {
                "https"
            } else {
                "http"
            };
            scheme.clone_into(&mut last.scheme);
            if port != "80" {
                last.skip_verify = Some(true);
            }
        }
    } else {
        host.clone_into(&mut last.host);
        default_scheme
            .unwrap_or("https")
            .clone_into(&mut last.scheme);
    }
    "/v2".clone_into(&mut last.path);
    last.capabilities = Capabilities::ALL;
}

fn registry_host(config: HostConfig) -> RegistryHost {
    let mut scheme = config.scheme.clone();
    let mut http_fallback = false;
    if scheme == "http" && config.has_tls() {
        let port = split_host_port(&config.host).map_or("", |(_, port)| port);
        if port != "80" {
            "https".clone_into(&mut scheme);
            http_fallback = true;
        }
    }
    RegistryHost {
        scheme,
        tls: Tls {
            skip_verify: config.skip_verify,
            ca: config.ca().to_vec(),
            client: config.client().to_vec(),
        },
        host: config.host,
        path: config.path,
        capabilities: config.capabilities,
        header: config.header,
        dial_timeout: config.dial_timeout,
        http_fallback,
    }
}
