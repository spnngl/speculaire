//! containerd's `config.toml`: the registry section the CRI image service reads (D17).
//!
//! Ported from containerd's `cmd/containerd/server/config/config.go` at v2.4.2 (`LoadConfigWithPlugins`,
//! `resolveImports`, `mergeConfig`, the migrations of config versions 1 to 3), the image and runtime services'
//! migrations (`plugins/cri/images/plugin.go:configMigration`, `plugins/cri/runtime/plugin.go:configMigration`) and
//! `internal/cri/config/config.go` (`Registry`, `ValidateImageConfig`). The `config` tests run it against
//! containerd's own loader.
//!
//! A config of version 1 or 2 keeps the registry under `plugins."io.containerd.grpc.v1.cri".registry`, a config of
//! version 3 or 4 under `plugins."io.containerd.cri.v1.images".registry`; containerd migrates the older in memory and
//! so does [`load`]. Keys the agent does not read are not checked: a config containerd refuses for one of them still
//! loads here.

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::Deserialize;
use toml::{Table, Value};

use crate::ParseError;
use crate::error::{from_toml, from_value};
use crate::fold::{fold_fields, fold_value_fields, go_toml, value_table_at, value_tables_in};
use crate::go::{clean_path, glob, parse_url};
use crate::header::Headers;
use crate::nri::RequestTimeout;

/// Where containerd reads its config unless told otherwise.
pub const DEFAULT_PATH: &str = "/etc/containerd/config.toml";

/// containerd's `root` unless its config names another (`defaults.DefaultRootDir`).
pub const DEFAULT_ROOT: &str = "/var/lib/containerd";

/// The highest config version this containerd reads (`version.ConfigVersion`).
const CONFIG_VERSION: i64 = 4;
const CRI_PLUGIN: &str = "io.containerd.grpc.v1.cri";
const IMAGES_PLUGIN: &str = "io.containerd.cri.v1.images";
const NRI_PLUGIN: &str = "io.containerd.nri.v1.nri";
const RUNTIME_PLUGIN: &str = "io.containerd.cri.v1.runtime";
/// `config_path` when the config sets neither it nor `mirrors` (`plugins/cri/images/plugin.go:76`).
const DEFAULT_CONFIG_PATH: &str = "/etc/containerd/certs.d:/etc/docker/certs.d";

/// The credentials of one registry (`AuthConfig`): the first that is set is used, in this order.
#[derive(Clone, Debug, Deserialize)]
pub struct Auth {
    /// The user name; not a secret.
    #[serde(default)]
    pub username: String,
    /// The password, used with `username`.
    #[serde(default = "empty")]
    pub password: SecretString,
    /// The base64 of `username:password`.
    #[serde(default = "empty")]
    pub auth: SecretString,
    /// A token to trade for an access token.
    #[serde(default = "empty", rename = "identitytoken")]
    pub identity_token: SecretString,
}

fn empty() -> SecretString {
    SecretString::from(String::new())
}

/// What an [`Auth`] logs in with.
#[derive(Clone, Debug)]
pub enum Login {
    /// A user name and password.
    Password {
        /// The user name.
        username: String,
        /// The password.
        password: SecretString,
    },
    /// An identity token, with no user name.
    IdentityToken(SecretString),
}

/// An `auth` that is not the base64 of `user:password`.
#[derive(Debug, thiserror::Error)]
#[error("auth is not the base64 of user:password")]
pub struct InvalidAuth;

impl Auth {
    /// The login `ParseAuth` makes of these credentials (`internal/cri/server/images/image_pull.go:358`): the user
    /// name and password, else the identity token, else `auth` split at its first `:`, with NULs trimmed off the
    /// password. `None` when nothing is set: the registry is asked as anyone.
    ///
    /// # Errors
    ///
    /// When `auth` is set and is not base64 with a `:` in it.
    pub fn login(&self) -> Result<Option<Login>, InvalidAuth> {
        use secrecy::ExposeSecret as _;
        if !self.username.is_empty() {
            return Ok(Some(Login::Password {
                username: self.username.clone(),
                password: self.password.clone(),
            }));
        }
        if !self.identity_token.expose_secret().is_empty() {
            return Ok(Some(Login::IdentityToken(self.identity_token.clone())));
        }
        let auth = self.auth.expose_secret();
        if auth.is_empty() {
            return Ok(None);
        }
        let decoded = crate::crio::auth::base64_decode(auth).ok_or(InvalidAuth)?;
        let (username, password) = crate::crio::auth::split_login(&decoded).ok_or(InvalidAuth)?;
        Ok(Some(Login::Password { username, password }))
    }
}

#[derive(Deserialize, Default)]
struct Mirror {
    #[serde(default)]
    endpoint: Vec<String>,
}

#[derive(Deserialize, Default)]
struct RegistryConfig {
    auth: Option<Auth>,
}

/// The `registry` section as the CRI image service decodes it, before it validates it (`Registry`).
#[derive(Deserialize, Default, Debug)]
pub struct RawRegistry {
    /// `config_path`: directories separated by `:`, empty when unset.
    #[serde(default)]
    pub config_path: String,
    /// `mirrors`, which cannot be combined with `config_path`: the endpoints of each registry.
    #[serde(default, deserialize_with = "mirrors")]
    pub mirrors: BTreeMap<String, Vec<String>>,
    /// `configs."<host>".auth`.
    #[serde(default, deserialize_with = "configs")]
    pub configs: BTreeMap<String, Option<Auth>>,
    /// `auths."<url>"`, the old form of `configs`.
    #[serde(default)]
    pub auths: BTreeMap<String, Auth>,
    /// `headers`, sent to every registry.
    #[serde(default)]
    pub headers: Headers,
}

fn mirrors<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Vec<String>>, D::Error> {
    let all = BTreeMap::<String, Mirror>::deserialize(deserializer)?;
    Ok(all
        .into_iter()
        .map(|(host, m)| (host, m.endpoint))
        .collect())
}

fn configs<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, Option<Auth>>, D::Error> {
    let all = BTreeMap::<String, RegistryConfig>::deserialize(deserializer)?;
    Ok(all.into_iter().map(|(host, c)| (host, c.auth)).collect())
}

/// Where the runtime finds the endpoints of a registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hosts {
    /// `config_path`: the directories of `hosts.toml` trees, tried in order (`filepath.SplitList`).
    ConfigPath(Vec<PathBuf>),
    /// The deprecated `mirrors`: the endpoints of each registry. Not combined with `config_path`.
    Mirrors(BTreeMap<String, Vec<String>>),
}

/// The registry settings of a containerd (D17), validated as the CRI image service does.
#[derive(Debug)]
pub struct Registry {
    /// Where the endpoints are.
    pub hosts: Hosts,
    /// The credentials per registry host, from `configs` and `auths`.
    pub configs: BTreeMap<String, Auth>,
    /// The headers sent to every registry.
    pub headers: Headers,
}

/// A registry section containerd refuses to start with (`ValidateImageConfig`).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistryError {
    /// Both `mirrors` and `config_path` are set.
    #[error("`mirrors` cannot be set when `config_path` is provided")]
    MirrorsWithConfigPath,
    /// An `auths` key is not a URL.
    #[error("failed to parse registry url {url:?} from `registry.auths`: {message}")]
    AuthsUrl {
        /// The key.
        url: String,
        /// Why it is not.
        message: String,
    },
}

impl TryFrom<RawRegistry> for Registry {
    type Error = RegistryError;

    fn try_from(raw: RawRegistry) -> Result<Self, RegistryError> {
        let hosts = if raw.mirrors.is_empty() {
            let list = if raw.config_path.is_empty() {
                DEFAULT_CONFIG_PATH
            } else {
                &raw.config_path
            };
            // Go's `filepath.SplitList`, of a list that is not empty.
            Hosts::ConfigPath(list.split(':').map(PathBuf::from).collect())
        } else if raw.config_path.is_empty() {
            Hosts::Mirrors(raw.mirrors)
        } else {
            return Err(RegistryError::MirrorsWithConfigPath);
        };
        let mut configs: BTreeMap<String, Auth> = raw
            .configs
            .into_iter()
            .filter_map(|(host, auth)| auth.map(|auth| (host, auth)))
            .collect();
        for (url, auth) in raw.auths {
            let parsed = parse_url(&url).map_err(|e| RegistryError::AuthsUrl {
                url: url.clone(),
                message: e.to_string(),
            })?;
            // The scheme is not part of the host a config is looked up by.
            let host = if parsed.scheme.is_empty() {
                url
            } else {
                parsed.host
            };
            configs.insert(host, auth);
        }
        Ok(Self {
            hosts,
            configs,
            headers: raw.headers,
        })
    }
}

/// A config that could not be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoadError {
    /// A file could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// A file is not a valid config.
    #[error("invalid config {}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// What is wrong, and where.
        source: ParseError,
    },
    /// An `imports` pattern is malformed.
    #[error("{}: bad import pattern {pattern:?}", path.display())]
    Import {
        /// The file that imports it.
        path: PathBuf,
        /// The pattern.
        pattern: String,
    },
    /// A file is of a version this containerd does not know.
    #[error(
        "expected containerd config version equal to or less than `{CONFIG_VERSION}`, got `{found}`"
    )]
    Version {
        /// The version.
        found: i64,
    },
    /// A plugin to disable or require is not named by a URI.
    #[error("invalid {list} plugin URI {name:?} expect io.containerd.x.vx")]
    PluginUri {
        /// `disabled` or `required`.
        list: &'static str,
        /// The name.
        name: String,
    },
    /// A plugin section has the wrong type, where containerd's migration reads it.
    #[error("{}: cannot migrate the config", path.display())]
    Migrate {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: ParseError,
    },
    /// The registry section of the merged config is not valid.
    #[error("invalid registry section of the config")]
    Registry(#[source] ParseError),
    /// The NRI section of the merged config is not valid.
    #[error("invalid NRI section of the config")]
    Nri(#[source] ParseError),
    /// The CRI runtime section of the merged config is not valid.
    #[error("invalid CRI runtime section of the config")]
    Runtime(#[source] ParseError),
    /// containerd would refuse the registry section.
    #[error(transparent)]
    Refused(#[from] RegistryError),
}

const FILE_FIELDS: &[&str] = &[
    "version",
    "root",
    "imports",
    "plugins",
    "disabled_plugins",
    "required_plugins",
];

/// The keys of the image service's section that the agent reads, matched in any case as go-toml does.
fn fold_images(images: &mut Table) {
    const AUTH: &[&str] = &["username", "password", "auth", "identitytoken"];
    fold_value_fields(
        images,
        &["registry", "discard_unpacked_layers", "snapshotter"],
    );
    let Some(registry) = value_table_at(images, "registry") else {
        return;
    };
    fold_value_fields(
        registry,
        &["config_path", "mirrors", "configs", "auths", "headers"],
    );
    if let Some(mirrors) = value_table_at(registry, "mirrors") {
        value_tables_in(mirrors).for_each(|mirror| fold_value_fields(mirror, &["endpoint"]));
    }
    if let Some(configs) = value_table_at(registry, "configs") {
        for config in value_tables_in(configs) {
            fold_value_fields(config, &["auth"]);
            if let Some(auth) = value_table_at(config, "auth") {
                fold_value_fields(auth, AUTH);
            }
        }
    }
    if let Some(auths) = value_table_at(registry, "auths") {
        value_tables_in(auths).for_each(|auth| fold_value_fields(auth, AUTH));
    }
}

/// The image service's plugin section, of which only `registry`, `discard_unpacked_layers` and `snapshotter` are read.
#[derive(Deserialize)]
struct Images {
    #[serde(default)]
    registry: RawRegistry,
    #[serde(default)]
    discard_unpacked_layers: bool,
    #[serde(default = "default_snapshotter")]
    snapshotter: String,
}

impl Default for Images {
    fn default() -> Self {
        Self {
            registry: RawRegistry::default(),
            discard_unpacked_layers: false,
            snapshotter: default_snapshotter(),
        }
    }
}

/// The snapshotter containerd's image service defaults to on Linux (v2.3.7 `defaults/defaults_linux.go:32`).
pub const DEFAULT_SNAPSHOTTER: &str = "overlayfs";

fn default_snapshotter() -> String {
    DEFAULT_SNAPSHOTTER.to_owned()
}

/// The NRI plugin's section, of which only `disable`, `disable_connections`, `plugin_request_timeout` and the default
/// validator's `required_plugins` are read.
#[derive(Deserialize, Default)]
struct RawNri {
    #[serde(default)]
    disable: bool,
    #[serde(default)]
    disable_connections: bool,
    #[serde(default)]
    plugin_request_timeout: RequestTimeout,
    #[serde(default)]
    default_validator: DefaultValidator,
}

/// The settings of containerd's NRI plugin that the agent depends on (D54, D64); the default is a config that sets none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Nri {
    /// `disable`: containerd's NRI is off altogether.
    pub disable: bool,
    /// `disable_connections`: plugins that start on their own cannot connect.
    pub disable_connections: bool,
    /// The plugin is in `disabled_plugins`, which the daemon honours as `disable`.
    pub plugin_disabled: bool,
    /// `required_plugins` of `default_validator`: the plugins containerd refuses containers without.
    pub required_plugins: Vec<String>,
    /// `plugin_request_timeout`: how long containerd waits for the gate's answer (D41).
    pub request_timeout: RequestTimeout,
}

impl Nri {
    /// Whether an external plugin can connect to this containerd.
    #[must_use]
    pub const fn accepts_plugins(&self) -> bool {
        !self.disable && !self.plugin_disabled && !self.disable_connections
    }
}

/// What the agent reads of containerd's plugin sections besides the registry (D15, D54, D86); the default is what
/// containerd runs on without a config file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plugins {
    /// `discard_unpacked_layers` of the image service: containerd drops the layers it has unpacked, so the node
    /// cannot serve them.
    pub discard_unpacked_layers: bool,
    /// The NRI plugin.
    pub nri: Nri,
}

/// The runtime handler of a pod that names none, unless the config names another (v2.3.7
/// `internal/cri/config/config_unix.go:91`).
pub const DEFAULT_RUNTIME: &str = "runc";

/// The snapshotters containerd creates containers on (D170, D171); the default is what containerd runs on without a
/// config file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshotters {
    /// `snapshotter` of the image service, as set: empty when the config sets it empty.
    pub images: String,
    /// `containerd.default_runtime_name` of the CRI runtime service.
    pub default_runtime: String,
    /// `snapshotter` of each runtime handler under `containerd.runtimes` of the CRI runtime service, as set.
    pub handlers: BTreeMap<String, String>,
}

impl Default for Snapshotters {
    fn default() -> Self {
        Self {
            images: default_snapshotter(),
            default_runtime: DEFAULT_RUNTIME.to_owned(),
            handlers: BTreeMap::new(),
        }
    }
}

impl Snapshotters {
    /// The snapshotter of the containers of a pod run by `handler`, the default handler when empty
    /// (`internal/cri/config/config.go:750`): the handler's own, else the image service's (v2.3.7
    /// `internal/cri/server/images/service.go:191`), else the default one, as containerd's client picks for an empty
    /// name.
    #[must_use]
    pub fn of(&self, handler: &str) -> &str {
        let handler = if handler.is_empty() {
            &self.default_runtime
        } else {
            handler
        };
        [self.handlers.get(handler), Some(&self.images)]
            .into_iter()
            .flatten()
            .find(|snapshotter| !snapshotter.is_empty())
            .map_or(DEFAULT_SNAPSHOTTER, String::as_str)
    }
}

/// The CRI runtime service's section, of which only `containerd.default_runtime_name` and each runtime's
/// `snapshotter` are read.
#[derive(Deserialize, Default)]
struct RawRuntime {
    #[serde(default)]
    containerd: RawContainerd,
}

#[derive(Deserialize)]
#[serde(default)]
struct RawContainerd {
    default_runtime_name: String,
    runtimes: BTreeMap<String, RawHandler>,
}

impl Default for RawContainerd {
    fn default() -> Self {
        Self {
            default_runtime_name: DEFAULT_RUNTIME.to_owned(),
            runtimes: BTreeMap::new(),
        }
    }
}

#[derive(Deserialize)]
struct RawHandler {
    #[serde(default)]
    snapshotter: String,
}

#[derive(Deserialize, Default)]
struct DefaultValidator {
    #[serde(default)]
    required_plugins: Vec<String>,
}

#[derive(Deserialize, Default)]
struct File {
    #[serde(default)]
    version: i64,
    #[serde(default)]
    root: String,
    #[serde(default)]
    imports: Vec<String>,
    #[serde(default)]
    plugins: Table,
    #[serde(default)]
    disabled_plugins: Vec<String>,
    #[serde(default)]
    required_plugins: Vec<String>,
}

/// The config of a containerd: what every file read contributes, merged as `mergeConfig` does.
#[derive(Default)]
struct Merged {
    /// The files read, the config and its imports, in the order read.
    files: Vec<PathBuf>,
    /// The last `root` set; empty when none is.
    root: String,
    plugins: Table,
    disabled: Vec<String>,
    required: Vec<String>,
}

/// The image service's section of the merged config, decoded as the daemon does.
fn images_section(merged: &mut Merged) -> Result<Images, LoadError> {
    let mut images = match merged.plugins.remove(IMAGES_PLUGIN) {
        None => return Ok(Images::default()),
        Some(Value::Table(images)) => images,
        Some(_) => {
            return Err(LoadError::Registry(ParseError::new(
                format!("plugins.{IMAGES_PLUGIN:?}"),
                "is not a table",
            )));
        }
    };
    fold_images(&mut images);
    from_value::<Images>(Value::Table(images)).map_err(LoadError::Registry)
}

/// Loads `path` and its imports, and returns the registry section as containerd decodes it.
///
/// # Errors
///
/// When a file cannot be read or is not a valid config, or the merged config is one containerd refuses.
pub fn load_raw(path: &Path) -> Result<RawRegistry, LoadError> {
    Ok(images_section(&mut load_merged(path)?)?.registry)
}

/// Loads `path` and its imports, and returns what the agent reads of the image service and NRI sections: the merged
/// config of the daemon, which on 2.3 is also the only source of `discard_unpacked_layers` (D15).
///
/// # Errors
///
/// As [`load_raw`], and when the NRI section is not a valid one.
pub fn load_plugins(path: &Path) -> Result<Plugins, LoadError> {
    let mut merged = load_merged(path)?;
    let images = images_section(&mut merged)?;
    let mut nri = match merged.plugins.remove(NRI_PLUGIN) {
        None => Table::new(),
        Some(Value::Table(nri)) => nri,
        Some(_) => {
            return Err(LoadError::Nri(ParseError::new(
                format!("plugins.{NRI_PLUGIN:?}"),
                "is not a table",
            )));
        }
    };
    fold_value_fields(
        &mut nri,
        &[
            "disable",
            "disable_connections",
            "plugin_request_timeout",
            "default_validator",
        ],
    );
    if let Some(validator) = value_table_at(&mut nri, "default_validator") {
        fold_value_fields(validator, &["required_plugins"]);
    }
    let nri = from_value::<RawNri>(Value::Table(nri)).map_err(LoadError::Nri)?;
    Ok(Plugins {
        discard_unpacked_layers: images.discard_unpacked_layers,
        nri: Nri {
            disable: nri.disable,
            disable_connections: nri.disable_connections,
            plugin_disabled: merged.disabled.iter().any(|name| name == NRI_PLUGIN),
            required_plugins: nri.default_validator.required_plugins,
            request_timeout: nri.plugin_request_timeout,
        },
    })
}

/// The CRI runtime service's section of the merged config, decoded as the daemon does.
fn runtime_section(merged: &mut Merged) -> Result<RawRuntime, LoadError> {
    let mut runtime = match merged.plugins.remove(RUNTIME_PLUGIN) {
        None => return Ok(RawRuntime::default()),
        Some(Value::Table(runtime)) => runtime,
        Some(_) => {
            return Err(LoadError::Runtime(ParseError::new(
                format!("plugins.{RUNTIME_PLUGIN:?}"),
                "is not a table",
            )));
        }
    };
    fold_value_fields(&mut runtime, &["containerd"]);
    if let Some(containerd) = value_table_at(&mut runtime, "containerd") {
        fold_value_fields(containerd, &["default_runtime_name", "runtimes"]);
        if let Some(runtimes) = value_table_at(containerd, "runtimes") {
            value_tables_in(runtimes)
                .for_each(|handler| fold_value_fields(handler, &["snapshotter"]));
        }
    }
    from_value::<RawRuntime>(Value::Table(runtime)).map_err(LoadError::Runtime)
}

/// Loads `path` and its imports, and returns the snapshotters of the image and runtime services.
///
/// # Errors
///
/// As [`load_raw`], and when the runtime section is not a valid one.
pub fn load_snapshotters(path: &Path) -> Result<Snapshotters, LoadError> {
    let mut merged = load_merged(path)?;
    let images = images_section(&mut merged)?;
    let runtime = runtime_section(&mut merged)?.containerd;
    Ok(Snapshotters {
        images: images.snapshotter,
        default_runtime: runtime.default_runtime_name,
        handlers: runtime
            .runtimes
            .into_iter()
            .map(|(name, handler)| (name, handler.snapshotter))
            .collect(),
    })
}

/// Loads `path` and its imports, and returns containerd's `root`, below which each plugin keeps its data in a
/// directory named by the plugin's ID (`cmd/containerd/server/server.go:171`).
///
/// # Errors
///
/// As [`load_raw`].
pub fn load_root(path: &Path) -> Result<String, LoadError> {
    let merged = load_merged(path)?;
    Ok(if merged.root.is_empty() {
        DEFAULT_ROOT.to_owned()
    } else {
        merged.root
    })
}

/// Reads `path` and its imports, migrates each file and merges them as containerd does.
fn load_merged(path: &Path) -> Result<Merged, LoadError> {
    let mut merged = Merged::default();
    let mut pending = VecDeque::from([path.to_owned()]);
    while let Some(file_path) = pending.pop_front() {
        if merged.files.contains(&file_path) {
            continue;
        }
        merged.files.push(file_path.clone());
        let text = std::fs::read_to_string(&file_path).map_err(|source| LoadError::Read {
            path: file_path.clone(),
            source,
        })?;
        let mut file: File = from_toml(&text, |table| fold_fields(table, FILE_FIELDS, go_toml))
            .map_err(|source| LoadError::Parse {
                path: file_path.clone(),
                source,
            })?;
        // containerd refuses the merged config when its version is above its own, and the version of a merge only
        // rises: the first file of a newer version decides.
        if file.version > CONFIG_VERSION {
            return Err(LoadError::Version {
                found: file.version,
            });
        }
        migrate(&mut file).map_err(|source| LoadError::Migrate {
            path: file_path.clone(),
            source,
        })?;
        pending.extend(resolve_imports(&file_path, &file.imports)?);
        merge(&mut merged, file);
    }
    validate(&merged)?;
    Ok(merged)
}

/// Loads `path` and its imports, and returns the registry settings of containerd (D17).
///
/// # Errors
///
/// As [`load_raw`], and when containerd would refuse the registry section ([`RegistryError`]).
pub fn load(path: &Path) -> Result<Registry, LoadError> {
    load_with_files(path).map(|(registry, _)| registry)
}

/// [`load`], and the files it read: the config and its imports. A config that cannot be read has no files to name, and
/// the caller watches `path` alone.
///
/// # Errors
///
/// As [`load`].
pub fn load_with_files(path: &Path) -> Result<(Registry, Vec<PathBuf>), LoadError> {
    let mut merged = load_merged(path)?;
    let files = std::mem::take(&mut merged.files);
    let registry = Registry::try_from(images_section(&mut merged)?.registry)?;
    tracing::trace!(?registry, path = %path.display(), "read the containerd registry config");
    Ok((registry, files))
}

fn validate(merged: &Merged) -> Result<(), LoadError> {
    for (list, names) in [
        ("disabled", &merged.disabled),
        ("required", &merged.required),
    ] {
        if let Some(name) = names.iter().find(|name| !name.contains('.')) {
            return Err(LoadError::PluginUri {
                list,
                name: name.clone(),
            });
        }
    }
    Ok(())
}

/// What containerd's migrations make of a file's plugin sections, for the agent: version 1 plugin names become URIs,
/// and before version 4 the image service's section takes `registry` from the CRI plugin's, and the runtime service's
/// takes `[containerd]`.
fn migrate(file: &mut File) -> Result<(), ParseError> {
    if file.version >= CONFIG_VERSION {
        return Ok(());
    }
    if file.version < 0 {
        return Err(ParseError::new("version", "is not a config version"));
    }
    if file.version <= 1 {
        file.plugins = std::mem::take(&mut file.plugins)
            .into_iter()
            .map(|(name, value)| (v1_plugin_name(&name), value))
            .collect();
        for name in file
            .disabled_plugins
            .iter_mut()
            .chain(&mut file.required_plugins)
        {
            *name = v1_plugin_name(name);
        }
    }
    file.version = CONFIG_VERSION;
    let Some(cri) = file.plugins.get(CRI_PLUGIN) else {
        return Ok(());
    };
    let Value::Table(cri) = cri else {
        return Err(ParseError::new(
            format!("plugins.{CRI_PLUGIN:?}"),
            "is not a table",
        ));
    };
    let registry = cri.get("registry").cloned();
    let carried = carried(cri)?;
    let containerd = match cri.get("containerd") {
        Some(Value::Table(containerd)) => Some(containerd.clone()),
        _ => None,
    };
    let mut images = match file.plugins.remove(IMAGES_PLUGIN) {
        None => Table::new(),
        Some(Value::Table(table)) => table,
        Some(_) => {
            return Err(ParseError::new(
                format!("plugins.{IMAGES_PLUGIN:?}"),
                "is not a table",
            ));
        }
    };
    // `migrateConfig` type-asserts these two sections of the image service, and the daemon crashes on others.
    for key in ["pinned_images", "runtime_platform"] {
        if images.get(key).is_some_and(|v| !v.is_table())
            && (key == "pinned_images" || carried.reached)
        {
            return Err(ParseError::new(
                format!("plugins.{IMAGES_PLUGIN:?}.{key}"),
                "is not a table",
            ));
        }
    }
    if let Some(registry) = registry {
        images.insert("registry".to_owned(), registry);
    }
    for (key, value) in carried.values {
        images.insert(key.to_owned(), value);
    }
    file.plugins
        .insert(IMAGES_PLUGIN.to_owned(), Value::Table(images));
    if let Some(containerd) = containerd {
        migrate_runtime(&mut file.plugins, containerd);
    }
    Ok(())
}

/// `migrateConfig` of the runtime service (`plugins/cri/runtime/plugin.go`, v2.4.2): each key of `[containerd]` of
/// the CRI plugin but those the image service takes goes to the runtime service's `[containerd]`, where that sets
/// none. A section of the runtime service that is not a table is replaced.
fn migrate_runtime(plugins: &mut Table, carried: Table) {
    const TAKEN: &[&str] = &[
        "snapshotter",
        "disable_snapshot_annotations",
        "discard_unpacked_layers",
    ];
    let mut runtime = match plugins.remove(RUNTIME_PLUGIN) {
        Some(Value::Table(runtime)) => runtime,
        _ => Table::new(),
    };
    let mut containerd = match runtime.remove("containerd") {
        Some(Value::Table(containerd)) => containerd,
        _ => Table::new(),
    };
    for (key, value) in carried {
        if !TAKEN.contains(&key.as_str()) {
            containerd.entry(key).or_insert(value);
        }
    }
    runtime.insert("containerd".to_owned(), Value::Table(containerd));
    plugins.insert(RUNTIME_PLUGIN.to_owned(), Value::Table(runtime));
}

/// What `migrateConfig` takes from `[containerd]` of the CRI plugin.
struct Carried {
    /// The migration got past `containerd.runtimes`, where it copies the keys it carries over.
    reached: bool,
    /// `containerd.discard_unpacked_layers` and `containerd.snapshotter`, those set, copied only when `reached`.
    values: Vec<(&'static str, Value)>,
}

/// `migrateConfig` (`plugins/cri/images/plugin.go`, v2.4.2): it copies `discard_unpacked_layers` and `snapshotter`
/// from `[containerd]` only when that table has `runtimes`, and asserts that `containerd`, `runtimes` and each runtime
/// are tables.
fn carried(cri: &Table) -> Result<Carried, ParseError> {
    let none = Carried {
        reached: false,
        values: Vec::new(),
    };
    let key = format!("plugins.{CRI_PLUGIN:?}");
    let Some(containerd) = cri.get("containerd") else {
        return Ok(none);
    };
    let Value::Table(containerd) = containerd else {
        return Err(ParseError::new(
            format!("{key}.containerd"),
            "is not a table",
        ));
    };
    let Some(runtimes) = containerd.get("runtimes") else {
        return Ok(none);
    };
    let Value::Table(runtimes) = runtimes else {
        return Err(ParseError::new(
            format!("{key}.containerd.runtimes"),
            "is not a table",
        ));
    };
    if let Some(name) = runtimes.iter().find(|(_, v)| !v.is_table()).map(|(n, _)| n) {
        return Err(ParseError::new(
            format!("{key}.containerd.runtimes.{name}"),
            "is not a table",
        ));
    }
    Ok(Carried {
        reached: true,
        values: ["discard_unpacked_layers", "snapshotter"]
            .into_iter()
            .filter_map(|key| Some((key, containerd.get(key)?.clone())))
            .collect(),
    })
}

/// `v1MigratePluginName` (`config.go:162`).
fn v1_plugin_name(plugin: &str) -> String {
    if plugin.contains('.') {
        return plugin.to_owned();
    }
    let core = match plugin {
        "cri" => "io.containerd.grpc.v1.cri",
        "cgroups" => "io.containerd.monitor.v1.cgroups",
        "linux" => "io.containerd.runtime.v1.linux",
        "scheduler" => "io.containerd.gc.v1.scheduler",
        "bolt" => "io.containerd.metadata.v1.bolt",
        "task" => "io.containerd.runtime.v2.task",
        "opt" => "io.containerd.internal.v1.opt",
        "restart" => "io.containerd.internal.v1.restart",
        "tracing" => "io.containerd.internal.v1.tracing",
        "otlp" => "io.containerd.tracing.processor.v1.otlp",
        "aufs" | "btrfs" | "devmapper" | "native" | "overlayfs" | "zfs" => {
            return format!("io.containerd.snapshotter.v1.{plugin}");
        }
        _ => "",
    };
    if !core.is_empty() {
        core.to_owned()
    } else if plugin.ends_with("-service") {
        format!("io.containerd.service.v1.{plugin}")
    } else if plugin == "windows" || plugin == "windows-lcow" {
        format!("io.containerd.snapshotter.v1.{plugin}")
    } else {
        format!("io.containerd.grpc.v1.{plugin}")
    }
}

/// `resolveImports` (`config.go:569`): absolute paths as they are, others relative to the importing file's directory,
/// and patterns with `*` expanded.
fn resolve_imports(parent: &Path, imports: &[String]) -> Result<Vec<PathBuf>, LoadError> {
    let mut paths = Vec::new();
    for import in imports {
        let mut path = clean_path(import);
        if !path.starts_with('/') {
            let parent = parent.to_string_lossy();
            let dir = parent.rfind('/').map_or("", |i| &parent[..=i]);
            path = clean_path(&format!("{}/{path}", clean_path(dir)));
        }
        if path.contains('*') {
            paths.extend(glob(&path).map_err(|_| LoadError::Import {
                path: parent.to_owned(),
                pattern: import.clone(),
            })?);
        } else {
            paths.push(PathBuf::from(path));
        }
    }
    Ok(paths)
}

/// `mergeConfig` (`config.go:604`): later files win; plugin tables merge by key, deeply, and any other value, an array
/// included, replaces; the plugin lists are unions; an empty `root` leaves the one before.
fn merge(into: &mut Merged, file: File) {
    if !file.root.is_empty() {
        into.root = file.root;
    }
    merge_table(&mut into.plugins, file.plugins);
    for (list, new) in [
        (&mut into.disabled, file.disabled_plugins),
        (&mut into.required, file.required_plugins),
    ] {
        for name in new {
            if !list.contains(&name) {
                list.push(name);
            }
        }
    }
}

fn merge_table(into: &mut Table, from: Table) {
    for (key, value) in from {
        match (into.get_mut(&key), value) {
            (Some(Value::Table(into)), Value::Table(from)) => merge_table(into, from),
            (_, value) => {
                into.insert(key, value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_files_read_are_the_config_and_its_imports() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let conf = dir.path().join("config.toml");
        std::fs::create_dir(dir.path().join("conf.d")).expect("a directory");
        std::fs::write(
            &conf,
            "version = 2\nimports = [\"conf.d/*.toml\"]\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\nconfig_path = \"/etc/containerd/certs.d\"\n",
        )
        .expect("a file");
        std::fs::write(dir.path().join("conf.d/a.toml"), "version = 2\n").expect("a file");
        let (registry, files) = load_with_files(&conf).expect("a valid config");
        assert_eq!(
            registry.hosts,
            Hosts::ConfigPath(vec![PathBuf::from("/etc/containerd/certs.d")])
        );
        assert_eq!(files, [conf.clone(), dir.path().join("conf.d/a.toml")]);
        std::fs::write(dir.path().join("conf.d/a.toml"), "version = [").expect("a file");
        assert!(matches!(
            load_with_files(&conf),
            Err(LoadError::Parse { .. })
        ));
    }

    #[test]
    fn the_root_is_the_last_one_set_else_the_default() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let conf = dir.path().join("config.toml");
        assert!(matches!(load_root(&conf), Err(LoadError::Read { .. })));
        std::fs::write(&conf, "version = 3\n").expect("a file");
        assert_eq!(load_root(&conf).expect("a valid config"), DEFAULT_ROOT);
        // go-toml matches keys in any case; an import's empty `root` keeps the config's.
        std::fs::write(
            &conf,
            "version = 3\nRoot = \"/data/containerd\"\nimports = [\"a.toml\"]\n",
        )
        .expect("a file");
        let import = dir.path().join("a.toml");
        std::fs::write(&import, "version = 3\nroot = \"\"\n").expect("a file");
        assert_eq!(
            load_root(&conf).expect("a valid config"),
            "/data/containerd"
        );
        std::fs::write(&import, "version = 3\nroot = \"/srv/c\"\n").expect("a file");
        assert_eq!(load_root(&conf).expect("a valid config"), "/srv/c");
    }

    /// The image service's snapshotter: its default, its own key, and version 2's `[containerd]` one, carried over
    /// only past `runtimes` (D170). The oracle's `config` case compares the same against containerd.
    #[test]
    fn the_snapshotter_is_the_image_service_s_else_overlayfs() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let conf = dir.path().join("config.toml");
        let cri = "[plugins.\"io.containerd.grpc.v1.cri\".containerd]\nsnapshotter = \"native\"\n";
        let images = "[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter";
        for (text, snapshotter) in [
            ("version = 3\n".to_owned(), "overlayfs"),
            (format!("version = 3\n{images} = \"zfs\"\n"), "zfs"),
            (format!("version = 3\n{images} = \"\"\n"), "overlayfs"),
            (format!("version = 2\n{cri}"), "overlayfs"),
            (
                format!(
                    "version = 2\n{cri}[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\n"
                ),
                "native",
            ),
        ] {
            std::fs::write(&conf, &text).expect("a file");
            let snapshotters = load_snapshotters(&conf).expect("a valid config");
            assert_eq!(snapshotters.of(""), snapshotter, "{text}");
        }
        assert_eq!(Snapshotters::default().of(""), DEFAULT_SNAPSHOTTER);
    }

    /// A runtime handler's snapshotter comes before the image service's, the default handler's for a pod that names
    /// none, and version 2 keeps the handlers in the CRI plugin (D171).
    #[test]
    fn a_runtime_handler_s_snapshotter_comes_before_the_image_service_s() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let conf = dir.path().join("config.toml");
        let runtime = "[plugins.\"io.containerd.cri.v1.runtime\".containerd";
        let cri = "[plugins.\"io.containerd.grpc.v1.cri\".containerd";
        let kata = format!("{runtime}.runtimes.kata]\nsnapshotter = \"devmapper\"\n");
        for (text, handler, snapshotter) in [
            (format!("version = 3\n{kata}"), "kata", "devmapper"),
            (format!("version = 3\n{kata}"), "runc", "overlayfs"),
            (format!("version = 3\n{kata}"), "", "overlayfs"),
            (format!("version = 3\n{kata}"), "unknown", "overlayfs"),
            (
                format!("version = 3\n{kata}{runtime}]\ndefault_runtime_name = \"kata\"\n"),
                "",
                "devmapper",
            ),
            (
                "version = 3\n[plugins.\"io.containerd.cri.v1.runtime\".Containerd.Runtimes.kata]\nSnapshotter = \"devmapper\"\n".to_owned(),
                "kata",
                "devmapper",
            ),
            (
                format!(
                    "version = 3\n{runtime}.runtimes.kata]\nsnapshotter = \"\"\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"zfs\"\n"
                ),
                "kata",
                "zfs",
            ),
            (
                format!("version = 2\n{cri}]\ndefault_runtime_name = \"kata\"\n{cri}.runtimes.kata]\nsnapshotter = \"devmapper\"\n"),
                "",
                "devmapper",
            ),
            (
                format!("version = 2\n{cri}.runtimes.a]\nsnapshotter = \"x\"\n{runtime}.runtimes.b]\nsnapshotter = \"y\"\n"),
                "a",
                "overlayfs",
            ),
            (
                format!("version = 2\n{cri}.runtimes.a]\nsnapshotter = \"x\"\n{runtime}.runtimes.b]\nsnapshotter = \"y\"\n"),
                "b",
                "y",
            ),
            (
                format!("version = 2\n{cri}.runtimes.a]\nsnapshotter = \"x\"\n[plugins.\"io.containerd.cri.v1.runtime\"]\ncontainerd = 1\n"),
                "a",
                "x",
            ),
            (
                format!("version = 4\n{cri}.runtimes.kata]\nsnapshotter = \"devmapper\"\n"),
                "kata",
                "overlayfs",
            ),
        ] {
            std::fs::write(&conf, &text).expect("a file");
            let snapshotters = load_snapshotters(&conf).expect("a valid config");
            assert_eq!(snapshotters.of(handler), snapshotter, "{handler:?} in {text}");
        }
        for text in [
            "version = 3\n[plugins]\n\"io.containerd.cri.v1.runtime\" = 1\n".to_owned(),
            format!("version = 3\n{runtime}]\nruntimes = 1\n"),
            format!("version = 3\n{runtime}.runtimes.kata]\nsnapshotter = 1\n"),
        ] {
            std::fs::write(&conf, &text).expect("a file");
            assert!(
                matches!(load_snapshotters(&conf), Err(LoadError::Runtime(_))),
                "{text}"
            );
        }
    }

    /// `migrateConfig` type-asserts `pinned_images` always, and `runtime_platform` only past `runtimes`.
    #[test]
    fn migration_refuses_what_containerd_cannot_type_assert() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let conf = dir.path().join("config.toml");
        let cri = "[plugins.\"io.containerd.grpc.v1.cri\"]\nsandbox_image = \"x\"\n";
        let runtimes = "[plugins.\"io.containerd.grpc.v1.cri\".containerd.runtimes.runc]\nx = 1\n";
        let images = "[plugins.\"io.containerd.cri.v1.images\"]\n";
        for (body, refused) in [
            (format!("{cri}{images}pinned_images = 1\n"), true),
            (format!("{cri}{images}pinned_images = {{}}\n"), false),
            (format!("{cri}{images}runtime_platform = 1\n"), false),
            (format!("{runtimes}{images}runtime_platform = 1\n"), true),
            (
                format!("{runtimes}{images}runtime_platform = {{}}\n"),
                false,
            ),
        ] {
            std::fs::write(&conf, format!("version = 2\n{body}")).expect("a file");
            assert_eq!(load_plugins(&conf).is_err(), refused, "{body}");
        }
    }

    #[test]
    fn nri_accepts_plugins_unless_any_one_switch_is_off() {
        assert!(Nri::default().accepts_plugins());
        for nri in [
            Nri {
                disable: true,
                ..Nri::default()
            },
            Nri {
                plugin_disabled: true,
                ..Nri::default()
            },
            Nri {
                disable_connections: true,
                ..Nri::default()
            },
        ] {
            assert!(!nri.accepts_plugins(), "{nri:?}");
        }
    }

    #[test]
    fn version_one_plugin_names_become_uris() {
        for (name, uri) in [
            ("cri", "io.containerd.grpc.v1.cri"),
            ("cgroups", "io.containerd.monitor.v1.cgroups"),
            ("linux", "io.containerd.runtime.v1.linux"),
            ("scheduler", "io.containerd.gc.v1.scheduler"),
            ("bolt", "io.containerd.metadata.v1.bolt"),
            ("task", "io.containerd.runtime.v2.task"),
            ("opt", "io.containerd.internal.v1.opt"),
            ("restart", "io.containerd.internal.v1.restart"),
            ("tracing", "io.containerd.internal.v1.tracing"),
            ("otlp", "io.containerd.tracing.processor.v1.otlp"),
            ("overlayfs", "io.containerd.snapshotter.v1.overlayfs"),
            ("zfs", "io.containerd.snapshotter.v1.zfs"),
            ("images-service", "io.containerd.service.v1.images-service"),
            ("windows", "io.containerd.snapshotter.v1.windows"),
            ("windows-lcow", "io.containerd.snapshotter.v1.windows-lcow"),
            ("other", "io.containerd.grpc.v1.other"),
            ("io.x.y", "io.x.y"),
        ] {
            assert_eq!(v1_plugin_name(name), uri, "{name}");
        }
    }

    fn auth(username: &str, password: &str, auth: &str, token: &str) -> Auth {
        Auth {
            username: username.to_owned(),
            password: password.to_owned().into(),
            auth: auth.to_owned().into(),
            identity_token: token.to_owned().into(),
        }
    }

    fn password(login: Option<Login>) -> (String, String) {
        use secrecy::ExposeSecret as _;
        match login {
            Some(Login::Password { username, password }) => {
                (username, password.expose_secret().to_owned())
            }
            other => panic!("not a password login: {other:?}"),
        }
    }

    #[test]
    fn the_user_name_wins_over_the_token_and_auth() {
        let login = auth("u", "p", "dTpw", "t").login().expect("valid");
        assert_eq!(password(login), ("u".to_owned(), "p".to_owned()));
    }

    #[test]
    fn the_token_wins_over_auth() {
        use secrecy::ExposeSecret as _;
        let login = auth("", "", "dTpw", "t").login().expect("valid");
        match login {
            Some(Login::IdentityToken(token)) => assert_eq!(token.expose_secret(), "t"),
            other => panic!("not a token: {other:?}"),
        }
    }

    #[test]
    fn auth_is_split_at_its_first_colon_and_loses_its_nuls() {
        // "u:p:q\0\0"
        let login = auth("", "", "dTpwOnEAAA==", "").login().expect("valid");
        assert_eq!(password(login), ("u".to_owned(), "p:q".to_owned()));
    }

    #[test]
    fn nothing_set_is_anonymous() {
        assert!(auth("", "", "", "").login().expect("valid").is_none());
    }

    #[test]
    fn an_auth_that_is_no_login_is_refused() {
        // "nocolon", and no base64.
        assert!(auth("", "", "bm9jb2xvbg==", "").login().is_err());
        assert!(auth("", "", "***", "").login().is_err());
    }
}
