//! containerd's `config.toml`: the registry section the CRI image service reads (D17).
//!
//! Ported from containerd's `cmd/containerd/server/config/config.go` at v2.4.2 (`LoadConfigWithPlugins`,
//! `resolveImports`, `mergeConfig`, the migrations of config versions 1 to 3), the image service's migration
//! (`plugins/cri/images/plugin.go:configMigration`) and `internal/cri/config/config.go` (`Registry`,
//! `ValidateImageConfig`). The `config` tests run it against containerd's own loader.
//!
//! A config of version 1 or 2 keeps the registry under `plugins."io.containerd.grpc.v1.cri".registry`, a config of
//! version 3 or 4 under `plugins."io.containerd.cri.v1.images".registry`; containerd migrates the older in memory and
//! so does [`load`]. Keys the agent does not read are not checked: a config containerd refuses for one of them still
//! loads here.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

use secrecy::SecretString;
use serde::Deserialize;
use toml::{Table, Value};

use crate::ParseError;
use crate::error::{from_toml, from_value};
use crate::fold::{fold_fields, fold_value_fields, value_table_at, value_tables_in};
use crate::go::{clean_path, glob, parse_url};
use crate::header::Headers;

/// Where containerd reads its config unless told otherwise.
pub const DEFAULT_PATH: &str = "/etc/containerd/config.toml";

/// The highest config version this containerd reads (`version.ConfigVersion`).
const CONFIG_VERSION: i64 = 4;
const CRI_PLUGIN: &str = "io.containerd.grpc.v1.cri";
const IMAGES_PLUGIN: &str = "io.containerd.cri.v1.images";
const NRI_PLUGIN: &str = "io.containerd.nri.v1.nri";
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
        let decoded = String::from_utf8_lossy(&decoded);
        let (username, password) = decoded.split_once(':').ok_or(InvalidAuth)?;
        Ok(Some(Login::Password {
            username: username.to_owned(),
            password: SecretString::from(password.trim_matches('\0').to_owned()),
        }))
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
            Hosts::ConfigPath(split_list(list))
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

/// Go's `filepath.SplitList`.
fn split_list(list: &str) -> Vec<PathBuf> {
    if list.is_empty() {
        return Vec::new();
    }
    list.split(':').map(PathBuf::from).collect()
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
    /// containerd would refuse the registry section.
    #[error(transparent)]
    Refused(#[from] RegistryError),
}

const FILE_FIELDS: &[&str] = &[
    "version",
    "imports",
    "plugins",
    "disabled_plugins",
    "required_plugins",
];

/// The keys of the image service's section that the agent reads, matched in any case as go-toml does.
fn fold_images(images: &mut Table) {
    const AUTH: &[&str] = &["username", "password", "auth", "identitytoken"];
    fold_value_fields(images, &["registry", "discard_unpacked_layers"]);
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

/// The image service's plugin section, of which only `registry` and `discard_unpacked_layers` are read.
#[derive(Deserialize, Default)]
struct Images {
    #[serde(default)]
    registry: RawRegistry,
    #[serde(default)]
    discard_unpacked_layers: bool,
}

/// The NRI plugin's section, of which only `disable`, `disable_connections` and the default validator's
/// `required_plugins` are read.
#[derive(Deserialize, Default)]
struct RawNri {
    #[serde(default)]
    disable: bool,
    #[serde(default)]
    disable_connections: bool,
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
        &["disable", "disable_connections", "default_validator"],
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
        },
    })
}

/// Reads `path` and its imports, migrates each file and merges them as containerd does.
fn load_merged(path: &Path) -> Result<Merged, LoadError> {
    let mut merged = Merged::default();
    let mut loaded = HashSet::new();
    let mut pending = VecDeque::from([path.to_owned()]);
    while let Some(file_path) = pending.pop_front() {
        if !loaded.insert(file_path.clone()) {
            continue;
        }
        merged.files.push(file_path.clone());
        let text = std::fs::read_to_string(&file_path).map_err(|source| LoadError::Read {
            path: file_path.clone(),
            source,
        })?;
        let mut file: File =
            from_toml(&text, |table| fold_fields(table, FILE_FIELDS)).map_err(|source| {
                LoadError::Parse {
                    path: file_path.clone(),
                    source,
                }
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
    let registry = Registry::try_from(load_raw(path)?)?;
    tracing::trace!(?registry, path = %path.display(), "read the containerd registry config");
    Ok(registry)
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

/// What containerd's migrations make of a file's plugin sections, for the registry: version 1 plugin names become
/// URIs, and before version 4 the image service's section takes `registry` from the CRI plugin's.
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
    let discard = discard_unpacked_layers(cri)?;
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
            && (key == "pinned_images" || discard.reached)
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
    if let Some(value) = discard.value {
        images.insert("discard_unpacked_layers".to_owned(), value);
    }
    file.plugins
        .insert(IMAGES_PLUGIN.to_owned(), Value::Table(images));
    Ok(())
}

/// What `migrateConfig` takes from `[containerd]` of the CRI plugin.
struct Discard {
    /// The migration got past `containerd.runtimes`, where it copies the keys it carries over.
    reached: bool,
    /// `containerd.discard_unpacked_layers`, copied only when `reached`.
    value: Option<Value>,
}

/// `migrateConfig` (`plugins/cri/images/plugin.go`, v2.4.2): it copies `discard_unpacked_layers` from `[containerd]`
/// only when that table has `runtimes`, and asserts that `containerd`, `runtimes` and each runtime are tables.
fn discard_unpacked_layers(cri: &Table) -> Result<Discard, ParseError> {
    let none = Discard {
        reached: false,
        value: None,
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
    Ok(Discard {
        reached: true,
        value: containerd.get("discard_unpacked_layers").cloned(),
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
/// included, replaces; the plugin lists are unions.
fn merge(into: &mut Merged, file: File) {
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
