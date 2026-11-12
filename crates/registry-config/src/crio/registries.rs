//! `registries.conf` and its drop-ins: which registry an image reference belongs to, and where its pulls go (D66).
//!
//! Ported from go.podman.io/image v5.40.0 `pkg/sysregistriesv2/system_registries_v2.go`, as vendored by CRI-O v1.37.2
//! (`Registry`, `Endpoint`, `postProcessRegistries`, `loadConfigFile`, `updateWithConfigurationFrom`, `FindRegistry`,
//! `PullSourcesFromReference`, `refMatchingPrefix`). (D25)
//!
//! Left out, as D80 records: short-name aliases and `unqualified-search-registries` are read for their types and
//! checked as the library checks them, except that an alias is not parsed as a reference; kubelet pulls fully
//! qualified names.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use toml::de::{DeTable, DeValue};

use super::Context;
use super::configfile::{self, Wanted};
use crate::ParseError;
use crate::error::from_toml;
use crate::fold::{fold_fields, table_at};

/// The credential helper that stands for the credential files.
pub const AUTHENTICATION_FILE_HELPER: &str = "containers-auth.json";

/// One location of a registry: the registry itself or one of its mirrors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Endpoint {
    /// Host, port and path; empty only for a wildcard prefix.
    pub location: String,
    /// Certificate verification is skipped and plain HTTP is allowed.
    pub insecure: bool,
    /// `pull-from-mirror` of a mirror: `all`, `digest-only`, `tag-only`, or empty.
    pub pull_from_mirror: String,
}

/// A `[[registry]]`: the images of `prefix` are pulled from its mirrors, then from its own location.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    /// What an image reference must start with; `*.example.com` matches subdomains.
    pub prefix: String,
    /// The registry's own location and `insecure`.
    pub endpoint: Endpoint,
    /// The mirrors, in order.
    pub mirrors: Vec<Endpoint>,
    /// Pulling from the registry is refused.
    pub blocked: bool,
    /// Mirrors serve digest references only.
    pub mirror_by_digest_only: bool,
}

/// Where a pull of one reference may go, and what the reference is there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullSource {
    /// The endpoint to try.
    pub endpoint: Endpoint,
    /// The reference at that endpoint: the prefix replaced by the endpoint's location.
    pub reference: String,
}

/// The settings of every file, merged: the registries by prefix, sorted by it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// The registries, one per prefix, sorted by prefix.
    pub registries: Vec<Registry>,
    /// The credential helpers, in the order they are asked; [`AUTHENTICATION_FILE_HELPER`] when none is set.
    pub credential_helpers: Vec<String>,
}

/// A file that cannot be loaded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A file or directory cannot be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file or directory.
        path: PathBuf,
        /// What failed.
        #[source]
        source: std::io::Error,
    },
    /// A file is not a valid `registries.conf`.
    #[error("loading registries configuration {}: {source}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        #[source]
        source: ParseError,
    },
}

/// The keys of a file, a `[[registry]]` and a mirror, matched in any case as BurntSushi/toml does.
const FILE_FIELDS: &[&str] = &[
    "registry",
    "unqualified-search-registries",
    "credential-helpers",
    "short-name-mode",
    "additional-layer-store-auth-helper",
    "aliases",
    "registries",
];
const REGISTRY_FIELDS: &[&str] = &[
    "prefix",
    "location",
    "insecure",
    "pull-from-mirror",
    "mirror",
    "blocked",
    "mirror-by-digest-only",
];
const ENDPOINT_FIELDS: &[&str] = &["location", "insecure", "pull-from-mirror"];
const V1_FIELDS: &[&str] = &["search", "insecure", "block"];

#[derive(Deserialize, Default)]
struct RawEndpoint {
    #[serde(default)]
    location: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default, rename = "pull-from-mirror")]
    pull_from_mirror: String,
}

#[derive(Deserialize, Default)]
struct RawRegistry {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    location: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default, rename = "pull-from-mirror")]
    pull_from_mirror: String,
    #[serde(default)]
    mirror: Vec<RawEndpoint>,
    #[serde(default)]
    blocked: bool,
    #[serde(default, rename = "mirror-by-digest-only")]
    mirror_by_digest_only: bool,
}

/// The list of a format 1 table: `registries = [...]`.
#[derive(Deserialize, Default)]
struct RawV1List {
    registries: Option<Vec<String>>,
}

/// The format 1 file, which is refused as soon as any list of it is set, an empty one too.
#[derive(Deserialize, Default)]
struct RawV1 {
    search: Option<RawV1List>,
    insecure: Option<RawV1List>,
    block: Option<RawV1List>,
}

impl RawV1 {
    fn is_set(&self) -> bool {
        [&self.search, &self.insecure, &self.block]
            .into_iter()
            .flatten()
            .any(|list| list.registries.is_some())
    }
}

#[derive(Deserialize, Default)]
struct RawFile {
    #[serde(default)]
    registry: Vec<RawRegistry>,
    #[serde(rename = "unqualified-search-registries")]
    unqualified_search_registries: Option<Vec<String>>,
    #[serde(rename = "credential-helpers")]
    credential_helpers: Option<Vec<String>>,
    #[serde(default, rename = "short-name-mode")]
    short_name_mode: String,
    // Read for the types of these two, as the library does; the values are not used.
    #[serde(default, rename = "additional-layer-store-auth-helper")]
    _additional_layer_store_auth_helper: String,
    #[serde(rename = "aliases")]
    _aliases: Option<BTreeMap<String, String>>,
    registries: Option<RawV1>,
}

/// One file, checked and normalized (`loadConfigFile`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct File {
    /// The registries of the file, one per prefix, sorted by prefix.
    pub registries: Vec<Registry>,
    /// The file's credential helpers, `None` when it sets none.
    pub credential_helpers: Option<Vec<String>>,
}

fn fold_file(table: &mut DeTable<'_>) {
    fold_fields(table, FILE_FIELDS);
    if let Some(DeValue::Array(registries)) = table.get_mut("registry").map(AsMut::as_mut) {
        for registry in registries.iter_mut() {
            let DeValue::Table(registry) = registry.as_mut() else {
                continue;
            };
            fold_fields(registry, REGISTRY_FIELDS);
            if let Some(DeValue::Array(mirrors)) = registry.get_mut("mirror").map(AsMut::as_mut) {
                for mirror in mirrors.iter_mut() {
                    if let DeValue::Table(mirror) = mirror.as_mut() {
                        fold_fields(mirror, ENDPOINT_FIELDS);
                    }
                }
            }
        }
    }
    if let Some(v1) = table_at(table, "registries") {
        fold_fields(v1, V1_FIELDS);
        for list in V1_FIELDS {
            if let Some(list) = table_at(v1, list) {
                fold_fields(list, &["registries"]);
            }
        }
    }
}

/// Parses and checks the text of one `registries.conf` or drop-in (`loadConfigFile`).
///
/// # Errors
///
/// When the text is not TOML or has a key of the wrong type, is in format 1, or fails the library's checks: a
/// `location` with a URI scheme, a registry with neither `location` nor `prefix`, two entries of one location that
/// disagree on `insecure` or `blocked`, an unknown `pull-from-mirror` or `short-name-mode`, a wildcard prefix that is
/// not `*.example.com`.
pub fn parse_file(text: &str) -> Result<File, ParseError> {
    // BurntSushi/toml skips a byte order mark.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let raw: RawFile = from_toml(text, fold_file)?;
    if raw.registries.as_ref().is_some_and(RawV1::is_set) {
        return Err(invalid("registries.conf must be in v2 format but is in v1"));
    }
    let registries = post_process(&raw.registry, raw.unqualified_search_registries.as_deref())?;
    if !raw.short_name_mode.is_empty()
        && !["disabled", "enforcing", "permissive"].contains(&raw.short_name_mode.as_str())
    {
        return Err(invalid(format!(
            "invalid short-name mode: {:?}",
            raw.short_name_mode
        )));
    }
    for registry in &registries {
        if registry.prefix.starts_with("*.") && registry.prefix.contains(['/', '@', ':']) {
            return Err(invalid(format!(
                "Wildcarded prefix should be in the format: *.example.com. Current prefix {:?} is incorrectly formatted",
                registry.prefix
            )));
        }
    }
    Ok(File {
        registries,
        credential_helpers: raw.credential_helpers,
    })
}

fn invalid(message: impl Into<String>) -> ParseError {
    ParseError::new("", message)
}

/// `parseLocation`: trailing slashes go, a URI scheme is refused.
fn parse_location(input: &str) -> Result<String, ParseError> {
    let trimmed = input.trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Err(invalid(format!(
            "invalid location '{input}': URI schemes are not supported"
        )));
    }
    Ok(trimmed.to_owned())
}

/// `postProcessRegistries`: prefixes default to locations, entries are checked, the first entry of a prefix wins,
/// and the result is sorted by prefix.
fn post_process(
    raw: &[RawRegistry],
    unqualified: Option<&[String]>,
) -> Result<Vec<Registry>, ParseError> {
    let mut registries = Vec::with_capacity(raw.len());
    for entry in raw {
        let location = parse_location(&entry.location)?;
        let prefix = if entry.prefix.is_empty() {
            if location.is_empty() {
                return Err(invalid(
                    "invalid condition: both location and prefix are unset",
                ));
            }
            location.clone()
        } else {
            let prefix = parse_location(&entry.prefix)?;
            if !prefix.starts_with("*.") && location.is_empty() {
                return Err(invalid(
                    "invalid condition: location is unset and prefix is not in the format: *.example.com",
                ));
            }
            prefix
        };
        if !entry.pull_from_mirror.is_empty() {
            return Err(invalid(format!(
                "pull-from-mirror must not be set for a non-mirror registry {prefix:?}"
            )));
        }
        let mut mirrors = Vec::with_capacity(entry.mirror.len());
        for mirror in &entry.mirror {
            let mirror_location = parse_location(&mirror.location)?;
            if mirror_location.is_empty() {
                return Err(invalid("invalid condition: mirror location is unset"));
            }
            if entry.mirror_by_digest_only && !mirror.pull_from_mirror.is_empty() {
                return Err(invalid(format!(
                    "cannot set mirror usage mirror-by-digest-only for the registry ({prefix:?}) and pull-from-mirror for per-mirror ({mirror_location:?}) at the same time"
                )));
            }
            if !["", "all", "digest-only", "tag-only"].contains(&mirror.pull_from_mirror.as_str()) {
                return Err(invalid(format!(
                    "unsupported pull-from-mirror value {:?} for mirror {mirror_location:?}",
                    mirror.pull_from_mirror
                )));
            }
            mirrors.push(Endpoint {
                location: mirror_location,
                insecure: mirror.insecure,
                pull_from_mirror: mirror.pull_from_mirror.clone(),
            });
        }
        registries.push(Registry {
            prefix,
            endpoint: Endpoint {
                location,
                insecure: entry.insecure,
                pull_from_mirror: String::new(),
            },
            mirrors,
            blocked: entry.blocked,
            mirror_by_digest_only: entry.mirror_by_digest_only,
        });
    }
    // Entries of one location may not disagree on `insecure` or `blocked`; a wildcard entry has no location, so
    // its prefix stands for it.
    let key = |registry: &Registry| {
        if registry.endpoint.location.is_empty() {
            registry.prefix.clone()
        } else {
            registry.endpoint.location.clone()
        }
    };
    for registry in &registries {
        for other in registries
            .iter()
            .filter(|other| key(other) == key(registry))
        {
            if registry.endpoint.insecure != other.endpoint.insecure {
                return Err(invalid(format!(
                    "registry '{}' is defined multiple times with conflicting 'insecure' setting",
                    registry.endpoint.location
                )));
            }
            if registry.blocked != other.blocked {
                return Err(invalid(format!(
                    "registry '{}' is defined multiple times with conflicting 'blocked' setting",
                    registry.endpoint.location
                )));
            }
        }
    }
    for entry in unqualified.unwrap_or_default() {
        let registry = parse_location(entry)?;
        if !is_domain(&registry) {
            return Err(invalid(format!(
                "Invalid unqualified-search-registries entry {registry:?}"
            )));
        }
    }
    let mut unique = BTreeMap::new();
    for registry in registries {
        unique.entry(registry.prefix.clone()).or_insert(registry);
    }
    Ok(unique.into_values().collect())
}

/// `^DomainRegexp$` of go.podman.io/image's `docker/reference`: dot-separated components of letters, digits and inner
/// hyphens, and an optional `:port`.
fn is_domain(text: &str) -> bool {
    let (host, port) = match text.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (text, None),
    };
    let component = |part: &str| {
        let bytes = part.as_bytes();
        let alphanumeric = |b: &u8| b.is_ascii_alphanumeric();
        !bytes.is_empty()
            && bytes.first().is_some_and(alphanumeric)
            && bytes.last().is_some_and(alphanumeric)
            && bytes.iter().all(|b| alphanumeric(b) || *b == b'-')
    };
    host.split('.').all(component)
        && port.is_none_or(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

impl Config {
    /// `updateWithConfigurationFrom`: a registry replaces the one of its prefix, the helpers replace the helpers.
    fn update(&mut self, file: File) {
        let mut by_prefix: BTreeMap<String, Registry> = std::mem::take(&mut self.registries)
            .into_iter()
            .map(|registry| (registry.prefix.clone(), registry))
            .collect();
        for registry in file.registries {
            by_prefix.insert(registry.prefix.clone(), registry);
        }
        self.registries = by_prefix.into_values().collect();
        if let Some(helpers) = file.credential_helpers {
            self.credential_helpers = helpers;
        }
    }

    /// `FindRegistry`: the registry with the longest prefix of `name`, a repository name such as
    /// `docker.io/library/busybox`.
    #[must_use]
    pub fn find_registry(&self, name: &str) -> Option<&Registry> {
        self.registries
            .iter()
            .filter(|registry| ref_matching_prefix(name, &registry.prefix).is_some())
            .fold(None, |best: Option<&Registry>, registry| {
                if best.is_none_or(|best| registry.prefix.len() > best.prefix.len()) {
                    Some(registry)
                } else {
                    best
                }
            })
    }
}

/// `refMatchingPrefix`: the length of `prefix` in `reference` when it starts with it, at a boundary, or when a
/// wildcard prefix matches its registry.
fn ref_matching_prefix(reference: &str, prefix: &str) -> Option<usize> {
    if prefix.starts_with("*.") {
        // `refMatchingSubdomainPrefix`; its `prefix[1:]` keeps the dot.
        let domain = &prefix[1..];
        let index = reference.find(domain)?;
        if reference[..index].contains('/') {
            return None;
        }
        let end = index + domain.len();
        return match reference.as_bytes().get(end) {
            None | Some(b':' | b'/' | b'@') => Some(end),
            Some(_) => None,
        };
    }
    let rest = reference.strip_prefix(prefix)?;
    match rest.as_bytes().first() {
        None | Some(b':' | b'/' | b'@') => Some(prefix.len()),
        Some(_) => None,
    }
}

impl Registry {
    /// `PullSourcesFromReference`: the mirrors that apply to `reference`, then the registry itself, each with the
    /// reference rewritten to its location. `reference` is a normalized reference such as
    /// `docker.io/library/busybox:1.37`; it is digested when it has an `@`.
    ///
    /// The library also parses each rewritten reference; this does not, so a location that is not a valid name
    /// gives a source where the library gives an error.
    ///
    /// # Errors
    ///
    /// When the registry's prefix does not match the reference, or an empty location has no wildcard prefix.
    pub fn pull_sources(&self, reference: &str) -> Result<Vec<PullSource>, ParseError> {
        let digested = reference.contains('@');
        let mut endpoints: Vec<&Endpoint> = Vec::new();
        if self.mirror_by_digest_only {
            if digested {
                endpoints.extend(&self.mirrors);
            }
        } else {
            endpoints.extend(self.mirrors.iter().filter(|mirror| {
                match mirror.pull_from_mirror.as_str() {
                    "digest-only" => digested,
                    "tag-only" => !digested,
                    _ => true,
                }
            }));
        }
        endpoints.push(&self.endpoint);
        endpoints
            .into_iter()
            .map(|endpoint| {
                Ok(PullSource {
                    endpoint: endpoint.clone(),
                    reference: endpoint.rewrite(reference, &self.prefix)?,
                })
            })
            .collect()
    }
}

impl Endpoint {
    /// `rewriteReference`, without the parse of its result.
    fn rewrite(&self, reference: &str, prefix: &str) -> Result<String, ParseError> {
        let Some(length) = ref_matching_prefix(reference, prefix) else {
            return Err(invalid(format!(
                "invalid prefix '{prefix}' for reference '{reference}'"
            )));
        };
        if self.location.is_empty() {
            if !prefix.starts_with("*.") {
                return Err(invalid(format!(
                    "invalid prefix '{prefix}' for empty location, should be in the format: *.example.com"
                )));
            }
            return Ok(reference.to_owned());
        }
        Ok(format!("{}{}", self.location, &reference[length..]))
    }
}

/// Loads `registries.conf` and its drop-ins as go.podman.io/image does for `ctx`, and merges them.
///
/// # Errors
///
/// When a file or directory cannot be read, or a file is not valid.
pub fn load(ctx: &Context) -> Result<Config, Error> {
    let paths = configfile::search_paths(
        ctx,
        &Wanted {
            name: "registries",
            extension: "conf",
            bare: false,
            custom_file: ctx.registries_conf.as_deref(),
            env_file: ctx.env_registries_conf.as_deref(),
            custom_dir: ctx.registries_conf_dir.as_deref(),
            env_override: ctx.env_registries_conf_override.as_deref(),
        },
    );
    let files = configfile::files(&paths, "conf").map_err(|e| Error::Read {
        path: e.path,
        source: e.source,
    })?;
    let mut config = Config {
        registries: Vec::new(),
        credential_helpers: Vec::new(),
    };
    for path in files {
        let file = read_file(&path)?;
        config.update(file);
    }
    if config.credential_helpers.is_empty() {
        config.credential_helpers = vec![AUTHENTICATION_FILE_HELPER.to_owned()];
    }
    Ok(config)
}

fn read_file(path: &Path) -> Result<File, Error> {
    let text = std::fs::read_to_string(path).map_err(|source| Error::Read {
        path: path.to_owned(),
        source,
    })?;
    parse_file(&text).map_err(|source| Error::Parse {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOCKER: &str = "[[registry]]\nprefix = \"docker.io\"\nlocation = \"docker.io\"\n[[registry.mirror]]\nlocation = \"mirror.example:5000/docker.io\"\npull-from-mirror = \"all\"\n[[registry.mirror]]\nlocation = \"digests.example\"\npull-from-mirror = \"digest-only\"\n[[registry.mirror]]\nlocation = \"tags.example\"\npull-from-mirror = \"tag-only\"\n";
    const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn config(text: &str) -> Config {
        let mut config = Config {
            registries: Vec::new(),
            credential_helpers: Vec::new(),
        };
        config.update(parse_file(text).expect("a registries.conf"));
        config
    }

    fn refused(text: &str) -> String {
        parse_file(text).expect_err("a refusal").to_string()
    }

    #[test]
    fn a_registry_defaults_its_prefix_to_its_location_and_keeps_its_mirrors_in_order() {
        let config = config(DOCKER);
        let docker = &config.registries[0];
        assert_eq!(docker.prefix, "docker.io");
        assert_eq!(docker.endpoint.location, "docker.io");
        let locations: Vec<_> = docker.mirrors.iter().map(|m| m.location.as_str()).collect();
        assert_eq!(
            locations,
            [
                "mirror.example:5000/docker.io",
                "digests.example",
                "tags.example"
            ]
        );
        let bare = parse_file("[[registry]]\nlocation = \"example.com/\"\ninsecure = true\n")
            .expect("a file");
        assert_eq!(bare.registries[0].prefix, "example.com");
        assert!(bare.registries[0].endpoint.insecure);
    }

    #[test]
    fn mirrors_apply_by_the_kind_of_reference() {
        let docker = &config(DOCKER).registries[0].clone();
        let sources = |reference: &str| -> Vec<String> {
            docker
                .pull_sources(reference)
                .expect("sources")
                .into_iter()
                .map(|s| s.reference)
                .collect()
        };
        assert_eq!(
            sources("docker.io/library/busybox:1.37"),
            [
                "mirror.example:5000/docker.io/library/busybox:1.37",
                "tags.example/library/busybox:1.37",
                "docker.io/library/busybox:1.37"
            ]
        );
        assert_eq!(
            sources(&format!("docker.io/library/busybox@{DIGEST}")),
            [
                format!("mirror.example:5000/docker.io/library/busybox@{DIGEST}"),
                format!("digests.example/library/busybox@{DIGEST}"),
                format!("docker.io/library/busybox@{DIGEST}")
            ]
        );
    }

    #[test]
    fn mirror_by_digest_only_keeps_mirrors_for_digests() {
        let config = config(
            "[[registry]]\nlocation = \"a.io\"\nmirror-by-digest-only = true\n[[registry.mirror]]\nlocation = \"m.io\"\n",
        );
        let a = &config.registries[0];
        assert_eq!(a.pull_sources("a.io/x:1").expect("sources").len(), 1);
        assert_eq!(
            a.pull_sources(&format!("a.io/x@{DIGEST}"))
                .expect("sources")
                .len(),
            2
        );
    }

    #[test]
    fn the_longest_prefix_wins_at_a_boundary_and_wildcards_match_subdomains() {
        let config = config(
            "[[registry]]\nprefix = \"example.com\"\nlocation = \"a\"\n[[registry]]\nprefix = \"example.com/foo\"\nlocation = \"b\"\n[[registry]]\nprefix = \"*.example.org\"\nlocation = \"\"\nblocked = true\n",
        );
        let prefix = |name: &str| config.find_registry(name).map(|r| r.prefix.as_str());
        assert_eq!(prefix("example.com/foo/bar"), Some("example.com/foo"));
        assert_eq!(prefix("example.com/foobar"), Some("example.com"));
        assert_eq!(prefix("example.com:5000/x"), Some("example.com"));
        assert_eq!(prefix("example.community/x"), None);
        assert_eq!(prefix("sub.example.org/x"), Some("*.example.org"));
        assert_eq!(prefix("a.b.example.org"), Some("*.example.org"));
        assert_eq!(prefix("example.org/x"), None);
        assert_eq!(prefix("x/sub.example.org"), None);
        assert_eq!(prefix("example.com/foo"), Some("example.com/foo"));
        assert_eq!(prefix("sub.example.orgs/x"), None);
        let wildcard = config
            .find_registry("sub.example.org/x")
            .expect("a registry");
        let sources = wildcard
            .pull_sources("sub.example.org/x:1")
            .expect("sources");
        assert_eq!(sources[0].reference, "sub.example.org/x:1");
        assert!(wildcard.pull_sources("other.com/x:1").is_err());
    }

    #[test]
    fn of_two_prefixes_of_one_length_the_first_in_prefix_order_wins() {
        let config = config(
            "[[registry]]\nprefix = \"x.a.io\"\nlocation = \"x\"\n[[registry]]\nprefix = \"*.a.io\"\nlocation = \"\"\nblocked = true\n",
        );
        assert_eq!(
            config
                .find_registry("x.a.io/app")
                .map(|r| r.prefix.as_str()),
            Some("*.a.io")
        );
    }

    #[test]
    fn a_later_file_replaces_the_registry_of_a_prefix_whole() {
        let mut merged = config(DOCKER);
        merged.update(parse_file("credential-helpers = []\n[[registry]]\nprefix = \"docker.io\"\nlocation = \"other.io\"\n").expect("a file"));
        merged.update(parse_file("credential-helpers = [\"h\"]\n").expect("a file"));
        assert_eq!(merged.registries.len(), 1);
        assert_eq!(merged.registries[0].endpoint.location, "other.io");
        assert_eq!(merged.registries[0].mirrors, Vec::<Endpoint>::new());
        assert_eq!(merged.credential_helpers, ["h"]);
    }

    #[test]
    fn registries_are_sorted_and_the_first_of_a_prefix_wins() {
        let file = parse_file("[[registry]]\nlocation = \"b.io\"\n[[registry]]\nlocation = \"a.io\"\n[[registry]]\nprefix = \"b.io\"\nlocation = \"b.io\"\n").expect("a file");
        let prefixes: Vec<_> = file.registries.iter().map(|r| r.prefix.as_str()).collect();
        assert_eq!(prefixes, ["a.io", "b.io"]);
    }

    #[test]
    fn keys_are_matched_in_any_case_and_other_keys_are_ignored() {
        let file = parse_file("\u{feff}Unknown = 1\n[[Registry]]\nLocation = \"a.io\"\nInsecure = true\n[[Registry.Mirror]]\nLocation = \"m.io\"\nPull-From-Mirror = \"all\"\n").expect("a file");
        assert!(file.registries[0].endpoint.insecure);
        assert_eq!(file.registries[0].mirrors[0].pull_from_mirror, "all");
    }

    #[test]
    fn invalid_files_are_refused() {
        for text in [
            "[[registry]]\n",
            "[[registry]]\nprefix = \"a.io\"\n",
            "[[registry]]\nlocation = \"https://a.io\"\n",
            "[[registry]]\nlocation = \"a.io\"\npull-from-mirror = \"all\"\n",
            "[[registry]]\nlocation = \"a.io\"\n[[registry.mirror]]\nlocation = \"\"\n",
            "[[registry]]\nlocation = \"a.io\"\n[[registry.mirror]]\nlocation = \"m.io\"\npull-from-mirror = \"sometimes\"\n",
            "[[registry]]\nlocation = \"a.io\"\nmirror-by-digest-only = true\n[[registry.mirror]]\nlocation = \"m.io\"\npull-from-mirror = \"all\"\n",
            "[[registry]]\nlocation = \"a.io\"\ninsecure = true\n[[registry]]\nprefix = \"a.io/x\"\nlocation = \"a.io\"\n",
            "[[registry]]\nlocation = \"a.io\"\nblocked = true\n[[registry]]\nprefix = \"a.io/x\"\nlocation = \"a.io\"\n",
            "[[registry]]\nprefix = \"*.a.io/x\"\nlocation = \"b.io\"\n",
            "[[registry]]\nprefix = \"*.a.io:5000\"\nlocation = \"b.io\"\n",
            "[[registry]]\nlocation = \"a.io\"\ninsecure = \"yes\"\n",
            "short-name-mode = \"sometimes\"\n",
            "unqualified-search-registries = [\"-a.io\"]\n",
            "[aliases]\nx = 1\n",
            "[registries.search]\nregistries = [\"a.io\"]\n",
            "[registries.block]\nregistries = []\n",
            "x = = 1\n",
        ] {
            assert!(parse_file(text).is_err(), "{text:?} is accepted");
        }
        assert!(refused("[registries.search]\nregistries = [\"a.io\"]\n").contains("v1"));
        assert!(refused("[[registry]]\nlocation = \"https://a.io\"\n").contains("URI schemes"));
        for text in [
            "",
            "short-name-mode = \"permissive\"\nunqualified-search-registries = [\"a.io\", \"b.example:5000\"]\n",
            "[[registry]]\nprefix = \"*.a.io\"\nlocation = \"\"\n",
            "[registries.search]\n",
        ] {
            assert!(parse_file(text).is_ok(), "{text:?} is refused");
        }
    }

    #[test]
    fn domains_are_dotted_labels_with_an_optional_port() {
        for domain in ["a.io", "localhost", "a-b.example.com:5000", "1.2.3.4"] {
            assert!(is_domain(domain), "{domain}");
        }
        for domain in [
            "", "-a.io", "a-.io", "a..io", ".a.io", "a.io:", "a.io:x", "a.io:1:2", "a_b.io",
            "a.io/x",
        ] {
            assert!(!is_domain(domain), "{domain}");
        }
    }

    #[test]
    fn files_are_loaded_in_search_order_and_the_helpers_default() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let write = |path: &str, text: &str| {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("a directory");
            std::fs::write(path, text).expect("a file");
        };
        write("etc/containers/registries.conf", DOCKER);
        write(
            "etc/containers/registries.conf.d/10-a.conf",
            "[[registry]]\nlocation = \"docker.io\"\n",
        );
        let ctx = Context {
            root: dir.path().to_owned(),
            home: dir.path().join("none"),
            ..Context::root()
        };
        let loaded = load(&ctx).expect("a config");
        assert_eq!(loaded.registries[0].mirrors, Vec::<Endpoint>::new());
        assert_eq!(loaded.credential_helpers, [AUTHENTICATION_FILE_HELPER]);
        write(
            "etc/containers/registries.conf.d/20-b.conf",
            "[[registry]\n",
        );
        assert!(matches!(load(&ctx), Err(Error::Parse { .. })));
        let named = Context {
            registries_conf: Some(dir.path().join("none.conf")),
            ..ctx
        };
        assert!(matches!(load(&named), Err(Error::Read { .. })));
    }
}
