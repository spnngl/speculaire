//! containerd's registry config: `config.toml`, its `imports`, and the `hosts.toml` trees of `config_path`, read as the
//! CRI image service reads them (D89), once and again when a file of them changes (D91).
//!
//! The endpoints of a registry are those of its host directory, the registry itself last (`ConfigureHosts`); the
//! credentials of an endpoint are the `configs.<host>.auth` of `config.toml`, by the endpoint's host (containerd
//! v2.4.2 `internal/cri/server/images/image_pull.go:108`). The deprecated `mirrors` table is not followed.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use secrecy::SecretString;
use speculaire_registry_config::Headers;
use speculaire_registry_config::containerd::config::{
    self, Auth, Hosts, LoadError, Login, Registry,
};
use speculaire_registry_config::containerd::hosts::{Capabilities, RegistryHost, Tree};

use super::live::Live;
use super::{
    ClientCert, Credentials, Endpoint, Error, Reference, Registries, Reloaded, Source, Tls,
    read_ca, read_client, split_name,
};
use crate::settings::chain;

/// What `config.toml`, the host directories and the certificate files they name held.
struct Snapshot {
    /// Who to be at each registry host: its `configs.<host>.auth` (D92).
    logins: BTreeMap<String, Credentials>,
    /// The `hosts.toml` trees of `config_path`; none under the deprecated `mirrors`.
    tree: Option<Tree>,
    certificates: Certificates,
}

/// The certificate files the host directories name, read once for all the hosts that name them (D92). A file that
/// could not be used is held as none, so that it is reported once.
#[derive(Default)]
struct Certificates {
    ca: BTreeMap<PathBuf, Option<Vec<u8>>>,
    /// By certificate file and key file; the key is the certificate file when it holds both.
    clients: BTreeMap<(PathBuf, PathBuf), Option<ClientCert>>,
}

impl Certificates {
    /// Reads the files `tree` names. Each is added to `paths`, for the reload to watch: they need not be below
    /// `config_path`. What cannot be used is noted in `problems`.
    fn read(tree: &Tree, paths: &mut Vec<PathBuf>, problems: &mut Vec<String>) -> Self {
        let mut found = Self::default();
        for host in tree.host_configs() {
            for ca in host.ca() {
                paths.push(ca.clone());
                found
                    .ca
                    .entry(ca.clone())
                    .or_insert_with(|| read_ca(ca, problems));
            }
            for pair in host.client() {
                let key = pair.key.as_ref().unwrap_or(&pair.cert);
                paths.extend([pair.cert.clone(), key.clone()]);
                found
                    .clients
                    .entry((pair.cert.clone(), key.clone()))
                    .or_insert_with(|| read_client(&pair.cert, key, problems));
            }
        }
        found
    }

    /// The CA certificates and the first client certificate of an endpoint, and its `skip_verify`.
    fn trust(&self, endpoint: &RegistryHost) -> Tls {
        let client = endpoint.tls.client.first().and_then(|pair| {
            let key = pair.key.as_ref().unwrap_or(&pair.cert);
            self.clients
                .get(&(pair.cert.clone(), key.clone()))
                .cloned()
                .flatten()
        });
        Tls {
            roots: endpoint
                .tls
                .ca
                .iter()
                .filter_map(|path| self.ca.get(path).cloned().flatten())
                .collect(),
            client,
            skip_verify: endpoint.tls.skip_verify.unwrap_or(false),
        }
    }
}

/// The registry config of a node that runs containerd, as `reload` last read it.
pub struct ContainerdRegistries {
    config: PathBuf,
    live: Live<Snapshot>,
}

impl ContainerdRegistries {
    /// The registry config of the containerd whose `config.toml` is `config`. Nothing is read until
    /// [`reload`](Registries::reload).
    #[must_use]
    pub fn new(config: impl Into<PathBuf>) -> Self {
        Self {
            config: config.into(),
            live: Live::new(),
        }
    }
}

/// `config.toml`, its imports, every host directory and the certificate files they name, and the paths they were read
/// from. A login or certificate file that cannot be used does not fail the read: `problems` says which, and the hosts
/// it is for are anonymous or without it (D92).
fn read(config: &Path, problems: &mut Vec<String>) -> (Vec<PathBuf>, Result<Snapshot, Error>) {
    let (registry, mut paths) = match config::load_with_files(config) {
        Ok(read) => read,
        // No `config.toml`: containerd runs on its defaults, which have no `config_path`.
        Err(LoadError::Read { source, .. }) if source.kind() == ErrorKind::NotFound => (
            Registry {
                hosts: Hosts::ConfigPath(Vec::new()),
                configs: std::collections::BTreeMap::new(),
                headers: Headers::default(),
            },
            Vec::new(),
        ),
        Err(err) => return (vec![config.to_owned()], Err(Error::Config(chain(&err)))),
    };
    // A file that appears, or a deletion, changes the directory it is in.
    paths.push(config.to_owned());
    let tree = match &registry.hosts {
        Hosts::ConfigPath(roots) => {
            paths.extend(roots.iter().cloned());
            match Tree::load(roots) {
                Ok(tree) => Some(tree),
                Err(err) => return (paths, Err(Error::Config(chain(&err)))),
            }
        }
        Hosts::Mirrors(_) => None,
    };
    let certificates = tree
        .as_ref()
        .map(|tree| Certificates::read(tree, &mut paths, problems))
        .unwrap_or_default();
    let logins = read_logins(&registry, problems);
    (
        paths,
        Ok(Snapshot {
            logins,
            tree,
            certificates,
        }),
    )
}

impl Registries for ContainerdRegistries {
    /// The endpoints of the registry of `name`, in the order containerd tries them, one source each.
    fn sources(&self, name: &str, reference: Reference<'_>) -> Result<Vec<Source>, Error> {
        let (host, repository) = split_name(name)?;
        let snapshot = self.live.get()?;
        let Some(tree) = &snapshot.tree else {
            return Err(Error::Config(
                "the deprecated `mirrors` is not followed: use `config_path`".to_owned(),
            ));
        };
        let wanted = match reference {
            Reference::Tag(_) => Capabilities::RESOLVE,
            Reference::Digest(_) => Capabilities::PULL,
        };
        Ok(tree
            .resolve(host, None)
            .into_iter()
            .filter(|endpoint| endpoint.capabilities.contains(wanted))
            .map(|endpoint| source(&snapshot, host, repository, &endpoint))
            .collect())
    }

    fn reload(&self, since: Option<SystemTime>) -> Result<Reloaded, Error> {
        let mut problems = Vec::new();
        let changed = self
            .live
            .reload(since, || read(&self.config, &mut problems))?;
        Ok(Reloaded { changed, problems })
    }
}

fn source(snapshot: &Snapshot, host: &str, repository: &str, endpoint: &RegistryHost) -> Source {
    let credentials = snapshot
        .logins
        .get(&endpoint.host)
        .cloned()
        .unwrap_or(Credentials::Anonymous);
    let namespace = endpoint.is_proxy(host).then(|| host.to_owned());
    let trust = snapshot.certificates.trust(endpoint);
    let headers: Vec<(String, SecretString)> = endpoint
        .header
        .iter()
        .flat_map(|(name, values)| values.iter().map(|value| (name.clone(), value.clone())))
        .collect();
    let candidate = |https: bool, tls: Tls| Endpoint {
        root: endpoint.path.clone(),
        namespace: namespace.clone(),
        tls,
        headers: headers.clone(),
        ..Endpoint::new(https, endpoint.host.clone())
    };
    let candidates = if endpoint.http_fallback {
        vec![candidate(true, trust), candidate(false, Tls::default())]
    } else {
        vec![candidate(endpoint.scheme == "https", trust)]
    };
    Source {
        candidates,
        repository: repository.to_owned(),
        credentials,
    }
}

/// Who to be at each registry host: what `ParseAuth` makes of its `configs` entry. An entry that cannot be parsed is
/// anonymous, and noted in `problems`, where containerd would fail the pull.
fn read_logins(registry: &Registry, problems: &mut Vec<String>) -> BTreeMap<String, Credentials> {
    let mut login = |host: &str, auth: &Auth| match auth.login() {
        Ok(None) => Credentials::Anonymous,
        Ok(Some(Login::Password { username, password })) => Credentials::Login {
            username,
            password,
            identity_token: None,
        },
        Ok(Some(Login::IdentityToken(token))) => Credentials::Login {
            username: String::new(),
            password: SecretString::from(String::new()),
            identity_token: Some(token),
        },
        Err(err) => {
            problems.push(format!(
                "the login of {host} in containerd's config is no user:password ({err}); the registry is asked anonymously"
            ));
            Credentials::Anonymous
        }
    };
    registry
        .configs
        .iter()
        .map(|(host, auth)| (host.clone(), login(host, auth)))
        .collect()
}

#[cfg(test)]
mod tests;
