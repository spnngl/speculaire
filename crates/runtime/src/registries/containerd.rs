//! containerd's registry config: `config.toml`, its `imports`, and the `hosts.toml` trees of `config_path`, read as the
//! CRI image service reads them (D89), once and again when a file of them changes (D91).
//!
//! The endpoints of a registry are those of its host directory, the registry itself last (`ConfigureHosts`); the
//! credentials of an endpoint are the `configs.<host>.auth` of `config.toml`, by the endpoint's host (containerd
//! v2.4.2 `internal/cri/server/images/image_pull.go:108`). The deprecated `mirrors` table is not followed.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use secrecy::SecretString;
use speculaire_registry_config::Headers;
use speculaire_registry_config::containerd::config::{
    self, Auth, Hosts, LoadError, Login, Registry,
};
use speculaire_registry_config::containerd::hosts::{Capabilities, RegistryHost, Tree};
use tracing::warn;

use super::live::Live;
use super::{
    Credentials, Endpoint, Error, Reference, Registries, Source, Tls, read_tls, split_name,
};
use crate::settings::chain;

/// What `config.toml` and the host directories hold.
struct Snapshot {
    registry: Registry,
    /// The `hosts.toml` trees of `config_path`; none under the deprecated `mirrors`.
    tree: Option<Tree>,
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

/// `config.toml`, its imports and every host directory, and the paths they were read from.
fn read(config: &Path) -> (Vec<PathBuf>, Result<Snapshot, Error>) {
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
    (paths, Ok(Snapshot { registry, tree }))
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
            .map(|endpoint| source(&snapshot.registry, host, repository, &endpoint))
            .collect())
    }

    fn reload(&self, since: Option<SystemTime>) -> Result<bool, Error> {
        self.live.reload(since, || read(&self.config))
    }
}

fn source(registry: &Registry, host: &str, repository: &str, endpoint: &RegistryHost) -> Source {
    let credentials = credentials(registry.configs.get(&endpoint.host));
    let namespace = endpoint.is_proxy(host).then(|| host.to_owned());
    let trust = tls(endpoint);
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

/// The CA files, the first client certificate and `skip_verify` of an endpoint.
fn tls(endpoint: &RegistryHost) -> Tls {
    let client = endpoint.tls.client.first().map(|pair| {
        (
            pair.cert.as_path(),
            pair.key.as_deref().unwrap_or(pair.cert.as_path()),
        )
    });
    Tls {
        skip_verify: endpoint.tls.skip_verify.unwrap_or(false),
        ..read_tls(&endpoint.host, &endpoint.tls.ca, client)
    }
}

/// Who to be at an endpoint: what `ParseAuth` makes of its `configs` entry. An entry that cannot be parsed is
/// anonymous, and logged, where containerd would fail the pull.
fn credentials(auth: Option<&Auth>) -> Credentials {
    match auth.map(Auth::login) {
        None | Some(Ok(None)) => Credentials::Anonymous,
        Some(Ok(Some(Login::Password { username, password }))) => Credentials::Login {
            username,
            password,
            identity_token: None,
        },
        Some(Ok(Some(Login::IdentityToken(token)))) => Credentials::Login {
            username: String::new(),
            password: SecretString::from(String::new()),
            identity_token: Some(token),
        },
        Some(Err(err)) => {
            warn!(error = %err, "the login of a registry in containerd's config is no user:password");
            Credentials::Anonymous
        }
    }
}

#[cfg(test)]
mod tests;
