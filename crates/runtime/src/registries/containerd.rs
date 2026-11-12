//! containerd's registry config: `config.toml`, its `imports`, and the `hosts.toml` trees of `config_path`, read as the
//! CRI image service reads them (D89).
//!
//! The endpoints of a registry are those of its host directory, the registry itself last (`ConfigureHosts`); the
//! credentials of an endpoint are the `configs.<host>.auth` of `config.toml`, by the endpoint's host (containerd
//! v2.4.2 `internal/cri/server/images/image_pull.go:108`). The deprecated `mirrors` table is not followed.

use std::path::PathBuf;

use secrecy::SecretString;
use speculaire_registry_config::containerd::config::{self, Auth, Hosts, Login, Registry};
use speculaire_registry_config::containerd::hosts::{self, Capabilities, RegistryHost};
use tracing::warn;

use super::{
    Credentials, Endpoint, Error, Reference, Registries, Source, Tls, read_tls, split_name,
};

/// The registry config of a node that runs containerd, read at every request.
#[derive(Debug)]
pub struct ContainerdRegistries {
    config: PathBuf,
}

impl ContainerdRegistries {
    /// The registry config of the containerd whose `config.toml` is `config`.
    #[must_use]
    pub fn new(config: impl Into<PathBuf>) -> Self {
        Self {
            config: config.into(),
        }
    }
}

impl Registries for ContainerdRegistries {
    /// The endpoints of the registry of `name`, in the order containerd tries them, one source each.
    fn sources(&self, name: &str, reference: Reference<'_>) -> Result<Vec<Source>, Error> {
        let (host, repository) = split_name(name)?;
        let registry = config::load(&self.config).map_err(|e| Error::Config(e.to_string()))?;
        let Hosts::ConfigPath(roots) = &registry.hosts else {
            return Err(Error::Config(
                "the deprecated `mirrors` is not followed: use `config_path`".to_owned(),
            ));
        };
        let wanted = match reference {
            Reference::Tag(_) => Capabilities::RESOLVE,
            Reference::Digest(_) => Capabilities::PULL,
        };
        let hosts = hosts::resolve(roots, host, None).map_err(|e| Error::Config(e.to_string()))?;
        Ok(hosts
            .into_iter()
            .filter(|endpoint| endpoint.capabilities.contains(wanted))
            .map(|endpoint| source(&registry, host, repository, &endpoint))
            .collect())
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
