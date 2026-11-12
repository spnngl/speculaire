//! CRI-O's registry config: `registries.conf` and its drop-ins, `certs.d` and the credential files, read as
//! go.podman.io/image reads them for CRI-O (D66, D80), with the auth file CRI-O names in its own config (D89).
//!
//! The mirror serves `docker.io/library/busybox`; the node's `registries.conf` and its drop-ins, without speculaire's
//! own, say where `docker.io` is, which mirrors it has and whether it is insecure; `certs.d` says how to trust each
//! host, and the credential files say who to be.

use std::path::PathBuf;
use std::time::SystemTime;

use speculaire_registry_config::crio::auth::{self, Lookup};
use speculaire_registry_config::crio::registries::{self, Config};
use speculaire_registry_config::crio::{Context, certs};
use tracing::warn;

use super::live::Live;
use super::{
    Credentials, Endpoint, Error, Reference, Registries, Source, Tls, read_tls, split_name,
};
use crate::crio;
use crate::settings::chain;

/// The host Docker Hub's API answers on, where `docker.io` names it.
const DOCKER_HUB: &str = "registry-1.docker.io";

/// What `registries.conf`, the credential files and CRI-O's config held.
struct Snapshot {
    context: Context,
    config: Config,
    auth: auth::Files,
}

/// The registry config of a node that runs CRI-O, as `reload` last read it.
pub struct CrioRegistries {
    context: Context,
    socket: PathBuf,
    skip: PathBuf,
    live: Live<Snapshot>,
}

impl CrioRegistries {
    /// The registry config below `context`, without the file `own_dropin`, which sends pulls to the mirror. The auth
    /// file is the one `[crio.image] global_auth_file` names in the config CRI-O serves on `socket`; when it names
    /// none, the default search of `context` applies (D89). Nothing is read until
    /// [`reload`](Registries::reload).
    #[must_use]
    pub fn new(
        context: Context,
        socket: impl Into<PathBuf>,
        own_dropin: impl Into<PathBuf>,
    ) -> Self {
        Self {
            context,
            socket: socket.into(),
            skip: own_dropin.into(),
            live: Live::new(),
        }
    }

    /// The registry config below the auth file CRI-O names, and the paths it was read from: the places the files are
    /// looked for, whether or not anything is there.
    fn read(&self) -> (Vec<PathBuf>, Result<Snapshot, Error>) {
        let mut paths = registries::watched(&self.context);
        paths.extend(certs::watched(&self.context));
        paths.extend(
            auth::auth_file_paths(&self.context)
                .into_iter()
                .map(|auth| auth.path),
        );
        let snapshot = || -> Result<Snapshot, Error> {
            let text = crio::config(&self.socket).map_err(|e| Error::Config(chain(&e)))?;
            let auth_file = crio::global_auth_file(&text).map_err(|e| Error::Config(chain(&e)))?;
            let context = Context {
                auth_file,
                ..self.context.clone()
            };
            let config = registries::load_except(&context, Some(&self.skip))
                .map_err(|e| Error::Config(chain(&e)))?;
            let auth = auth::Files::load(&context).map_err(|e| Error::Config(chain(&e)))?;
            Ok(Snapshot {
                context,
                config,
                auth,
            })
        };
        (paths, snapshot())
    }
}

impl Registries for CrioRegistries {
    /// The registries in the order CRI-O would try them: the mirrors the admin configured, then the registry itself.
    fn sources(&self, name: &str, reference: Reference<'_>) -> Result<Vec<Source>, Error> {
        let (host, _) = split_name(name)?;
        let snapshot = self.live.get()?;
        let Snapshot {
            context,
            config,
            auth,
        } = &*snapshot;
        let reference = match reference {
            Reference::Digest(digest) => format!("{name}@{digest}"),
            Reference::Tag(tag) => format!("{name}:{tag}"),
        };
        let pulls = match config.find_registry(name) {
            Some(registry) if registry.blocked => return Ok(Vec::new()),
            Some(registry) => registry
                .pull_sources(&reference)
                .map_err(|e| Error::Name(e.to_string()))?
                .into_iter()
                .map(|source| (source.reference, source.endpoint.insecure))
                .collect(),
            // No entry: the registry itself, as the reference says.
            None => vec![(reference, false)],
        };
        let mut sources = Vec::new();
        for (reference, insecure) in pulls {
            let Some(source) = source(context, config, auth, &reference, insecure) else {
                warn!(
                    reference,
                    host, "a pull source is no registry and repository"
                );
                continue;
            };
            sources.push(source);
        }
        Ok(sources)
    }

    fn reload(&self, since: Option<SystemTime>) -> Result<bool, Error> {
        self.live.reload(since, || self.read())
    }
}

fn source(
    context: &Context,
    config: &Config,
    auth: &auth::Files,
    reference: &str,
    insecure: bool,
) -> Option<Source> {
    let (authority, rest) = reference.split_once('/')?;
    let repository = rest
        .split_once('@')
        .map_or(rest, |(repository, _)| repository);
    // A tag follows the last `:` of the last segment.
    let repository = match repository.rsplit_once(':') {
        Some((before, tag)) if !tag.contains('/') => before,
        _ => repository,
    };
    if authority.is_empty() || repository.is_empty() {
        return None;
    }
    let authority = if authority == "docker.io" || authority == "index.docker.io" {
        DOCKER_HUB
    } else {
        authority
    };
    let key = format!("{authority}/{repository}");
    let credentials = credentials(config, auth, &key, reference);
    let trust = tls(context, authority);
    let candidates = if insecure {
        vec![
            Endpoint {
                tls: Tls {
                    skip_verify: true,
                    ..trust
                },
                ..Endpoint::new(true, authority)
            },
            Endpoint::new(false, authority),
        ]
    } else {
        vec![Endpoint {
            tls: trust,
            ..Endpoint::new(true, authority)
        }]
    };
    Some(Source {
        candidates,
        repository: repository.to_owned(),
        credentials,
    })
}

/// The trust of a host: the CA files and the first client certificate of its `certs.d` directory.
fn tls(context: &Context, authority: &str) -> Tls {
    let found = match certs::load(context, authority) {
        Ok(found) => found,
        Err(err) => {
            warn!(authority, error = %err, "the certificate directory of a registry cannot be read");
            return Tls::default();
        }
    };
    let client = found
        .client
        .first()
        .map(|pair| (pair.cert.as_path(), pair.key.as_path()));
    read_tls(authority, &found.ca, client)
}

/// Who to be at a registry: the first login of the credential files for the repository, its namespaces and its
/// registry. A credential helper is not run (D80): its registry is reached anonymously, and logged.
fn credentials(config: &Config, auth: &auth::Files, key: &str, reference: &str) -> Credentials {
    match auth.credentials(&config.credential_helpers, key) {
        Ok(Lookup::Found(found)) => {
            use secrecy::ExposeSecret as _;
            let has_token = !found.identity_token.expose_secret().is_empty();
            Credentials::Login {
                username: found.username,
                password: found.password,
                identity_token: has_token.then_some(found.identity_token),
            }
        }
        Ok(Lookup::NotFound) => Credentials::Anonymous,
        Ok(Lookup::Helper(helper)) => {
            warn!(
                reference,
                helper, "the login is in a credential helper, which the agent does not run"
            );
            Credentials::Anonymous
        }
        Err(err) => {
            warn!(reference, error = %err, "the credential files cannot be read");
            Credentials::Anonymous
        }
    }
}

#[cfg(test)]
mod tests;
