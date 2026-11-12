//! containerd's settings as the agent depends on them (D15, D54, D86).

use std::io;

use speculaire_registry_config::containerd::config::{
    self as containerd_config, Hosts, Nri, Plugins,
};

use super::{Containerd, image_exports};
use crate::detect::Runtime;
use crate::settings::{Required, Settings, chain, check_version};
use crate::version::Release;
use crate::wiring::{Error, Problem};

/// The oldest containerd the agent supports (D15).
pub const MINIMUM: Release = Release::new(2, 3, 0);

/// The first containerd that exports the image service's settings through introspection (D15, D86).
const EXPORTS: Release = Release::new(2, 4, 0);

/// The key of containerd's NRI config that `unconfigure` checks.
const REQUIRED: &str =
    "`required_plugins` of [plugins.'io.containerd.nri.v1.nri'.default_validator]";

impl Settings for Containerd {
    fn required_plugins(&self) -> Result<Required, Error> {
        let config = self.config();
        // containerd without a config file has no NRI validator either.
        let plugins = match containerd_config::load_plugins(&config).map(|p| p.nri.required_plugins)
        {
            Err(containerd_config::LoadError::Read { source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                Vec::new()
            }
            other => other.map_err(|source| Error::Containerd {
                path: config,
                source: Box::new(source),
            })?,
        };
        Ok(Required {
            runtime: Runtime::Containerd.name(),
            key: REQUIRED,
            plugins,
        })
    }

    fn preflight(&self) -> Vec<Problem> {
        let (mut problems, release) = check_version(
            Runtime::Containerd,
            &self.socket,
            "containerd_socket",
            MINIMUM,
        );
        let config = self.config();
        let at_config = |message: String| Problem {
            path: config.clone(),
            message,
        };
        let plugins = match containerd_config::load_plugins(&config) {
            Ok(plugins) => plugins,
            // containerd without a config file runs on its defaults.
            Err(containerd_config::LoadError::Read { path, source })
                if path == config && source.kind() == io::ErrorKind::NotFound =>
            {
                Plugins::default()
            }
            Err(e) => {
                problems.push(at_config(format!(
                    "cannot read containerd's config: {}",
                    chain(&e)
                )));
                return problems;
            }
        };
        nri(&plugins.nri, &at_config, &mut problems);
        // 2.4 says what its image service runs with; on 2.3 the config file is all there is (D15).
        if release.is_some_and(|release| release >= EXPORTS) {
            match image_exports(&self.socket) {
                Ok(Some(exports)) => {
                    images(exports.discard_unpacked_layers, &at_config, &mut problems);
                    registry_path(
                        exports.registry_config_path.is_empty(),
                        &at_config,
                        &mut problems,
                    );
                }
                Ok(None) => problems.push(Problem {
                    path: self.socket.clone(),
                    message: "does not export the settings of the CRI image service, `io.containerd.cri.v1.images`: it is disabled or failed to start".to_owned(),
                }),
                Err(e) => problems.push(Problem {
                    path: self.socket.clone(),
                    message: e.to_string(),
                }),
            }
        } else if release.is_some() {
            images(plugins.discard_unpacked_layers, &at_config, &mut problems);
            match containerd_config::load(&config) {
                Ok(registry) => registry_path(
                    matches!(registry.hosts, Hosts::Mirrors(_)),
                    &at_config,
                    &mut problems,
                ),
                Err(containerd_config::LoadError::Read { .. }) => {}
                Err(e) => problems.push(at_config(format!(
                    "the registry section is invalid: {}",
                    chain(&e)
                ))),
            }
        }
        problems
    }
}

fn images(discard: bool, at_config: &dyn Fn(String) -> Problem, problems: &mut Vec<Problem>) {
    if discard {
        problems.push(at_config(
            "`discard_unpacked_layers = true` in [plugins.'io.containerd.cri.v1.images'] (or [plugins.'io.containerd.grpc.v1.cri'.containerd] in a config of version 2): containerd deletes the layers it has unpacked, so the node has nothing to serve the mirror's peers; set it to false and restart containerd".to_owned(),
        ));
    }
}

fn registry_path(unset: bool, at_config: &dyn Fn(String) -> Problem, problems: &mut Vec<Problem>) {
    if unset {
        problems.push(at_config(
            "`config_path` is not set in [plugins.'io.containerd.cri.v1.images'.registry] (the deprecated `mirrors` is in use, or the key is empty): containerd reads no hosts.toml, so no pull goes through the mirror; set it to \"/etc/containerd/certs.d\" and restart containerd".to_owned(),
        ));
    }
}

fn nri(nri: &Nri, at_config: &dyn Fn(String) -> Problem, problems: &mut Vec<Problem>) {
    const SECTION: &str = "[plugins.'io.containerd.nri.v1.nri']";
    let mut report = |message: &str| {
        problems.push(at_config(format!(
            "{message}: the gate cannot run, and it cannot be turned off (D54); restart containerd after the change"
        )));
    };
    if nri.disable {
        report(&format!("`disable = true` in {SECTION}: set it to false"));
    }
    if nri.plugin_disabled {
        report("`io.containerd.nri.v1.nri` is in `disabled_plugins`: remove it");
    }
    if nri.disable_connections {
        report(&format!(
            "`disable_connections = true` in {SECTION} closes NRI to plugins that start on their own: set it to false"
        ));
    }
}

#[cfg(test)]
mod tests;
