//! Preflight: the agent refuses to start on a node where it would mirror or gate wrongly, and `check-config` says why
//! without starting it (D15, D54, D55, D56, D64, D66, D86).
//!
//! Every problem names the file or socket it comes from, the key to change, and what to set.

use std::io;
use std::time::SystemTime;

use speculaire_registry_config::containerd::config::{Hosts, Nri, Plugins};
use speculaire_runtime::cri::RuntimeVersion;
use speculaire_runtime::detect::Runtime;
use speculaire_runtime::version::Release;

use crate::{
    Host, Paths, Problem, Settings, check_certificates, containerd_config, crio_dropin_missing,
};

/// The oldest containerd the agent supports (D15).
pub const CONTAINERD_MINIMUM: Release = Release::new(2, 3, 0);

/// The oldest CRI-O the agent supports: the oldest Kubernetes minor kind ships (D63, D86).
pub const CRIO_MINIMUM: Release = Release::new(1, 35, 0);

/// The first containerd that exports the image service's settings through introspection (D15, D86).
const CONTAINERD_EXPORTS: Release = Release::new(2, 4, 0);

/// What is wrong on the node that would make the agent mirror or gate wrongly, so that it must not start: nothing
/// when it may.
#[must_use]
pub fn preflight(
    runtime: Runtime,
    paths: &Paths,
    settings: &Settings,
    host: &dyn Host,
    now: SystemTime,
) -> Vec<Problem> {
    let socket = host.socket(runtime);
    let problem = |message: String| Problem {
        path: socket.clone(),
        message,
    };
    let mut problems = Vec::new();
    let version = match host.runtime_version(runtime) {
        Ok(version) => Some(version),
        Err(e) => {
            problems.push(problem(format!(
                "{e}: the agent needs {runtime} running, and the socket is `runtime.{}_socket`",
                key_prefix(runtime)
            )));
            None
        }
    };
    let release = version
        .as_ref()
        .and_then(|version| check_version(runtime, version, &mut problems, &problem));
    match runtime {
        Runtime::Containerd => containerd(paths, host, release, &mut problems),
        Runtime::CriO => crio(paths, host, &mut problems),
    }
    problems.extend(check_certificates(settings, now));
    problems
}

const fn key_prefix(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::Containerd => "containerd",
        Runtime::CriO => "crio",
    }
}

/// The release the runtime reports, when it is one the agent supports; a problem otherwise.
fn check_version(
    runtime: Runtime,
    version: &RuntimeVersion,
    problems: &mut Vec<Problem>,
    problem: &dyn Fn(String) -> Problem,
) -> Option<Release> {
    if version.name != runtime.name() {
        problems.push(problem(format!(
            "answers as {:?}, not {runtime}: the sockets of `[runtime]` name the wrong runtime",
            version.name
        )));
        return None;
    }
    let Some(release) = version.release() else {
        problems.push(problem(format!(
            "{runtime} reports the version {:?}, which is no release: the agent cannot tell whether it supports it",
            version.version
        )));
        return None;
    };
    let minimum = match runtime {
        Runtime::Containerd => CONTAINERD_MINIMUM,
        Runtime::CriO => CRIO_MINIMUM,
    };
    if release < minimum {
        problems.push(problem(format!(
            "{runtime} {release} is older than {minimum}, the oldest the agent supports: upgrade it"
        )));
    }
    Some(release)
}

fn containerd(
    paths: &Paths,
    host: &dyn Host,
    release: Option<Release>,
    problems: &mut Vec<Problem>,
) {
    let config = paths.containerd_config();
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
            return;
        }
    };
    nri(&plugins.nri, &at_config, problems);
    // 2.4 says what its image service runs with; on 2.3 the config file is all there is (D15).
    if release.is_some_and(|release| release >= CONTAINERD_EXPORTS) {
        match host.containerd_image_exports() {
            Ok(Some(exports)) => {
                images(exports.discard_unpacked_layers, &at_config, problems);
                registry_path(exports.registry_config_path.is_empty(), &at_config, problems);
            }
            Ok(None) => problems.push(Problem {
                path: host.socket(Runtime::Containerd),
                message: "does not export the settings of the CRI image service, `io.containerd.cri.v1.images`: it is disabled or failed to start".to_owned(),
            }),
            Err(e) => problems.push(Problem {
                path: host.socket(Runtime::Containerd),
                message: e.to_string(),
            }),
        }
    } else if release.is_some() {
        images(plugins.discard_unpacked_layers, &at_config, problems);
        match containerd_config::load(&config) {
            Ok(registry) => registry_path(
                matches!(registry.hosts, Hosts::Mirrors(_)),
                &at_config,
                problems,
            ),
            Err(containerd_config::LoadError::Read { .. }) => {}
            Err(e) => problems.push(at_config(format!(
                "the registry section is invalid: {}",
                chain(&e)
            ))),
        }
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

fn crio(paths: &Paths, host: &dyn Host, problems: &mut Vec<Problem>) {
    let socket = host.socket(Runtime::CriO);
    match host.crio_nri() {
        Ok(nri) => {
            let mut report = |message: &str| {
                problems.push(Problem {
                    path: socket.clone(),
                    message: format!(
                        "{message}: the gate cannot run, and it cannot be turned off (D54, D64); restart CRI-O after the change"
                    ),
                });
            };
            if !nri.enabled {
                report("`enable_nri = false` in [crio.nri]: set it to true");
            }
            if nri.disable_connections {
                report(
                    "`nri_disable_connections = true` in [crio.nri] closes NRI to plugins that start on their own: set it to false",
                );
            }
        }
        Err(e) => problems.push(Problem {
            path: socket,
            message: e.to_string(),
        }),
    }
    problems.extend(crio_dropin_missing(paths));
}

/// An error and its sources, as one line.
fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}
