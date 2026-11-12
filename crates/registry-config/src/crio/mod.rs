//! CRI-O's registry config, as go.podman.io/image v5.40.0 (CRI-O v1.37.2) reads it (D66): `registries.conf` and its
//! drop-ins ([`registries`]), the per-host certificate directories ([`certs`]) and the credential files ([`auth`]).
//!
//! The three share the files' search paths and the inputs go.podman.io/image takes from the process:
//! [`Context`].

pub mod auth;
pub mod certs;
mod configfile;
pub mod registries;

use std::path::PathBuf;

/// What go.podman.io/image reads from the process and from CRI-O's settings to find its files: the fields of
/// `types.SystemContext` and the environment variables it consults. The agent runs as root next to CRI-O, whose own
/// environment it cannot see, so [`Context::root`] holds the defaults of a root service.
#[derive(Clone, Debug)]
pub struct Context {
    /// `RootForImplicitAbsolutePaths`: prefixed to the default system paths (not to `$HOME`'s); empty for the real root.
    pub root: PathBuf,
    /// The uid whose drop-in directories and `/run/containers/<uid>/auth.json` apply.
    pub uid: u32,
    /// `$HOME`, where the user's config lives.
    pub home: PathBuf,
    /// `$XDG_CONFIG_HOME`.
    pub xdg_config_home: Option<PathBuf>,
    /// `$XDG_RUNTIME_DIR`.
    pub xdg_runtime_dir: Option<PathBuf>,
    /// `$DOCKER_CONFIG`.
    pub docker_config: Option<PathBuf>,
    /// `$CONTAINERS_REGISTRIES_CONF`: the one `registries.conf`, without drop-ins.
    pub env_registries_conf: Option<PathBuf>,
    /// `$CONTAINERS_REGISTRIES_CONF_OVERRIDE`: a file read after the drop-ins.
    pub env_registries_conf_override: Option<PathBuf>,
    /// `SystemRegistriesConfPath` (CRI-O's `registries_conf`): the `registries.conf`, which must exist.
    pub registries_conf: Option<PathBuf>,
    /// `SystemRegistriesConfDirPath` (CRI-O's `registries_conf_dir`): the only drop-in directory.
    pub registries_conf_dir: Option<PathBuf>,
    /// `AuthFilePath` (CRI-O's `global_auth_file`): the only credential file.
    pub auth_file: Option<PathBuf>,
}

impl Context {
    /// The context of a service running as root, with CRI-O's defaults and no environment.
    #[must_use]
    pub fn root() -> Self {
        Self {
            root: PathBuf::new(),
            uid: 0,
            home: PathBuf::from("/root"),
            xdg_config_home: None,
            xdg_runtime_dir: None,
            docker_config: None,
            env_registries_conf: None,
            env_registries_conf_override: None,
            registries_conf: None,
            registries_conf_dir: None,
            auth_file: None,
        }
    }

    /// `path` below [`Context::root`].
    pub(crate) fn under_root(&self, path: &str) -> PathBuf {
        if self.root.as_os_str().is_empty() {
            PathBuf::from(path)
        } else {
            self.root.join(path.trim_start_matches('/'))
        }
    }
}
