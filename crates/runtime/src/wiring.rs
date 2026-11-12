//! Pointing a runtime at the mirror, and back: what `configure`, `unconfigure` and `check` do to a node's files (D14,
//! D32, D55, D56, D66, D82, D83).
//!
//! Each runtime implements [`Wiring`] on the files it reads. Every path goes through [`Paths`](crate::paths::Paths),
//! so that tests run on a temporary directory. The certificates the mirror serves with are the runtime-agnostic part:
//! [`certificates`](crate::certificates).

use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use speculaire_pki::mirror;
use speculaire_registry_config::containerd::config as containerd_config;
use speculaire_registry_config::crio::registries;

use crate::containerd::hosts;
use crate::crio;
pub use crate::files::Change;

/// What the mirror is, from the agent's config (D30).
#[derive(Clone, Debug)]
pub struct Target {
    /// `mirror.address`.
    pub address: SocketAddr,
    /// `mirror.registries`.
    pub registries: Vec<String>,
    /// `mirror.directory`: where the mirror's CA and certificates live (D14).
    pub directory: PathBuf,
}

/// What a runtime's files say about the mirror, and how to change them.
pub trait Wiring: Send + Sync {
    /// Points the runtime at the mirror: makes the certificates, and puts the mirror first in the runtime's registry
    /// config.
    ///
    /// It reads and decides everything first, then writes: a config it cannot read changes nothing. Running it again,
    /// with the same target, changes no file.
    ///
    /// # Errors
    ///
    /// When a config cannot be read or edited, or a file cannot be written, or the runtime does not reload.
    fn configure(&self, target: &Target, now: SystemTime) -> Result<Report, Error>;

    /// Takes the mirror back out of the runtime's config, then deletes the certificates (D32).
    ///
    /// # Errors
    ///
    /// When a config cannot be read or edited, or a file cannot be removed, or the runtime does not reload.
    fn unconfigure(&self, target: &Target) -> Result<Report, Error>;

    /// What the runtime's config lacks of what [`configure`](Wiring::configure) makes, the certificates apart: nothing
    /// when it is as `configure` would leave it.
    ///
    /// # Errors
    ///
    /// When a config cannot be read.
    fn check(&self, target: &Target) -> Result<Vec<Problem>, Error>;
}

/// What a run did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The files it created, changed or removed.
    pub changes: Vec<Change>,
    /// What it left alone, and why.
    pub notes: Vec<String>,
}

/// A file or socket of the node that is not as the agent needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The file or socket.
    pub path: PathBuf,
    /// What is wrong.
    pub message: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path.display(), self.message)
    }
}

/// Why a run stopped.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or directory could not be read or written.
    #[error("{}: {source}", path.display())]
    Io {
        /// The file.
        path: PathBuf,
        /// What failed.
        source: io::Error,
    },
    /// containerd's config cannot be read.
    #[error("{}: {source}", path.display())]
    Containerd {
        /// The `config.toml`.
        path: PathBuf,
        /// What is wrong.
        source: Box<containerd_config::LoadError>,
    },
    /// containerd's config uses `mirrors`, which `hosts.toml` cannot be added beside.
    #[error(
        "{}: the registry section uses `mirrors`, which containerd 2.x refuses beside `config_path` and this agent does not edit: move them to `hosts.toml` files and set `config_path`",
        .0.display()
    )]
    LegacyMirrors(PathBuf),
    /// A `hosts.toml` cannot be edited.
    #[error("{}: {source}", path.display())]
    Edit {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        source: hosts::EditError,
    },
    /// CRI-O's registry config cannot be read.
    #[error(transparent)]
    Registries(Box<registries::Error>),
    /// The mirror's certificates cannot be made.
    #[error(transparent)]
    Generate(#[from] mirror::GenerateError),
    /// A runtime config names `speculaire` among the plugins it requires.
    #[error(
        "{key} names speculaire: the runtime refuses every container while the agent is not running. Remove it, restart {runtime}, and run unconfigure again (--force skips this check)"
    )]
    Required {
        /// The runtime's name.
        runtime: &'static str,
        /// The key.
        key: &'static str,
    },
    /// CRI-O's inspect API could not be read.
    #[error("cannot read CRI-O's config: {0}")]
    Inspect(#[from] crio::Error),
    /// CRI-O did not reload.
    #[error("cannot reload CRI-O: {0}")]
    Reload(io::Error),
}

pub(crate) fn io_at(path: &Path) -> impl FnOnce(io::Error) -> Error {
    let path = path.to_owned();
    move |source| Error::Io { path, source }
}

#[cfg(test)]
mod tests;
