//! The node the agent runs on, as its config names it: the runtime's sockets and files, and what `configure`,
//! `check-config` and the agent's startup read of them (D86, D87, D90).

use std::path::PathBuf;

use speculaire_runtime::detect::{self, Runtime, Sockets};
use speculaire_runtime::paths::Paths;
use speculaire_runtime::wiring::Target;

use crate::config::Config;

/// What the agent's commands ask of the node, before they know which runtime it runs.
#[derive(Debug)]
pub struct Node {
    /// Where the node's files are.
    pub paths: Paths,
    /// `mirror.address`, `mirror.registries` and `mirror.directory`.
    pub target: Target,
    /// The sockets of both runtimes.
    pub sockets: Sockets,
    /// `runtime.containerd_config`.
    pub containerd_config: PathBuf,
}

impl Node {
    /// The node `config` names.
    #[must_use]
    pub fn new(config: &Config) -> Self {
        let runtime = &config.runtime;
        Self {
            paths: Paths::system(),
            target: Target {
                address: config.mirror.address.get().get(),
                registries: config
                    .mirror
                    .registries
                    .get()
                    .iter()
                    .map(|name| name.as_str().to_owned())
                    .collect(),
                directory: config.mirror.directory.get().get().to_owned(),
            },
            sockets: Sockets {
                containerd: runtime.containerd_socket.get().get().to_owned(),
                crio: runtime.crio_socket.get().get().to_owned(),
            },
            containerd_config: runtime.containerd_config.get().get().to_owned(),
        }
    }

    /// The runtime whose socket accepts a connection (D64).
    ///
    /// # Errors
    ///
    /// When none or both do.
    pub fn runtime(&self) -> Result<Runtime, detect::DetectError> {
        detect::detect(&self.sockets)
    }

    /// The node as `runtime` runs on it: the one thing that hands out wiring, settings, registries and content (D90).
    #[must_use]
    pub fn on(&self, runtime: Runtime) -> speculaire_runtime::Node {
        speculaire_runtime::Node::new(
            runtime,
            &self.sockets,
            self.paths.clone(),
            Some(self.containerd_config.clone()),
            "systemctl",
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::config;

    fn node_of(text: &str) -> Node {
        Node::new(&config::parse(text).expect("a valid config"))
    }

    #[test]
    fn the_defaults_are_the_nodes_own_files_and_sockets() {
        let node = node_of("");
        assert_eq!(node.target.address, "127.0.0.1:7480".parse().unwrap());
        assert_eq!(
            node.target.registries,
            ["docker.io", "registry.k8s.io", "quay.io", "ghcr.io"]
        );
        assert_eq!(
            node.target.directory,
            Path::new("/var/lib/speculaire/mirror")
        );
        assert_eq!(
            node.sockets.containerd,
            Path::new("/run/containerd/containerd.sock")
        );
        assert_eq!(node.sockets.crio, Path::new("/var/run/crio/crio.sock"));
        assert_eq!(
            node.containerd_config.as_path(),
            Path::new("/etc/containerd/config.toml")
        );
    }

    #[test]
    fn the_config_moves_the_sockets_the_registries_and_the_containerd_config() {
        let node = node_of(
            "[runtime]\ncontainerd_socket = \"/t/c.sock\"\ncontainerd_config = \"/t/c.toml\"\ncrio_socket = \"/t/o.sock\"\n[mirror]\naddress = \"127.0.0.2:7490\"\nregistries = [\"docker.io\", \"localhost:5000\"]\ndirectory = \"/t/mirror\"\n",
        );
        assert_eq!(node.sockets.containerd, Path::new("/t/c.sock"));
        assert_eq!(node.sockets.crio, Path::new("/t/o.sock"));
        assert_eq!(node.containerd_config.as_path(), Path::new("/t/c.toml"));
        assert_eq!(node.target.address, "127.0.0.2:7490".parse().unwrap());
        assert_eq!(node.target.registries, ["docker.io", "localhost:5000"]);
        assert_eq!(node.target.directory, Path::new("/t/mirror"));
        // Neither socket answers: the runtime is not found, naming both.
        let err = node.runtime().unwrap_err().to_string();
        assert!(
            err.contains("/t/c.sock") && err.contains("/t/o.sock"),
            "{err}"
        );
    }
}
