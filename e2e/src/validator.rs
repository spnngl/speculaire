//! The runtime's default validator requiring `speculaire` on a node, as an admin turns on fail-closed (D44, D84).

use crate::{Cluster, Failure, Runtime};

/// The chart's default `gate.tolerateAnnotation`, which it sets on its pods.
pub const TOLERATE: &str = "speculaire.spnngl.github.io/tolerate-missing-plugins";
/// containerd's config, which holds the validator's section.
const CONTAINERD: &str = "/etc/containerd/config.toml";
/// containerd's config as `just e2e-up` left it, while [`Required`]'s section is in.
const ORIGINAL: &str = "/root/speculaire-e2e-validator.toml";
/// The CRI-O drop-in that holds [`Required`]'s section.
const CRIO: &str = "/etc/crio/crio.conf.d/90-e2e-validator.conf";

/// The validator's section in the node's runtime config, requiring `speculaire` and tolerating [`TOLERATE`], until
/// this drops; the runtime restarts at each end, and the node's agent is ready after.
pub struct Required<'a> {
    cluster: &'a Cluster,
    node: &'a str,
}

impl<'a> Required<'a> {
    /// Adds the section and restarts the node's runtime.
    ///
    /// # Errors
    ///
    /// When the node's command fails, or its agent is not ready again; the section is taken out again then.
    pub fn set(cluster: &'a Cluster, node: &'a str) -> Result<Self, Failure> {
        let section = match cluster.runtime() {
            Runtime::Containerd => format!(
                "cp {CONTAINERD} {ORIGINAL} && cat >>{CONTAINERD} <<'EOF'\n\n\
                 [plugins.'io.containerd.nri.v1.nri'.default_validator]\n  enable = true\n  \
                 required_plugins = [\"speculaire\"]\n  tolerate_missing_plugins_annotation = \"{TOLERATE}\"\nEOF\n"
            ),
            Runtime::Crio => format!(
                "cat >{CRIO} <<'EOF'\n[crio.nri.default_validator]\nnri_enable_default_validator = true\n\
                 nri_validator_required_plugins = [\"speculaire\"]\n\
                 nri_validator_tolerate_missing_plugins_annotation = \"{TOLERATE}\"\nEOF\n"
            ),
        };
        let required = Self { cluster, node };
        cluster.exec(node, &["sh", "-c", &section])?;
        cluster.restart_runtime(node)?;
        cluster.wait_ready(node)?;
        Ok(required)
    }

    /// Takes the section out, restarts the runtime, and waits until the agent is ready.
    fn restore(&self) -> Result<(), Failure> {
        let (cluster, node) = (self.cluster, self.node);
        let config = match cluster.runtime() {
            Runtime::Containerd => format!("test ! -f {ORIGINAL} || mv {ORIGINAL} {CONTAINERD}"),
            Runtime::Crio => format!("rm -f {CRIO}"),
        };
        cluster.exec(node, &["sh", "-c", &config])?;
        cluster.restart_runtime(node)?;
        cluster.wait_ready(node)
    }
}

impl Drop for Required<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            assert!(std::thread::panicking(), "{}: {e}", self.node);
            eprintln!("{}: {e}", self.node);
        }
    }
}
