//! `prewarm.images` on both reflectors (D51, D186): a suite writes the list into their config, which each polls every
//! second, and reads what each node's runtime lists.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use crate::registry::fail;
use crate::{Cluster, Failure};

/// The agent's config on every node.
const CONFIG: &str = "/etc/speculaire/config.toml";
/// Where [`Cluster::prewarm`] keeps a reflector's config to put it back.
const SAVED: &str = "/etc/speculaire/config.toml.prewarm";
/// How long the reflectors may take to count every agent.
const STREAMING: Duration = Duration::from_secs(60);

/// Both reflectors polling their config every second, until dropped: then their config is put back and reloaded, which
/// empties the list and withdraws its images.
pub struct Prewarm<'a> {
    cluster: &'a Cluster,
}

impl Cluster {
    /// Makes both reflectors poll their config every second, then waits until each counts every node's agent
    /// streaming: a wave picks its seeds among those (D181).
    ///
    /// # Errors
    ///
    /// When a node's command fails, or a reflector counts another number of agents after 60 s.
    pub fn prewarm(&self) -> Result<Prewarm<'_>, Failure> {
        let guard = Prewarm { cluster: self };
        for reflector in self.reflectors() {
            // A killed run may have left its copy: that one is the config to put back.
            self.sh(
                &reflector,
                &format!(
                    "{{ test ! -f {SAVED} || mv {SAVED} {CONFIG}; }} && cp {CONFIG} {SAVED} \
                     && sed -i 's/^#\\{{0,1\\}}poll_interval = [0-9]*$/poll_interval = 1/' {CONFIG} \
                     && grep -q '^poll_interval = 1$' {CONFIG}"
                ),
            )?;
            self.reload_agent(&reflector)?;
        }
        let nodes =
            u32::try_from(self.nodes()?.len()).map_err(|e| fail("kubectl get nodes", &e))?;
        let deadline = Instant::now() + STREAMING;
        for reflector in self.reflectors() {
            loop {
                let agents = self.metrics(&reflector)?.get("speculaire_reflector_agents");
                if agents.is_some_and(|agents| agents >= f64::from(nodes)) {
                    break;
                }
                if Instant::now() > deadline {
                    return Err(fail(
                        &reflector,
                        &format!(
                            "speculaire_reflector_agents is {agents:?}, not {nodes}, after {STREAMING:?}"
                        ),
                    ));
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        }
        Ok(guard)
    }

    /// Whether the runtime of `node` lists `reference`.
    ///
    /// # Errors
    ///
    /// When `docker exec` fails.
    pub fn lists(&self, node: &str, reference: &str) -> Result<bool, Failure> {
        Ok(self
            .exec_output(node, &["crictl", "inspecti", "-q", reference])?
            .success)
    }

    /// Removes every image of `node` that no container uses and the runtime does not pin, as the kubelet's image
    /// garbage collection does past its threshold: `crictl rmi --prune` skips the images the CRI says are pinned
    /// (cri-tools v1.37.0 `cmd/crictl/image.go:466`). The kubelet's own collection runs 5 minutes apart, and its run at
    /// startup fails while its stats are not ready (D192).
    ///
    /// # Errors
    ///
    /// When `docker exec` fails.
    pub fn prune(&self, node: &str) -> Result<(), Failure> {
        self.exec(node, &["crictl", "rmi", "--prune"]).map(drop)
    }

    /// The tags of the images the runtime of `node` pins, which the kubelet's image garbage collection keeps (D191).
    ///
    /// # Errors
    ///
    /// When `docker exec` fails, or `crictl` prints no image list.
    pub fn pinned(&self, node: &str) -> Result<BTreeSet<String>, Failure> {
        let json = self.exec(node, &["crictl", "images", "-o", "json"])?;
        let list: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| fail("crictl images", &e))?;
        let images = list["images"]
            .as_array()
            .ok_or_else(|| fail("crictl images", &json))?;
        Ok(images
            .iter()
            .filter(|image| image["pinned"] == true)
            .filter_map(|image| image["repoTags"].as_array())
            .flatten()
            .filter_map(|tag| tag.as_str().map(str::to_owned))
            .collect())
    }
}

impl Prewarm<'_> {
    /// Writes `images` as both reflectors' `prewarm.images`, with `prewarm.seeds = 2` and `seed_timeout` seconds of
    /// `prewarm.seed_timeout`, for their next poll; returns when the first write began.
    ///
    /// # Errors
    ///
    /// When a node's command fails.
    pub fn write(&self, images: &[&str], seed_timeout: u64) -> Result<Instant, Failure> {
        let list = images
            .iter()
            .map(|image| format!("\"{image}\""))
            .collect::<Vec<_>>()
            .join(", ");
        // `sed -i` renames its output over the file: a poll reads the old config or the new one.
        let script = format!(
            "sed -i -e '/^\\[prewarm\\]$/,/^\\[/ {{ s|^#\\{{0,1\\}}images = .*$|images = [{list}]|; \
             s|^#\\{{0,1\\}}seeds = [0-9]*$|seeds = 2|; \
             s|^#\\{{0,1\\}}seed_timeout = [0-9]*$|seed_timeout = {seed_timeout}|; }}' {CONFIG} \
             && grep -qF 'images = [{list}]' {CONFIG} && grep -q '^seeds = 2$' {CONFIG} \
             && grep -q '^seed_timeout = {seed_timeout}$' {CONFIG}"
        );
        let written = Instant::now();
        for reflector in self.cluster.reflectors() {
            self.cluster.sh(&reflector, &script)?;
        }
        Ok(written)
    }
}

impl Drop for Prewarm<'_> {
    fn drop(&mut self) {
        for reflector in self.cluster.reflectors() {
            let _ = self.cluster.exec_output(
                &reflector,
                &[
                    "sh",
                    "-c",
                    &format!("test ! -f {SAVED} || mv {SAVED} {CONFIG}"),
                ],
            );
            let _ = self.cluster.reload_agent(&reflector);
        }
    }
}
