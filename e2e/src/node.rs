//! What the peer suites do to a node (D94): stop, start or kill its agent, slow its network, corrupt a blob it serves,
//! and read its metrics.

use std::time::{Duration, Instant};

use crate::registry::fail;
use crate::upstream::Digest;
use crate::{Cluster, Failure, Runtime};

impl Cluster {
    /// The file a node serves its peers `digest` from (D67): in containerd's content store, or in the agent's blob
    /// cache on CRI-O.
    #[must_use]
    pub fn blob_path(&self, digest: &Digest) -> String {
        let blobs = match self.runtime {
            Runtime::Containerd => {
                "/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256"
            }
            Runtime::Crio => "/var/lib/speculaire/blobs/blobs/sha256",
        };
        format!("{blobs}/{}", digest.hex())
    }

    fn sh(&self, node: &str, script: &str) -> Result<String, Failure> {
        self.exec(node, &["sh", "-c", script])
    }

    /// Stops the node's agent, as an admin does.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails.
    pub fn stop_agent(&self, node: &str) -> Result<(), Failure> {
        self.sh(node, "systemctl stop speculaire").map(drop)
    }

    /// Starts the node's agent and waits until it is ready.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails, or the agent is not ready within 120 s.
    pub fn start_agent(&self, node: &str) -> Result<(), Failure> {
        self.sh(
            node,
            "systemctl reset-failed speculaire; systemctl start speculaire",
        )?;
        self.wait_ready(node)
    }

    /// Kills the node's agent with `SIGKILL`; systemd starts it again (`Restart=on-failure`).
    ///
    /// # Errors
    ///
    /// When `systemctl` fails.
    pub fn kill_agent(&self, node: &str) -> Result<(), Failure> {
        self.sh(node, "systemctl kill --signal=SIGKILL speculaire")
            .map(drop)
    }

    /// Empties the node's journal and restarts its agent, which writes its start entries again: `unit.rs` asserts the
    /// journal holds no warning, and a kill leaves some.
    ///
    /// # Errors
    ///
    /// When the agent is not ready within 120 s.
    pub fn reset_agent(&self, node: &str) -> Result<(), Failure> {
        self.sh(
            node,
            "journalctl --rotate && journalctl --vacuum-time=1s; systemctl reset-failed speculaire; systemctl restart speculaire",
        )?;
        self.wait_ready(node)
    }

    /// Waits until the node's agent answers `/readyz`.
    ///
    /// # Errors
    ///
    /// When it does not within 120 s.
    pub fn wait_ready(&self, node: &str) -> Result<(), Failure> {
        let deadline = Instant::now() + Duration::from_secs(120);
        while !self
            .exec_output(
                node,
                &[
                    "curl",
                    "-sf",
                    "-o",
                    "/dev/null",
                    "http://127.0.0.1:7482/readyz",
                ],
            )?
            .success
        {
            if Instant::now() > deadline {
                return Err(fail(node, &"the agent is not ready after 120 s"));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Ok(())
    }

    /// Puts `tc netem <args>`, such as `delay 200ms` or `loss 100%`, on what leaves the node through kind's network.
    ///
    /// # Errors
    ///
    /// When `tc` fails; the host's kernel needs `sch_netem`.
    pub fn netem(&self, node: &str, args: &str) -> Result<Netem<'_>, Failure> {
        // `replace`: a killed run may have left one.
        self.sh(
            node,
            &format!("tc qdisc replace dev eth0 root netem {args}"),
        )?;
        Ok(Netem {
            cluster: self,
            node: node.to_owned(),
        })
    }

    /// Changes the first byte of the blob the node serves its peers as `digest`, keeping its size.
    ///
    /// # Errors
    ///
    /// When the node holds no such blob.
    pub fn corrupt_blob(&self, node: &str, digest: &Digest) -> Result<(), Failure> {
        let path = self.blob_path(digest);
        // `x`, or `y` when the byte is `x`.
        self.sh(
            node,
            &format!(
                "test -f {path} || {{ echo 'no blob {digest}' >&2; exit 1; }}; c=x; [ \"$(head -c 1 {path})\" != x ] || c=y; printf $c | dd of={path} bs=1 count=1 conv=notrunc 2>/dev/null"
            ),
        )
        .map(drop)
    }

    /// The node's metrics, as its agent serves them now.
    ///
    /// # Errors
    ///
    /// When the agent does not answer.
    pub fn metrics(&self, node: &str) -> Result<Metrics, Failure> {
        self.exec(node, &["curl", "-sf", "http://127.0.0.1:7482/metrics"])
            .map(Metrics)
    }
}

/// A `tc netem` qdisc on a node, removed when this drops.
pub struct Netem<'a> {
    cluster: &'a Cluster,
    node: String,
}

impl Drop for Netem<'_> {
    fn drop(&mut self) {
        let _ = self.cluster.sh(&self.node, "tc qdisc del dev eth0 root");
    }
}

/// What an agent's `/metrics` answered, in the Prometheus text format.
pub struct Metrics(String);

impl Metrics {
    /// The value of `series`, written as the agent writes it, such as
    /// `speculaire_mirror_requests_total{kind="blob",result="served"}`; `None` when the agent has not written it.
    #[must_use]
    pub fn get(&self, series: &str) -> Option<f64> {
        self.0.lines().find_map(|line| {
            let (name, value) = line.rsplit_once(' ')?;
            (name == series).then(|| value.parse().ok()).flatten()
        })
    }
}
