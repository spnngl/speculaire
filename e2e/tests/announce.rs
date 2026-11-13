//! Every agent announces what its node holds to every reflector, keeps it current, and a lookup on either reflector
//! finds it (D2, D36, D56, D98, D99).
//!
//! The tests pull on the second worker, a plain agent, and look up from the control plane: a reflector never returns
//! the node that asks. Some change the second worker's config and put it back, so they run one at a time.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use e2e::balancer::PORT;
use e2e::reflector::Holder;
use e2e::upstream::{Digest, Image};
use e2e::{Cluster, IpFamily, Runtime};

static SERIAL: Mutex<()> = Mutex::new(());

/// Held by each test: they pull on, and change, the same worker.
fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

const CONFIG: &str = "/etc/speculaire/config.toml";
/// The peer API's port when `peer.address` is `"auto"` (D36).
const PEER_PORT: u16 = 7481;
/// How often containerd's content is listed again (D99), plus the time a listing and a lookup take.
const RECONCILE: Duration = Duration::from_secs(75);

/// The second worker, whose config the test may change: it is put back, and the agent restarted, when this drops.
struct Agent {
    cluster: Cluster,
    name: String,
    observer: String,
    reflectors: Vec<SocketAddr>,
    changed: bool,
}

impl Agent {
    fn new() -> Self {
        let cluster = Cluster::from_env();
        let name = cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .find(|name| name.ends_with("-worker2"))
            .expect("a second worker");
        let reflectors = cluster
            .reflectors()
            .iter()
            .map(|reflector| SocketAddr::new(cluster.family_address(reflector).unwrap(), PORT))
            .collect();
        let [observer, _] = cluster.reflectors();
        let agent = Self {
            cluster,
            name,
            observer,
            reflectors,
            changed: false,
        };
        agent.wait_connected(&agent.name);
        agent
    }

    fn sh(&self, script: &str) -> String {
        self.cluster
            .exec(&self.name, &["sh", "-c", script])
            .unwrap()
    }

    /// Edits the agent's config with `sed` scripts, restarts it and waits for its streams.
    fn config(&mut self, scripts: &[&str]) {
        if !self.changed {
            self.sh(&format!("cp {CONFIG} {CONFIG}.e2e"));
            self.changed = true;
        }
        for script in scripts {
            self.sh(&format!("sed -i '{script}' {CONFIG}"));
        }
        self.restart();
    }

    fn restart(&self) {
        self.sh("systemctl reset-failed speculaire; systemctl restart speculaire");
        self.cluster.wait_ready(&self.name).unwrap();
        self.wait_connected(&self.name);
    }

    /// Waits until `node`'s agent has its stream to every reflector up.
    fn wait_connected(&self, node: &str) {
        let series: Vec<String> = self
            .cluster
            .reflectors()
            .iter()
            .map(|member| format!("speculaire_reflector_connected{{member=\"{member}\"}}"))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let metrics = self.cluster.metrics(node).unwrap();
            if series.iter().all(|s| metrics.get(s) == Some(1.0)) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{node}: not streaming to every reflector: {:?}",
                series.iter().map(|s| metrics.get(s)).collect::<Vec<_>>()
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// A new image of the upstream with a layer of `size` bytes: no node holds its blobs.
    fn image(&self, size: u64) -> Image {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        self.cluster
            .upstream()
            .push(&format!("announce/{nanos}"), size)
            .unwrap()
    }

    fn pull(&self, image: &Image) {
        self.sh(&format!("crictl pull {}", image.reference));
    }

    /// The holders each reflector returns for `digest`.
    fn lookups(&self, digest: &Digest) -> Vec<Vec<Holder>> {
        self.reflectors
            .iter()
            .map(|reflector| {
                self.cluster
                    .lookup(&self.observer, *reflector, digest)
                    .unwrap()
            })
            .collect()
    }

    /// Waits until every reflector returns `expected` for each of `digests`, and fails past `within`.
    fn wait_holders(&self, digests: &[Digest], expected: &[Holder], within: Duration) {
        let start = Instant::now();
        for digest in digests {
            loop {
                let lookups = self.lookups(digest);
                if lookups.iter().all(|holders| holders == expected) {
                    break;
                }
                assert!(
                    start.elapsed() < within,
                    "{digest} after {:?}: {lookups:?}, not {expected:?} on each reflector",
                    start.elapsed()
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    /// This agent as a holder with `address`.
    fn holder(&self, address: SocketAddr) -> Holder {
        Holder {
            node: self.name.clone(),
            address: address.to_string(),
        }
    }

    /// The address the agent announces with `peer.address = "auto"`: its IP on the reflectors' family, port 7481.
    fn auto(&self) -> SocketAddr {
        SocketAddr::new(self.cluster.family_address(&self.name).unwrap(), PEER_PORT)
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if self.changed {
            let _ = self.cluster.exec(
                &self.name,
                &[
                    "sh",
                    "-c",
                    &format!("mv {CONFIG}.e2e {CONFIG}; systemctl reset-failed speculaire; systemctl restart speculaire"),
                ],
            );
            let _ = self.cluster.wait_ready(&self.name);
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn every_agent_streams_to_each_reflector_and_both_find_a_pull_within_2_s() {
    let _serial = serial();
    let agent = Agent::new();
    for node in agent.cluster.nodes().unwrap() {
        agent.wait_connected(&node.name);
    }
    let image = agent.image(1 << 20);
    agent.pull(&image);
    // On the reflectors' family: IPv6 on a dual-stack cluster.
    let auto = agent.auto();
    assert_eq!(
        auto.is_ipv6(),
        agent.cluster.ip_family() == IpFamily::Dual,
        "{auto}"
    );
    agent.wait_holders(&image.blobs, &[agent.holder(auto)], Duration::from_secs(2));
    agent.sh(&format!("crictl rmi {}", image.reference));
    // containerd's CRI deletes the last reference with a synchronous garbage collection, which publishes no content
    // event (`internal/cri/server/images/image_remove.go:64` at v2.4.2): the next listing withdraws the blobs. On
    // CRI-O the blob cache keeps them.
    if agent.cluster.runtime() == Runtime::Containerd {
        agent.wait_holders(&image.blobs, &[], RECONCILE);
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_a_blob_the_cache_evicts_is_withdrawn_within_2_s() {
    let _serial = serial();
    let mut agent = Agent::new();
    if agent.cluster.runtime() != Runtime::Crio {
        return;
    }
    agent.config(&[r#"/^\[blob_cache\]/,/^\[/ s/^#max_size = .*/max_size = "4MiB"/"#]);
    let first = agent.image(2 << 20);
    agent.pull(&first);
    let auto = agent.auto();
    agent.wait_holders(&first.blobs, &[agent.holder(auto)], Duration::from_secs(2));
    // The blobs of an image CRI-O lists go last (D67).
    agent.sh(&format!("crictl rmi {}", first.reference));
    let second = agent.image(3 << 20);
    agent.pull(&second);
    let layer = &first.blobs[1];
    let deadline = Instant::now() + Duration::from_secs(60);
    let path = agent.cluster.blob_path(layer);
    while !agent
        .sh(&format!("test -e {path} && echo kept; true"))
        .is_empty()
    {
        assert!(Instant::now() < deadline, "{layer} is still cached");
        std::thread::sleep(Duration::from_millis(100));
    }
    agent.wait_holders(std::slice::from_ref(layer), &[], Duration::from_secs(2));
    agent.sh(&format!("crictl rmi {}", second.reference));
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_containerd_a_blob_of_another_namespace_is_never_announced() {
    let _serial = serial();
    let agent = Agent::new();
    if agent.cluster.runtime() != Runtime::Containerd {
        return;
    }
    let pulled = agent.image(1 << 20);
    agent.pull(&pulled);
    let holder = agent.holder(agent.auto());
    agent.wait_holders(
        &pulled.blobs,
        std::slice::from_ref(&holder),
        Duration::from_secs(2),
    );
    let other = agent.image(1 << 20);
    agent.sh(&format!(
        "ctr -n default image pull --plain-http {} >/dev/null",
        other.reference
    ));
    std::thread::sleep(Duration::from_secs(3));
    for blob in &other.blobs {
        assert_eq!(agent.lookups(blob), [vec![], vec![]], "{blob}");
    }
    // A restarted agent announces from a listing: the image of `k8s.io` comes back, the other does not.
    agent.restart();
    agent.wait_holders(&pulled.blobs, &[holder], Duration::from_secs(10));
    for blob in &other.blobs {
        assert_eq!(agent.lookups(blob), [vec![], vec![]], "{blob}");
    }
    agent.sh(&format!(
        "ctr -n default image rm --sync {}; crictl rmi {}",
        other.reference, pulled.reference
    ));
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn peer_address_replaces_the_ip_and_the_port_announced() {
    let _serial = serial();
    let mut agent = Agent::new();
    // Documentation addresses: nothing checks that the node owns them.
    let fixed = match agent.cluster.ip_family() {
        IpFamily::Ipv4 => SocketAddr::new(IpAddr::from([192, 0, 2, 7]), 9000),
        IpFamily::Dual => SocketAddr::new(IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 7]), 9000),
    };
    agent.config(&[&format!(r#"s/^#address = "auto"$/address = "{fixed}"/"#)]);
    let image = agent.image(1 << 20);
    agent.pull(&image);
    agent.wait_holders(&image.blobs, &[agent.holder(fixed)], Duration::from_secs(2));
    agent.sh(&format!("crictl rmi {}", image.reference));
}
