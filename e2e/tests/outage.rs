//! The peer path degrades to falling through and never fails a pull: reflectors that stop or restart, an agent before
//! its certificate exists, an agent that stops while it serves (D1, D16, D39, D103).
//!
//! A, the second worker, runs an agent; B, the first worker, and C, the control plane, run the reflectors. The tests
//! stop agents and reflectors, so they run one at a time, and each ends with every node restarted with an empty
//! journal: an agent that has missed a reflector for 60 s writes warnings (D98) that `unit.rs` would find.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use e2e::balancer::PORT;
use e2e::reflector::Holder;
use e2e::upstream::{Digest, Image};
use e2e::{Cluster, Output, Runtime};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

const CONFIG: &str = "/etc/speculaire/config.toml";
/// The peer API's port when `peer.address` is `"auto"` (D36).
const PEER_PORT: u16 = 7481;
const UPLOAD_BYTES: &str = "speculaire_peer_upload_bytes_total";
const P2P: &str = "speculaire_p2p_enabled";
/// Where test 4 points A's certificate: a file that exists only while the test links it to kubelet's, so kubelet
/// keeps its own.
const CERTIFICATE: &str = "/var/lib/kubelet/pki/speculaire-e2e.pem";

/// The cluster and its three nodes.
struct Nodes {
    cluster: Cluster,
    a: String,
    b: String,
    c: String,
}

impl Nodes {
    fn new() -> Self {
        let cluster = Cluster::from_env();
        let names: Vec<String> = cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .collect();
        let find = |suffix: &str| {
            names
                .iter()
                .find(|name| name.ends_with(suffix))
                .expect("a node of each name")
                .clone()
        };
        let (a, b, c) = (find("-worker2"), find("-worker"), find("-control-plane"));
        Self { cluster, a, b, c }
    }

    fn sh(&self, node: &str, script: &str) -> String {
        self.cluster.exec(node, &["sh", "-c", script]).unwrap()
    }

    /// A new image of the upstream with a layer of `size` bytes: no node holds its blobs.
    fn image(&self, size: u64) -> Image {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        self.cluster
            .upstream()
            .push(&format!("outage/{nanos}"), size)
            .unwrap()
    }

    fn pull(&self, node: &str, image: &Image) -> Output {
        self.cluster
            .exec_output(node, &["crictl", "pull", &image.reference])
            .unwrap()
    }

    fn pulled(&self, node: &str, image: &Image) {
        let pull = self.pull(node, image);
        assert!(pull.success, "{node}: {pull:?}");
    }

    /// Removes `image` from each of `nodes`, which may not hold it.
    fn rmi(&self, nodes: &[&str], image: &Image) {
        for node in nodes {
            self.sh(
                node,
                &format!("crictl rmi {} >/dev/null 2>&1; true", image.reference),
            );
        }
    }

    /// `node` as a holder with its peer API on `"auto"`: its IP on the reflectors' family, port 7481.
    fn holder(&self, node: &str) -> Holder {
        let address = SocketAddr::new(self.cluster.family_address(node).unwrap(), PEER_PORT);
        Holder {
            node: node.to_owned(),
            address: address.to_string(),
        }
    }

    /// The holders of `digest` that each reflector returns to C, sorted.
    fn lookups(&self, digest: &Digest) -> Vec<Vec<Holder>> {
        self.cluster
            .reflectors()
            .iter()
            .map(|r| {
                let address = SocketAddr::new(self.cluster.family_address(r).unwrap(), PORT);
                self.cluster.lookup(&self.c, address, digest).unwrap()
            })
            .collect()
    }

    /// Waits up to `within` until every reflector returns `expected`, sorted, for each blob of `image`; returns how
    /// long it waited.
    fn wait_holders(&self, image: &Image, expected: &[Holder], within: Duration) -> Duration {
        let start = Instant::now();
        for digest in &image.blobs {
            loop {
                let lookups = self.lookups(digest);
                if lookups.iter().all(|holders| holders == expected) {
                    break;
                }
                assert!(
                    start.elapsed() < within,
                    "{digest}: {lookups:?}, not {expected:?}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        start.elapsed()
    }

    /// Waits until `node`'s agent streams to every reflector, so that its lookups and announcements reach them.
    fn wait_connected(&self, node: &str) {
        let series: Vec<String> = self
            .cluster
            .reflectors()
            .iter()
            .map(|member| format!("speculaire_reflector_connected{{member=\"{member}\"}}"))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !series.iter().all(|s| self.metric(node, s) >= 1.0) {
            assert!(
                Instant::now() < deadline,
                "{node} does not stream to every reflector"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// The value of `series` on `node`'s agent, 0 when it has not written it.
    fn metric(&self, node: &str, series: &str) -> f64 {
        self.cluster
            .metrics(node)
            .unwrap()
            .get(series)
            .unwrap_or(0.0)
    }

    /// The lookups of `node`'s agent that found no reflector to ask (D103).
    fn no_reflector(&self, node: &str) -> u64 {
        self.cluster
            .histogram_count(
                node,
                "speculaire_lookup_seconds",
                ("result", "no_reflector"),
            )
            .unwrap()
    }

    /// What `node`'s mirror left to the upstream: the blob requests that fell through on containerd, the bytes it
    /// relayed from the upstream on CRI-O (D66).
    fn went_upstream(&self, node: &str) -> f64 {
        let series = match self.cluster.runtime() {
            Runtime::Containerd => {
                r#"speculaire_mirror_requests_total{kind="blob",result="fall_through"}"#
            }
            Runtime::Crio => r#"speculaire_mirror_bytes_total{source="upstream"}"#,
        };
        self.metric(node, series)
    }

    fn gets(&self, image: &Image) -> BTreeMap<Digest, usize> {
        self.cluster.upstream().blob_gets(image).unwrap()
    }

    /// Whether anything on `node` listens on the peer API's port.
    fn listens(&self, node: &str) -> bool {
        !self
            .sh(node, &format!("ss -Hltn 'sport = :{PEER_PORT}'"))
            .trim()
            .is_empty()
    }

    /// Waits up to `within` until `node`'s peer API listens; returns how long it waited.
    fn wait_listens(&self, node: &str, within: Duration) -> Duration {
        let start = Instant::now();
        while !self.listens(node) {
            assert!(start.elapsed() < within, "{node}'s peer API is closed");
            std::thread::sleep(Duration::from_millis(500));
        }
        start.elapsed()
    }
}

/// Puts every node back when this drops: its config, if a test changed it, and its agent, restarted with an empty
/// journal, reflectors first.
struct Restore<'a>(&'a Nodes);

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let nodes = self.0;
        let _ = nodes.cluster.exec(&nodes.a, &["rm", "-f", CERTIFICATE]);
        let order = [&nodes.c, &nodes.b, &nodes.a];
        for node in order {
            let _ = nodes.cluster.exec(
                node,
                &[
                    "sh",
                    "-c",
                    &format!("[ ! -f {CONFIG}.e2e ] || mv {CONFIG}.e2e {CONFIG}"),
                ],
            );
        }
        let restarted = order
            .iter()
            .all(|node| nodes.cluster.reset_agent(node).is_ok());
        if restarted && !std::thread::panicking() {
            for node in order {
                nodes.wait_connected(node);
            }
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn with_one_reflector_stopped_lookups_still_find_peers_and_with_both_pulls_fall_through() {
    let _serial = serial();
    let nodes = Nodes::new();
    let _restore = Restore(&nodes);
    let held = nodes.image(1 << 20);
    nodes.pulled(&nodes.b, &held);
    nodes.wait_holders(&held, &[nodes.holder(&nodes.b)], Duration::from_secs(10));

    nodes.cluster.stop_agent(&nodes.c).unwrap();
    let gets = nodes.gets(&held);
    nodes.pulled(&nodes.a, &held);
    assert_eq!(nodes.gets(&held), gets, "A got a blob from upstream");

    nodes.cluster.stop_agent(&nodes.b).unwrap();
    let image = nodes.image(1 << 20);
    let (missed, fell) = (nodes.no_reflector(&nodes.a), nodes.went_upstream(&nodes.a));
    nodes.pulled(&nodes.a, &image);
    assert!(nodes.no_reflector(&nodes.a) > missed, "no lookup counted");
    assert!(nodes.went_upstream(&nodes.a) > fell, "nothing fell through");
    nodes.rmi(&[&nodes.a, &nodes.b], &held);
    nodes.rmi(&[&nodes.a], &image);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn an_agent_started_without_reflectors_opens_its_peer_api_once_one_starts() {
    let _serial = serial();
    let nodes = Nodes::new();
    let _restore = Restore(&nodes);
    nodes.cluster.stop_agent(&nodes.c).unwrap();
    nodes.cluster.stop_agent(&nodes.b).unwrap();
    nodes.cluster.reset_agent(&nodes.a).unwrap();
    let image = nodes.image(1 << 20);
    let fell = nodes.went_upstream(&nodes.a);
    nodes.pulled(&nodes.a, &image);
    assert!(nodes.went_upstream(&nodes.a) > fell, "nothing fell through");
    // The address comes from the first stream (D36): none has been up, so nothing listens.
    assert!(!nodes.listens(&nodes.a), "A's peer API listens");

    nodes.cluster.start_agent(&nodes.c).unwrap();
    // Asking the balancer again waits up to 60 s after failures (D33).
    let took = nodes.wait_listens(&nodes.a, Duration::from_secs(90));
    println!("A's peer API opened {took:?} after C's reflector was ready");
    nodes.rmi(&[&nodes.a], &image);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn after_a_reflector_restarts_its_lookups_find_every_holder_within_10_s() {
    let _serial = serial();
    let nodes = Nodes::new();
    let _restore = Restore(&nodes);
    let image = nodes.image(1 << 20);
    nodes.pulled(&nodes.a, &image);
    nodes.pulled(&nodes.b, &image);
    let mut holders = vec![nodes.holder(&nodes.a), nodes.holder(&nodes.b)];
    holders.sort();
    nodes.wait_holders(&image, &holders, Duration::from_secs(10));

    // Its index starts empty: the agents' opening snapshots fill it again (D98).
    nodes.cluster.reset_agent(&nodes.c).unwrap();
    let took = nodes.wait_holders(&image, &holders, Duration::from_secs(10));
    println!("C's lookups found every holder {took:?} after it was ready");
    nodes.rmi(&[&nodes.a, &nodes.b], &image);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn an_agent_without_its_certificate_falls_through_until_the_certificate_comes() {
    let _serial = serial();
    let nodes = Nodes::new();
    let _restore = Restore(&nodes);
    nodes.sh(
        &nodes.a,
        &format!(
            r#"cp {CONFIG} {CONFIG}.e2e && sed -i 's|^#certificate = .*|certificate = "{CERTIFICATE}"|' {CONFIG}"#
        ),
    );
    nodes.cluster.reset_agent(&nodes.a).unwrap();
    let pid = nodes.sh(&nodes.a, "systemctl show -p MainPID --value speculaire");
    assert_eq!(nodes.metric(&nodes.a, P2P), 0.0);
    let image = nodes.image(1 << 20);
    nodes.pulled(&nodes.b, &image);
    nodes.wait_holders(&image, &[nodes.holder(&nodes.b)], Duration::from_secs(10));
    let gets = nodes.gets(&image);
    nodes.pulled(&nodes.a, &image);
    assert_ne!(nodes.gets(&image), gets, "A got no blob from upstream");
    assert!(!nodes.listens(&nodes.a), "A's peer API listens");

    nodes.sh(
        &nodes.a,
        &format!("ln -s kubelet-client-current.pem {CERTIFICATE}"),
    );
    // The agent reads the certificate at its next poll (D95), then streams, and its peer API opens (D36).
    let took = nodes.wait_listens(&nodes.a, Duration::from_secs(30));
    println!("A's peer API opened {took:?} after its certificate came");
    assert_eq!(nodes.metric(&nodes.a, P2P), 1.0);
    nodes.wait_connected(&nodes.a);
    nodes.rmi(&[&nodes.a], &image);
    let gets = nodes.gets(&image);
    nodes.pulled(&nodes.a, &image);
    assert_eq!(nodes.gets(&image), gets, "A got a blob from upstream");
    assert_eq!(
        nodes.sh(&nodes.a, "systemctl show -p MainPID --value speculaire"),
        pid,
        "A's agent restarted"
    );
    nodes.rmi(&[&nodes.a, &nodes.b], &image);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn an_agent_stopped_while_it_serves_leaves_lookups_within_1_s_and_finishes_the_upload() {
    let _serial = serial();
    let nodes = Nodes::new();
    let _restore = Restore(&nodes);
    let image = nodes.image(16 << 20);
    nodes.pulled(&nodes.a, &image);
    nodes.wait_holders(&image, &[nodes.holder(&nodes.a)], Duration::from_secs(10));
    let layer = image.blobs.last().unwrap();
    let (gets, sent) = (nodes.gets(&image), nodes.metric(&nodes.a, UPLOAD_BYTES));
    // A sends 4 MB/s: B's pull of the layer lasts 4 s, and A stops in the middle of it.
    let slow = nodes.cluster.netem(&nodes.a, "rate 32mbit").unwrap();
    let nodes = &nodes;
    let (gone, stopped) = std::thread::scope(|scope| {
        let pull = scope.spawn(|| nodes.pull(&nodes.b, &image));
        let deadline = Instant::now() + Duration::from_secs(20);
        while nodes.metric(&nodes.a, UPLOAD_BYTES) < sent + f64::from(1 << 20) {
            assert!(Instant::now() < deadline, "A sent B no layer");
            std::thread::sleep(Duration::from_millis(50));
        }
        let start = Instant::now();
        let stop = scope.spawn(move || {
            nodes.cluster.stop_agent(&nodes.a).unwrap();
            start.elapsed()
        });
        while nodes
            .lookups(layer)
            .iter()
            .any(|holders| !holders.is_empty())
        {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "A is still found"
            );
        }
        let gone = start.elapsed();
        let pull = pull.join().unwrap();
        assert!(pull.success, "{pull:?}");
        (gone, stop.join().unwrap())
    });
    drop(slow);
    println!("lookups left A {gone:?} after its stop began; the stop took {stopped:?}");
    assert!(gone < Duration::from_secs(1), "{gone:?}");
    // `TimeoutStopSec` (D39).
    assert!(stopped < Duration::from_secs(20), "{stopped:?}");
    assert_eq!(
        nodes
            .sh(&nodes.a, "systemctl show -p Result --value speculaire")
            .trim(),
        "success"
    );
    assert_eq!(nodes.gets(&image), gets, "B got a blob from upstream");
    nodes.rmi(&[&nodes.a, &nodes.b], &image);
}
