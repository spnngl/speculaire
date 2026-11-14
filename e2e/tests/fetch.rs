//! A node's mirror fetches what its node lacks from the peers a lookup names before falling through (D7, D24, D52,
//! D73, D102).
//!
//! A, the second worker, holds what B, the first worker, pulls; C, the control plane, holds it too where a test needs a
//! second holder. The upstream's access log is the oracle: a blob B got from a peer is a blob nobody `GET` there again.
//! The tests break A and change agents' configs, so they run one at a time.
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
use e2e::{Cluster, IpFamily, Output, Runtime};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

const CONFIG: &str = "/etc/speculaire/config.toml";
/// The peer API's port when `peer.address` is `"auto"` (D36).
const PEER_PORT: u16 = 7481;
/// `peer.stall_timeout` in the reference config (D73).
const STALL: Duration = Duration::from_secs(5);
const UPLOADED: &str = r#"speculaire_peer_uploads_total{result="served"}"#;
const UPLOAD_BYTES: &str = "speculaire_peer_upload_bytes_total";

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
            .push(&format!("fetch/{nanos}"), size)
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

    /// `node` as a holder with its peer API on `"auto"`: its IP on the reflectors' family, port 7481.
    fn holder(&self, node: &str) -> Holder {
        let address = SocketAddr::new(self.cluster.family_address(node).unwrap(), PEER_PORT);
        Holder {
            node: node.to_owned(),
            address: address.to_string(),
        }
    }

    /// Waits until every reflector returns `expected`, sorted, to B for each blob of `image`.
    fn wait_holders(&self, image: &Image, expected: &[Holder]) {
        let reflectors: Vec<SocketAddr> = self
            .cluster
            .reflectors()
            .iter()
            .map(|r| SocketAddr::new(self.cluster.family_address(r).unwrap(), PORT))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        for digest in &image.blobs {
            loop {
                let lookups: Vec<Vec<Holder>> = reflectors
                    .iter()
                    .map(|r| self.cluster.lookup(&self.b, *r, digest).unwrap())
                    .collect();
                if lookups.iter().all(|holders| holders == expected) {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "{digest}: {lookups:?}, not {expected:?}"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
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

    fn gets(&self, image: &Image) -> BTreeMap<Digest, usize> {
        self.cluster.upstream().blob_gets(image).unwrap()
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
}

/// A change to a node's config, put back when this drops; the agent restarts with an empty journal both times, so the
/// warnings a test causes do not reach `unit.rs`.
struct Changed<'a> {
    nodes: &'a Nodes,
    node: String,
}

impl<'a> Changed<'a> {
    fn new(nodes: &'a Nodes, node: &str, scripts: &[&str]) -> Self {
        nodes.sh(node, &format!("cp {CONFIG} {CONFIG}.e2e"));
        for script in scripts {
            nodes.sh(node, &format!("sed -i '{script}' {CONFIG}"));
        }
        nodes.cluster.reset_agent(node).unwrap();
        nodes.wait_connected(node);
        Self {
            nodes,
            node: node.to_owned(),
        }
    }
}

impl Drop for Changed<'_> {
    fn drop(&mut self) {
        let _ = self
            .nodes
            .cluster
            .exec(&self.node, &["mv", &format!("{CONFIG}.e2e"), CONFIG]);
        if self.nodes.cluster.reset_agent(&self.node).is_ok() {
            self.nodes.wait_connected(&self.node);
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn an_image_pulled_on_a_comes_to_b_from_a_and_none_of_its_blobs_from_upstream() {
    let _serial = serial();
    let nodes = Nodes::new();
    let image = nodes.image(1 << 20);
    nodes.pulled(&nodes.a, &image);
    let a = nodes.holder(&nodes.a);
    // On a dual-stack cluster, peers dial each other over IPv6.
    assert_eq!(
        a.address.starts_with('['),
        nodes.cluster.ip_family() == IpFamily::Dual,
        "{a:?}"
    );
    nodes.wait_holders(&image, &[a]);
    let gets = nodes.gets(&image);
    let (served, bytes) = (
        nodes.metric(&nodes.a, UPLOADED),
        nodes.metric(&nodes.b, r#"speculaire_mirror_bytes_total{source="peer"}"#),
    );
    nodes.pulled(&nodes.b, &image);
    assert_eq!(nodes.gets(&image), gets, "B got a blob from upstream");
    assert!(nodes.metric(&nodes.a, UPLOADED) > served);
    assert!(
        nodes.metric(&nodes.b, r#"speculaire_mirror_bytes_total{source="peer"}"#)
            >= bytes + f64::from(1 << 20)
    );
    nodes.rmi(&[&nodes.a, &nodes.b], &image);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_peer_whose_certificate_names_another_node_than_the_lookup_is_refused() {
    let _serial = serial();
    let nodes = Nodes::new();
    // A announces C's peer API as its own: B dials C and must find A's certificate there.
    let c = nodes.holder(&nodes.c).address;
    let _changed = Changed::new(
        &nodes,
        &nodes.a,
        &[&format!(r#"s/^#address = "auto"$/address = "{c}"/"#)],
    );
    let image = nodes.image(1 << 20);
    nodes.pulled(&nodes.a, &image);
    nodes.wait_holders(
        &image,
        &[Holder {
            node: nodes.a.clone(),
            address: c,
        }],
    );
    let (errors, served) = (
        nodes.metric(&nodes.b, r#"speculaire_peer_fetches_total{result="error"}"#),
        nodes.metric(&nodes.c, UPLOADED),
    );
    nodes.pulled(&nodes.b, &image);
    assert!(
        nodes.gets(&image).values().all(|&n| n == 2),
        "B did not fall through"
    );
    assert!(nodes.metric(&nodes.b, r#"speculaire_peer_fetches_total{result="error"}"#) > errors);
    assert_eq!(nodes.metric(&nodes.c, UPLOADED), served, "C answered B");
    nodes.rmi(&[&nodes.a, &nodes.b], &image);
}

/// Has A and C hold a new image of 16 MiB, has B pull it from A, and breaks A with `fault` once A has sent 1 MiB of
/// the layer: B completes the pull from C. Returns how long B's pull took.
fn interrupted(nodes: &Nodes, fault: impl FnOnce(&e2e::node::Netem<'_>)) -> Duration {
    let image = nodes.image(16 << 20);
    nodes.pulled(&nodes.a, &image);
    nodes.pulled(&nodes.c, &image);
    let mut holders = vec![nodes.holder(&nodes.a), nodes.holder(&nodes.c)];
    holders.sort();
    nodes.wait_holders(&image, &holders);
    let gets = nodes.gets(&image);
    let (sent, from_c) = (
        nodes.metric(&nodes.a, UPLOAD_BYTES),
        nodes.metric(&nodes.c, UPLOAD_BYTES),
    );
    // A sends 2 MB/s; C answers 1 s late, so A wins the race.
    let slow = nodes.cluster.netem(&nodes.a, "rate 16mbit").unwrap();
    let late = nodes.cluster.netem(&nodes.c, "delay 1s").unwrap();
    let took = std::thread::scope(|scope| {
        let pull = scope.spawn(|| {
            let start = Instant::now();
            (nodes.pull(&nodes.b, &image), start.elapsed())
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        while nodes.metric(&nodes.a, UPLOAD_BYTES) < sent + f64::from(1 << 20) {
            assert!(Instant::now() < deadline, "A sent B no layer");
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(late);
        fault(&slow);
        let (pull, took) = pull.join().unwrap();
        assert!(pull.success, "{pull:?}");
        took
    });
    drop(slow);
    assert_eq!(nodes.gets(&image), gets, "B got a blob from upstream");
    assert!(
        nodes.metric(&nodes.c, UPLOAD_BYTES) > from_c,
        "C sent B nothing"
    );
    nodes.rmi(&[&nodes.a, &nodes.b, &nodes.c], &image);
    took
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn when_a_is_killed_mid_blob_b_completes_the_pull_from_c() {
    let _serial = serial();
    let nodes = Nodes::new();
    let took = interrupted(&nodes, |_| nodes.cluster.kill_agent(&nodes.a).unwrap());
    println!("a pull resumed from C after A was killed took {took:?}");
    nodes.cluster.reset_agent(&nodes.a).unwrap();
    nodes.wait_connected(&nodes.a);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn when_a_stalls_mid_blob_b_completes_from_c_after_the_stall_timeout_and_a_serves_again_once_it_recovers()
 {
    let _serial = serial();
    let nodes = Nodes::new();
    let took = interrupted(&nodes, |netem| netem.change("loss 100%").unwrap());
    println!("a pull resumed from C after A stalled took {took:?}");
    assert!(took >= STALL, "{took:?}");
    // A was not denied: it serves the next image B pulls.
    let image = nodes.image(1 << 20);
    nodes.pulled(&nodes.a, &image);
    nodes.wait_holders(&image, &[nodes.holder(&nodes.a)]);
    let (gets, served) = (nodes.gets(&image), nodes.metric(&nodes.a, UPLOADED));
    nodes.pulled(&nodes.b, &image);
    assert_eq!(nodes.gets(&image), gets, "B got a blob from upstream");
    assert!(nodes.metric(&nodes.a, UPLOADED) > served);
    nodes.rmi(&[&nodes.a, &nodes.b], &image);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_peer_that_serves_a_corrupted_blob_is_denied_with_a_warning_and_an_audit_event() {
    let _serial = serial();
    let nodes = Nodes::new();
    let _audit = Changed::new(
        &nodes,
        &nodes.b,
        &[r"/^\[audit\]/,/^\[/ s/^#enabled = false$/enabled = true/"],
    );
    let both = |image: &Image| {
        nodes.pulled(&nodes.a, image);
        nodes.pulled(&nodes.c, image);
        let mut holders = vec![nodes.holder(&nodes.a), nodes.holder(&nodes.c)];
        holders.sort();
        nodes.wait_holders(image, &holders);
    };
    let image = nodes.image(1 << 20);
    both(&image);
    let layer = &image.blobs[1];
    let path = nodes.cluster.blob_path(layer);
    nodes.sh(&nodes.a, &format!("cp -p {path} {path}.e2e"));
    nodes.cluster.corrupt_blob(&nodes.a, layer).unwrap();
    let mismatches = nodes.metric(
        &nodes.b,
        r#"speculaire_peer_fetches_total{result="digest_mismatch"}"#,
    );
    {
        // C answers 1 s late, so A is asked first.
        let _late = nodes.cluster.netem(&nodes.c, "delay 1s").unwrap();
        let pull = nodes.pull(&nodes.b, &image);
        match nodes.cluster.runtime() {
            // containerd gets nothing before the whole blob matched: the pull goes on from C.
            Runtime::Containerd => assert!(pull.success, "{pull:?}"),
            // CRI-O gets all but the last chunk: the pull fails, and kubelet's retry goes to C.
            Runtime::Crio => {
                if !pull.success {
                    println!("CRI-O's first pull failed: {}", pull.stderr.trim());
                    nodes.pulled(&nodes.b, &image);
                }
            }
        }
    }
    nodes.sh(&nodes.a, &format!("mv {path}.e2e {path}"));
    assert!(
        nodes.metric(
            &nodes.b,
            r#"speculaire_peer_fetches_total{result="digest_mismatch"}"#
        ) > mismatches
    );
    let warning = nodes.sh(
        &nodes.b,
        "journalctl -u speculaire -p warning --no-pager -o verbose",
    );
    assert!(
        warning.contains("a peer sent content that is not its digest")
            && warning.contains(&nodes.a),
        "{warning}"
    );
    let audit = nodes.sh(
        &nodes.b,
        "journalctl -t speculaire-audit --no-pager -o verbose",
    );
    assert!(
        audit.contains("EVENT=peer") && audit.contains(&nodes.a),
        "{audit}"
    );

    // A is skipped: C serves the next image although it answers late.
    let next = nodes.image(1 << 20);
    both(&next);
    let served = nodes.metric(&nodes.a, UPLOADED);
    {
        let _late = nodes.cluster.netem(&nodes.c, "delay 1s").unwrap();
        nodes.pulled(&nodes.b, &next);
    }
    assert_eq!(
        nodes.metric(&nodes.a, UPLOADED),
        served,
        "A served a denied fetch"
    );
    nodes.rmi(&[&nodes.a, &nodes.b, &nodes.c], &image);
    nodes.rmi(&[&nodes.a, &nodes.b, &nodes.c], &next);
}
