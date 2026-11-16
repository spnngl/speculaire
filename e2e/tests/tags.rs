//! A pull by tag resolves from the peers whose runtime lists the tag, else upstream (D123).
//!
//! A, the first worker, holds [`SIGNED`]; B, the second worker, which runs no reflector, pulls it with upstream
//! unreachable and restarts after; C, the control plane, pulls it with `mirror.resolve_tags` off. The upstream's access
//! log, read by client, is the oracle: another node's discovery asks upstream for the image's artifacts whenever its
//! image list changes (D121). The tests remove the image from every node, so they run one at a time.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use e2e::Cluster;
use e2e::balancer::PORT;
use e2e::node::addresses;
use e2e::reflector::Holder;
use e2e::upstream::{Digest, Kind, SIGNED, Upstream};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

const CONFIG: &str = "/etc/speculaire/config.toml";
/// The peer API's port when `peer.address` is `"auto"` (D36).
const PEER_PORT: u16 = 7481;
const PEER: &str = r#"speculaire_tag_lookups_total{result="peer"}"#;
const MISS: &str = r#"speculaire_tag_lookups_total{result="miss"}"#;

/// The cluster, its three nodes, and the upstream of [`SIGNED`].
struct Nodes {
    cluster: Cluster,
    upstream: Upstream,
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
        let (a, b, c) = (find("-worker"), find("-worker2"), find("-control-plane"));
        let upstream = cluster.upstream(Kind::Plain);
        Self {
            cluster,
            upstream,
            a,
            b,
            c,
        }
    }

    fn sh(&self, node: &str, script: &str) -> String {
        self.cluster.exec(node, &["sh", "-c", script]).unwrap()
    }

    /// `<upstream>/<repository>:<tag>`.
    fn reference(&self, image: &str) -> String {
        format!("{}/{image}", self.upstream.address())
    }

    fn pulled(&self, node: &str, reference: &str) {
        let pull = self
            .cluster
            .exec_output(node, &["crictl", "pull", reference])
            .unwrap();
        assert!(pull.success, "{node}: {pull:?}");
    }

    /// Removes `reference` from every node, which may not hold it.
    fn rmi(&self, reference: &str) {
        for node in [&self.a, &self.b, &self.c] {
            self.sh(
                node,
                &format!("crictl rmi {reference} >/dev/null 2>&1; true"),
            );
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

    /// How many requests of `node` upstream has answered for the manifest `<repository>:<tag>` by its tag, or for a
    /// blob of `repository`.
    fn upstream_pulls(&self, node: &str, image: &str) -> usize {
        let (repository, tag) = image.split_once(':').unwrap();
        let manifest = format!("/v2/{repository}/manifests/{tag}");
        let blobs = format!("/v2/{repository}/blobs/");
        let clients = addresses(node).unwrap();
        self.upstream
            .requests()
            .unwrap()
            .iter()
            .filter(|r| clients.contains(&r.client))
            .filter(|r| r.path == manifest || r.path.starts_with(&blobs))
            .count()
    }

    /// The key a node announces for `reference`, as `speculaire_oci::tagged::Tagged::key` computes it.
    fn key(&self, reference: &str) -> Digest {
        let hex = self.sh(
            &self.b,
            &format!(r"printf 'speculaire tag\000%s' '{reference}' | sha256sum | cut -d' ' -f1"),
        );
        format!("sha256:{}", hex.trim()).parse().unwrap()
    }

    /// Waits until every reflector returns `expected` to B for the tag `reference`.
    fn wait_holders(&self, reference: &str, expected: &[&str]) {
        let key = self.key(reference);
        let expected: Vec<Holder> = expected
            .iter()
            .map(|node| Holder {
                node: (*node).to_owned(),
                address: SocketAddr::new(self.cluster.family_address(node).unwrap(), PEER_PORT)
                    .to_string(),
            })
            .collect();
        let reflectors: Vec<SocketAddr> = self
            .cluster
            .reflectors()
            .iter()
            .map(|r| SocketAddr::new(self.cluster.family_address(r).unwrap(), PORT))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let lookups: Vec<Vec<Holder>> = reflectors
                .iter()
                .map(|r| self.cluster.lookup(&self.b, *r, &key).unwrap())
                .collect();
            if lookups.iter().all(|holders| *holders == expected) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{reference}: {lookups:?}, not {expected:?}"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// A holds [`SIGNED`], and no other node does.
    fn only_a_holds_signed(&self) -> String {
        let reference = self.reference(SIGNED);
        self.rmi(&reference);
        self.wait_holders(&reference, &[]);
        self.pulled(&self.a, &reference);
        self.wait_holders(&reference, &[&self.a]);
        reference
    }
}

/// `mirror.resolve_tags = false` on a node, read live, and put back when this drops.
struct Off<'a> {
    nodes: &'a Nodes,
    node: String,
}

impl<'a> Off<'a> {
    fn new(nodes: &'a Nodes, node: &str) -> Self {
        nodes.sh(
            node,
            &format!(
                "cp {CONFIG} {CONFIG}.e2e && sed -i 's/^#resolve_tags = true$/resolve_tags = false/' {CONFIG} \
                 && grep -q '^resolve_tags = false$' {CONFIG} && systemctl reload speculaire"
            ),
        );
        Self {
            nodes,
            node: node.to_owned(),
        }
    }
}

impl Drop for Off<'_> {
    fn drop(&mut self) {
        let _ = self.nodes.cluster.exec(
            &self.node,
            &[
                "sh",
                "-c",
                &format!("mv {CONFIG}.e2e {CONFIG} && systemctl reload speculaire"),
            ],
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_tag_pulled_on_a_resolves_on_b_from_a_while_b_cannot_reach_upstream() {
    let _serial = serial();
    let nodes = Nodes::new();
    let reference = nodes.only_a_holds_signed();
    let (pulls, peer) = (
        nodes.upstream_pulls(&nodes.b, SIGNED),
        nodes.metric(&nodes.b, PEER),
    );
    {
        let _rejected = nodes
            .cluster
            .reject(&nodes.b, nodes.upstream.address())
            .unwrap();
        let start = Instant::now();
        nodes.pulled(&nodes.b, &reference);
        println!("B pulled {SIGNED} by tag from A in {:?}", start.elapsed());
        // Read before upstream is reachable again: then B's discovery may ask it for the image's artifacts (D121).
        assert_eq!(
            nodes.upstream_pulls(&nodes.b, SIGNED),
            pulls,
            "upstream answered B"
        );
    }
    assert!(
        nodes.metric(&nodes.b, PEER) > peer,
        "B resolved no tag from peers"
    );
    nodes.rmi(&reference);
    // Discovery warned that upstream did not answer for the image's artifacts (D121): `unit.rs` reads the journal.
    nodes.cluster.reset_agent(&nodes.b).unwrap();
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn with_resolve_tags_off_c_resolves_the_tag_a_holds_upstream() {
    let _serial = serial();
    let nodes = Nodes::new();
    let reference = nodes.only_a_holds_signed();
    let (pulls, peer, miss) = (
        nodes.upstream_pulls(&nodes.c, SIGNED),
        nodes.metric(&nodes.c, PEER),
        nodes.metric(&nodes.c, MISS),
    );
    {
        let _off = Off::new(&nodes, &nodes.c);
        // The reload is read at once, but no readiness tells when: the first pull may still ask peers.
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            nodes.pulled(&nodes.c, &reference);
            if nodes.upstream_pulls(&nodes.c, SIGNED) > pulls {
                break;
            }
            assert!(Instant::now() < deadline, "C never asked upstream");
            nodes.sh(&nodes.c, &format!("crictl rmi {reference}"));
            std::thread::sleep(Duration::from_secs(1));
        }
        assert_eq!(nodes.metric(&nodes.c, MISS), miss, "C asked peers");
        let peer_after = nodes.metric(&nodes.c, PEER);
        assert!(
            peer_after - peer <= 1.0,
            "C resolved more than one pull from peers"
        );
    }
    nodes.rmi(&reference);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_tag_no_node_holds_resolves_upstream() {
    let _serial = serial();
    let nodes = Nodes::new();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let repository = format!("tags/{nanos}");
    let image = nodes.upstream.push(&repository, 1 << 10).unwrap();
    let miss = nodes.metric(&nodes.b, MISS);
    nodes.pulled(&nodes.b, &image.reference);
    assert!(
        nodes.upstream_pulls(&nodes.b, &format!("{repository}:1")) > 0,
        "B did not resolve the tag upstream"
    );
    assert!(nodes.metric(&nodes.b, MISS) > miss, "B asked no peer");
    nodes.rmi(&image.reference);
}
