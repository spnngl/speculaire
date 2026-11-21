//! The bench's check of a node between runs (D35, D178), run on a worker of the e2e cluster: containerd only, as the
//! bench, and on the IPv4 pass only, since nothing in it depends on the family.

use e2e::{Cluster, IpFamily, Runtime};

/// `bench/bench.sh` runs it on each node after the reset, in the host's namespaces, with the node's name.
const CHECK: &str = include_str!("../../bench/node/check.sh");
/// The label containerd gives the blobs it pulls from `ghcr.io/spegel-org/benchmark`.
const SOURCE: &str = "containerd.io/distribution.source.ghcr.io";

/// A blob of the node's content store labelled as a benchmark blob, unlabelled when this drops.
struct Labelled<'a> {
    cluster: &'a Cluster,
    node: &'a str,
    digest: String,
}

impl Drop for Labelled<'_> {
    fn drop(&mut self) {
        let unlabel = format!("{SOURCE}=");
        let _ = self.cluster.exec(
            self.node,
            &[
                "ctr",
                "-n",
                "k8s.io",
                "content",
                "label",
                &self.digest,
                &unlabel,
            ],
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_node_left_with_a_mirror_entry_and_a_bench_blob_fails_the_check_naming_the_node_and_both() {
    let cluster = Cluster::from_env();
    if cluster.runtime() != Runtime::Containerd || cluster.ip_family() == IpFamily::Dual {
        return;
    }
    let node = cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .find(|name| name.ends_with("-worker2"))
        .expect("a second worker");
    // `just e2e-up` configured the node: its agent's mirror entry is in every hosts.toml. The blob labelled is one
    // with no `ghcr.io` source, so that unlabelling it restores it.
    let digest = cluster
        .exec(
            &node,
            &[
                "sh",
                "-c",
                &format!("ctr -n k8s.io content ls | awk -v s={SOURCE}= 'NR > 1 && !index($0, s) {{ print $1; exit }}'"),
            ],
        )
        .unwrap()
        .trim()
        .to_owned();
    assert!(!digest.is_empty(), "no blob in the content store of {node}");
    let label = format!("{SOURCE}=spegel-org/benchmark");
    cluster
        .exec(
            &node,
            &["ctr", "-n", "k8s.io", "content", "label", &digest, &label],
        )
        .unwrap();
    let _labelled = Labelled {
        cluster: &cluster,
        node: &node,
        digest,
    };

    let out = cluster
        .exec_output(&node, &["bash", "-c", CHECK, "check.sh", &node])
        .unwrap();

    assert!(!out.success, "the check passed: {out:?}");
    for left in [
        "/etc/containerd/certs.d/_default/hosts.toml: a mirror entry is left",
        "containerd's content store holds 1 blob of ghcr.io/spegel-org/benchmark",
    ] {
        assert!(
            out.stdout
                .lines()
                .any(|line| line == format!("{node}: {left}")),
            "no {node}: {left}: {out:?}"
        );
    }
}
