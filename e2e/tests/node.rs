//! The node image and the installed binary: what every later suite assumes.

use e2e::{Cluster, TEST_IMAGE};

#[test]
#[ignore = "needs a kind cluster: just e2e <minor>"]
fn every_node_is_ready() {
    let nodes = Cluster::from_env().nodes().unwrap();
    assert_eq!(nodes.len(), 3, "e2e/kind.yaml has 3 nodes: {nodes:?}");
    assert!(nodes.iter().all(|n| n.ready), "{nodes:?}");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <minor>"]
fn containerd_is_the_pinned_release_with_nri_and_config_path() {
    let cluster = Cluster::from_env();
    let release = format!(" v{} ", cluster.containerd());
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let version = cluster.exec(&node, &["containerd", "--version"]).unwrap();
        assert!(version.contains(&release), "{node}: {version}");
        cluster
            .exec(&node, &["test", "-S", "/var/run/nri/nri.sock"])
            .unwrap();
        // 2.3 dropped the registry config from `crictl info`; the merged config still shows it (D27, Measured).
        let dump = cluster
            .exec(&node, &["containerd", "config", "dump"])
            .unwrap();
        for line in [
            "config_path = '/etc/containerd/certs.d'",
            "discard_unpacked_layers = false",
            "disable = false",
        ] {
            assert!(
                dump.lines().any(|l| l.trim() == line),
                "{node}: no `{line}` in containerd config dump"
            );
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <minor>"]
fn speculaire_version_runs_on_every_node() {
    let cluster = Cluster::from_env();
    let prefix = concat!("speculaire ", env!("CARGO_PKG_VERSION"), " ");
    for node in cluster.nodes().unwrap() {
        let out = cluster
            .exec(&node.name, &["speculaire", "version"])
            .unwrap();
        let out = out.trim();
        assert!(
            out.starts_with(prefix) && out.ends_with("-linux-musl"),
            "{}: {out}",
            node.name
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <minor>"]
fn a_pod_runs() {
    let cluster = Cluster::from_env();
    let pod = "e2e-node-busybox";
    cluster
        .kubectl(&["delete", "pod", pod, "--ignore-not-found", "--wait"])
        .unwrap();
    cluster
        .kubectl(&[
            "run",
            pod,
            &format!("--image={TEST_IMAGE}"),
            "--restart=Never",
            "--",
            "sleep",
            "3600",
        ])
        .unwrap();
    let ready = cluster.kubectl(&[
        "wait",
        "--for=condition=Ready",
        &format!("pod/{pod}"),
        "--timeout=120s",
    ]);
    cluster
        .kubectl(&["delete", "pod", pod, "--wait=false"])
        .unwrap();
    ready.unwrap();
}
