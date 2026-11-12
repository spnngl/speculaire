//! The node image and the installed binary: what every later suite assumes.

use e2e::{Cluster, Runtime, TEST_IMAGE};

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn every_node_is_ready_on_the_pinned_runtime_and_kubernetes() {
    let cluster = Cluster::from_env();
    let runtime = format!("{}://{}", cluster.runtime().scheme(), cluster.release());
    // A kubelet that asked its runtime for its version while the runtime reloaded (`speculaire configure` reloads CRI-O)
    // reports `Unknown` until its next status update, at most 10 s later.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let nodes = loop {
        let nodes = cluster.nodes().unwrap();
        if nodes.iter().all(|node| node.runtime == runtime) || std::time::Instant::now() > deadline
        {
            break nodes;
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    };
    assert_eq!(nodes.len(), 3, "e2e/kind.yaml has 3 nodes: {nodes:?}");
    let kubelet = format!("v{}.", cluster.kubernetes());
    for node in &nodes {
        assert!(node.ready, "{node:?}");
        assert_eq!(node.runtime, runtime, "{node:?}");
        assert!(
            node.kubelet.starts_with(&kubelet),
            "{node:?}: want {kubelet}*"
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_runtime_has_nri_and_the_settings_speculaire_needs() {
    let cluster = Cluster::from_env();
    // The merged config of each runtime; containerd 2.3 dropped the registry config from `crictl info` (D27, Measured).
    let (command, lines): (&[&str], &[&str]) = match cluster.runtime() {
        Runtime::Containerd => (
            &["containerd", "config", "dump"],
            &[
                "config_path = '/etc/containerd/certs.d'",
                "discard_unpacked_layers = false",
                "disable = false",
            ],
        ),
        Runtime::Crio => (
            &["crio", "status", "config"],
            &[
                "enable_nri = true",
                "nri_disable_connections = false",
                "default_runtime = \"runc\"",
            ],
        ),
    };
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        cluster
            .exec(&node, &["test", "-S", "/var/run/nri/nri.sock"])
            .unwrap();
        let config = cluster.exec(&node, command).unwrap();
        for line in lines {
            assert!(
                config.lines().any(|l| l.trim() == *line),
                "{node}: no `{line}` in `{}`",
                command.join(" ")
            );
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
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
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
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
