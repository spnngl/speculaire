//! The chart's upgrade and uninstall (D211), the pod twins of the package's removal and reinstall in `operations.rs`.
//!
//! In order, on the release `just e2e-up` installed: an upgrade of `reflector.image.tag` alone rolls the reflectors
//! alone; an uninstall while the second worker's runtime requires `speculaire` fails, naming the node and the key, and
//! leaves the agents running; an uninstall then leaves every node as before the install; and an install with the values
//! of `just e2e-up` brings every pod ready again, for the later suites. `DaemonSet` mode only.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::time::Instant;

use e2e::daemonset::{NAMESPACE, RELEASE};
use e2e::upstream::{AGENT_IMAGE, Kind};
use e2e::{Cluster, Runtime, validator};

/// The reflectors' tag of the upgrade: [`AGENT_IMAGE`] under another tag.
const REFLECTOR_TAG: &str = "e2e-reflector";
/// The shell command that prints whatever `configure` wrote and `unconfigure` takes out, on any runtime: the mirror,
/// `127.0.0.1:7480`, in a registry config, CRI-O's drop-in and certificates, and the mirror's own certificates.
const LEFT: &str = "grep -rl ':7480' /etc/containerd /etc/containers 2>/dev/null; \
     ls -d /etc/containers/registries.conf.d/99-speculaire.conf /etc/containers/certs.d/127.0.0.1:7480 \
     /var/lib/speculaire/mirror 2>/dev/null; true";
/// The containerd filter of the images the agent pinned (D191).
const PINNED: &str = r#"labels."speculaire.prewarm"==pinned"#;

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_chart_upgrades_one_component_and_uninstalls_to_the_node_before_it() {
    let cluster = Cluster::from_env();
    if cluster.has_unit() {
        return;
    }
    let chart = std::env::var("SPECULAIRE_E2E_CHART")
        .expect("SPECULAIRE_E2E_CHART is unset: run the suites with just e2e <runtime> <version>");
    let nodes: Vec<String> = cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .collect();
    let start = Instant::now();
    let lap = |what: &str| eprintln!("{:?} {what}", start.elapsed());
    // `just e2e-up`'s values, which the install at the end gives again.
    let values = cluster
        .helm(&["get", "values", RELEASE, "--output", "yaml"])
        .unwrap();

    for node in &nodes {
        assert_ne!(
            cluster.exec(node, &["sh", "-c", LEFT]).unwrap(),
            "",
            "{node}: configured"
        );
    }

    upgrade(&cluster, &chart);
    lap("upgrade");
    refuse(&cluster, &nodes);
    lap("uninstall refused");
    uninstall(&cluster, &nodes);
    lap("uninstall");
    install(&cluster, &chart, &values, &nodes);
    lap("install");
}

/// Criterion 3: `reflector.image.tag` alone rolls the reflectors, and no agent.
fn upgrade(cluster: &Cluster, chart: &str) {
    let upstream = cluster.upstream(Kind::Plain);
    let host = upstream.address();
    upstream
        .regctl(&format!(
            "regctl image copy {host}/{AGENT_IMAGE} {host}/speculaire:{REFLECTOR_TAG}"
        ))
        .unwrap();
    let agents = pods(cluster, "agent");
    let reflectors = pods(cluster, "reflector");
    cluster
        .helm(&[
            "upgrade",
            RELEASE,
            chart,
            "--reuse-values",
            "--wait",
            "--timeout",
            "5m",
            "--set",
            &format!("reflector.image.tag={REFLECTOR_TAG}"),
        ])
        .unwrap();
    assert_eq!(pods(cluster, "agent"), agents, "the agents rolled");
    let rolled = pods(cluster, "reflector");
    assert_eq!(rolled.len(), reflectors.len(), "{rolled:?}");
    assert!(
        rolled.is_disjoint(&reflectors),
        "{reflectors:?} → {rolled:?}"
    );
}

/// Criterion 2: while the second worker's runtime requires `speculaire`, the uninstall fails naming the node and the
/// runtime's key, and every pod of the release runs on.
fn refuse(cluster: &Cluster, nodes: &[String]) {
    let node = nodes
        .iter()
        .find(|name| name.ends_with("-worker2"))
        .expect("a second worker");
    let running: BTreeSet<String> = pods(cluster, "agent")
        .union(&pods(cluster, "reflector"))
        .cloned()
        .collect();
    let required = validator::Required::set(cluster, node).unwrap();
    let err = cluster
        .helm(&["uninstall", RELEASE, "--wait", "--timeout", "3m"])
        .unwrap_err()
        .to_string();
    eprintln!("{err}");
    let key = match cluster.runtime() {
        Runtime::Containerd => {
            "`required_plugins` of [plugins.'io.containerd.nri.v1.nri'.default_validator]"
        }
        Runtime::Crio => "nri_validator_required_plugins",
    };
    assert!(
        err.contains(&format!("{node}: unconfigure failed: ")) && err.contains(key),
        "{err}"
    );
    let after: BTreeSet<String> = pods(cluster, "agent")
        .union(&pods(cluster, "reflector"))
        .cloned()
        .collect();
    assert_eq!(after, running, "the release's pods");
    cluster
        .kubectl(&[
            "wait",
            "--namespace",
            NAMESPACE,
            "--for=condition=Ready",
            "pods",
            "--selector",
            &format!("app.kubernetes.io/instance={RELEASE},app.kubernetes.io/component in (agent,reflector)"),
            "--timeout=60s",
        ])
        .unwrap();
    drop(required);
}

/// Criterion 1, first half: the uninstall takes out of every node what `configure` wrote and the images the agent
/// pinned, and a node pulls a new image by tag from its upstream.
fn uninstall(cluster: &Cluster, nodes: &[String]) {
    // An image of the agent's prewarm on every node, pinned and marked as the agent does (D191): the agents pin only
    // what a reflector's list names.
    let image = cluster
        .upstream(Kind::Plain)
        .push("lifecycle", 1024)
        .unwrap();
    for node in nodes {
        cluster
            .exec(node, &["crictl", "pull", &image.reference])
            .unwrap();
        if cluster.runtime() == Runtime::Containerd {
            cluster
                .exec(
                    node,
                    &[
                        "ctr",
                        "-n",
                        "k8s.io",
                        "images",
                        "label",
                        &image.reference,
                        "io.cri-containerd.pinned=pinned",
                        "speculaire.prewarm=pinned",
                    ],
                )
                .unwrap();
            assert!(
                cluster.pinned(node).unwrap().contains(&image.reference),
                "{node}: pinned"
            );
        }
        cluster.scrape(node).unwrap();
    }
    cluster
        .helm(&["uninstall", RELEASE, "--wait", "--timeout", "3m"])
        .unwrap();
    for node in nodes {
        assert_eq!(
            cluster.exec(node, &["sh", "-c", LEFT]).unwrap(),
            "",
            "{node}: left"
        );
        if cluster.runtime() == Runtime::Containerd {
            let marked = cluster
                .exec(node, &["ctr", "-n", "k8s.io", "images", "ls", "-q", PINNED])
                .unwrap();
            assert_eq!(marked, "", "{node}: marked");
            assert!(
                !cluster.pinned(node).unwrap().contains(&image.reference),
                "{node}: pinned"
            );
        }
        cluster
            .exec(node, &["crictl", "rmi", &image.reference])
            .unwrap();
        cluster
            .exec(node, &["crictl", "pull", &image.reference])
            .unwrap();
        cluster
            .exec(node, &["crictl", "rmi", &image.reference])
            .unwrap();
    }
}

/// Criterion 1, second half: an install with `just e2e-up`'s values brings every pod ready, one per node.
fn install(cluster: &Cluster, chart: &str, values: &str, nodes: &[String]) {
    let file = std::env::temp_dir().join(format!(
        "speculaire-e2e-lifecycle-{}.yaml",
        std::process::id()
    ));
    std::fs::write(&file, values).unwrap();
    let installed = cluster.helm(&[
        "install",
        RELEASE,
        chart,
        "--wait",
        "--timeout",
        "5m",
        "--values",
        file.to_str().unwrap(),
    ]);
    std::fs::remove_file(&file).unwrap();
    installed.unwrap();
    let all = pods(cluster, "agent").len() + pods(cluster, "reflector").len();
    assert_eq!(all, nodes.len(), "one pod per node");
    for node in nodes {
        cluster.wait_ready(node).unwrap();
    }
}

/// The UIDs of the release's pods of `component`.
fn pods(cluster: &Cluster, component: &str) -> BTreeSet<String> {
    cluster
        .kubectl(&[
            "get",
            "pods",
            "--namespace",
            NAMESPACE,
            "--selector",
            &format!(
                "app.kubernetes.io/instance={RELEASE},app.kubernetes.io/component={component}"
            ),
            "--output",
            "jsonpath={.items[*].metadata.uid}",
        ])
        .unwrap()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}
