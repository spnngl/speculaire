//! The mirror on every node (D14, D45, D66): who it lets in, how fast it falls through, and what it counts.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use e2e::{Cluster, Runtime};

const MIRROR: &str = "https://127.0.0.1:7480";
const DIR: &str = "/var/lib/speculaire/mirror";
/// A digest that no node holds.
const UNHELD: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
/// An image no other suite pulls (`configure.rs` has its own).
const IMAGE: &str = "docker.io/library/busybox:1.36.0";
/// What the mirror counts of a manifest request: on containerd it falls through; on CRI-O it relays (D66).
const fn manifest_result(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::Containerd => {
            r#"speculaire_mirror_requests_total{kind="manifest",result="fall_through"}"#
        }
        Runtime::Crio => r#"speculaire_mirror_requests_total{kind="manifest",result="served"}"#,
    }
}

fn sh(cluster: &Cluster, node: &str, script: &str) -> String {
    cluster.exec(node, &["sh", "-c", script]).unwrap()
}

fn workers(cluster: &Cluster) -> Vec<String> {
    cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .filter(|name| !name.contains("control-plane"))
        .collect()
}

/// The value of a series of the node's `/metrics`, 0 when it is not there.
fn series(cluster: &Cluster, node: &str, name: &str) -> f64 {
    cluster.metrics(node).unwrap().get(name).unwrap_or(0.0)
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_mirror_serves_a_client_with_the_local_certificate_and_refuses_one_without() {
    let cluster = Cluster::from_env();
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let with = sh(
            &cluster,
            &node,
            &format!(
                "curl -s -o /dev/null -w '%{{http_code}}' --cacert {DIR}/ca.crt --cert {DIR}/client.pem {MIRROR}/v2/"
            ),
        );
        assert_eq!(with.trim(), "200", "{node}");
        let without = cluster
            .exec_output(
                &node,
                &[
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "--cacert",
                    &format!("{DIR}/ca.crt"),
                    &format!("{MIRROR}/v2/"),
                ],
            )
            .unwrap();
        assert!(
            !without.success,
            "{node}: a client without a certificate was served: {without:?}"
        );
        // The kubelet's own certificate is not the mirror's CA's.
        let wrong_ca = cluster
            .exec_output(
                &node,
                &[
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "--cert",
                    &format!("{DIR}/client.pem"),
                    &format!("{MIRROR}/v2/"),
                ],
            )
            .unwrap();
        assert!(
            !wrong_ca.success,
            "{node}: curl trusted the mirror without its CA"
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_digest_the_node_does_not_hold_falls_through_in_under_5_ms_at_p99() {
    let cluster = Cluster::from_env();
    let node = workers(&cluster).remove(0);
    let before = series(
        &cluster,
        &node,
        r#"speculaire_mirror_requests_total{kind="blob",result="fall_through"}"#,
    );
    // One connection, 1000 requests: curl reuses it for the URLs of one invocation.
    let times = sh(
        &cluster,
        &node,
        &format!(
            "curl -s -o /dev/null -w '%{{time_total}}\\n' --cacert {DIR}/ca.crt --cert {DIR}/client.pem '{MIRROR}/v2/library/busybox/blobs/sha256:0000000000000000000000000000000000000000000000000000000000000[000-999]'"
        ),
    );
    let mut seconds: Vec<f64> = times.lines().map(|l| l.trim().parse().unwrap()).collect();
    assert_eq!(seconds.len(), 1000, "{times}");
    seconds.sort_by(f64::total_cmp);
    let p99 = seconds[989];
    println!(
        "fall through, 1000 requests: p50 {} s, p99 {p99} s, max {} s",
        seconds[500], seconds[999]
    );
    assert!(
        p99 < 0.005,
        "p99 of a fall through is {p99} s; median {} s, max {} s",
        seconds[500],
        seconds[999]
    );
    let after = series(
        &cluster,
        &node,
        r#"speculaire_mirror_requests_total{kind="blob",result="fall_through"}"#,
    );
    assert!(
        after - before >= 1000.0,
        "the counter went from {before} to {after}"
    );
    // The unheld manifest of a digest too.
    let status = sh(
        &cluster,
        &node,
        &format!(
            "curl -s -o /dev/null -w '%{{http_code}}' --cacert {DIR}/ca.crt --cert {DIR}/client.pem {MIRROR}/v2/x/manifests/{UNHELD}"
        ),
    );
    assert_eq!(status.trim(), "404");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_pull_goes_through_the_mirror() {
    let cluster = Cluster::from_env();
    let node = workers(&cluster).remove(1);
    sh(
        &cluster,
        &node,
        &format!("crictl rmi {IMAGE} >/dev/null 2>&1; true"),
    );
    let manifests = |cluster: &Cluster| series(cluster, &node, manifest_result(cluster.runtime()));
    let before = manifests(&cluster);
    let pull = cluster
        .exec_output(&node, &["crictl", "pull", IMAGE])
        .unwrap();
    let after = manifests(&cluster);
    sh(&cluster, &node, &format!("crictl rmi {IMAGE}"));
    assert!(pull.success, "{pull:?}");
    assert!(
        after > before,
        "the pull sent the mirror no manifest request: {before} then {after}"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_mirror_metrics_are_exported() {
    let cluster = Cluster::from_env();
    let node = workers(&cluster).remove(0);
    let text = sh(&cluster, &node, "curl -sf http://127.0.0.1:7482/metrics");
    for name in [
        r#"speculaire_mirror_requests_total{kind="blob",result="served"}"#,
        r#"speculaire_mirror_requests_total{kind="referrers",result="error"}"#,
        r#"speculaire_mirror_bytes_total{source="local"}"#,
    ] {
        assert!(
            text.lines().any(|l| l.starts_with(name)),
            "{node}: no {name} in\n{text}"
        );
    }
    // The histogram is native: protobuf only.
    let protobuf = sh(
        &cluster,
        &node,
        "curl -sf -H 'Accept: application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited' http://127.0.0.1:7482/metrics | grep -a -c speculaire_mirror_first_byte_seconds",
    );
    assert!(protobuf.trim() != "0", "{protobuf}");
}
