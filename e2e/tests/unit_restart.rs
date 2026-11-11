//! Stopping and restarting the unit (D31, D39). A test binary of its own, so that no other suite runs while the
//! agent is down.

use e2e::Cluster;

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_unit_stops_cleanly_and_keeps_its_run_directory() {
    let cluster = Cluster::from_env();
    let node = cluster.nodes().unwrap().remove(0).name;
    let sh = |script: &str| cluster.exec(&node, &["sh", "-c", script]).unwrap();
    sh("echo kept > /run/speculaire/e2e-marker");
    let stop = sh(
        "start=$(date +%s%N); systemctl stop speculaire; echo $(( ($(date +%s%N) - start) / 1000000 ))",
    );
    let millis: u64 = stop.trim().parse().unwrap();
    assert!(
        millis < 20_000,
        "{node}: stop took {millis} ms, past TimeoutStopSec"
    );
    let status = sh("systemctl show speculaire -p ExecMainStatus -p Result");
    assert!(
        status.contains("ExecMainStatus=0") && status.contains("Result=success"),
        "{node}: {status}"
    );
    sh("systemctl start speculaire");
    assert_eq!(
        sh("cat /run/speculaire/e2e-marker").trim(),
        "kept",
        "{node}"
    );
    sh("rm /run/speculaire/e2e-marker");
    assert_eq!(
        sh("systemctl is-active speculaire").trim(),
        "active",
        "{node}"
    );
}
