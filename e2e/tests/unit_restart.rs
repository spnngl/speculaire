//! Stopping and restarting the unit (D31, D39, D204). A test binary of its own, so that no other suite runs while the
//! agent is down.

use e2e::Cluster;

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_unit_stops_cleanly_and_keeps_its_run_directory() {
    let cluster = Cluster::from_env();
    let node = cluster.nodes().unwrap().remove(0).name;
    let sh = |script: &str| cluster.exec(&node, &["sh", "-c", script]).unwrap();
    sh("echo kept > /run/speculaire/e2e-marker");
    cluster.scrape(&node).unwrap();
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

/// Started with a soft open-file limit below the hard one, as a container runtime may start it, the agent raises the
/// soft one to the hard one (D204).
#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_agent_raises_its_soft_open_file_limit_to_the_hard_one() {
    let cluster = Cluster::from_env();
    let node = cluster.nodes().unwrap().remove(0).name;
    let drop_in = cluster
        .drop_in(&node, "e2e-limits", "[Service]\nLimitNOFILE=1024:524288\n")
        .unwrap();
    cluster.stop_agent(&node).unwrap();
    cluster.start_agent(&node).unwrap();
    let pid = cluster.agent_pid(&node).unwrap().expect("the agent runs");
    let limits = cluster
        .exec(&node, &["cat", &format!("/proc/{pid}/limits")])
        .unwrap();
    let open_files: Vec<&str> = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))
        .unwrap_or_else(|| panic!("{node}: no open-file limit in {limits}"))
        .split_whitespace()
        .collect();
    assert_eq!(open_files, ["524288", "524288", "files"], "{node}");
    drop(drop_in);
}
