//! Reloading the unit (D30, D39). A test binary of its own, so that no other suite sees the unit in `reloading`.

use e2e::Cluster;

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn readyz_answers_another_node_and_stays_200_across_a_reload() {
    let cluster = Cluster::from_env();
    let nodes = cluster.nodes().unwrap();
    let readyz = |from: &str, to: &str| {
        cluster
            .exec(
                from,
                &[
                    "curl",
                    "-s",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    &format!("http://{to}:7482/readyz"),
                ],
            )
            .unwrap()
    };
    for (i, node) in nodes.iter().enumerate() {
        let from = &nodes[(i + 1) % nodes.len()].name;
        assert_eq!(
            readyz(from, &node.address),
            "200",
            "{} from {from}",
            node.name
        );
        cluster
            .exec(&node.name, &["systemctl", "reload", "speculaire"])
            .unwrap();
        assert_eq!(
            readyz(from, &node.address),
            "200",
            "{} after reload",
            node.name
        );
        let active = cluster
            .exec(&node.name, &["systemctl", "is-active", "speculaire"])
            .unwrap();
        assert_eq!(active.trim(), "active", "{} after reload", node.name);
    }
}
