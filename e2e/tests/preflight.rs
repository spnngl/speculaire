//! The agent's preflight on the nodes' real runtimes (D15, D41, D54, D55, D86).
//!
//! The agents run already, so these start a second `speculaire agent` on a worker, with a config of its own, and expect
//! it to stop before it opens a listener.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::time::{Duration, Instant};

use e2e::{Cluster, Runtime};

fn worker(cluster: &Cluster) -> String {
    cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .find(|name| name.ends_with("-worker"))
        .expect("a worker")
}

/// Writes `config` at `/tmp/<name>.toml` on the node, and returns that path.
fn put(cluster: &Cluster, node: &str, name: &str, config: &str) -> String {
    let path = format!("/tmp/{name}.toml");
    cluster
        .exec(
            node,
            &["sh", "-c", &format!("cat > {path} <<'EOF'\n{config}EOF\n")],
        )
        .unwrap();
    path
}

/// Runs `speculaire agent` on the node with `config` as its config file; it must stop, and this returns its stderr.
fn refused(cluster: &Cluster, node: &str, name: &str, config: &str) -> String {
    put(cluster, node, name, config);
    let out = cluster
        .exec_output(
            node,
            &[
                "speculaire",
                "agent",
                "--config",
                &format!("/tmp/{name}.toml"),
            ],
        )
        .unwrap();
    assert!(!out.success, "{node}: the agent started: {out:?}");
    out.stderr
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_agent_refuses_to_start_without_the_mirror_certificates() {
    let cluster = Cluster::from_env();
    let node = worker(&cluster);
    let stderr = refused(
        &cluster,
        &node,
        "no-certificates",
        "[metrics]\naddress = \"127.0.0.1:7499\"\n[mirror]\ndirectory = \"/nonexistent/mirror\"\n",
    );
    assert!(
        stderr.contains("1 problem on this node keeps the agent from starting")
            && stderr
                .contains("/nonexistent/mirror/ca.crt: is missing: run `speculaire configure`"),
        "{stderr}"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_agent_refuses_to_start_when_the_runtime_is_not_the_one_the_config_names() {
    let cluster = Cluster::from_env();
    let node = worker(&cluster);
    // A socket that nothing listens on stands for the runtime: detection reports both sockets.
    let stderr = refused(
        &cluster,
        &node,
        "no-runtime",
        "[metrics]\naddress = \"127.0.0.1:7499\"\n[runtime]\ncontainerd_socket = \"/nonexistent/containerd.sock\"\ncrio_socket = \"/nonexistent/crio.sock\"\n",
    );
    assert!(
        stderr.contains("/nonexistent/containerd.sock")
            && stderr.contains("/nonexistent/crio.sock"),
        "{stderr}"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn containerd_with_nri_off_in_its_config_is_refused_naming_the_key() {
    let cluster = Cluster::from_env();
    if cluster.runtime() != Runtime::Containerd {
        return;
    }
    let node = worker(&cluster);
    cluster
        .exec(
            &node,
            &[
                "sh",
                "-c",
                "printf \"version = 3\\n[plugins.'io.containerd.nri.v1.nri']\\ndisable = true\\n\" > /tmp/nri-off.toml",
            ],
        )
        .unwrap();
    let stderr = refused(
        &cluster,
        &node,
        "agent-nri-off",
        "[metrics]\naddress = \"127.0.0.1:7499\"\n[runtime]\ncontainerd_config = \"/tmp/nri-off.toml\"\n",
    );
    assert!(
        stderr.contains(
            "/tmp/nri-off.toml: `disable = true` in [plugins.'io.containerd.nri.v1.nri']"
        ),
        "{stderr}"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn containerd_refuses_a_gate_wait_at_half_of_its_request_timeout() {
    let cluster = Cluster::from_env();
    if cluster.runtime() != Runtime::Containerd {
        return;
    }
    let node = worker(&cluster);
    let containerd = put(
        &cluster,
        &node,
        "nri-2s",
        "version = 3\n[plugins.'io.containerd.nri.v1.nri']\nplugin_request_timeout = \"2s\"\n",
    );
    let config = put(
        &cluster,
        &node,
        "wait-1s",
        &format!(
            "[metrics]\naddress = \"127.0.0.1:7499\"\n[gate]\nwait = 1\n[runtime]\ncontainerd_config = \"{containerd}\"\n"
        ),
    );
    let line = format!(
        "{containerd}: `gate.wait = 1 s` is not below half of `plugin_request_timeout = 2s` in [plugins.'io.containerd.nri.v1.nri']"
    );
    let check = cluster
        .exec_output(&node, &["speculaire", "check-config", &config])
        .unwrap();
    assert!(!check.success && check.stderr.contains(&line), "{check:?}");
    // The agent with its stderr in the journal, as its unit has it, says the same. kind's nodes have no D-Bus for
    // `systemd-run`; the identifier is new to this run.
    let identifier = format!("speculaire-wait-1s-{}", std::process::id());
    let agent = cluster
        .exec_output(
            &node,
            &[
                "systemd-cat",
                &format!("--identifier={identifier}"),
                "speculaire",
                "agent",
                "--config",
                &config,
            ],
        )
        .unwrap();
    assert!(!agent.success, "the agent started: {agent:?}");
    // journald stores the agent's stderr a moment after it ends.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let journal = cluster
            .exec(
                &node,
                &[
                    "journalctl",
                    &format!("--identifier={identifier}"),
                    "--output=cat",
                    "--no-pager",
                ],
            )
            .unwrap();
        if journal.contains("on this node keep") && journal.contains(&line) {
            break;
        }
        assert!(Instant::now() < deadline, "{journal}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn every_node_passes_preflight_as_check_config_runs_it() {
    let cluster = Cluster::from_env();
    for node in cluster.nodes().unwrap() {
        let out = cluster
            .exec_output(&node.name, &["speculaire", "check-config"])
            .unwrap();
        assert!(out.success, "{}: {out:?}", node.name);
        assert_eq!(out.stderr, "", "{}", node.name);
    }
}
