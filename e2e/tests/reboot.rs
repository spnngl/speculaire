//! A node rebooted while its runtime requires `speculaire` (D44, D209): the chart's agent pod, which carries the tolerate
//! annotation, runs first, then the node's other pods, which the runtime's validator holds until the agent registers.
//!
//! On the second worker, which runs an agent and no reflector: kind takes `docker restart` of a node for its reboot. An
//! unannotated pod and an unannotated static pod stay on the node across it. The node's runtime config and manifests are
//! put back as `just e2e-up` left them, even when a step fails. `DaemonSet` mode only: the validator does not gate the
//! unit.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use e2e::{Cluster, Failure, Runtime, validator};
use jiff::Timestamp;
use serde_json::Value;

const CONTAINERD: &str = "/etc/containerd/config.toml";
/// The suite's static pod.
const STATIC: &str = "/etc/kubernetes/manifests/speculaire-e2e-reboot.yaml";
/// The suite's pod, in `default`, and the name of its static pod.
const POD: &str = "speculaire-e2e-reboot";
/// The namespace `just e2e-up` installs the chart in.
const NAMESPACE: &str = "speculaire";
/// The validator's message for a container created while the agent is not registered.
const MISSING: &str = r#"required plugin "speculaire" not present"#;
/// How long the agent pod may take to be ready again after the reboot (step 07).
const AGENT_BOUND: Duration = Duration::from_secs(180);
/// How long the node's other pods may take to run again after the agent pod is ready.
const OTHERS_BOUND: Duration = Duration::from_secs(120);

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_rebooted_node_runs_the_agent_pod_first_then_the_others() {
    let cluster = Cluster::from_env();
    if cluster.has_unit() {
        return;
    }
    let node = cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .find(|name| name.ends_with("-worker2"))
        .expect("a second worker");
    let config = runtime_config(&cluster, &node);
    let required = Required::set(&cluster, &node);
    // Every container that runs on the node must run again, after the start it had. `startedAt` is to the second: a
    // container started in the second before the reboot is told by its earlier start.
    let before: BTreeMap<String, Timestamp> = running(&cluster, &node)
        .into_iter()
        .map(|c| (c.key(), c.started))
        .collect();
    let boot = Timestamp::try_from(cluster.clock(&node).unwrap()).unwrap();
    let boot = Timestamp::from_second(boot.as_second()).unwrap();
    let restart = Instant::now();
    cluster.reboot(&node).unwrap();

    // The first time each container is seen running since the reboot, from the restart's start.
    let mut seen = BTreeMap::new();
    let mut ready = None;
    let containers = loop {
        let containers: Vec<Container> = running(&cluster, &node)
            .into_iter()
            .filter(|c| {
                c.started >= boot && before.get(&c.key()).is_none_or(|was| c.started > *was)
            })
            .collect();
        for container in &containers {
            seen.entry(container.key())
                .or_insert_with(|| restart.elapsed());
        }
        if ready.is_none() && containers.iter().any(|c| c.is_agent() && c.ready) {
            ready = Some(restart.elapsed());
        }
        let back = |key: &String| containers.iter().any(|c| c.key() == *key);
        match ready {
            Some(_) if before.keys().all(back) => break containers,
            Some(ready) => assert!(
                restart.elapsed() < ready + OTHERS_BOUND,
                "{node}: not running {OTHERS_BOUND:?} after the agent pod was ready: {:?}",
                before.keys().filter(|key| !back(key)).collect::<Vec<_>>()
            ),
            None => assert!(
                restart.elapsed() < AGENT_BOUND,
                "{node}: the agent pod is not ready {AGENT_BOUND:?} after the reboot; rejections {:?}",
                rejections(&cluster, boot)
            ),
        }
        std::thread::sleep(Duration::from_millis(500));
    };

    let agent = containers.iter().find(|c| c.is_agent()).expect("the agent");
    let after = |c: &Container| c.started.duration_since(boot).as_secs_f64();
    let order: Vec<String> = containers
        .iter()
        .map(|c| format!("{} +{}s (seen {:?})", c.key(), after(c), seen[&c.key()]))
        .collect();
    eprintln!(
        "{node}: the agent pod ready {:?} after the restart began; started, from the reboot: {order:?}; rejections {:?}",
        ready.unwrap_or_default(),
        rejections(&cluster, boot)
    );
    let early: Vec<&String> = order
        .iter()
        .zip(&containers)
        .filter(|(_, c)| !c.is_agent() && c.started < agent.started)
        .map(|(line, _)| line)
        .collect();
    assert!(
        early.is_empty(),
        "{node}: ran before the agent at +{}s: {early:?}",
        after(agent)
    );

    drop(required);
    assert_eq!(
        runtime_config(&cluster, &node),
        config,
        "{node}: the runtime config"
    );
}

/// The validator's section in the node's runtime config ([`validator::Required`]) and the suite's pods on the node,
/// until this drops.
struct Required<'a> {
    cluster: &'a Cluster,
    node: &'a str,
    /// Dropped after [`Required::drop`] deleted the pods.
    _validator: validator::Required<'a>,
}

impl<'a> Required<'a> {
    fn set(cluster: &'a Cluster, node: &'a str) -> Self {
        let required = Self {
            cluster,
            node,
            _validator: validator::Required::set(cluster, node).unwrap(),
        };

        // Both are created while the agent runs, so the gate admits them.
        let pause = pause(cluster, node);
        let overrides =
            format!(r#"{{"spec":{{"nodeName":"{node}","terminationGracePeriodSeconds":0}}}}"#);
        cluster
            .kubectl(&[
                "run",
                POD,
                "--namespace",
                "default",
                "--image",
                &pause,
                "--image-pull-policy=IfNotPresent",
                &format!("--overrides={overrides}"),
            ])
            .unwrap();
        let manifest = format!(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: {POD}\n  namespace: default\nspec:\n  containers:\n    \
             - name: pause\n      image: {pause}\n      imagePullPolicy: IfNotPresent\n  \
             terminationGracePeriodSeconds: 0\n"
        );
        cluster
            .exec(
                node,
                &[
                    "sh",
                    "-c",
                    &format!("cat >{STATIC} <<'EOF'\n{manifest}EOF\n"),
                ],
            )
            .unwrap();
        for pod in [POD.to_owned(), format!("{POD}-{node}")] {
            wait_until(&format!("{node}: {pod}"), || {
                cluster
                    .kubectl(&[
                        "wait",
                        "--namespace",
                        "default",
                        "--for=condition=Ready",
                        &format!("pod/{pod}"),
                        "--timeout=60s",
                    ])
                    .is_ok()
            });
        }
        required
    }

    /// Deletes the suite's pods.
    fn restore(&self) -> Result<(), Failure> {
        let (cluster, node) = (self.cluster, self.node);
        cluster.kubectl(&[
            "delete",
            "pod",
            "--namespace",
            "default",
            POD,
            "--now",
            "--ignore-not-found",
            "--timeout=60s",
        ])?;
        cluster.exec(node, &["rm", "-f", STATIC]).map(drop)
    }
}

impl Drop for Required<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.restore() {
            assert!(std::thread::panicking(), "{}: {e}", self.node);
            eprintln!("{}: {e}", self.node);
        }
    }
}

/// The node's runtime config: what the suite changes, with each file's SHA-256.
fn runtime_config(cluster: &Cluster, node: &str) -> String {
    let files = match cluster.runtime() {
        Runtime::Containerd => CONTAINERD,
        Runtime::Crio => "/etc/crio/crio.conf.d/*",
    };
    cluster
        .exec(node, &["sh", "-c", &format!("sha256sum {files}")])
        .unwrap()
}

/// The node's pause image, held by the runtime for its sandboxes: it runs as it is, and a pull never waits.
fn pause(cluster: &Cluster, node: &str) -> String {
    let images: Value = serde_json::from_str(
        &cluster
            .exec(node, &["crictl", "images", "-o", "json"])
            .unwrap(),
    )
    .unwrap();
    images["images"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|image| image["repoTags"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .find(|tag| tag.starts_with("registry.k8s.io/pause:"))
        .expect("the pause image")
        .to_owned()
}

/// A running container of a pod on the node, as the API server has it.
struct Container {
    /// `<namespace>/<pod>`.
    pod: String,
    name: String,
    started: Timestamp,
    ready: bool,
}

impl Container {
    fn key(&self) -> String {
        format!("{}/{}", self.pod, self.name)
    }

    fn is_agent(&self) -> bool {
        self.pod.starts_with(&format!("{NAMESPACE}/")) && self.name == "agent"
    }
}

/// The running containers of the node's pods.
fn running(cluster: &Cluster, node: &str) -> Vec<Container> {
    let field = format!("spec.nodeName={node}");
    let pods: Value = serde_json::from_str(
        &cluster
            .kubectl(&[
                "get",
                "pods",
                "--all-namespaces",
                "--field-selector",
                &field,
                "--output",
                "json",
            ])
            .unwrap(),
    )
    .unwrap();
    let mut containers = Vec::new();
    for pod in pods["items"].as_array().into_iter().flatten() {
        let name = format!(
            "{}/{}",
            pod["metadata"]["namespace"].as_str().unwrap_or_default(),
            pod["metadata"]["name"].as_str().unwrap_or_default()
        );
        for status in pod["status"]["containerStatuses"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let started = status
                .pointer("/state/running/startedAt")
                .and_then(Value::as_str)
                .and_then(|at| at.parse().ok());
            if let (Some(started), Some(container)) = (started, status["name"].as_str()) {
                containers.push(Container {
                    pod: name.clone(),
                    name: container.to_owned(),
                    started,
                    ready: status["ready"].as_bool() == Some(true),
                });
            }
        }
    }
    containers
}

/// How many times the validator refused each pod's containers since `since`, by `<namespace>/<pod>`.
fn rejections(cluster: &Cluster, since: Timestamp) -> BTreeMap<String, u64> {
    let events: Value = serde_json::from_str(
        &cluster
            .kubectl(&[
                "get",
                "events",
                "--all-namespaces",
                "--field-selector",
                "reason=Failed",
                "--output",
                "json",
            ])
            .unwrap(),
    )
    .unwrap();
    let mut rejections = BTreeMap::new();
    for event in events["items"].as_array().into_iter().flatten() {
        let recent = event["lastTimestamp"]
            .as_str()
            .and_then(|at| at.parse::<Timestamp>().ok())
            .is_some_and(|at| at >= since);
        let missing = event["message"]
            .as_str()
            .is_some_and(|message| message.contains(MISSING));
        if recent && missing {
            let pod = format!(
                "{}/{}",
                event["involvedObject"]["namespace"]
                    .as_str()
                    .unwrap_or_default(),
                event["involvedObject"]["name"].as_str().unwrap_or_default()
            );
            *rejections.entry(pod).or_default() += event["count"].as_u64().unwrap_or(1);
        }
    }
    rejections
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(90);
    while !done() {
        assert!(Instant::now() < deadline, "{what}: not after 90 s");
        std::thread::sleep(Duration::from_secs(1));
    }
}
