//! The chart's release with `config.source: configMap` (D210): an edit of the policy in the `ConfigMap` reaches the
//! agents without a restart, and a restart key's change (D47) waits for `kubectl rollout restart`.
//!
//! A test binary of its own, in `DaemonSet` mode only: it switches the release, which no other suite may see.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use e2e::Cluster;
use e2e::daemonset::{NAMESPACE, RELEASE};
use e2e::logs::tail;
use e2e::node::TRUSTED_ROOT;
use e2e::upstream::{FIXTURES, Kind, RUNNABLE, runnable_policy};

/// The longest an edit of `policy.yaml` may take to start the pod it refused (D210): the kubelet's sync of the agent's
/// pod, every `SyncFrequency` (1 min) plus up to half of it, `config.poll_interval` (10 s), and two of the kubelet's
/// retries of the pod's container, every 10 s plus up to half of it, the first of which may find the image's verdict
/// pending under the new policy.
const BOUND: Duration = Duration::from_secs(150);
/// The suite's pod, refused, then started by the edit.
const POD: &str = "speculaire-e2e-configmap";
/// The directory of the `verify.cache` the restart key case sets, which the agent makes at start.
const CACHE_DIR: &str = "/run/speculaire/e2e";
/// The agent's warning that a reload left a restart key at its running value.
const KEPT: &str = "config reload: this key changes only on restart";

/// The release switched to `config.source: configMap`, until dropped: then the suite's pod goes, the release rolls back
/// to the revision it had, and the nodes lose [`CACHE_DIR`].
struct Switched<'a> {
    cluster: &'a Cluster,
    revision: u64,
    files: tempfile::TempDir,
}

impl<'a> Switched<'a> {
    /// Upgrades the release to read `toml`, `policy` and the nodes' trusted root from its `ConfigMap`.
    fn on(cluster: &'a Cluster, toml: &str, policy: &str, root: &str) -> Self {
        let status = cluster.helm(&["status", RELEASE, "-o", "json"]).unwrap();
        let status: serde_json::Value = serde_json::from_str(&status).unwrap();
        let revision = status["version"].as_u64().expect("a revision");
        let switched = Self {
            cluster,
            revision,
            files: tempfile::tempdir().unwrap(),
        };
        switched.upgrade(toml, policy, Some(root));
        switched
    }

    /// Upgrades the release to `toml` and `policy`, and `root` when given, keeping its other values, and waits until its
    /// pods are ready.
    fn upgrade(&self, toml: &str, policy: &str, root: Option<&str>) {
        let chart = std::env::var("SPECULAIRE_E2E_CHART").expect(
            "SPECULAIRE_E2E_CHART is unset: run the suites with just e2e <runtime> <version>",
        );
        let mut args: Vec<String> = [
            "upgrade",
            RELEASE,
            &chart,
            "--reuse-values",
            // The fields `kubectl patch` took.
            "--force-conflicts",
            "--wait",
            "--timeout",
            "5m",
            "--set",
            "config.source=configMap",
        ]
        .map(str::to_owned)
        .into();
        let values = [
            ("config.toml", Some(toml)),
            ("config.policy", Some(policy)),
            ("config.trustedRoot", root),
        ];
        // A file each: `--set` splits a value at its commas.
        for (key, value) in values {
            if let Some(value) = value {
                let path = self.file(key, value);
                args.extend(["--set-file".to_owned(), format!("{key}={}", path.display())]);
            }
        }
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        self.cluster.helm(&args).unwrap();
    }

    /// Writes `text` to the file `name` of the switch's directory, and returns its path.
    fn file(&self, name: &str, text: &str) -> PathBuf {
        let path = self.files.path().join(name);
        std::fs::write(&path, text).unwrap();
        path
    }
}

impl Drop for Switched<'_> {
    fn drop(&mut self) {
        let cluster = self.cluster;
        let _ = cluster.kubectl(&["delete", "pod", POD, "--now", "--timeout=60s"]);
        let revision = self.revision.to_string();
        let rollback = [
            "rollback",
            RELEASE,
            &revision,
            "--force-conflicts",
            "--wait",
            "--timeout",
            "5m",
        ];
        cluster.helm(&rollback).unwrap();
        for node in cluster.nodes().unwrap() {
            cluster.exec(&node.name, &["rm", "-rf", CACHE_DIR]).unwrap();
        }
    }
}

/// Each of the chart's pods: its name, its UID and its container's restart count, a line each, sorted.
fn pods(cluster: &Cluster) -> Vec<String> {
    let pods = cluster
        .kubectl(&[
            "get",
            "pods",
            "--namespace",
            NAMESPACE,
            "-o",
            r#"jsonpath={range .items[*]}{.metadata.name} {.metadata.uid} {.status.containerStatuses[*].restartCount}{"\n"}{end}"#,
        ])
        .unwrap();
    let mut pods: Vec<String> = pods.lines().map(str::to_owned).collect();
    pods.sort();
    pods
}

/// Whether [`CACHE_DIR`] is on `node`.
fn cache_dir(cluster: &Cluster, node: &str) -> bool {
    cluster
        .exec_output(node, &["test", "-d", CACHE_DIR])
        .unwrap()
        .success
}

/// Replaces the one `from` in `text` with `to`.
fn edit(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from:?} in {text}");
    text.replacen(from, to, 1)
}

/// Waits until the agent on `node` warns, since `since`, that a reload kept the running `key`.
fn warned(cluster: &Cluster, node: &str, since: SystemTime, key: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let logs = cluster.agent_logs(node, Some(since)).unwrap();
        if logs
            .iter()
            .any(|entry| entry.message.starts_with(KEPT) && entry.field("key") == Some(key))
        {
            return;
        }
        assert!(Instant::now() < deadline, "{node}: {}", tail(&logs, 30));
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Runs a pod of `image` on `node`, sees the gate refuse it, then has `kubectl` edit `policy.yaml` alone to `allowing`:
/// the same pod starts within [`BOUND`], and no chart pod restarts.
fn policy_edit_starts_the_pod(cluster: &Cluster, node: &str, image: &str, allowing: &str) {
    let overrides =
        format!(r#"{{"spec":{{"nodeName":"{node}","terminationGracePeriodSeconds":0}}}}"#);
    let overrides = format!("--overrides={overrides}");
    let run = [
        "run",
        POD,
        "--image",
        image,
        "--image-pull-policy=IfNotPresent",
        "--restart=Never",
        &overrides,
        "--command",
        "--",
        "sleep",
        "3600",
    ];
    cluster.kubectl(&run).unwrap();
    cluster.refused("default", POD, "rejected: ").unwrap();

    let before = pods(cluster);
    let patch = serde_json::json!({ "data": { "policy.yaml": allowing } }).to_string();
    let edited = Instant::now();
    let namespace = ["--namespace", NAMESPACE];
    cluster
        .kubectl(
            &[
                &[
                    "patch",
                    "configmap",
                    RELEASE,
                    "--type",
                    "merge",
                    "--patch",
                    &patch,
                ],
                namespace.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
    let pod = format!("pod/{POD}");
    cluster
        .kubectl(&["wait", "--for=condition=Ready", &pod, "--timeout=180s"])
        .unwrap();
    let took = edited.elapsed();
    eprintln!("{node}: the policy edit started the refused pod in {took:?}");
    assert!(took <= BOUND, "{took:?}");
    assert_eq!(pods(cluster), before);
}

/// Upgrades the release to set `verify.cache` in [`CACHE_DIR`]: no pod rolls, and the agent on `node` warns and keeps
/// the running value, until `kubectl rollout restart` makes it the new one.
fn restart_key_waits_for_a_rollout(switched: &Switched<'_>, node: &str, toml: &str, policy: &str) {
    let cluster = switched.cluster;
    let before = pods(cluster);
    let since = cluster.clock(node).unwrap();
    let cache = format!("cache = \"{CACHE_DIR}/cache.bin\"");
    let toml = edit(toml, "#cache = \"/run/speculaire/cache.bin\"", &cache);
    switched.upgrade(&toml, policy, None);
    assert_eq!(pods(cluster), before);
    // A change of the pod has the kubelet sync its volumes now, not at its next resync (D210).
    let stamp = since
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let annotation = format!("speculaire.e2e/synced={stamp}");
    let namespace = ["--namespace", NAMESPACE];
    cluster
        .kubectl(
            &[
                &["annotate", "pods", "--all", "--overwrite", &annotation],
                namespace.as_slice(),
            ]
            .concat(),
        )
        .unwrap();
    warned(cluster, node, since, "verify.cache");
    assert_eq!(pods(cluster), before);
    assert!(!cache_dir(cluster, node));

    let daemonset = format!("daemonset/{RELEASE}-agent");
    let restart = ["rollout", "restart", &daemonset];
    let status = ["rollout", "status", &daemonset, "--timeout=180s"];
    for action in [restart.as_slice(), status.as_slice()] {
        cluster
            .kubectl(&[action, namespace.as_slice()].concat())
            .unwrap();
    }
    assert!(cache_dir(cluster, node));
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_agents_take_a_policy_edit_live_and_a_restart_key_at_a_rollout_restart() {
    let cluster = Cluster::from_env();
    if cluster.has_unit() {
        return;
    }
    let reflectors = cluster.reflectors();
    let node = cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|node| node.name)
        .find(|name| !reflectors.contains(name))
        .expect("a node of the agents' DaemonSet");
    // The node's config, enforcing with the chart's namespace and `kube-system` exempt, and the trusted root it pins.
    let toml = cluster
        .exec(&node, &["cat", "/etc/speculaire/config.toml"])
        .unwrap();
    let toml = edit(&toml, "#mode = \"audit\"", "mode = \"enforce\"");
    let namespaces = format!("namespaces = [\"kube-system\", \"{NAMESPACE}\"]");
    let toml = edit(&toml, "#namespaces = []", &namespaces);
    let root = cluster.exec(&node, &["cat", TRUSTED_ROOT]).unwrap();
    // The runnable image's policy, but for another signer under another name, so no verdict of another suite is its.
    let host = cluster.upstream(Kind::Referrers).address().to_owned();
    let allowing = runnable_policy(&host);
    let refusing = edit(
        &allowing,
        &format!("name: {RUNNABLE}"),
        "name: another-signer",
    );
    let refusing = edit(&refusing, "subject: ", "subject: https://e2e.invalid/");

    let switched = Switched::on(&cluster, &toml, &refusing, &root);
    let image = format!("{host}/{FIXTURES}:{RUNNABLE}");
    policy_edit_starts_the_pod(&cluster, &node, &image, &allowing);
    restart_key_waits_for_a_rollout(&switched, &node, &toml, &allowing);
}
