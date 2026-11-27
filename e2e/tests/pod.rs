//! The chart's test file (D211): the twin, on the chart's pods, of each check the suites make of the systemd unit, or
//! why it has none. These run on clusters whose agents are the chart's pods (D208), one at a time: each acts on a pod
//! the next one reads.
//!
//! | Unit check | Pod twin | Property |
//! |---|---|---|
//! | `unit.rs`: the unit is active | `the_daemonsets_are_ready_on_every_node`: each `DaemonSet`'s `numberReady` is its `desiredNumberScheduled`, together one pod per node, each `Ready` | an agent serves on every node |
//! | `unit.rs`: `Type=notify` | the same test: the startup probe asks `/livez`, the readiness probe `/readyz` | the agent counts as started once it serves |
//! | `unit.rs`: `WatchdogUSec=30s` | `a_hung_agent_is_restarted_within_40_s`: the liveness probe asks `/livez` for 30 s; after `kill -STOP`, a new container runs within 40 s | a hung agent is replaced |
//! | `unit.rs`: `Restart=on-failure` | the same test: after `kill -KILL`, the kubelet starts the agent again | a dead agent is replaced |
//! | `unit.rs`: `User=root` | `the_agent_runs_as_root_with_no_capability_nor_privilege_gain`: `Uid` 0 | the agent owns the runtime's root-owned files |
//! | `unit.rs`: `TimeoutStopUSec=20s` | `a_stopped_pod_drains_and_keeps_its_run_directory`: `terminationGracePeriodSeconds` 20, and the agent exits 0 within it | a stop never kills the agent mid-drain |
//! | `unit.rs`: `StateDirectory`, `RuntimeDirectory` | `the_agent_sees_its_root_and_every_read_only_mount_read_only`: `/var/lib/speculaire` and `/run/speculaire` are among its few writable mounts | the agent writes its state on the node |
//! | `unit.rs`: `RuntimeDirectoryMode=0700`, `RuntimeDirectoryPreserve=yes` | `a_stopped_pod_drains_and_keeps_its_run_directory`: `/run/speculaire` is 0700, and a file in it outlives the pod | the cache outlives a restart, readable by root alone |
//! | `unit.rs`: `LimitNOFILE=524288` | `the_agent_raises_its_soft_open_file_limit_to_the_hard_one` | the agent gets the open files the node allows |
//! | `unit.rs`: `ProtectHome=read-only` | `the_agent_sees_its_root_and_every_read_only_mount_read_only`: no mount under `/home` or `/root` | the agent sees no home directory |
//! | `unit.rs`: `SystemCallErrorNumber=EPERM` | none: the runtime's default seccomp profile picks the errno | — |
//! | `unit.rs`: the hardening settings, by `systemd-analyze security` | `the_agent_runs_as_root_with_no_capability_nor_privilege_gain`: no capability, `NoNewPrivs` 1, `Seccomp` 2; `the_agent_sees_its_root_and_every_read_only_mount_read_only`: `ProtectSystem=strict`'s read-only root; docs/security.md, *The chart's pod hardens less than the unit*, names the settings it lacks | the agent cannot gain privileges nor change the node's software |
//! | `unit.rs`: every scraped metric is in the catalog | the same test, which runs on both installs | — |
//! | `unit.rs`: the journal holds structured entries and nothing at warning | `the_pod_log_holds_json_entries_and_nothing_at_warning`: `status listener open` has `fields.address` `[::]:7482` and target `speculaire_agent::serve` | the agent's log is structured and quiet when healthy |
//! | `unit.rs`: `SYSLOG_IDENTIFIER=speculaire` | none: the container's log holds the agent's lines alone | — |
//! | the suites' audit events, by the identifier `speculaire-audit` | `Cluster::audit` in the same suites: the lines of target `speculaire::audit` | the audit events stand apart from the diagnostics |
//! | `unit_restart.rs`: the unit stops cleanly and keeps its run directory | `a_stopped_pod_drains_and_keeps_its_run_directory` | as above |
//! | `unit_restart.rs`: the agent raises its soft open-file limit, under a drop-in `LimitNOFILE=1024:524288` | `the_agent_raises_its_soft_open_file_limit_to_the_hard_one`, under the limits the runtime gives | as above |
//! | `unit_reload.rs`: `/readyz` answers another node and stays 200 across a reload | `a_hangup_reloads_the_agent_in_place_and_a_changed_config_by_poll`: `pkill -HUP` on the node; the same process, no restart | a reload never takes the agent down |
//! | the poll of the config (`relay.rs`, `reflector.rs`, on both installs) | the same test: a broken config counts in `speculaire_config_reload_failures_total` within a poll | the agent reads its config again by itself |
//! | `preflight.rs`: a second agent refuses to start, without the mirror's certificates, on another runtime, with NRI off, with `gate.wait` too long; every node passes `check-config` | the same tests, which run the node's binary on both installs | — |
//! | `preflight.rs`: the refusal lands in the journal (`systemd-cat`) | `a_failing_configure_holds_the_pod_in_init_error_with_its_message`: the init container fails, the agent does not start, and the init container's log and status hold the reason | a node that cannot take the agent says why |
//! | `gate.rs`: containers created while the agent stops (D39) | `a_stopped_pod_drains_and_keeps_its_run_directory`: while it stops, the mirror answers 404 and `/readyz` 503; `shutdown.drain_timeout` cuts a held transfer | the pod's stop drains as the unit's does |
//! | `gate.rs`: after a stop, the first container in a running pod passes (D180) | none: the kubelet's removal of the agent's pod is an NRI request, which clears the closed plugin (D208) | — |
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use e2e::logs::Level;
use e2e::upstream::Kind;
use e2e::{Cluster, Runtime};
use serde_json::Value;

/// The namespace `just e2e-up` installs the chart in.
const NAMESPACE: &str = "speculaire";
/// The node's config, which the chart's pods read (`config.source: host`).
const CONFIG: &str = "/etc/speculaire/config.toml";
/// The node label on which the chart's `DaemonSet`s drop the node's pod.
const OPT_OUT: &str = "speculaire.spnngl.github.io/disabled";
const MIRROR: &str = "https://127.0.0.1:7480";
const MIRROR_DIR: &str = "/var/lib/speculaire/mirror";
/// What the agent logs when `shutdown.drain_timeout` cuts transfers (D39 step 4).
const CUT: &str = "transfers still in flight at shutdown.drain_timeout are cut";

static SERIAL: Mutex<()> = Mutex::new(());

/// The cluster when its agents are the chart's pods, and the lock that runs these tests one at a time.
fn chart() -> Option<(Cluster, MutexGuard<'static, ()>)> {
    let cluster = Cluster::from_env();
    if cluster.has_unit() {
        return None;
    }
    Some((
        cluster,
        SERIAL.lock().unwrap_or_else(PoisonError::into_inner),
    ))
}

fn sh(cluster: &Cluster, node: &str, script: &str) -> String {
    cluster.exec(node, &["sh", "-c", script]).unwrap()
}

/// A node whose agent is no reflector: the tests that stop or break an agent leave the peer harness alone.
fn agent_node(cluster: &Cluster) -> String {
    let reflectors = cluster.reflectors();
    cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|node| node.name)
        .find(|name| !reflectors.contains(name))
        .expect("a node with an agent")
}

fn pid(cluster: &Cluster, node: &str) -> u32 {
    cluster
        .agent_pid(node)
        .unwrap()
        .unwrap_or_else(|| panic!("{node}: no agent runs"))
}

/// The node's agent pod that is not being deleted.
fn pod(cluster: &Cluster, node: &str) -> Value {
    current(cluster, node).unwrap_or_else(|| panic!("{node}: no agent pod"))
}

/// The node's agent pod that is not being deleted, if any.
fn current(cluster: &Cluster, node: &str) -> Option<Value> {
    let field = format!("spec.nodeName={node}");
    let pods = cluster
        .kubectl(&[
            "get",
            "pods",
            "--namespace",
            NAMESPACE,
            "--field-selector",
            &field,
            "--output",
            "json",
        ])
        .unwrap();
    let pods: Value = serde_json::from_str(&pods).unwrap();
    pods["items"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|pod| pod.pointer("/metadata/deletionTimestamp").is_none())
        .cloned()
}

/// The node's agent pod, once the kubelet counts it `Ready`.
fn ready(cluster: &Cluster, node: &str) -> Value {
    let name = format!(
        "pod/{}",
        pod(cluster, node)["metadata"]["name"].as_str().unwrap()
    );
    cluster
        .kubectl(&[
            "wait",
            "--namespace",
            NAMESPACE,
            "--for=condition=Ready",
            "--timeout=60s",
            &name,
        ])
        .unwrap();
    pod(cluster, node)
}

/// The pod's agent container, `agent` or `reflector`, in its spec.
fn container(pod: &Value) -> &Value {
    pod.pointer("/spec/containers/0")
        .unwrap_or_else(|| panic!("no container: {pod}"))
}

/// The restarts of the pod's agent container.
fn restarts(pod: &Value) -> u64 {
    pod.pointer("/status/containerStatuses/0/restartCount")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("no restart count: {pod}"))
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_daemonsets_are_ready_on_every_node() {
    let Some((cluster, _serial)) = chart() else {
        return;
    };
    let nodes = cluster.nodes().unwrap();
    // The tests before may have just replaced a pod: the kubelet sees it ready at its next readiness probe, the
    // DaemonSet controller after.
    for node in &nodes {
        ready(&cluster, &node.name);
    }
    for set in ["agent", "reflector"] {
        let set = format!("daemonset/speculaire-{set}");
        cluster
            .kubectl(&[
                "rollout",
                "status",
                "--namespace",
                NAMESPACE,
                "--timeout=60s",
                &set,
            ])
            .unwrap();
    }
    let sets = cluster
        .kubectl(&[
            "get",
            "daemonsets",
            "--namespace",
            NAMESPACE,
            "--output",
            "json",
        ])
        .unwrap();
    let sets: Value = serde_json::from_str(&sets).unwrap();
    let mut scheduled = 0;
    for set in sets["items"].as_array().unwrap() {
        let status = &set["status"];
        let desired = status["desiredNumberScheduled"].as_u64().unwrap();
        assert_eq!(
            status["numberReady"].as_u64(),
            Some(desired),
            "{}: {status}",
            set["metadata"]["name"]
        );
        scheduled += desired;
    }
    assert_eq!(
        usize::try_from(scheduled).unwrap(),
        nodes.len(),
        "one agent per node"
    );
    for node in &nodes {
        let pod = pod(&cluster, &node.name);
        let ready = pod["status"]["conditions"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|c| c["type"] == "Ready" && c["status"] == "True");
        assert!(ready, "{}: {}", node.name, pod["status"]);
        let container = container(&pod);
        assert_eq!(
            (
                &container["startupProbe"]["httpGet"]["path"],
                &container["readinessProbe"]["httpGet"]["path"]
            ),
            (&Value::from("/livez"), &Value::from("/readyz")),
            "{}",
            node.name
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_agent_runs_as_root_with_no_capability_nor_privilege_gain() {
    const NONE: &str = "0000000000000000";
    let Some((cluster, _serial)) = chart() else {
        return;
    };
    let expected = [
        ("Uid", "0\t0\t0\t0"),
        ("Gid", "0\t0\t0\t0"),
        ("CapPrm", NONE),
        ("CapEff", NONE),
        ("CapBnd", NONE),
        ("CapAmb", NONE),
        ("NoNewPrivs", "1"),
        // SECCOMP_MODE_FILTER.
        ("Seccomp", "2"),
    ];
    let mut wrong = Vec::new();
    for node in cluster.nodes().unwrap() {
        let pid = pid(&cluster, &node.name);
        let status = sh(&cluster, &node.name, &format!("cat /proc/{pid}/status"));
        for (name, value) in expected {
            let found = status
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix(':'))
                .map(str::trim);
            if found != Some(value) {
                wrong.push(format!("{}: {name}: {found:?}, not {value:?}", node.name));
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// `ProtectSystem=strict` and `ProtectHome=read-only`: the agent's root is read-only, and so is each mount the pod
/// spec makes read-only, with the node's mounts below it; it writes only where the pod spec lets it.
#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_agent_sees_its_root_and_every_read_only_mount_read_only() {
    let Some((cluster, _serial)) = chart() else {
        return;
    };
    let mut wrong = Vec::new();
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let pod = pod(&cluster, &node);
        let mounts = container(&pod)["volumeMounts"].as_array().unwrap();
        let path = |mount: &Value| mount["mountPath"].as_str().unwrap().to_owned();
        let read_only: Vec<String> = mounts
            .iter()
            .filter(|m| m["readOnly"] == true)
            .map(path)
            .collect();
        let writable: BTreeSet<String> = mounts
            .iter()
            .filter(|m| m["readOnly"] != true)
            .map(path)
            .collect();
        for state in ["/var/lib/speculaire", "/run/speculaire"] {
            if !writable.contains(state) {
                wrong.push(format!("{node}: {state} is not a writable mount"));
            }
        }
        let pid = pid(&cluster, &node);
        // Each line: ID, parent, device, root, mount point, mount options, ... (proc(5)).
        let info = sh(&cluster, &node, &format!("cat /proc/{pid}/mountinfo"));
        let found: Vec<(&str, bool)> = info
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(' ').skip(4);
                let point = fields.next()?;
                let ro = fields.next()?.split(',').any(|o| o == "ro");
                Some((point, ro))
            })
            .collect();
        for (point, ro) in &found {
            let under = |dir: &str| *point == dir || point.starts_with(&format!("{dir}/"));
            // A node directory mounted read-only, or below one, other than the writable mounts the spec nests in one.
            let in_read_only = (*point == "/" || read_only.iter().any(|dir| under(dir)))
                && !writable.iter().any(|dir| under(dir));
            if in_read_only && !ro {
                wrong.push(format!("{node}: {point} is writable"));
            }
            if under("/home") || under("/root") {
                wrong.push(format!("{node}: {point} is mounted"));
            }
        }
        for dir in &read_only {
            if !found.iter().any(|(point, _)| *point == dir.as_str()) {
                wrong.push(format!("{node}: {dir} is not mounted"));
            }
        }
        let touch = format!("/proc/{pid}/root/usr/speculaire-e2e");
        let out = cluster.exec_output(&node, &["touch", &touch]).unwrap();
        if out.success || !out.stderr.contains("Read-only file system") {
            wrong.push(format!("{node}: touch {touch}: {out:?}"));
            sh(&cluster, &node, &format!("rm -f {touch}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_agent_raises_its_soft_open_file_limit_to_the_hard_one() {
    let Some((cluster, _serial)) = chart() else {
        return;
    };
    for node in cluster.nodes().unwrap() {
        let pid = pid(&cluster, &node.name);
        let limits = sh(&cluster, &node.name, &format!("cat /proc/{pid}/limits"));
        let line = limits
            .lines()
            .find_map(|l| l.strip_prefix("Max open files"))
            .unwrap_or_else(|| panic!("{}: {limits}", node.name));
        let [soft, hard, ..] = line.split_whitespace().collect::<Vec<_>>()[..] else {
            panic!("{}: {line}", node.name)
        };
        assert_eq!(soft, hard, "{}: {line}", node.name);
    }
}

/// `WatchdogSec=30s` and `Restart=on-failure`: the liveness probe stands in for the watchdog (D69), the kubelet for
/// systemd's restart.
#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_hung_agent_is_restarted_within_40_s() {
    let Some((cluster, _serial)) = chart() else {
        return;
    };
    let node = agent_node(&cluster);
    // A new pod: the kubelet backs off the restarts of a container that ended before. Ready, its startup probe has
    // passed, and the liveness probe runs.
    cluster.reset_agent(&node).unwrap();
    let pod = ready(&cluster, &node);
    let probe = &container(&pod)["livenessProbe"];
    assert_eq!(probe["httpGet"]["path"], "/livez", "{probe}");
    let watchdog =
        probe["periodSeconds"].as_u64().unwrap() * probe["failureThreshold"].as_u64().unwrap();
    assert_eq!(watchdog, 30, "{probe}");
    assert_eq!(pod["spec"]["restartPolicy"], "Always");

    let hung = pid(&cluster, &node);
    let began = Instant::now();
    sh(&cluster, &node, &format!("kill -STOP {hung}"));
    let unhung = replaced(&cluster, &node, hung);
    let restarted = began.elapsed();
    eprintln!("{node}: the hung agent ran again after {restarted:?}");

    let dead = pid(&cluster, &node);
    cluster.kill_agent(&node).unwrap();
    let killed = replaced(&cluster, &node, dead);
    cluster.reset_agent(&node).unwrap();
    assert!(
        unhung && restarted < Duration::from_secs(40),
        "{node}: the hung agent ran again after {restarted:?}"
    );
    assert!(killed, "{node}: the killed agent did not run again");
}

/// Whether a process other than `old` runs the node's agent within 60 s.
fn replaced(cluster: &Cluster, node: &str, old: u32) -> bool {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if cluster
            .agent_pid(node)
            .unwrap()
            .is_some_and(|pid| pid != old)
        {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// `TimeoutStopSec=20s`, `RuntimeDirectoryMode=0700` and `RuntimeDirectoryPreserve=yes`, and the stop of D39: the
/// node's opt-out label deletes the pod, as `unit_restart.rs` stops the unit, with a mirror transfer in flight.
#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_stopped_pod_drains_and_keeps_its_run_directory() {
    let Some((cluster, _serial)) = chart() else {
        return;
    };
    let node = agent_node(&cluster);
    let pod = pod(&cluster, &node);
    assert_eq!(pod["spec"]["terminationGracePeriodSeconds"], 20);
    let mode = || {
        sh(&cluster, &node, "stat -c %a /run/speculaire")
            .trim()
            .to_owned()
    };
    assert_eq!(mode(), "700");
    let marker = "/run/speculaire/e2e-marker";
    sh(&cluster, &node, &format!("echo kept > {marker}"));

    // At 1 MiB/s, a 32 MiB layer outlasts `shutdown.drain_timeout`. Pulled first, the node holds the layer, which the
    // mirror then serves on either runtime; containerd names the registry in `ns`, CRI-O first in the path (D66).
    let upstream = cluster.upstream(Kind::Plain);
    let repository = "speculaire-e2e-pod-drain";
    let image = upstream.push(repository, 32 << 20).unwrap();
    let layer = image.blobs.last().unwrap();
    let host = upstream.address();
    let path = match cluster.runtime() {
        Runtime::Containerd => format!("/v2/{repository}/blobs/{layer}?ns={host}"),
        Runtime::Crio => format!("/v2/{host}/{repository}/blobs/{layer}"),
    };
    let curl = format!("curl -s --cacert {MIRROR_DIR}/ca.crt --cert {MIRROR_DIR}/client.pem");
    let held = "/tmp/speculaire-e2e-pod-drain";
    let reference = &image.reference;
    sh(
        &cluster,
        &node,
        &format!(
            "crictl pull {reference} >/dev/null && rm -f {held}
             nohup {curl} --limit-rate 1M -o {held} '{MIRROR}{path}' >/dev/null 2>&1 &
             for _ in $(seq 100); do [ -s {held} ] && exit 0; sleep 0.1; done; exit 1"
        ),
    );
    // The mirror's and `/readyz`'s answers while the agent stops.
    let answers = format!(
        "echo $({curl} -o /dev/null -w '%{{http_code}}' {MIRROR}/v2/) \
              $(curl -s -o /dev/null -w '%{{http_code}}' http://127.0.0.1:7482/readyz)"
    );
    let began = Instant::now();
    let (stop, seen) = std::thread::scope(|scope| {
        let stop = scope.spawn(|| cluster.stop_agent(&node));
        let mut seen = BTreeSet::new();
        while !stop.is_finished() {
            seen.insert(sh(&cluster, &node, &answers).trim().to_owned());
        }
        (stop.join().unwrap(), seen)
    });
    let stopped = began.elapsed();
    stop.unwrap();
    let exited = cluster.wait_stopped(&node);
    let cut = cluster
        .agent_logs(&node, None)
        .unwrap()
        .iter()
        .any(|e| e.message == CUT);
    let kept = sh(&cluster, &node, &format!("cat {marker}"));
    cluster.reset_agent(&node).unwrap();
    let restarted = (mode(), sh(&cluster, &node, &format!("cat {marker}")));
    sh(
        &cluster,
        &node,
        &format!("rm -f {marker} {held}; crictl rmi {reference} >/dev/null"),
    );

    exited.unwrap();
    assert!(seen.contains("404 503"), "while stopping: {seen:?}");
    assert!(cut, "{node}: no transfer held the agent");
    assert!(
        stopped < Duration::from_secs(20),
        "{node}: stopped in {stopped:?}"
    );
    assert_eq!(kept.trim(), "kept", "after the stop");
    assert_eq!(
        (restarted.0.as_str(), restarted.1.trim()),
        ("700", "kept"),
        "after the restart"
    );
}

/// The unit's reload's twin is `SIGHUP` from the node, as an admin without the unit sends it.
#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_hangup_reloads_the_agent_in_place_and_a_changed_config_by_poll() {
    let Some((cluster, _serial)) = chart() else {
        return;
    };
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
        let node_name = &node.name;
        assert_eq!(
            readyz(from, &node.address),
            "200",
            "{node_name} from {from}"
        );
        let before = (
            pid(&cluster, node_name),
            restarts(&pod(&cluster, node_name)),
        );
        sh(&cluster, node_name, "pkill -HUP -x speculaire");
        assert_eq!(
            readyz(from, &node.address),
            "200",
            "{node_name} after SIGHUP"
        );
        let after = (
            pid(&cluster, node_name),
            restarts(&pod(&cluster, node_name)),
        );
        assert_eq!(
            after, before,
            "{node_name}: the agent and its restarts after SIGHUP"
        );
    }

    // A config the agent refuses: it keeps the one it has, and counts the refusal.
    let node = agent_node(&cluster);
    let failures = || {
        cluster
            .metrics(&node)
            .unwrap()
            .get("speculaire_config_reload_failures_total")
            .unwrap_or_default()
    };
    let before = (pid(&cluster, &node), failures());
    sh(
        &cluster,
        &node,
        &format!("cp {CONFIG} {CONFIG}.e2e && echo 'not = [toml' >>{CONFIG}"),
    );
    // `config.poll_interval`, 10 s by default, and some.
    let deadline = Instant::now() + Duration::from_secs(15);
    while failures() <= before.1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(500));
    }
    let after = (pid(&cluster, &node), failures());
    sh(&cluster, &node, &format!("mv {CONFIG}.e2e {CONFIG}"));
    // The refusal's warning.
    cluster.reset_agent(&node).unwrap();
    assert_eq!(after.0, before.0, "{node}: the agent after the poll");
    assert!(after.1 > before.1, "{node}: no reload failed: {after:?}");
}

/// The twin of `preflight.rs`'s refusal in the journal: the init container runs `speculaire configure`, whose failure
/// keeps the agent from starting and lands in the init container's log, which its status quotes.
#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_failing_configure_holds_the_pod_in_init_error_with_its_message() {
    let Some((cluster, _serial)) = chart() else {
        return;
    };
    let node = agent_node(&cluster);
    cluster.stop_agent(&node).unwrap();
    // Sockets that nothing listens on stand for the runtime: detection names both.
    sh(
        &cluster,
        &node,
        &format!(
            "cp {CONFIG} {CONFIG}.e2e && printf '[runtime]\\ncontainerd_socket = \"/nonexistent/containerd.sock\"\\n\
             crio_socket = \"/nonexistent/crio.sock\"\\n' >{CONFIG}"
        ),
    );
    cluster
        .kubectl(&["label", "node", &node, &format!("{OPT_OUT}-")])
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let (pod, terminated) = loop {
        let pod = current(&cluster, &node).unwrap_or_default();
        let init = pod.pointer("/status/initContainerStatuses/0");
        let terminated = init
            .and_then(|s| {
                s.pointer("/state/terminated")
                    .or_else(|| s.pointer("/lastState/terminated"))
            })
            .cloned();
        if let Some(terminated) = terminated {
            break (pod, terminated);
        }
        assert!(
            Instant::now() < deadline,
            "{node}: configure did not end: {pod}"
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    let name = pod["metadata"]["name"].as_str().unwrap().to_owned();
    let logs = |previous: bool| {
        let mut args = vec![
            "logs",
            "--namespace",
            NAMESPACE,
            name.as_str(),
            "--container",
            "configure",
        ];
        if previous {
            args.push("--previous");
        }
        cluster.kubectl(&args).unwrap_or_default()
    };
    let named = |text: &str| {
        text.contains("/nonexistent/containerd.sock") && text.contains("/nonexistent/crio.sock")
    };
    let logged = named(&logs(false)) || named(&logs(true));
    let waiting = pod
        .pointer("/status/containerStatuses/0/state/waiting/reason")
        .cloned();
    sh(&cluster, &node, &format!("mv {CONFIG}.e2e {CONFIG}"));
    cluster.start_agent(&node).unwrap();

    assert_ne!(terminated["exitCode"], 0, "{terminated}");
    assert_eq!(terminated["reason"], "Error", "{terminated}");
    assert!(
        named(terminated["message"].as_str().unwrap_or_default()),
        "the status: {terminated}"
    );
    assert!(logged, "the log of {name}'s configure");
    assert_eq!(
        waiting,
        Some(Value::from("PodInitializing")),
        "the agent of {name}"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_pod_log_holds_json_entries_and_nothing_at_warning() {
    let Some((cluster, _serial)) = chart() else {
        return;
    };
    // containerd 2.3's NRI names no image: the gate warns of the identity gap at each registration (D15, D170).
    let gap = cluster.runtime() == Runtime::Containerd && cluster.release().starts_with("2.3.");
    for node in cluster.nodes().unwrap() {
        let node = node.name;
        let entries = cluster.agent_logs(&node, None).unwrap();
        let warnings: Vec<String> = entries
            .iter()
            .filter(|e| e.level >= Some(Level::Warn))
            .filter(|e| !(gap && e.message.ends_with("(identity gap, D15)")))
            .map(ToString::to_string)
            .collect();
        assert!(warnings.is_empty(), "{node}:\n{}", warnings.join("\n"));
        let opened = entries
            .iter()
            .find(|e| e.message == "status listener open")
            .unwrap_or_else(|| panic!("{node}: no `status listener open` entry"));
        assert_eq!(
            (opened.field("address"), opened.target.as_deref()),
            (Some("[::]:7482"), Some("speculaire_agent::serve")),
            "{node}: {opened}"
        );
    }
}
