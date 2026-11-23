//! `docs/operations.md` followed as written on the control-plane node, from a fresh install: § Install, § Before turning
//! on `enforce`, then § Break glass steps 1 to 3, each checked for the result the document states.
//!
//! The control-plane node holds the static pods that the toleration annotation is for. Copying the binary and the unit
//! back stands for installing the package, which is not built yet; the agent's config stays, as the package's would.
//! The node is put back as `just e2e-up` left it, even when a step fails. On the IPv4 pass only: nothing in it depends
//! on the family.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use e2e::{Cluster, IpFamily, Runtime};

const CONFIG: &str = "/etc/speculaire/config.toml";
/// containerd's config, to which the suite adds the validator section.
const CONTAINERD: &str = "/etc/containerd/config.toml";
/// The CRI-O drop-in that holds the suite's validator section.
const CRIO_VALIDATOR: &str = "/etc/crio/crio.conf.d/90-validator.conf";
/// The static pod that the suite gives the toleration annotation.
const SCHEDULER: &str = "/etc/kubernetes/manifests/kube-scheduler.yaml";
/// The toleration annotation the suite picks (§ Before turning on `enforce` step 3).
const TOLERATE: &str = "speculaire.e2e/tolerate-missing-plugins";
/// Where the suite keeps the package's files while they are away, and the originals of the files it edits.
const KEPT: &str = "/root/speculaire-e2e-operations";
/// The label of the suite's pods.
const LABEL: &str = "speculaire-e2e=operations";
/// The validator's message for a container created while the agent is not registered.
const MISSING: &str = r#"required plugin "speculaire" not present"#;

/// The control-plane node and the image of the suite's pods.
struct Node {
    cluster: Cluster,
    name: String,
    /// The node's pause image, held by the runtime for its sandboxes: it runs as it is, and a pull never waits.
    pause: String,
}

impl Node {
    /// Runs `script` on the node and returns its output.
    fn sh(&self, script: &str) -> String {
        self.cluster
            .exec(&self.name, &["sh", "-c", script])
            .unwrap()
    }

    /// Appends `text` to the node's file `path`.
    fn append(&self, path: &str, text: &str) {
        self.sh(&format!(
            "cat >>{path} <<'SPECULAIRE_E2E_EOF'\n{text}SPECULAIRE_E2E_EOF\n"
        ));
    }

    /// The SHA-256 of each file under `dirs`, one per line.
    fn files(&self, dirs: &str) -> String {
        self.sh(&format!(
            "find {dirs} -type f 2>/dev/null | sort | xargs -r sha256sum"
        ))
    }

    /// The directories of the runtime's config.
    fn runtime_config(&self) -> &'static str {
        match self.cluster.runtime() {
            Runtime::Containerd => "/etc/containerd",
            Runtime::Crio => "/etc/crio /etc/containers",
        }
    }

    /// Edits the agent's config with the `sed` script `edit`, checks that `line` is in it, and reloads the agent.
    fn reload(&self, edit: &str, line: &str) {
        self.sh(&format!(
            "sed -i -e '{edit}' {CONFIG} && grep -q '^{line}$' {CONFIG}"
        ));
        self.cluster.reload_agent(&self.name).unwrap();
    }

    /// Creates `pod` of the pause image in `namespace` on the node, labelled [`LABEL`].
    fn start(&self, namespace: &str, pod: &str) {
        let overrides = format!(
            r#"{{"spec":{{"nodeName":"{}","terminationGracePeriodSeconds":0}}}}"#,
            self.name
        );
        self.cluster
            .kubectl(&[
                "run",
                pod,
                "-n",
                namespace,
                "--labels",
                LABEL,
                "--image",
                &self.pause,
                "--image-pull-policy=IfNotPresent",
                "--restart=Never",
                &format!("--overrides={overrides}"),
            ])
            .unwrap();
    }

    /// Waits until `pod` is ready.
    fn ready(&self, namespace: &str, pod: &str) {
        self.cluster
            .kubectl(&[
                "wait",
                "-n",
                namespace,
                "--for=condition=Ready",
                &format!("pod/{pod}"),
                "--timeout=90s",
            ])
            .unwrap();
    }

    /// The IDs of the node's running containers.
    fn running(&self) -> BTreeSet<String> {
        self.sh("crictl ps -q --state running")
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// Waits until kube-scheduler runs in a pod that carries [`TOLERATE`] or not, as `annotated` says, in a container
    /// other than `other`, and returns that container's ID.
    fn scheduler(&self, annotated: bool, other: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let pods: serde_json::Value = serde_json::from_str(
                &self.sh("crictl pods --name kube-scheduler --state ready -o json"),
            )
            .unwrap();
            let found = pods["items"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|pod| (pod["annotations"][TOLERATE] == "true") == annotated)
                .filter_map(|pod| pod["id"].as_str())
                .flat_map(|pod| {
                    self.sh(&format!(
                        "crictl ps -q --name kube-scheduler --state running --pod {pod}"
                    ))
                    .lines()
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
                })
                .find(|id| id != other);
            if let Some(id) = found {
                return id;
            }
            assert!(
                Instant::now() < deadline,
                "{}: kube-scheduler does not run, annotated {annotated}",
                self.name
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// The file that holds the runtime's validator section.
    fn validator(&self) -> &'static str {
        match self.cluster.runtime() {
            Runtime::Containerd => CONTAINERD,
            Runtime::Crio => CRIO_VALIDATOR,
        }
    }

    /// Restarts the runtime while the agent is stopped, and waits until it answers.
    fn restart_runtime(&self) {
        self.sh(&format!(
            "systemctl restart {}",
            self.cluster.runtime().unit()
        ));
        self.cluster.wait_runtime(&self.name).unwrap();
    }
}

/// Puts the node back as `just e2e-up` left it once dropped: the package's files, the agent's state and config, the
/// runtime's config and the static pod's manifest, with the agent configured and running.
struct Restore<'a>(&'a Node);

impl<'a> Restore<'a> {
    fn keep(node: &'a Node) -> Self {
        let runtime = match node.cluster.runtime() {
            Runtime::Containerd => format!(" && cp {CONTAINERD} {KEPT}/containerd.toml"),
            Runtime::Crio => String::new(),
        };
        node.sh(&format!(
            "mkdir -p {KEPT}/package && cp {SCHEDULER} {KEPT}/kube-scheduler.yaml && \
             cp {CONFIG} {KEPT}/speculaire.toml{runtime}"
        ));
        Self(node)
    }
}

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let node = self.0;
        let _ =
            node.cluster
                .kubectl(&["delete", "pod", "-A", "-l", LABEL, "--now", "--timeout=60s"]);
        let runtime = match node.cluster.runtime() {
            Runtime::Containerd => format!("cp {KEPT}/containerd.toml {CONTAINERD}"),
            Runtime::Crio => format!("rm -f {CRIO_VALIDATOR}"),
        };
        let script = format!(
            "systemctl stop speculaire; cp {KEPT}/kube-scheduler.yaml {SCHEDULER}; {runtime}; \
             test -f {KEPT}/package/speculaire && install -m 0755 {KEPT}/package/speculaire /usr/bin/speculaire; \
             test -f {KEPT}/package/speculaire.service && \
             install -m 0644 {KEPT}/package/speculaire.service /usr/lib/systemd/system/speculaire.service; \
             test -d {KEPT}/lib && rm -rf /var/lib/speculaire && mv {KEPT}/lib /var/lib/speculaire; \
             test -d {KEPT}/run && rm -rf /run/speculaire && mv {KEPT}/run /run/speculaire; \
             cp {KEPT}/speculaire.toml {CONFIG}; systemctl daemon-reload; systemctl restart {unit}",
            unit = node.cluster.runtime().unit()
        );
        let _ = node.cluster.scrape(&node.name);
        let _ = node.cluster.exec_output(&node.name, &["sh", "-c", &script]);
        node.cluster.wait_runtime(&node.name).unwrap();
        node.sh(&format!(
            "speculaire configure >/dev/null && systemctl reset-failed speculaire; \
             systemctl enable --now speculaire && rm -rf {KEPT}"
        ));
        node.cluster.wait_ready(&node.name).unwrap();
        node.scheduler(false, "");
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_operations_guide_from_install_to_break_glass_gives_each_stated_result() {
    let cluster = Cluster::from_env();
    if !cluster.has_unit() {
        return;
    }
    if cluster.ip_family() == IpFamily::Dual {
        return;
    }
    let name = cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .find(|name| name.ends_with("-control-plane"))
        .expect("a control-plane node");
    let images: serde_json::Value = serde_json::from_str(
        &cluster
            .exec(&name, &["crictl", "images", "-o", "json"])
            .unwrap(),
    )
    .unwrap();
    let pause = images["images"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|image| image["repoTags"].as_array().into_iter().flatten())
        .filter_map(serde_json::Value::as_str)
        .find(|tag| tag.starts_with("registry.k8s.io/pause:"))
        .expect("the pause image")
        .to_owned();
    let node = Node {
        cluster,
        name,
        pause,
    };
    let start = Instant::now();
    let lap = |what: &str| eprintln!("{}: {:?} {what}", node.name, start.elapsed());
    let restore = Restore::keep(&node);

    install(&node);
    lap("§ Install");
    before_enforce(&node);
    lap("§ Before turning on enforce");
    break_glass(&node);
    lap("§ Break glass");
    drop(restore);
    lap("restored");
}

/// § Install, from a node where the package is not installed nor `configure` run.
fn install(node: &Node) {
    // The agent's state is kept for the later suites; its config stays, as the package's would.
    node.cluster.scrape(&node.name).unwrap();
    node.sh(&format!(
        "systemctl disable --now speculaire && speculaire unconfigure >/dev/null && \
         mv /usr/bin/speculaire /usr/lib/systemd/system/speculaire.service {KEPT}/package/ && \
         mv /var/lib/speculaire {KEPT}/lib && {{ test ! -e /run/speculaire || mv /run/speculaire {KEPT}/run; }} && systemctl daemon-reload"
    ));

    // Step 1: the package does not touch the runtime's config.
    let untouched = node.files(node.runtime_config());
    node.sh(&format!(
        "install -m 0755 {KEPT}/package/speculaire /usr/bin/speculaire && \
         install -m 0644 {KEPT}/package/speculaire.service /usr/lib/systemd/system/speculaire.service && \
         systemctl daemon-reload"
    ));
    assert_eq!(node.files(node.runtime_config()), untouched, "step 1");

    // Step 2: `configure` makes the certificates and the mirror entries, names each file, and changes nothing again.
    let printed = node.sh("speculaire configure");
    let entry = match node.cluster.runtime() {
        Runtime::Containerd => "/etc/containerd/certs.d/_default/hosts.toml",
        Runtime::Crio => "/etc/containers/registries.conf.d/99-speculaire.conf",
    };
    assert!(printed.contains(entry), "step 2: {printed}");
    match node.cluster.runtime() {
        Runtime::Containerd => assert_eq!(
            node.sh(&format!("grep -m1 '^\\[host\\.' {entry}")).trim(),
            r#"[host."https://127.0.0.1:7480"]"#,
            "step 2: the mirror comes first"
        ),
        Runtime::Crio => assert!(
            !node
                .files("/etc/containers/certs.d/127.0.0.1:7480")
                .is_empty(),
            "step 2: the certificates for CRI-O"
        ),
    }
    let dirs = format!("{} /var/lib/speculaire/mirror", node.runtime_config());
    let configured = node.files(&dirs);
    assert_ne!(configured, untouched, "step 2");
    assert!(
        configured.contains("/var/lib/speculaire/mirror/"),
        "step 2: {configured}"
    );
    let again = node.sh("speculaire configure");
    assert_eq!(
        (again.as_str(), node.files(&dirs)),
        ("", configured),
        "step 2: configure again"
    );

    // Step 3: `/readyz` answers 200 once the gate registered. Its 503 lasts less than a poll here; step 5 sees it.
    node.sh("systemctl enable speculaire");
    let changes = node
        .cluster
        .watch(&node.name, "systemctl start speculaire")
        .unwrap();
    let states: Vec<&str> = changes
        .iter()
        .map(|c| c.split_once(' ').unwrap().1)
        .collect();
    assert!(
        states
            .iter()
            .all(|s| !s.starts_with("200 ") || *s == "200 1"),
        "step 3: {changes:?}"
    );
    assert_eq!(states.last(), Some(&"200 1"), "step 3: {changes:?}");

    // Step 4: the gate starts in audit: an image no policy matches runs, counted as `unmatched`.
    node.start("default", "speculaire-e2e-audit");
    node.ready("default", "speculaire-e2e-audit");
    let metrics = node.sh("curl -sf http://127.0.0.1:7482/metrics");
    let audited = metrics.lines().find(|line| {
        line.starts_with("speculaire_gate_total{")
            && line.contains(r#"mode="audit""#)
            && line.contains(r#"result="unmatched""#)
    });
    assert!(
        audited.is_some_and(|line| !line.ends_with(" 0")),
        "step 4: {audited:?}"
    );
}

/// § Before turning on `enforce`, steps 2 to 5; step 1's `unmatched` is [`install`]'s step 4.
fn before_enforce(node: &Node) {
    // Step 2: `kube-system` is exempt; [`break_glass`] step 2 checks that a stopped agent exempts nothing.
    node.reload(
        r#"/^\[gate.exempt\]/,/^\[/ s/^#namespaces = \[\]$/namespaces = ["kube-system"]/"#,
        r#"namespaces = \["kube-system"\]"#,
    );

    // Step 3: the toleration annotation, in the runtime's validator section and on the static pod.
    let tolerate = match node.cluster.runtime() {
        Runtime::Containerd => format!(
            "\n[plugins.'io.containerd.nri.v1.nri'.default_validator]\n  tolerate_missing_plugins_annotation = \"{TOLERATE}\"\n"
        ),
        Runtime::Crio => format!(
            "[crio.nri.default_validator]\nnri_validator_tolerate_missing_plugins_annotation = \"{TOLERATE}\"\n"
        ),
    };
    node.append(node.validator(), &tolerate);
    node.sh(&format!(
        "sed -i 's|^metadata:$|metadata:\\n  annotations:\\n    {TOLERATE}: \"true\"|' {SCHEDULER} && \
         grep -q '^    {TOLERATE}: \"true\"$' {SCHEDULER}"
    ));
    node.scheduler(true, "");

    // Step 4: `check-config` exits 0.
    node.sh("speculaire check-config");

    // Step 5: fail-closed; the runtime's restart makes `/readyz` 503 until the gate registers again.
    let required = match node.cluster.runtime() {
        Runtime::Containerd => "  enable = true\n  required_plugins = [\"speculaire\"]\n",
        Runtime::Crio => {
            "nri_enable_default_validator = true\nnri_validator_required_plugins = [\"speculaire\"]\n"
        }
    };
    node.append(node.validator(), required);
    let changes = node.cluster.restart_runtime(&node.name).unwrap();
    let states: Vec<&str> = changes
        .iter()
        .map(|c| c.split_once(' ').unwrap().1)
        .collect();
    assert!(
        states.iter().any(|s| s.starts_with("503 ")),
        "step 5: {changes:?}"
    );
    assert_eq!(states.last(), Some(&"200 1"), "step 5: {changes:?}");
}

/// § Break glass steps 1 to 3, from `enforce`.
fn break_glass(node: &Node) {
    let mode = |from: &str, to: &str| {
        node.reload(
            &format!(r#"/^\[gate\]/,/^\[/ s/^#\?mode = "{from}"$/mode = "{to}"/"#),
            &format!(r#"mode = "{to}""#),
        );
    };
    mode("audit", "enforce");
    node.start("default", "speculaire-e2e-glass");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let state = node
            .cluster
            .kubectl(&[
                "get",
                "pod",
                "speculaire-e2e-glass",
                "-o",
                r"jsonpath={.status.containerStatuses[0].state.waiting.message}",
            ])
            .unwrap();
        if state.contains("unmatched") {
            break;
        }
        assert!(Instant::now() < deadline, "enforce: {state:?}");
        std::thread::sleep(Duration::from_millis(500));
    }

    // Step 1: back to audit, the rejected pod starts on kubelet's next retry.
    mode("enforce", "audit");
    let retry = Instant::now();
    node.ready("default", "speculaire-e2e-glass");
    eprintln!(
        "{}: step 1: started {:?} after the reload",
        node.name,
        retry.elapsed()
    );

    // Step 2: with the agent down, the validator rejects every container, exempt or not, but the static pod restarts
    // through its toleration annotation; `systemctl restart speculaire` brings the agent back.
    node.cluster.stop_agent(&node.name).unwrap();
    node.start("kube-system", "speculaire-e2e-exempt");
    node.cluster
        .rejected("kube-system", "speculaire-e2e-exempt", MISSING)
        .unwrap();
    let scheduler = node.scheduler(true, "");
    node.sh(&format!("crictl stop {scheduler} >/dev/null"));
    node.scheduler(true, &scheduler);
    node.cluster.restart_agent(&node.name).unwrap();
    node.cluster.wait_ready(&node.name).unwrap();

    // Step 3: with `speculaire` no longer required, the runtime's restart keeps the running containers, and new ones
    // start ungated.
    node.cluster.stop_agent(&node.name).unwrap();
    let running = node.running();
    node.sh(&format!(
        r#"sed -i '/required_plugins = /s/"speculaire"//' {file} && grep -q 'required_plugins = \[\]$' {file}"#,
        file = node.validator()
    ));
    node.restart_runtime();
    let after = node.running();
    assert!(
        running.is_subset(&after),
        "step 3: gone {:?}",
        running.difference(&after).collect::<Vec<_>>()
    );
    node.start("default", "speculaire-e2e-ungated");
    node.ready("default", "speculaire-e2e-ungated");
}
