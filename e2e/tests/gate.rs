//! The gate on the nodes' real runtimes (D9, D15, D41, D64, D168, D170): containerd's image store and snapshots, the gate's
//! registration with the runtime's NRI, and from M6's later steps its decisions.
//!
//! containerd's socket of a worker is relayed to this host, one `docker exec` per connection, so the runtime crate's
//! clients run here against it. The tests that restart a worker's runtime or agent run one at a time, on the IPv4 pass
//! only: nothing in them depends on the family.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use e2e::node::POLICY;
use e2e::upstream::{FIXTURES, Kind, RUNNABLE, SIGNED, UNSIGNED, runnable_policy};
use e2e::{Cluster, IpFamily, Runtime};
use speculaire_oci::chain::of_config;
use speculaire_oci::index::Index;
use speculaire_oci::manifest::{Children, children};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_runtime::containerd::Containerd;
use speculaire_runtime::containerd::store::Store;
use speculaire_runtime::identity::MISMATCH;
use speculaire_runtime::paths::Paths;

/// Copies bytes both ways between stdin and stdout and containerd's socket, until either side ends.
const RELAY: &str = r#"
use IO::Socket::UNIX; use IO::Select;
my $s = IO::Socket::UNIX->new(Peer => "/run/containerd/containerd.sock") or die "connect: $!";
binmode STDIN; binmode STDOUT;
my $select = IO::Select->new(\*STDIN, $s);
while (my @ready = $select->can_read) {
    for my $from (@ready) {
        my $n = sysread($from, my $bytes, 65536);
        exit 0 unless $n;
        my $to = $from == $s ? \*STDOUT : $s;
        while (length $bytes) {
            my $written = syswrite($to, $bytes) // die "write: $!";
            substr($bytes, 0, $written) = "";
        }
    }
}
"#;

fn worker(cluster: &Cluster) -> String {
    cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|n| n.name)
        .find(|name| name.ends_with("-worker"))
        .expect("a worker")
}

/// A socket on this host that reaches containerd's on `node`, until dropped.
struct Relay {
    dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl Relay {
    fn start(node: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let listener = tokio::net::UnixListener::bind(dir.path().join("containerd.sock")).unwrap();
        let node = node.to_owned();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut docker = tokio::process::Command::new("docker");
                docker
                    .args(["exec", "-i", &node, "perl", "-e", RELAY])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .kill_on_drop(true);
                tokio::spawn(async move {
                    let mut child = docker.spawn().unwrap();
                    let mut stdin = child.stdin.take().unwrap();
                    let mut stdout = child.stdout.take().unwrap();
                    let (mut from, mut to) = stream.split();
                    // Either side ending ends the connection.
                    tokio::select! {
                        _ = tokio::io::copy(&mut from, &mut stdin) => {}
                        _ = tokio::io::copy(&mut stdout, &mut to) => {}
                    }
                });
            }
        });
        Self { dir, task }
    }

    fn socket(&self) -> PathBuf {
        self.dir.path().join("containerd.sock")
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Runs `ctr -n k8s.io` with `args` on `node`.
fn ctr(cluster: &Cluster, node: &str, args: &[&str]) -> String {
    let command: Vec<&str> = ["ctr", "-n", "k8s.io"]
        .iter()
        .chain(args)
        .copied()
        .collect();
    cluster.exec(node, &command).unwrap()
}

/// The chain ID of the image whose target is `target`, for the node's platform, read with `ctr content get`.
fn chain(cluster: &Cluster, node: &str, target: &Digest) -> Digest {
    let host = Host {
        os: "linux".to_owned(),
        ..Host::current()
    };
    let read = |digest: &Digest| ctr(cluster, node, &["content", "get", &digest.to_string()]);
    let mut manifest = read(target);
    if let Children::Index { .. } = children(manifest.as_bytes()).unwrap() {
        let index = Index::parse(manifest.as_bytes()).unwrap();
        manifest = read(
            index
                .platform_manifest(&host)
                .expect("a manifest for the node"),
        );
    }
    let Children::Image { config, .. } = children(manifest.as_bytes()).unwrap() else {
        panic!("{target}: no image manifest for the node");
    };
    of_config(read(&config).as_bytes()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
async fn the_image_store_and_the_chain_ids_match_containerds() {
    let cluster = Cluster::from_env();
    if cluster.runtime() != Runtime::Containerd {
        return;
    }
    let node = worker(&cluster);
    let relay = Relay::start(&node);
    let dir = tempfile::tempdir().unwrap();
    let containerd = std::sync::Arc::new(Containerd::new(
        Paths::under(dir.path()),
        relay.socket(),
        None,
    ));
    let store = std::sync::Arc::new(Store::default());
    let keeper = tokio::spawn({
        let (containerd, store) = (
            std::sync::Arc::clone(&containerd),
            std::sync::Arc::clone(&store),
        );
        async move { containerd.keep(&store).await }
    });

    // The store lists what `ctr` lists, once its first listing is in.
    let listed: BTreeSet<String> = ctr(&cluster, &node, &["images", "ls", "-q"])
        .lines()
        .map(str::to_owned)
        .collect();
    let start = Instant::now();
    loop {
        let held: BTreeSet<String> = store.names().into_iter().collect();
        if held == listed {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the store holds {held:?}, ctr lists {listed:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Each running container rests on the chain ID of its image.
    let ids = cluster
        .exec(&node, &["crictl", "ps", "-q", "--no-trunc"])
        .unwrap();
    let mut checked = 0;
    for id in ids.lines() {
        let info: serde_json::Value =
            serde_json::from_str(&ctr(&cluster, &node, &["containers", "info", id])).unwrap();
        let field = |name: &str| {
            info[name]
                .as_str()
                .expect("a field of the container")
                .to_owned()
        };
        let (image, snapshotter, key) =
            (field("Image"), field("Snapshotter"), field("SnapshotKey"));
        let target = store
            .get(&image)
            .unwrap_or_else(|| panic!("{image} is in the store"));
        let chain = chain(&cluster, &node, &target);
        let base = containerd
            .snapshot_base(&snapshotter, &key, &chain)
            .await
            .unwrap();
        assert_eq!(base, chain.to_string(), "{image} of container {id}");
        checked += 1;
    }
    assert!(checked > 0, "no running container on {node}");
    keeper.abort();
}

static SERIAL: Mutex<()> = Mutex::new(());

const CONFIG: &str = "/etc/speculaire/config.toml";
const NRI_SOCKET: &str = "/var/run/nri/nri.sock";
/// Where a test points `nri.socket`, to hold the agent before its registration.
const HELD: &str = "/run/speculaire-e2e/nri.sock";
/// The agent's `/readyz` and `speculaire_nri_connected`, as one line: `200 1` when registered.
const STATE: &str = "state() { echo \"$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7482/readyz) \
                     $(curl -s http://127.0.0.1:7482/metrics | sed -n 's/^speculaire_nri_connected //p')\"; }";

/// A worker that is not a reflector, whose readiness waits for the gate alone, on the IPv4 pass.
struct Worker {
    cluster: Cluster,
    node: String,
    _serial: MutexGuard<'static, ()>,
}

impl Worker {
    fn new() -> Option<Self> {
        let cluster = Cluster::from_env();
        if cluster.ip_family() == IpFamily::Dual {
            return None;
        }
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let reflectors = cluster.reflectors();
        let node = cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .find(|name| !name.contains("control-plane") && !reflectors.contains(name))
            .unwrap();
        // A suite run first, right after the cluster came up, may find the agent not yet registered.
        cluster.wait_ready(&node).unwrap();
        Some(Self {
            cluster,
            node,
            _serial: serial,
        })
    }

    fn sh(&self, script: &str) -> String {
        self.cluster
            .exec(&self.node, &["sh", "-c", script])
            .unwrap()
    }

    /// Restarts the node's runtime, and returns each change of the agent's state from before the restart until the
    /// agent is registered again, as `<ms since the restart> <readyz> <speculaire_nri_connected>`.
    fn restart_runtime(&self) -> Vec<String> {
        let service = match self.cluster.runtime() {
            Runtime::Containerd => "containerd",
            Runtime::Crio => "crio",
        };
        // Polled on the node: a registration takes milliseconds, less than an exec from the host.
        let changes = self.sh(&format!(
            "{STATE}
             last=$(state); echo \"0 $last\"; away=0
             start=$(date +%s%N); end=$((start + 30000000000))
             systemctl restart {service} &
             while [ \"$(date +%s%N)\" -lt \"$end\" ]; do
                 s=$(state)
                 if [ \"$s\" != \"$last\" ]; then echo \"$((($(date +%s%N) - start) / 1000000)) $s\"; last=$s; fi
                 if [ \"$s\" = '200 1' ]; then [ $away = 1 ] && break; else away=1; fi
                 sleep 0.02
             done
             wait"
        ));
        self.wait_runtime();
        changes.lines().map(str::to_owned).collect()
    }

    /// Waits until the runtime answers, so that kubelet and the next suite find it.
    fn wait_runtime(&self) {
        let check = match self.cluster.runtime() {
            Runtime::Containerd => "crictl version",
            Runtime::Crio => "crictl version && crio status config | grep -q nri",
        };
        let deadline = Instant::now() + Duration::from_secs(90);
        while !self
            .cluster
            .exec_output(&self.node, &["sh", "-c", check])
            .is_ok_and(|o| o.success)
        {
            assert!(
                Instant::now() < deadline,
                "{}: the runtime is not back",
                self.node
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// The agent's `speculaire_build_info` series, each as its labels and value.
    fn build_info(&self) -> Vec<String> {
        self.series("speculaire_build_info")
    }

    /// The agent's series of metric `name`, each as its labels and value.
    fn series(&self, name: &str) -> Vec<String> {
        let prefix = format!("{name}{{");
        self.cluster
            .exec(
                &self.node,
                &["curl", "-sf", "http://127.0.0.1:7482/metrics"],
            )
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_prefix(&prefix))
            .map(str::to_owned)
            .collect()
    }
}

/// Puts `nri.socket` back and restarts the agent with an empty journal, even when the test fails.
struct Held<'a>(&'a Worker);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let worker = self.0;
        worker.sh(&format!(
            "sed -i 's|^socket = \"{HELD}\"$|#socket = \"{NRI_SOCKET}\"|' {CONFIG}; rm -rf {}",
            parent(HELD)
        ));
        worker.cluster.reset_agent(&worker.node).unwrap();
    }
}

fn parent(path: &str) -> &str {
    path.rsplit_once('/').unwrap().0
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_gate_registers_again_after_the_runtime_restarts() {
    let Some(worker) = Worker::new() else { return };
    let changes = worker.restart_runtime();
    eprintln!("{}: {changes:?}", worker.node);
    let states: Vec<&str> = changes
        .iter()
        .map(|c| c.split_once(' ').unwrap().1)
        .collect();
    assert_eq!(states.first(), Some(&"200 1"), "{changes:?}");
    assert_eq!(states.last(), Some(&"200 1"), "{changes:?}");
    // A state is two requests, which a change can fall between: only the states either side are sure.
    assert!(states.contains(&"503 0"), "{changes:?}");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn readyz_is_503_until_the_gate_registers_and_build_info_names_the_runtime() {
    let Some(worker) = Worker::new() else { return };
    // The agent starts on a socket nothing listens on yet, which the test then links to NRI's.
    worker.sh(&format!(
        "mkdir -p {dir} && sed -i 's|^#socket = \"{NRI_SOCKET}\"$|socket = \"{HELD}\"|' {CONFIG} && \
         grep -q '^socket = \"{HELD}\"$' {CONFIG}",
        dir = parent(HELD)
    ));
    let held = Held(&worker);
    worker.sh("systemctl restart speculaire");
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(worker.sh(&format!("{STATE}; state")).trim(), "503 0");
    let version = env!("CARGO_PKG_VERSION");
    let empty = format!(r#"version="{version}",runtime="",runtime_version="",nri_version=""}}"#);
    assert_eq!(worker.build_info(), [format!("{empty} 1")]);

    worker.sh(&format!("ln -s {NRI_SOCKET} {HELD}"));
    let start = Instant::now();
    worker.cluster.wait_ready(&worker.node).unwrap();
    eprintln!(
        "{}: ready {:?} after NRI's socket appeared",
        worker.node,
        start.elapsed()
    );
    assert_eq!(worker.sh(&format!("{STATE}; state")).trim(), "200 1");
    let release = worker.cluster.release();
    let runtime = worker.cluster.runtime();
    let info = worker.build_info();
    assert!(info.contains(&format!("{empty} 0")), "{info:?}");
    let named: Vec<&String> = info.iter().filter(|s| s.ends_with(" 1")).collect();
    let [named] = named.as_slice() else {
        panic!("not one series at 1: {info:?}")
    };
    let prefix = format!(
        r#"version="{version}",runtime="{}",runtime_version=""#,
        runtime.scheme()
    );
    let rest = named
        .strip_prefix(&prefix)
        .unwrap_or_else(|| panic!("{named}"));
    let (runtime_version, nri_version) = rest
        .strip_suffix("\"} 1")
        .and_then(|r| r.split_once(r#"",nri_version=""#))
        .unwrap_or_else(|| panic!("{named}"));
    assert_eq!(runtime_version.trim_start_matches('v'), release, "{named}");
    // CRI-O 1.35 and 1.36 announce no NRI version, and NRI infers none from a version without a `v` (D64, D166).
    let unknown =
        runtime == Runtime::Crio && (release.starts_with("1.35.") || release.starts_with("1.36."));
    assert_eq!(nri_version.is_empty(), unknown, "{named}");
    drop(held);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_gate_reads_the_image_identity_by_annotation_on_containerd_2_3_from_nri_on_2_4_and_from_the_image_id_on_cri_o()
 {
    let Some(worker) = Worker::new() else { return };
    // containerd 2.3 announces NRI v0.12.0, which names no image (D15, D170).
    let release = worker.cluster.release();
    let path = match worker.cluster.runtime() {
        Runtime::Containerd if release.starts_with("2.3.") => "annotation",
        Runtime::Containerd => "nri",
        Runtime::Crio => "image_id",
    };
    assert_eq!(
        worker.series("speculaire_identity_path"),
        [format!(r#"path="{path}"}} 1"#)]
    );
    // The `annotation` path alone warns of its identity gap, at each registration since the journal was emptied.
    let warnings = worker.sh("journalctl -u speculaire -p warning -o cat --no-pager");
    assert_eq!(
        warnings.contains("identity gap, D15"),
        path == "annotation",
        "{warnings}"
    );
}

/// A policy named `name` over the unsigned image at `host`: any keyless signer passes it, and it has none.
fn unsigned_policy(host: &str, name: &str) -> String {
    let image = UNSIGNED.split_once(':').expect("a tag").0;
    format!(
        "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: {name}\nspec:\n  \
         images:\n  - glob: {host}/{image}\n  authorities:\n  - keyless:\n      identities:\n      - issuerRegExp: \
         \".*\"\n        subjectRegExp: \".*\"\n"
    )
}

/// The sum of the agent's `name` series whose labels hold each of `labels`.
fn count(worker: &Worker, name: &str, labels: &[&str]) -> u64 {
    worker
        .series(name)
        .iter()
        .filter(|series| labels.iter().all(|label| series.contains(label)))
        .map(|series| {
            let value = series.rsplit_once(' ').unwrap().1;
            value.parse::<u64>().unwrap_or_else(|_| panic!("{series}"))
        })
        .sum()
}

/// Waits until the agent counts a rejected verification since it started, of `image`.
fn wait_rejected(worker: &Worker, image: &str) {
    let start = Instant::now();
    while count(
        worker,
        "speculaire_verifications_total",
        &[r#"result="rejected""#],
    ) == 0
    {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "{}: no rejected verification of {image}",
            worker.node
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Runs `pod`, a container of `image` on the worker, and waits until it is ready.
fn run(worker: &Worker, pod: &str, image: &str) {
    let overrides = format!(r#"{{"spec":{{"nodeName":"{}"}}}}"#, worker.node);
    worker
        .cluster
        .kubectl(&[
            "run",
            pod,
            "--image",
            image,
            "--image-pull-policy=IfNotPresent",
            "--restart=Never",
            &format!("--overrides={overrides}"),
            "--command",
            "--",
            "sleep",
            "3600",
        ])
        .unwrap();
    worker
        .cluster
        .kubectl(&[
            "wait",
            "--for=condition=Ready",
            &format!("pod/{pod}"),
            "--timeout=120s",
        ])
        .unwrap();
}

/// Deletes the pod, the policy file and the image, and restarts the agent, even when the test fails.
struct Unsigned<'a> {
    worker: &'a Worker,
    pod: &'static str,
    image: String,
}

impl Unsigned<'_> {
    fn delete_pod(&self) {
        let _ = self
            .worker
            .cluster
            .kubectl(&["delete", "pod", self.pod, "--now", "--timeout=60s"]);
    }
}

impl Drop for Unsigned<'_> {
    fn drop(&mut self) {
        self.delete_pod();
        let Unsigned { worker, image, .. } = self;
        let _ = worker.cluster.exec_output(
            &worker.node,
            &["sh", "-c", &format!("rm -f {POLICY}; crictl rmi {image}")],
        );
        worker.cluster.reset_agent(&worker.node).unwrap();
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn in_audit_a_pod_of_a_rejected_image_runs_and_counts_as_rejected() {
    let Some(worker) = Worker::new() else { return };
    let host = worker
        .cluster
        .upstream(Kind::Referrers)
        .address()
        .to_owned();
    worker
        .cluster
        .policy(&worker.node, &unsigned_policy(&host, "unsigned"))
        .unwrap();
    let guard = Unsigned {
        worker: &worker,
        pod: "speculaire-e2e-unsigned",
        image: format!("{host}/{UNSIGNED}"),
    };
    worker.cluster.reset_agent(&worker.node).unwrap();
    // The verdict is in before the pod: the first `CreateContainer` finds it, not `Pending`.
    worker.sh(&format!("crictl pull {} >/dev/null", guard.image));
    wait_rejected(&worker, &guard.image);
    let rejected = [r#"mode="audit""#, r#"result="rejected""#];
    let before = count(&worker, "speculaire_gate_total", &rejected);

    run(&worker, guard.pod, &guard.image);
    let after = count(&worker, "speculaire_gate_total", &rejected);
    assert_eq!(
        after,
        before + 1,
        "{:?}",
        worker.series("speculaire_gate_total")
    );
    drop(guard);
}

/// The journal field of each field of `event` in `docs/operations.md` § Audit events: its name in capitals behind
/// `F_`, as `tracing-journald` writes it (D173).
fn audit_fields(event: &str) -> Vec<String> {
    let doc = include_str!("../../docs/operations.md");
    let (_, section) = doc
        .split_once("## Audit events\n")
        .expect("operations.md has the section");
    let section = section.split("\n## ").next().unwrap_or(section);
    let row = format!("| `{event}` | `");
    section
        .lines()
        .filter_map(|line| line.strip_prefix(row.as_str())?.split_once('`'))
        .map(|(field, _)| format!("F_{}", field.to_uppercase()))
        .collect()
}

/// The audit events `event` in the worker's journal whose field `key` is `value`, each checked to hold every field
/// `docs/operations.md` names.
fn audited(
    worker: &Worker,
    event: &str,
    (key, value): (&str, &str),
) -> Vec<serde_json::Map<String, serde_json::Value>> {
    let events: Vec<_> = worker
        .cluster
        .audit(&worker.node)
        .unwrap()
        .into_iter()
        .filter(|record| {
            record.get("F_EVENT").is_some_and(|e| e == event)
                && record.get(key).is_some_and(|v| v == value)
        })
        .collect();
    let fields = audit_fields(event);
    for record in &events {
        let missing: Vec<&String> = fields
            .iter()
            .filter(|field| !record.contains_key(*field))
            .collect();
        assert!(missing.is_empty(), "{missing:?} not in {record:?}");
    }
    events
}

/// A name no earlier run gave a policy, so that its verdicts are new to the agent's cache (D31).
fn fresh(prefix: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{prefix}-{nanos}")
}

/// Turns the audit log on and every other log off in the agent's config and restarts the agent, until dropped.
struct Audit<'a>(&'a Worker);

impl<'a> Audit<'a> {
    fn on(worker: &'a Worker) -> Self {
        worker.sh(&format!(
            "cp {CONFIG} {CONFIG}.e2e && sed -i -e '/^\\[audit\\]/,/^\\[/ s/^#enabled = false$/enabled = true/' -e \
             '/^\\[log\\]/,/^\\[/ s/^#*filter = .*$/filter = \"off\"/' {CONFIG} && grep -q '^enabled = true$' \
             {CONFIG} && grep -q '^filter = \"off\"$' {CONFIG}"
        ));
        worker.cluster.reset_agent(&worker.node).unwrap();
        Self(worker)
    }
}

impl Drop for Audit<'_> {
    fn drop(&mut self) {
        let worker = self.0;
        let _ = worker
            .cluster
            .exec(&worker.node, &["mv", &format!("{CONFIG}.e2e"), CONFIG]);
        worker.cluster.reset_agent(&worker.node).unwrap();
    }
}

/// Writes a policy of a fresh name over the unsigned image, reloads the agent and waits for its rejected verdict;
/// returns the name.
fn edit_policy(worker: &Worker, host: &str, image: &str) -> String {
    let name = fresh("audit");
    worker
        .cluster
        .policy(&worker.node, &unsigned_policy(host, &name))
        .unwrap();
    worker.sh("systemctl reload speculaire");
    wait_rejected(worker, image);
    name
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn with_the_audit_on_a_creation_and_a_changed_verdict_are_one_event_each_and_with_it_off_none() {
    let Some(worker) = Worker::new() else { return };
    let host = worker
        .cluster
        .upstream(Kind::Referrers)
        .address()
        .to_owned();
    let guard = Unsigned {
        worker: &worker,
        pod: "speculaire-e2e-audit",
        image: format!("{host}/{UNSIGNED}"),
    };
    worker.sh(&format!(
        "rm -f {POLICY}; crictl pull {} >/dev/null",
        guard.image
    ));
    let audit = Audit::on(&worker);

    // No policy matches the image: `audit` mode allows it, and no verification runs.
    run(&worker, guard.pod, &guard.image);
    let created = audited(&worker, "gate", ("F_POD", guard.pod));
    let [gate] = created.as_slice() else {
        panic!("not one gate event: {created:?}")
    };
    assert_eq!(gate["F_CONTAINER"], guard.pod, "{gate:?}");
    // CRI-O passes no pod-spec name: the event names the image's repositories (D65, D173).
    let image_name = match worker.cluster.runtime() {
        Runtime::Containerd => guard.image.as_str(),
        Runtime::Crio => guard.image.rsplit_once(':').unwrap().0,
    };
    assert_eq!(gate["F_IMAGE_NAME"], image_name, "{gate:?}");
    assert_eq!(gate["F_MODE"], "audit", "{gate:?}");
    assert_eq!(gate["F_RESULT"], "unmatched", "{gate:?}");

    let name = edit_policy(&worker, &host, &guard.image);
    let changed = audited(&worker, "verdict", ("F_MATCHED_POLICIES", &name));
    let [verdict] = changed.as_slice() else {
        panic!("not one verdict event: {changed:?}")
    };
    assert_eq!(verdict["F_RESULT"], "rejected", "{verdict:?}");

    drop(audit);
    guard.delete_pod();
    edit_policy(&worker, &host, &guard.image);
    run(&worker, guard.pod, &guard.image);
    let journal = worker.cluster.audit(&worker.node).unwrap();
    assert!(journal.is_empty(), "{journal:?}");
    drop(guard);
}

/// The label of the enforce suite's pods, by which its guard deletes them in any namespace.
const ENFORCE: &str = "speculaire-e2e=enforce";

/// The worker under `gate.mode = "enforce"`, with `kube-system` exempt, a policy over the runnable and the unsigned
/// images, and the runtime requiring the plugin as `docs/operations.md` § Before turning on `enforce` step 5 says, until
/// dropped: then the suite's pods and `images` go, and the runtime's config, the agent's and the policy are put back.
struct Enforced<'a> {
    worker: &'a Worker,
    images: Vec<String>,
}

impl<'a> Enforced<'a> {
    fn on(worker: &'a Worker, policy: &str, images: Vec<String>) -> Self {
        worker.sh(&format!(
            "cp {CONFIG} {CONFIG}.e2e && sed -i -e '/^\\[gate\\]/,/^\\[/ s/^#mode = \"audit\"$/mode = \"enforce\"/' -e \
             '/^\\[gate.exempt\\]/,/^\\[/ s/^#namespaces = \\[\\]$/namespaces = [\"kube-system\"]/' {CONFIG} && grep -q \
             '^mode = \"enforce\"$' {CONFIG} && grep -q '^namespaces = \\[\"kube-system\"\\]$' {CONFIG}"
        ));
        let enforced = Self { worker, images };
        worker.cluster.policy(&worker.node, policy).unwrap();
        enforced.restart_agent();
        let require = match worker.cluster.runtime() {
            Runtime::Containerd => format!(
                "cp {CONTAINERD} {CONTAINERD}.e2e && printf '\\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\\n  \
                 enable = true\\n  required_plugins = [\"speculaire\"]\\n' >> {CONTAINERD}"
            ),
            Runtime::Crio => format!(
                "printf '[crio.nri.default_validator]\\nnri_enable_default_validator = true\\n\
                 nri_validator_required_plugins = [\"speculaire\"]\\n' > {CRIO_REQUIRED}"
            ),
        };
        worker.sh(&require);
        enforced.restart_runtime();
        enforced
    }

    /// Edits the agent's config with the `sed` script `edit`, checks that `line` is in it, and restarts the agent.
    fn set(&self, edit: &str, line: &str) {
        self.worker.sh(&format!(
            "sed -i -e '{edit}' {CONFIG} && grep -q '^{line}$' {CONFIG}"
        ));
        self.restart_agent();
    }

    /// Restarts the agent, keeping its journal, and waits until it is registered again.
    fn restart_agent(&self) {
        self.worker.sh("systemctl restart speculaire");
        self.worker.cluster.wait_ready(&self.worker.node).unwrap();
    }

    /// Restarts the runtime, and waits until it answers and the agent is registered again.
    fn restart_runtime(&self) {
        self.worker.sh(match self.worker.cluster.runtime() {
            Runtime::Containerd => "systemctl restart containerd",
            Runtime::Crio => "systemctl restart crio",
        });
        self.worker.wait_runtime();
        self.worker.cluster.wait_ready(&self.worker.node).unwrap();
    }
}

impl Drop for Enforced<'_> {
    fn drop(&mut self) {
        let worker = self.worker;
        let _ = worker.cluster.kubectl(&[
            "delete",
            "pod",
            "-A",
            "-l",
            ENFORCE,
            "--now",
            "--timeout=60s",
        ]);
        let unrequire = match worker.cluster.runtime() {
            Runtime::Containerd => format!("mv {CONTAINERD}.e2e {CONTAINERD}"),
            Runtime::Crio => format!("rm -f {CRIO_REQUIRED}"),
        };
        let _ = worker
            .cluster
            .exec_output(&worker.node, &["sh", "-c", &unrequire]);
        self.restart_runtime();
        let _ = worker.cluster.exec_output(
            &worker.node,
            &[
                "sh",
                "-c",
                &format!("mv {CONFIG}.e2e {CONFIG}; rm -f {POLICY}"),
            ],
        );
        self.restart_agent();
        for image in &self.images {
            if !remove(worker, image) {
                eprintln!("{image} stays on {}", worker.node);
            }
        }
    }
}

/// containerd's config, which the enforce suite makes require the plugin.
const CONTAINERD: &str = "/etc/containerd/config.toml";
/// The CRI-O drop-in by which the enforce suite makes CRI-O require the plugin.
const CRIO_REQUIRED: &str = "/etc/crio/crio.conf.d/90-required.conf";

/// Removes `image` from the worker, by its ID, so every name of it goes, waiting up to a minute for the kubelet to
/// remove the containers that use it; whether it went.
fn remove(worker: &Worker, image: &str) -> bool {
    let script = format!(
        "id=$(crictl inspecti -o go-template --template '{{{{.status.id}}}}' {image} 2>/dev/null) || exit 0; \
         crictl rmi \"$id\" >/dev/null 2>&1; exit 1"
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while !worker
        .cluster
        .exec_output(&worker.node, &["sh", "-c", &script])
        .is_ok_and(|out| out.success)
    {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    true
}

/// Removes `image` from the worker, then starts `pod` of it: its start is a first pull.
fn create(worker: &Worker, namespace: &str, pod: &str, image: &str) {
    assert!(remove(worker, image), "{image} stays on {}", worker.node);
    start(worker, namespace, pod, image);
}

/// Creates `pod` in `namespace` on the worker, labelled [`ENFORCE`], one container of `image`.
fn start(worker: &Worker, namespace: &str, pod: &str, image: &str) {
    let overrides = format!(r#"{{"spec":{{"nodeName":"{}"}}}}"#, worker.node);
    worker
        .cluster
        .kubectl(&[
            "run",
            pod,
            "-n",
            namespace,
            "--labels",
            ENFORCE,
            "--image",
            image,
            "--image-pull-policy=IfNotPresent",
            "--restart=Never",
            &format!("--overrides={overrides}"),
            "--command",
            "--",
            "sleep",
            "3600",
        ])
        .unwrap();
}

/// Waits until `pod` is ready, then deletes it, and returns the creation errors the kubelet met on the way: the
/// messages of its `Failed` events, each as many times as the kubelet counted it.
fn ready(worker: &Worker, namespace: &str, pod: &str) -> Vec<String> {
    let kubectl = |args: &[&str]| -> String {
        let mut all = vec!["-n", namespace];
        all.extend_from_slice(args);
        worker.cluster.kubectl(&all).unwrap()
    };
    kubectl(&[
        "wait",
        "--for=condition=Ready",
        &format!("pod/{pod}"),
        "--timeout=120s",
    ]);
    // By UID: an earlier run's pod of the same name has its own events.
    let uid = kubectl(&["get", "pod", pod, "-o", "jsonpath={.metadata.uid}"]);
    let events = kubectl(&[
        "get",
        "events",
        "--field-selector",
        &format!("involvedObject.uid={uid},reason=Failed"),
        "-o",
        r#"jsonpath={range .items[*]}{.count} {.message}{"\n"}{end}"#,
    ]);
    kubectl(&["delete", "pod", pod, "--now", "--timeout=60s"]);
    events
        .lines()
        .flat_map(|line| {
            let (count, message) = line.split_once(' ').unwrap();
            let count = count.parse().unwrap_or(1);
            std::iter::repeat_n(message.to_owned(), count)
        })
        .collect()
}

/// Waits until the creation of `pod`'s container fails with a message that holds `reason`, then deletes the pod, and
/// returns the message.
fn rejected(worker: &Worker, namespace: &str, pod: &str, reason: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut state = String::new();
    while Instant::now() < deadline {
        state = worker
            .cluster
            .kubectl(&[
                "get",
                "pod",
                "-n",
                namespace,
                pod,
                "-o",
                r#"jsonpath={.status.containerStatuses[0].state.waiting.reason}{"\n"}{.status.containerStatuses[0].state.waiting.message}"#,
            ])
            .unwrap();
        if let Some(("CreateContainerError", message)) = state.split_once('\n')
            && message.contains(reason)
        {
            let message = message.to_owned();
            worker
                .cluster
                .kubectl(&[
                    "delete",
                    "pod",
                    "-n",
                    namespace,
                    pod,
                    "--now",
                    "--timeout=60s",
                ])
                .unwrap();
            return message;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("{pod}: no creation error holding {reason:?}, last {state:?}")
}

/// The decisions of the worker's agent since it started, on a verdict at hand or after a wait, take under half of
/// `gate.wait` at the 99th percentile (D41, D107); the path they took.
fn latency(worker: &Worker) -> &'static str {
    let path = match worker.cluster.runtime() {
        Runtime::Containerd if worker.cluster.release().starts_with("2.3.") => "annotation",
        Runtime::Containerd => "nri",
        Runtime::Crio => "image_id",
    };
    let seconds = worker
        .cluster
        .histogram(&worker.node, "speculaire_gate_seconds", ("path", path))
        .unwrap();
    let p99 = seconds.percentile(99);
    eprintln!(
        "{}: speculaire_gate_seconds{{path=\"{path}\"}} p99 {p99} s over {} decisions",
        worker.node, seconds.count
    );
    assert!(seconds.count > 0 && p99 <= 0.15, "p99 {p99} s");
    path
}

/// A cold node, as after a reboot, which wipes `/run`: `runnable` is held, and the agent starts with no verdict of
/// it. A pod of it starts within three of the kubelet's retries: the startup list names the image, and a creation
/// that finds its verdict pending has the engine discover it at once, under `gate_miss` (D174).
fn cold(worker: &Worker, runnable: &str) {
    assert!(remove(worker, runnable));
    worker.sh(&format!("crictl pull {runnable} >/dev/null"));
    worker.cluster.stop_agent(&worker.node).unwrap();
    worker.sh("rm -f /run/speculaire/cache.bin");
    worker.cluster.start_agent(&worker.node).unwrap();
    start(worker, "default", "speculaire-e2e-cold", runnable);
    let failures = ready(worker, "default", "speculaire-e2e-cold");
    let verifications = worker.series("speculaire_verifications_total");
    eprintln!("{}: cold node {failures:?}, {verifications:?}", worker.node);
    assert!(failures.len() <= 3, "{failures:?}");
    // The listing verifies `runnable` first when its discovery comes before the creation.
    let missed = count(
        worker,
        "speculaire_verifications_total",
        &[r#"result="allow""#, r#"trigger="gate_miss""#],
    );
    assert!(failures.is_empty() || missed > 0, "{verifications:?}");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn under_enforce_signed_images_start_on_their_first_pull_and_the_rest_are_refused() {
    let Some(worker) = Worker::new() else { return };
    let begun = Instant::now();
    let lap = |case: &str| eprintln!("{}: {case} at {:?}", worker.node, begun.elapsed());
    let upstream = worker.cluster.upstream(Kind::Referrers);
    let host = upstream.address().to_owned();
    let runnable = format!("{host}/{FIXTURES}:{RUNNABLE}");
    let by_digest = format!(
        "{host}/{FIXTURES}@{}",
        upstream.digest(&format!("{FIXTURES}:{RUNNABLE}")).unwrap()
    );
    let unsigned = format!("{host}/{UNSIGNED}");
    let signed = format!("{host}/{SIGNED}");
    let policy = format!(
        "{}---\n{}",
        runnable_policy(&host),
        unsigned_policy(&host, "unsigned")
    );
    let enforced = Enforced::on(
        &worker,
        &policy,
        vec![
            runnable.clone(),
            by_digest.clone(),
            unsigned.clone(),
            signed.clone(),
        ],
    );
    lap("switched");

    // The verdict's reason, which containerd wraps and CRI-O does not (D64).
    create(&worker, "default", "speculaire-e2e-unsigned", &unsigned);
    let message = rejected(
        &worker,
        "default",
        "speculaire-e2e-unsigned",
        "rejected: no signature",
    );
    assert_eq!(
        message.contains("failed to get NRI adjustment for container"),
        worker.cluster.runtime() == Runtime::Containerd,
        "{message}"
    );
    lap("unsigned");

    // The verification that the manifest fetch starts lands before the container: no retry (D22).
    for (pod, image) in [
        ("speculaire-e2e-tag", &runnable),
        ("speculaire-e2e-digest", &by_digest),
    ] {
        create(&worker, "default", pod, image);
        let failures = ready(&worker, "default", pod);
        assert!(failures.is_empty(), "{image}: {failures:?}");
        lap(pod);
    }

    // No policy matches the signed image: an exempt namespace runs it, any other is denied.
    create(&worker, "kube-system", "speculaire-e2e-exempt", &signed);
    ready(&worker, "kube-system", "speculaire-e2e-exempt");
    create(&worker, "default", "speculaire-e2e-unmatched", &signed);
    rejected(&worker, "default", "speculaire-e2e-unmatched", "unmatched");
    lap("exempt and unmatched");

    // Read before the agent restarts, which empties its histograms.
    if latency(&worker) == "annotation" {
        mismatch(&worker, &runnable, &unsigned);
        lap("mismatch");
    }

    enforced.set(
        r#"/^\[gate.exempt\]/,/^\[/ s/^namespaces = \["kube-system"\]$/namespaces = []/"#,
        r"namespaces = \[\]",
    );
    create(&worker, "kube-system", "speculaire-e2e-exempt", &signed);
    rejected(&worker, "kube-system", "speculaire-e2e-exempt", "unmatched");
    enforced.set(
        r#"/^\[gate\]/,/^\[/ s/^#unmatched = "deny"$/unmatched = "allow"/"#,
        r#"unmatched = "allow""#,
    );
    create(&worker, "default", "speculaire-e2e-unmatched", &signed);
    ready(&worker, "default", "speculaire-e2e-unmatched");
    lap("no exemption, then unmatched allowed");

    // The runtime requires the plugin: without the agent, nothing starts (D64).
    worker.cluster.stop_agent(&worker.node).unwrap();
    create(&worker, "default", "speculaire-e2e-stopped", &signed);
    let message = rejected(
        &worker,
        "default",
        "speculaire-e2e-stopped",
        r#"required plugin "speculaire" not present"#,
    );
    worker.cluster.start_agent(&worker.node).unwrap();
    lap(&format!("agent stopped: {message}"));

    cold(&worker, &runnable);
    lap("cold node");
    drop(enforced);
    lap("restored");
}

/// On containerd 2.3, a container whose image name another image took after the kubelet resolved it, as a retag between
/// the pull and the creation does, is rejected (D15, D170). The container is created as the kubelet creates it: from
/// the image ID, naming the image as the pod spec does.
fn mismatch(worker: &Worker, a: &str, b: &str) {
    assert!(remove(worker, a) && remove(worker, b));
    let dir = "/tmp/speculaire-e2e-mismatch";
    let id = worker.sh(&format!(
        "crictl pull {a} >/dev/null && crictl pull {b} >/dev/null && \
         crictl inspecti -o go-template --template '{{{{.status.id}}}}' {a}"
    ));
    let id = id.trim();
    let pod = r#"{"metadata":{"name":"speculaire-e2e-mismatch","namespace":"default","uid":"speculaire-e2e-mismatch"},"linux":{"cgroup_parent":"speculaire-e2e.slice"}}"#;
    let container = format!(
        r#"{{"metadata":{{"name":"mismatch"}},"image":{{"image":"{id}","user_specified_image":"{a}"}},"command":["sleep","3600"],"linux":{{}}}}"#
    );
    let sandbox = worker.sh(&format!(
        "crictl pods -q --name speculaire-e2e-mismatch | xargs -r -n1 crictl rmp -f >/dev/null && mkdir -p {dir} && \
         printf '%s' '{pod}' > {dir}/pod.json && printf '%s' '{container}' > {dir}/container.json && \
         crictl runp {dir}/pod.json && ctr -n k8s.io images tag --force {b} {a} >/dev/null"
    ));
    let sandbox = sandbox.trim();
    // The agent follows the retag by containerd's events: a container created before it is removed, and made again.
    let create = format!("crictl create {sandbox} {dir}/container.json {dir}/pod.json");
    let deadline = Instant::now() + Duration::from_secs(10);
    let refused = loop {
        let out = worker
            .cluster
            .exec_output(&worker.node, &["sh", "-c", &create])
            .unwrap();
        if out.success {
            worker.sh(&format!("crictl rm {}", out.stdout.trim()));
        } else if out.stderr.contains(MISMATCH) || Instant::now() > deadline {
            break out.stderr;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    worker.sh(&format!(
        "crictl rmp -f {sandbox} >/dev/null && rm -rf {dir}"
    ));
    assert!(refused.contains(MISMATCH), "{refused}");
    assert!(remove(worker, id) && remove(worker, b));
}
