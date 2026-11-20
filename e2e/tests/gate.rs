//! The gate on the nodes' real runtimes (D9, D15, D41, D64, D168): containerd's image store and snapshots, the gate's
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

use e2e::{Cluster, IpFamily, Runtime};
use speculaire_oci::chain::of_config;
use speculaire_oci::index::Index;
use speculaire_oci::manifest::{Children, children};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_runtime::containerd::Containerd;
use speculaire_runtime::containerd::store::Store;
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
fn the_gate_reads_the_image_identity_from_nri_on_containerd_and_from_the_image_id_on_cri_o() {
    let Some(worker) = Worker::new() else { return };
    // containerd 2.3 takes step 07's `annotation` path.
    let release = worker.cluster.release();
    let path = match worker.cluster.runtime() {
        Runtime::Containerd if release.starts_with("2.3.") => return,
        Runtime::Containerd => "nri",
        Runtime::Crio => "image_id",
    };
    assert_eq!(
        worker.series("speculaire_identity_path"),
        [format!(r#"path="{path}"}} 1"#)]
    );
    // No warning of an identity gap, which the `annotation` path alone has (D15, D169).
    let warnings = worker.sh("journalctl -u speculaire -p warning -o cat --no-pager");
    assert!(
        !warnings.to_lowercase().contains("image identity"),
        "{warnings}"
    );
}
