//! The gate on the nodes' real runtimes (D15).
//!
//! containerd's socket of a worker is relayed to this host, one `docker exec` per connection, so the runtime crate's
//! clients run here against it.
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};

use e2e::{Cluster, Runtime};
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
