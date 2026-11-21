//! The gate's whole decision on a cached verdict, on each containerd identity path (D107, D172).

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use divan::Bencher;
use speculaire_agent::config;
use speculaire_agent::gate::decision::{Decider, Decision, Settings, Verifier};
use speculaire_fake_runtime::{Answers, Fake, Snapshot};
use speculaire_nri::NriVersion;
use speculaire_nri::api::{self, Container, CreateContainerRequest, PodSandbox};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_runtime::containerd::Containerd;
use speculaire_runtime::identity::NodeIdentity;
use speculaire_runtime::identity::annotation::{Annotation, IMAGE_NAME};
use speculaire_runtime::paths::Paths;
use speculaire_verify::{Absent, Key, Lookup, MatchHash, Policies, Verdict, Verdicts};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

const NAME: &str = "registry.test/team/app:1.0";

fn main() {
    divan::main();
}

/// The policy over `registry.test/team/app`.
const POLICY: &str = "apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: app
spec:
  images:
  - glob: registry.test/team/app
  authorities:
  - keyless:
      identities:
      - issuer: https://issuer.test
        subject: someone
";

/// A node on a fake containerd 2.3 whose store holds `NAME`, an index over one manifest of 16 layers, the container's
/// snapshot on them, and an `Allow` kept for the index under `POLICY`.
struct Node {
    _dir: tempfile::TempDir,
    _fake: Fake,
    runtime: tokio::runtime::Runtime,
    decider: Arc<Decider>,
    settings: Arc<Settings>,
    request: CreateContainerRequest,
}

impl Node {
    fn start(nri_version: &str) -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let (target, config, chain) = image(dir.path());
        let socket = dir.path().join("containerd.sock");
        let mut answers = Answers::containerd("2.3.7");
        answers.image_store = vec![(NAME.to_owned(), target.to_string())];
        answers.snapshots = vec![Snapshot {
            snapshotter: "overlayfs".to_owned(),
            key: "container".to_owned(),
            parent: chain.to_string(),
            labels: Vec::new(),
        }];
        let fake = Fake::start(&socket, answers).expect("a fake containerd");
        let host = Host {
            os: "linux".to_owned(),
            arch: "amd64".to_owned(),
            variant: String::new(),
        };
        let containerd = Containerd::new(Paths::under(dir.path()), &socket, None);
        let identity = NodeIdentity::containerd(Annotation::new(containerd, host));
        identity.configure(&NriVersion::Announced(nri_version.to_owned()));

        let policies = Policies::parse(POLICY).expect("the policy parses");
        let verdicts = Arc::new(Verdicts::default());
        let key = Key {
            image: &target,
            policies: MatchHash::of(policies.iter()),
            root: None,
        };
        verdicts.keep(key, Verdict::Allow);
        let verifier = Verifier {
            verdicts,
            policies: watch::channel(Arc::new(policies)).1,
            trust: watch::channel(Err(Absent::new("none in the benchmark"))).1,
            asker: mpsc::unbounded_channel().0,
        };
        let gate = config::parse(
            "[gate]\nmode = \"enforce\"\n[gate.exempt]\nnamespaces = [\"kube-system\"]\n",
        )
        .expect("the settings parse")
        .gate;
        let settings = Arc::new(Settings::new(&gate));
        let decider = Arc::new(Decider::new(
            Arc::new(identity),
            verifier,
            watch::channel(Arc::clone(&settings)).1,
        ));
        let request = CreateContainerRequest {
            pod: Some(PodSandbox {
                namespace: "default".to_owned(),
                ..PodSandbox::default()
            }),
            container: Some(Container {
                id: "container".to_owned(),
                annotations: [(IMAGE_NAME.to_owned(), NAME.to_owned())].into(),
                image: Some(api::Image {
                    name: NAME.to_owned(),
                    digest: target.to_string(),
                    config_digest: config.to_string(),
                }),
                ..Container::default()
            }),
        };
        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let following = Arc::clone(&decider);
        runtime.spawn(async move { following.identity().follow().await });
        let node = Self {
            _dir: dir,
            _fake: fake,
            runtime,
            decider,
            settings,
            request,
        };
        // The store is read, and the chain ID kept, before the first sample.
        while node.decide() != allowed() {
            std::thread::sleep(Duration::from_millis(5));
        }
        node
    }

    fn decide(&self) -> Decision {
        let deadline = Instant::now() + Duration::from_secs(1);
        self.runtime.block_on(self.decider.decide(
            black_box(&self.request),
            &self.settings,
            deadline,
        ))
    }
}

/// Puts in containerd's content store under `root` an index over one manifest of 16 layers, and returns its digest, its
/// manifest's config digest and its chain ID.
fn image(root: &std::path::Path) -> (Digest, Digest, Digest) {
    let blobs = root.join("var/lib/containerd/io.containerd.content.v1.content/blobs/sha256");
    std::fs::create_dir_all(&blobs).expect("a content directory");
    let put = |value: serde_json::Value| {
        let bytes = serde_json::to_vec(&value).expect("JSON");
        let digest = speculaire_oci::hash::of("sha256", &bytes).expect("SHA-256 hashes");
        std::fs::write(blobs.join(digest.encoded()), bytes).expect("a blob");
        digest
    };
    let diff_ids: Vec<Digest> = (0..16_u8)
        .map(|layer| {
            Digest::parse(&format!("sha256:{}", format!("{layer:02x}").repeat(32)))
                .expect("a digest")
        })
        .collect();
    let config = put(serde_json::json!({
        "architecture": "amd64", "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": diff_ids.iter().map(ToString::to_string).collect::<Vec<_>>()},
    }));
    let manifest = put(serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config.to_string(), "size": 1},
        "layers": [],
    }));
    let target = put(serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest.to_string(), "size": 1,
            "platform": {"os": "linux", "architecture": "amd64"},
        }],
    }));
    let chain = speculaire_oci::chain::chain_id(&diff_ids).expect("layers");
    (target, config, chain)
}

fn allowed() -> Decision {
    Decision::Verdict(Lookup {
        verdict: Verdict::Allow,
        stale: false,
    })
}

/// The decision on containerd 2.4's path, the identity in the request (D169). Its p99 is under 5 ms: so is the
/// slowest of the samples.
#[divan::bench(sample_count = 2000, sample_size = 1)]
fn decide_nri(bencher: Bencher<'_, '_>) {
    let node = Node::start("v0.12.3");
    assert_eq!(node.decider.identity().path(), "nri");
    bencher.bench_local(|| assert_eq!(node.decide(), allowed()));
}

/// The decision on containerd 2.3's path: the image store lookup, the chain ID kept, one snapshot `Stat` (D170).
#[divan::bench(sample_count = 2000, sample_size = 1)]
fn decide_annotation(bencher: Bencher<'_, '_>) {
    let node = Node::start("v0.12.0");
    assert_eq!(node.decider.identity().path(), "annotation");
    bencher.bench_local(|| assert_eq!(node.decide(), allowed()));
}
