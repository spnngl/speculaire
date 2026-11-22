//! The gate on a cached verdict, on each identity path (D107, D172): its decision alone, and the whole `CreateContainer`
//! from the request's bytes on NRI's socket to the answer's.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use divan::Bencher;
use speculaire_agent::gate::decision::{Decider, Decision, Settings};
use speculaire_fake_runtime::Fake;
use speculaire_nri::api::{self, Container, CreateContainerRequest, PodSandbox};
use speculaire_nri::{Answer, NriVersion, create};
use speculaire_runtime::detect::Runtime;
use speculaire_runtime::identity::annotation::IMAGE_NAME;
use speculaire_verify::{Lookup, Verdict};
use tokio::sync::watch;
use tokio::time::Instant;
use wire::{CONTAINER_ID, NAME, Path, Wire, containerd, gate_settings, image, list, verifier};

#[path = "../tests/wire/mod.rs"]
mod wire;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

fn main() {
    divan::main();
}

/// A node on a fake containerd 2.3 whose store and list hold `NAME`, an index over one manifest of 16 layers, the
/// container's snapshot on them, and an `Allow` kept for the index under `POLICY`.
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
        let pulled = image(dir.path());
        let (fake, identity) = containerd(dir.path(), &pulled);
        identity.configure(&NriVersion::Announced(nri_version.to_owned()));
        let settings = Arc::new(Settings::new(&gate_settings()));
        let decider = Arc::new(Decider::new(
            Arc::new(identity),
            verifier(&pulled),
            watch::channel(Arc::clone(&settings)).1,
        ));
        // The runtime's list, which confirms the name the pod asked for on the `nri` path (D179).
        decider.keep(&list(&pulled, Runtime::Containerd));
        let request = CreateContainerRequest {
            pod: Some(PodSandbox {
                namespace: "default".to_owned(),
                ..PodSandbox::default()
            }),
            container: Some(Container {
                id: CONTAINER_ID.to_owned(),
                annotations: [(IMAGE_NAME.to_owned(), NAME.to_owned())].into(),
                image: Some(api::Image {
                    name: NAME.to_owned(),
                    digest: pulled.target.to_string(),
                    config_digest: pulled.config.to_string(),
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
            black_box(&create::Request::from(&self.request)),
            &self.settings,
            deadline,
        ))
    }
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

/// The whole `CreateContainer` on each path, with the `gate` audit event written or not (D37): the request decoded, the
/// decision, its metrics and the answer encoded and written. The verdict is kept, and `enforce` allows.
#[divan::bench(
    sample_count = 2000,
    sample_size = 1,
    consts = [false, true],
    args = [Path::Nri, Path::Annotation, Path::ImageId],
)]
fn request<const AUDIT: bool>(bencher: Bencher<'_, '_>, path: Path) {
    let mut wire = Wire::start(path, AUDIT);
    bencher.bench_local(|| assert_eq!(wire.create(), Answer::Allow));
}
