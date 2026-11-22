//! The gate on a cached verdict, on each identity path (D107, D172): its decision alone, and the whole `CreateContainer`
//! from the request's bytes on NRI's socket to the answer's.

use std::future::{Future, pending};
use std::hint::black_box;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use divan::Bencher;
use metrics_exporter_prometheus::PrometheusHandle;
use speculaire_agent::gate::Gate;
use speculaire_agent::gate::decision::{Decider, Decision, Settings, Verifier};
use speculaire_agent::log::AUDIT_TARGET;
use speculaire_agent::status::Status;
use speculaire_agent::{config, telemetry};
use speculaire_fake_runtime::{Answers, Fake, Snapshot};
use speculaire_mirror::listed::Listed;
use speculaire_nri::api::{self, Container, CreateContainerRequest, PodSandbox};
use speculaire_nri::{Answer, NriVersion, testing};
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_runtime::containerd::Containerd;
use speculaire_runtime::cri::ListedImage;
use speculaire_runtime::detect::Runtime;
use speculaire_runtime::identity::annotation::{Annotation, IMAGE_NAME};
use speculaire_runtime::identity::{IMAGE_REF, NodeIdentity};
use speculaire_runtime::images::{Image, Images, List, Update};
use speculaire_runtime::paths::Paths;
use speculaire_verify::{Absent, Key, Lookup, MatchHash, Policies, Verdict, Verdicts};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tracing::subscriber::DefaultGuard;
use tracing_subscriber::Layer as _;
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::layer::SubscriberExt as _;

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

const NAME: &str = "registry.test/team/app:1.0";

/// The container's ID, which is also its snapshot's key on containerd.
const CONTAINER_ID: &str = "4f9e0c8d2b7a6153e4d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7";

/// The pod's ID.
const POD_ID: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";

/// The ttrpc stream of each `CreateContainer` call.
const STREAM: u32 = 1001;

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

/// The gate's settings in every benchmark: `enforce`, which rejects unless the verdict allows.
const GATE: &str = "[gate]\nmode = \"enforce\"\n[gate.exempt]\nnamespaces = [\"kube-system\"]\n";

/// The image every container runs, as `image` puts it in containerd's content store.
#[derive(Clone)]
struct Pulled {
    /// The index, which containerd lists and keys verdicts by.
    target: Digest,
    /// Its one manifest, which CRI-O lists as a repository digest.
    manifest: Digest,
    /// The manifest's config: the image ID.
    config: Digest,
    /// The chain ID of its 16 layers.
    chain: Digest,
}

/// Puts in containerd's content store under `root` an index over one manifest of 16 layers.
fn image(root: &std::path::Path) -> Pulled {
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
    Pulled {
        target,
        manifest,
        config,
        chain,
    }
}

/// A fake containerd 2.3 on `dir`, whose store holds `NAME` and whose container snapshot rests on `pulled`, and the
/// identity that reads it.
fn containerd(dir: &std::path::Path, pulled: &Pulled) -> (Fake, NodeIdentity) {
    let socket = dir.join("containerd.sock");
    let mut answers = Answers::containerd("2.3.7");
    answers.image_store = vec![(NAME.to_owned(), pulled.target.to_string())];
    answers.snapshots = vec![Snapshot {
        snapshotter: "overlayfs".to_owned(),
        key: CONTAINER_ID.to_owned(),
        parent: pulled.chain.to_string(),
        labels: Vec::new(),
    }];
    let fake = Fake::start(&socket, answers).expect("a fake containerd");
    let host = Host {
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        variant: String::new(),
    };
    let containerd = Containerd::new(Paths::under(dir), &socket, None);
    (
        fake,
        NodeIdentity::containerd(Annotation::new(containerd, host)),
    )
}

/// The runtime's image list: `NAME`, pulled by its index on containerd and by its manifest on CRI-O.
fn list(pulled: &Pulled, runtime: Runtime) -> List {
    let pulled_by = match runtime {
        Runtime::Containerd => &pulled.target,
        Runtime::CriO => &pulled.manifest,
    };
    let listed = ListedImage {
        id: pulled.config.to_string(),
        repo_tags: vec![NAME.to_owned()],
        repo_digests: vec![format!("registry.test/team/app@{pulled_by}")],
    };
    let mut list = List::default();
    list.apply(Update::Listing(
        Image::from_listed(&listed).into_iter().collect(),
    ));
    list
}

/// The verifier's side, with an `Allow` kept under `POLICY` for both the index and the manifest of `pulled`.
fn verifier(pulled: &Pulled) -> Verifier {
    let policies = Policies::parse(POLICY).expect("the policy parses");
    let verdicts = Arc::new(Verdicts::default());
    for image in [&pulled.target, &pulled.manifest] {
        let key = Key {
            image,
            policies: MatchHash::of(policies.iter()),
            root: None,
        };
        verdicts.keep(key, Verdict::Allow);
    }
    Verifier {
        verdicts,
        policies: watch::channel(Arc::new(policies)).1,
        trust: watch::channel(Err(Absent::new("none in the benchmark"))).1,
        asker: mpsc::unbounded_channel().0,
        synchronized: Arc::default(),
    }
}

fn gate_settings() -> config::Gate {
    config::parse(GATE).expect("the settings parse").gate
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
            black_box(&self.request),
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

/// An identity path, as the runtime and the NRI version it announces choose it (D169, D170).
#[derive(Clone, Copy, Debug)]
enum Path {
    /// containerd 2.4: `Container.image`.
    Nri,
    /// containerd 2.3: the image name containerd annotates, and one snapshot `Stat`.
    Annotation,
    /// CRI-O: the image ID it annotates.
    ImageId,
}

impl Path {
    /// What the runtime's side of NRI says in `Configure`.
    fn runtime(self) -> testing::Runtime {
        let (name, version, nri_version) = match self {
            Self::Nri => ("containerd", "2.4.2", "v0.12.3"),
            Self::Annotation => ("containerd", "2.3.7", "v0.12.0"),
            Self::ImageId => ("cri-o", "1.37.2", "v0.12.2"),
        };
        testing::Runtime {
            name: name.to_owned(),
            version: version.to_owned(),
            nri_version: nri_version.to_owned(),
            request_timeout: Duration::from_secs(2),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Nri => "nri",
            Self::Annotation => "annotation",
            Self::ImageId => "image_id",
        }
    }
}

/// The recorder every [`Wire`] records to, as the agent installs it.
static METRICS: LazyLock<PrometheusHandle> =
    LazyLock::new(|| telemetry::install().expect("the only recorder"));

/// A list that holds the images it is given, and never changes.
struct Fixed(List);

impl Images for Fixed {
    fn follow(
        self: Arc<Self>,
        updates: mpsc::Sender<Update>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        Box::pin(async move {
            let images = self.0.images().cloned().collect();
            // A closed channel means the list is no longer read, which ends the benchmark first.
            let _ = updates.send(Update::Listing(images)).await;
            pending::<()>().await;
        })
    }
}

/// The gate as the agent starts it, registered on NRI's socket by this thread, which plays the runtime: each sample
/// writes a `CreateContainer` call's bytes and reads the answer's. Every task runs on this thread, where the allocations
/// are counted.
struct Wire {
    runtime: tokio::runtime::Runtime,
    trunk: UnixStream,
    /// The call's bytes on the trunk.
    call: Vec<u8>,
    /// The answer's, kept between samples.
    answer: Vec<u8>,
    _gate: Gate,
    _fake: Option<Fake>,
    _audit: Option<DefaultGuard>,
    _dir: tempfile::TempDir,
}

impl Wire {
    /// The gate on `path`, writing each `gate` audit event to nowhere when `audit` is set.
    fn start(path: Path, audit: bool) -> Self {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let pulled = image(dir.path());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        let audit = audit.then(|| {
            let layer = tracing_subscriber::fmt::layer()
                .json()
                .with_writer(std::io::sink)
                .with_filter(filter_fn(|meta| meta.target() == AUDIT_TARGET));
            tracing::subscriber::set_default(tracing_subscriber::registry().with(layer))
        });
        let (fake, identity, kind) = match path {
            Path::Nri | Path::Annotation => {
                let (fake, identity) = containerd(dir.path(), &pulled);
                (Some(fake), identity, Runtime::Containerd)
            }
            Path::ImageId => (None, NodeIdentity::crio(), Runtime::CriO),
        };
        let socket = dir.path().join("nri.sock");
        let status = Arc::new(Status::new(METRICS.clone(), false));
        let (gate, trunk) = runtime.block_on(async {
            let listener = UnixListener::bind(&socket).expect("NRI's socket");
            let listed = Listed::follow(Arc::new(Fixed(list(&pulled, kind))));
            let gate = Gate::start(
                socket.clone(),
                kind,
                (identity, listed),
                verifier(&pulled),
                &gate_settings(),
                status,
            );
            let (mut trunk, _) = listener.accept().await.expect("the gate connects");
            path.runtime()
                .register(&mut trunk)
                .await
                .expect("the gate registers");
            (gate, trunk)
        });
        let payload = payload(path, &pulled);
        let mut wire = Self {
            runtime,
            trunk,
            call: testing::call(STREAM, "CreateContainer", &payload, Duration::from_secs(2)),
            answer: Vec::new(),
            _gate: gate,
            _fake: fake,
            _audit: audit,
            _dir: dir,
        };
        // The store is read, the list kept and the chain ID cached before the first sample.
        while wire.create() != Answer::Allow {
            std::thread::sleep(Duration::from_millis(5));
        }
        wire
    }

    /// Writes the call, and reads its answer.
    fn create(&mut self) -> Answer {
        let Self {
            runtime,
            trunk,
            call,
            answer,
            ..
        } = self;
        runtime.block_on(async {
            trunk.write_all(black_box(call)).await.expect("the call");
            testing::answer(trunk, answer).await.expect("an answer")
        })
    }
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

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Protobuf's wire format, enough to write NRI's messages whole: the crate's subset of them leaves fields out, which a
/// runtime sends and the plugin skips.
#[derive(Default)]
struct Proto(Vec<u8>);

impl Proto {
    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.0.push(value.to_le_bytes()[0] | 0x80);
            value >>= 7;
        }
        self.0.push(value.to_le_bytes()[0]);
    }

    fn tag(&mut self, field: u32, wire_type: u8) {
        self.varint(u64::from(field) << 3 | u64::from(wire_type));
    }

    fn uint(&mut self, field: u32, value: u64) {
        self.tag(field, 0);
        self.varint(value);
    }

    fn bytes(&mut self, field: u32, value: &[u8]) {
        self.tag(field, 2);
        self.varint(u64::try_from(value.len()).expect("a length fits in u64"));
        self.0.extend_from_slice(value);
    }

    fn string(&mut self, field: u32, value: &str) {
        self.bytes(field, value.as_bytes());
    }

    fn strings(&mut self, field: u32, values: &[&str]) {
        for value in values {
            self.string(field, value);
        }
    }

    fn message(&mut self, field: u32, write: impl FnOnce(&mut Self)) {
        let mut message = Self::default();
        write(&mut message);
        self.bytes(field, &message.0);
    }

    fn map(&mut self, field: u32, entries: &[(&str, &str)]) {
        for (key, value) in entries {
            self.message(field, |entry| {
                entry.string(1, key);
                entry.string(2, value);
            });
        }
    }

    /// An `OptionalInt`, `OptionalInt64` or `OptionalUInt64`: a message of one `value`.
    fn optional(&mut self, field: u32, value: u64) {
        self.message(field, |optional| optional.uint(1, value));
    }
}

/// The `CreateContainerRequest` of a Deployment's container on `path`, as NRI v0.12.3's `pkg/api/api.proto` carries
/// it and the runtime fills it: about 20 labels and annotations on the pod, the container's environment, mounts and
/// Linux settings. Only containerd 2.4 fills `Container.image` (D15, D169); CRI-O annotates its image ID (D65).
fn payload(path: Path, pulled: &Pulled) -> Vec<u8> {
    let target = pulled.target.to_string();
    let config = pulled.config.to_string();
    let mut request = Proto::default();
    request.message(1, |pod| {
        pod.string(1, POD_ID);
        pod.string(2, "app-7d9f8b6c5d-x2k4q");
        pod.string(3, "3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b");
        pod.string(4, "team");
        pod.map(5, &POD_LABELS);
        pod.map(6, &POD_ANNOTATIONS);
        pod.message(8, |linux| {
            linux.string(
                3,
                "kubepods-burstable-pod3f1c2a9e_8b7d_4e6f_9a1b_2c3d4e5f6a7b.slice",
            );
            for (kind, path) in NAMESPACES {
                linux.message(5, |namespace| {
                    namespace.string(1, kind);
                    namespace.string(2, path);
                });
            }
        });
        pod.uint(9, 48_213);
        pod.strings(10, &["10.244.1.17", "fd00:10:244:1::11"]);
    });
    request.message(2, |container| {
        container.string(1, CONTAINER_ID);
        container.string(2, POD_ID);
        container.string(3, "app");
        container.map(5, &CONTAINER_LABELS);
        container.map(6, &CONTAINER_ANNOTATIONS);
        match path {
            Path::Nri | Path::Annotation => container.map(6, &[(IMAGE_NAME, NAME)]),
            Path::ImageId => container.map(
                6,
                &[
                    (IMAGE_REF, config.as_str()),
                    ("io.kubernetes.cri-o.ImageName", NAME),
                    ("io.kubernetes.cri-o.ContainerID", CONTAINER_ID),
                    ("io.kubernetes.cri-o.SandboxID", POD_ID),
                ],
            ),
        }
        container.strings(
            7,
            &[
                "/app/server",
                "--config=/etc/app/config.yaml",
                "--listen=:8080",
                "--log-level=info",
            ],
        );
        container.strings(8, &ENV);
        for (destination, source, options) in MOUNTS {
            container.message(9, |mount| {
                mount.string(1, destination);
                mount.string(2, "bind");
                mount.string(3, source);
                mount.strings(4, options);
            });
        }
        container.message(11, |linux| {
            for (kind, path) in NAMESPACES {
                linux.message(1, |namespace| {
                    namespace.string(1, kind);
                    namespace.string(2, if kind == "network" { path } else { "" });
                });
            }
            linux.message(3, |resources| {
                resources.message(1, |memory| memory.optional(1, 512 << 20));
                resources.message(2, |cpu| {
                    cpu.optional(1, 512);
                    cpu.optional(2, 50_000);
                    cpu.optional(3, 100_000);
                });
            });
            linux.optional(4, 985);
            linux.string(
                5,
                "kubepods-burstable-pod3f1c2a9e_8b7d_4e6f_9a1b_2c3d4e5f6a7b.slice:cri-containerd:4f9e0c8d2b7a",
            );
        });
        container.message(13, |rlimit| {
            rlimit.string(1, "RLIMIT_NOFILE");
            rlimit.uint(2, 1_048_576);
            rlimit.uint(3, 1_048_576);
        });
        container.message(21, |user| {
            user.uint(1, 65_532);
            user.uint(2, 65_532);
        });
        if let Path::Nri = path {
            container.message(22, |image| {
                image.string(1, NAME);
                image.string(2, &target);
                image.string(3, &config);
            });
        }
    });
    request.0
}

const POD_LABELS: [(&str, &str); 20] = [
    ("app", "app"),
    ("pod-template-hash", "7d9f8b6c5d"),
    ("app.kubernetes.io/name", "app"),
    ("app.kubernetes.io/instance", "app-production"),
    ("app.kubernetes.io/version", "1.0.0"),
    ("app.kubernetes.io/component", "server"),
    ("app.kubernetes.io/part-of", "shop"),
    ("app.kubernetes.io/managed-by", "Helm"),
    ("helm.sh/chart", "app-1.4.2"),
    ("io.kubernetes.pod.name", "app-7d9f8b6c5d-x2k4q"),
    ("io.kubernetes.pod.namespace", "team"),
    (
        "io.kubernetes.pod.uid",
        "3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b",
    ),
    ("team", "checkout"),
    ("environment", "production"),
    ("tier", "backend"),
    ("release", "app-production"),
    ("heritage", "Helm"),
    ("security.istio.io/tlsMode", "istio"),
    ("service.istio.io/canonical-name", "app"),
    ("service.istio.io/canonical-revision", "1.0.0"),
];

const POD_ANNOTATIONS: [(&str, &str); 18] = [
    (
        "kubernetes.io/config.seen",
        "2026-11-20T09:14:03.512345678Z",
    ),
    ("kubernetes.io/config.source", "api"),
    ("io.kubernetes.cri.container-type", "sandbox"),
    ("io.kubernetes.cri.sandbox-id", POD_ID),
    (
        "io.kubernetes.cri.sandbox-log-directory",
        "/var/log/pods/team_app-7d9f8b6c5d-x2k4q_3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b",
    ),
    ("io.kubernetes.cri.sandbox-name", "app-7d9f8b6c5d-x2k4q"),
    ("io.kubernetes.cri.sandbox-namespace", "team"),
    (
        "io.kubernetes.cri.sandbox-uid",
        "3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b",
    ),
    ("io.kubernetes.cri.sandbox-cpu-period", "100000"),
    ("io.kubernetes.cri.sandbox-cpu-quota", "50000"),
    ("io.kubernetes.cri.sandbox-cpu-shares", "512"),
    ("io.kubernetes.cri.sandbox-memory", "536870912"),
    ("prometheus.io/scrape", "true"),
    ("prometheus.io/port", "9090"),
    (
        "checksum/config",
        "0b3f1e9d8c7a6b5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a19",
    ),
    ("kubectl.kubernetes.io/restartedAt", "2026-11-19T17:02:44Z"),
    ("cluster-autoscaler.kubernetes.io/safe-to-evict", "true"),
    (
        "sidecar.istio.io/status",
        r#"{"initContainers":["istio-init"],"containers":["istio-proxy"],"volumes":["istio-envoy","istio-data","istio-podinfo","istio-token","istiod-ca-cert"],"imagePullSecrets":null,"revision":"default"}"#,
    ),
];

const CONTAINER_LABELS: [(&str, &str); 4] = [
    ("io.kubernetes.container.name", "app"),
    ("io.kubernetes.pod.name", "app-7d9f8b6c5d-x2k4q"),
    ("io.kubernetes.pod.namespace", "team"),
    (
        "io.kubernetes.pod.uid",
        "3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b",
    ),
];

const CONTAINER_ANNOTATIONS: [(&str, &str); 12] = [
    ("io.kubernetes.cri.container-name", "app"),
    ("io.kubernetes.cri.container-type", "container"),
    ("io.kubernetes.cri.sandbox-id", POD_ID),
    ("io.kubernetes.cri.sandbox-name", "app-7d9f8b6c5d-x2k4q"),
    ("io.kubernetes.cri.sandbox-namespace", "team"),
    (
        "io.kubernetes.cri.sandbox-uid",
        "3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b",
    ),
    ("io.kubernetes.container.hash", "8f2c4e1a"),
    ("io.kubernetes.container.restartCount", "0"),
    (
        "io.kubernetes.container.terminationMessagePath",
        "/dev/termination-log",
    ),
    ("io.kubernetes.container.terminationMessagePolicy", "File"),
    ("io.kubernetes.pod.terminationGracePeriod", "30"),
    (
        "io.kubernetes.container.ports",
        r#"[{"name":"http","containerPort":8080,"protocol":"TCP"},{"name":"metrics","containerPort":9090,"protocol":"TCP"}]"#,
    ),
];

const ENV: [&str; 24] = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOSTNAME=app-7d9f8b6c5d-x2k4q",
    "APP_ENV=production",
    "APP_LOG_FORMAT=json",
    "POD_NAME=app-7d9f8b6c5d-x2k4q",
    "POD_NAMESPACE=team",
    "POD_IP=10.244.1.17",
    "NODE_NAME=worker-3",
    "GOMAXPROCS=1",
    "GOMEMLIMIT=483183820",
    "KUBERNETES_SERVICE_HOST=10.96.0.1",
    "KUBERNETES_SERVICE_PORT=443",
    "KUBERNETES_SERVICE_PORT_HTTPS=443",
    "KUBERNETES_PORT=tcp://10.96.0.1:443",
    "KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443",
    "KUBERNETES_PORT_443_TCP_PROTO=tcp",
    "KUBERNETES_PORT_443_TCP_PORT=443",
    "KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1",
    "APP_SERVICE_HOST=10.96.143.27",
    "APP_SERVICE_PORT=80",
    "APP_PORT=tcp://10.96.143.27:80",
    "APP_PORT_80_TCP=tcp://10.96.143.27:80",
    "APP_PORT_80_TCP_PROTO=tcp",
    "APP_PORT_80_TCP_ADDR=10.96.143.27",
];

const NAMESPACES: [(&str, &str); 5] = [
    ("pid", ""),
    ("ipc", "/proc/48213/ns/ipc"),
    ("uts", "/proc/48213/ns/uts"),
    ("mount", ""),
    (
        "network",
        "/var/run/netns/cni-6f1d2c3b-4a5e-6f70-8192-a3b4c5d6e7f8",
    ),
];

const MOUNTS: [(&str, &str, &[&str]); 6] = [
    (
        "/etc/hosts",
        "/var/lib/kubelet/pods/3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b/etc-hosts",
        &["rbind", "rprivate", "rw"],
    ),
    (
        "/dev/termination-log",
        "/var/lib/kubelet/pods/3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b/containers/app/5c1d9e2f",
        &["rbind", "rprivate", "rw"],
    ),
    (
        "/etc/hostname",
        "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/a1b2c3d4e5f6/hostname",
        &["rbind", "rprivate", "rw"],
    ),
    (
        "/etc/resolv.conf",
        "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/a1b2c3d4e5f6/resolv.conf",
        &["rbind", "rprivate", "rw"],
    ),
    (
        "/dev/shm",
        "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/a1b2c3d4e5f6/shm",
        &["rbind", "rprivate", "rw"],
    ),
    (
        "/var/run/secrets/kubernetes.io/serviceaccount",
        "/var/lib/kubelet/pods/3f1c2a9e-8b7d-4e6f-9a1b-2c3d4e5f6a7b/volumes/kubernetes.io~projected/kube-api-access-7x2kq",
        &["rbind", "rprivate", "ro"],
    ),
];
