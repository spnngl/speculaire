//! The polls of the registry config (D93), the reads of a blob, whole or streamed, a lookup in the image store (D15),
//! and containerd 2.3's identity check (D170): `just bench-micro`.

use std::hint::black_box;
use std::sync::Arc;
use std::time::Duration;

use divan::Bencher;
use futures_util::TryStreamExt as _;
use speculaire_fake_runtime::{Answers, Fake, Snapshot};
use speculaire_nri::api::Container;
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_runtime::containerd::Containerd;
use speculaire_runtime::containerd::store::Store;
use speculaire_runtime::content::Blob;
use speculaire_runtime::identity::Identified;
use speculaire_runtime::identity::annotation::{Annotation, IMAGE_NAME};
use speculaire_runtime::paths::Paths;
use speculaire_runtime::registries::{ContainerdRegistries, Registries};

#[global_allocator]
static ALLOC: divan::AllocProfiler = divan::AllocProfiler::system();

/// The hosts below `config_path`, a `hosts.toml` each.
const HOSTS: usize = 16;

fn main() {
    divan::main();
}

/// A containerd `config.toml` whose `config_path` holds [`HOSTS`] hosts, read.
fn registries() -> (tempfile::TempDir, ContainerdRegistries) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let certs = dir.path().join("certs.d");
    for host in 0..HOSTS {
        let host = certs.join(format!("registry-{host}.test"));
        std::fs::create_dir_all(&host).expect("a host directory");
        std::fs::write(host.join("hosts.toml"), "[host.\"https://a.test\"]\n")
            .expect("a hosts.toml");
    }
    let config = dir.path().join("config.toml");
    let section = "plugins.\"io.containerd.cri.v1.images\".registry";
    let text = format!(
        "version = 3\n[{section}]\nconfig_path = {:?}\n",
        certs.display().to_string()
    );
    std::fs::write(&config, text).expect("a config.toml");
    let registries = ContainerdRegistries::new(config);
    registries.reload().expect("a read");
    (dir, registries)
}

/// A poll that finds nothing changed, as most do.
#[divan::bench]
fn unchanged(bencher: Bencher<'_, '_>) {
    let (_dir, registries) = registries();
    bencher.bench_local(|| registries.poll().is_none());
}

/// A poll after a `hosts.toml` changed, which reads the registry config again; the write is measured too. Each write
/// changes the length: a coarse file clock dates writes within one tick alike (D93).
#[divan::bench]
fn changed(bencher: Bencher<'_, '_>) {
    let (dir, registries) = registries();
    let hosts = dir.path().join("certs.d/registry-0.test/hosts.toml");
    let mut texts = [
        "[host.\"https://bb.test\"]\n",
        "[host.\"https://a.test\"]\n",
    ]
    .into_iter()
    .cycle();
    bencher.bench_local(|| {
        std::fs::write(&hosts, texts.next().unwrap_or_default()).expect("a write");
        registries.poll().expect("a change")
    });
}

/// A blob of `size` bytes read whole from a file, as the mirror reads a manifest it serves.
#[divan::bench(args = [2 << 10, 64 << 10])]
fn read_all(bencher: Bencher<'_, '_>, size: usize) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("blob");
    std::fs::write(&path, vec![0x5a; size]).expect("a blob");
    let length = std::fs::metadata(&path).expect("the blob").len();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    bencher.bench_local(|| {
        let blob = Blob::from_open(std::fs::File::open(&path).expect("the blob"), length);
        runtime.block_on(blob.read_all(length)).expect("the blob")
    });
}

/// A layer of 16 MiB streamed from a file, its chunks held as a response body in flight holds them.
#[divan::bench]
fn stream(bencher: Bencher<'_, '_>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("blob");
    std::fs::write(&path, vec![0x5a; 16 << 20]).expect("a blob");
    let length = std::fs::metadata(&path).expect("the blob").len();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    bencher.bench_local(|| {
        let blob = Blob::from_open(std::fs::File::open(&path).expect("the blob"), length);
        runtime.block_on(async {
            let chunks = blob.stream(0, length).await.expect("a stream");
            chunks.try_collect::<Vec<_>>().await.expect("the chunks")
        })
    });
}

/// A lookup in an image store of 1k names, as the gate makes one while it holds the runtime's NRI call: no allocation
/// (D107).
#[divan::bench]
fn store_get(bencher: Bencher<'_, '_>) {
    let digest =
        Digest::parse("sha256:6c3c624b58dbbcd3c0dd82b4c53f04194d1247c6eebdaab7c610cf7d66709b3b")
            .expect("a valid digest");
    let store: Store = (0..1000)
        .map(|n| (format!("registry.test/team/image-{n}:1.0"), digest.clone()))
        .collect();
    bencher.bench_local(|| store.get(black_box("registry.test/team/image-500:1.0")));
}

/// containerd 2.3's identity check of one container against a fake containerd, as the gate makes it in NRI's
/// `CreateContainer`: a lookup in the image store, the image's chain ID kept, one snapshot `Stat` over the socket (D15,
/// D170). Its p99 is under 5 ms: so is the slowest of the samples.
#[divan::bench(sample_count = 2000, sample_size = 1)]
fn identity_check(bencher: Bencher<'_, '_>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let blobs = dir
        .path()
        .join("var/lib/containerd/io.containerd.content.v1.content/blobs/sha256");
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
    let socket = dir.path().join("containerd.sock");
    let mut answers = Answers::containerd("2.3.7");
    answers.image_store = vec![("registry.test/team/app:1.0".to_owned(), target.to_string())];
    answers.snapshots = vec![Snapshot {
        key: "container".to_owned(),
        parent: chain.to_string(),
        labels: Vec::new(),
    }];
    let _fake = Fake::start(&socket, answers).expect("a fake containerd");
    let host = Host {
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        variant: String::new(),
    };
    let containerd = Containerd::new(Paths::under(dir.path()), &socket, None);
    let annotation = Arc::new(Annotation::new(containerd, host));
    let container = Container {
        id: "container".to_owned(),
        annotations: [(
            IMAGE_NAME.to_owned(),
            "registry.test/team/app:1.0".to_owned(),
        )]
        .into(),
        ..Container::default()
    };
    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    let following = Arc::clone(&annotation);
    runtime.spawn(async move { following.follow().await });
    // The store is read, and the chain ID kept, before the first sample.
    runtime.block_on(async {
        while !matches!(
            annotation.identify(&container).await,
            Identified::Listed { .. }
        ) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });
    bencher.bench_local(|| {
        let identified = runtime.block_on(annotation.identify(black_box(&container)));
        assert!(matches!(identified, Identified::Listed { .. }));
    });
}
