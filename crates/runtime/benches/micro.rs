//! The polls of the registry config (D93) and the reads of a blob, whole or streamed: `just bench-micro`.

use divan::Bencher;
use futures_util::TryStreamExt as _;
use speculaire_runtime::content::Blob;
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
