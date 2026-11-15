//! The polls of the registry config (D93): `just bench-micro`.

use divan::Bencher;
use speculaire_runtime::registries::{ContainerdRegistries, Registries};

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
