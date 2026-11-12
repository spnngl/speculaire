//! `configure`, `unconfigure` and `check` on a temporary tree standing for a node's root.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use speculaire_runtime::containerd::ImageExports;
use speculaire_runtime::crio::Nri;

use super::*;

const NOW: Duration = Duration::from_hours(500_000);

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + NOW
}

/// What a test sets on the fake: CRI-O's NRI answer, whether a reload fails, and what exists at each reload.
struct Fake {
    required: RefCell<Vec<String>>,
    /// CRI-O's `enable_nri` and `nri_disable_connections`.
    nri: Cell<(bool, bool)>,
    /// Whether CRI-O's inspect API answers.
    inspect_fails: Cell<bool>,
    /// What `RuntimeService.Version` answers as (name, version); `None`: nothing listens.
    version: RefCell<Option<(String, String)>>,
    /// What containerd's introspection exports; the outer `Err` is a failed call.
    exports: RefCell<Result<Option<ImageExports>, ()>>,
    reload_fails: Cell<bool>,
    reloads: Cell<u32>,
    watch: RefCell<Option<PathBuf>>,
    seen: RefCell<Vec<bool>>,
}

impl Fake {
    fn new() -> Self {
        Self {
            required: RefCell::new(Vec::new()),
            nri: Cell::new((true, false)),
            inspect_fails: Cell::new(false),
            version: RefCell::new(Some(("containerd".to_owned(), "v2.4.2".to_owned()))),
            exports: RefCell::new(Ok(Some(ImageExports {
                discard_unpacked_layers: false,
                registry_config_path: "/etc/containerd/certs.d".to_owned(),
            }))),
            reload_fails: Cell::new(false),
            reloads: Cell::new(0),
            watch: RefCell::new(None),
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl Host for Fake {
    fn reload_crio(&self) -> io::Result<()> {
        self.reloads.set(self.reloads.get() + 1);
        if let Some(path) = &*self.watch.borrow() {
            self.seen.borrow_mut().push(path.exists());
        }
        if self.reload_fails.get() {
            Err(io::Error::other("no systemd"))
        } else {
            Ok(())
        }
    }

    fn crio_nri(&self) -> Result<Nri, speculaire_runtime::crio::Error> {
        if self.inspect_fails.get() {
            return Err(speculaire_runtime::crio::Error::Response(
                "\"HTTP/1.0 503\"".to_owned(),
            ));
        }
        let (enabled, disable_connections) = self.nri.get();
        Ok(Nri {
            enabled,
            disable_connections,
            required_plugins: self.required.borrow().clone(),
        })
    }

    fn socket(&self, runtime: Runtime) -> PathBuf {
        PathBuf::from(format!("/run/{runtime}.sock"))
    }

    fn runtime_version(&self, runtime: Runtime) -> Result<RuntimeVersion, cri::Error> {
        match &*self.version.borrow() {
            Some((name, version)) => Ok(RuntimeVersion {
                name: name.clone(),
                version: version.clone(),
            }),
            None => Err(cri::Error::Connect {
                path: self.socket(runtime),
                message: "connection refused".to_owned(),
            }),
        }
    }

    fn containerd_image_exports(&self) -> Result<Option<ImageExports>, cri::Error> {
        self.exports
            .borrow()
            .clone()
            .map_err(|()| cri::Error::Call {
                path: self.socket(Runtime::Containerd),
                method: "Plugins",
                message: "Unavailable".to_owned(),
            })
    }
}

fn put(path: &Path, text: &str) -> PathBuf {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    path.to_owned()
}

struct Node {
    dir: tempfile::TempDir,
    paths: Paths,
    settings: Settings,
}

impl Node {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings {
            address: "127.0.0.1:7480".parse().unwrap(),
            registries: ["docker.io", "registry.k8s.io"].map(str::to_owned).to_vec(),
            directory: dir.path().join("var/lib/speculaire/mirror"),
        };
        Self {
            paths: Paths::under(dir.path()),
            dir,
            settings,
        }
    }

    fn certs_d(&self) -> PathBuf {
        self.dir.path().join("etc/containerd/certs.d")
    }

    /// A containerd node as the e2e images are: `config_path` set, no `certs.d` content.
    fn containerd(&self) {
        put(
            &self.paths.containerd_config(),
            &format!(
                "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"{}\"\n",
                self.certs_d().display()
            ),
        );
    }

    /// Every file under the root, with its contents and mode.
    fn tree(&self) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
        fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, (Vec<u8>, u32)>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    let mode = std::fs::metadata(&path).unwrap().mode() & 0o7777;
                    out.insert(path.clone(), (std::fs::read(&path).unwrap(), mode));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(self.dir.path(), &mut out);
        out
    }

    fn configure(&self, runtime: Runtime, host: &Fake) -> Result<Report, Error> {
        configure(runtime, &self.paths, &self.settings, now(), host)
    }

    fn unconfigure(&self, runtime: Runtime, force: bool, host: &Fake) -> Result<Report, Error> {
        unconfigure(runtime, &self.paths, &self.settings, force, host)
    }

    fn check(&self, runtime: Runtime) -> Vec<String> {
        check(runtime, &self.paths, &self.settings, now())
            .unwrap()
            .iter()
            .map(|p| p.to_string().replace(self.dir.path().to_str().unwrap(), ""))
            .collect()
    }
}

const DOCKER_IO: &str = "# docker.io, through the corporate proxy\nserver = \"https://registry-1.docker.io\"\n\n[host.\"https://proxy.corp\"]\n  capabilities = [\"pull\", \"resolve\"]\n";

// ---- containerd ----

#[test]
fn configure_makes_the_certificates_and_puts_the_mirror_first_in_every_hosts_toml() {
    let node = Node::new();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    let fake = Fake::new();
    let report = node.configure(Runtime::Containerd, &fake).unwrap();
    let tree = node.tree();
    let mirror = node.dir.path().join("var/lib/speculaire/mirror");
    for (name, mode) in [
        ("ca.crt", 0o644),
        ("server.crt", 0o644),
        ("server.key", 0o600),
        ("client.pem", 0o600),
    ] {
        assert_eq!(tree[&mirror.join(name)].1, mode, "{name}");
    }
    let docker =
        String::from_utf8(tree[&node.certs_d().join("docker.io/hosts.toml")].0.clone()).unwrap();
    insta::assert_snapshot!(
        "node-docker-io",
        docker.replace(node.dir.path().to_str().unwrap(), "<root>")
    );
    let default =
        String::from_utf8(tree[&node.certs_d().join("_default/hosts.toml")].0.clone()).unwrap();
    insta::assert_snapshot!(
        "node-default",
        default.replace(node.dir.path().to_str().unwrap(), "<root>")
    );
    assert_eq!(
        report.changes.len(),
        4 + 2,
        "four certificates, two hosts.toml"
    );
    assert_eq!(
        fake.reloads.get(),
        0,
        "containerd reads hosts.toml on every pull"
    );
    assert_eq!(node.check(Runtime::Containerd), Vec::<String>::new());
}

#[test]
fn a_second_run_changes_nothing_byte_for_byte() {
    let node = Node::new();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    let once = node.tree();
    let report = node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    assert_eq!(report.changes, []);
    assert_eq!(node.tree(), once);
    node.unconfigure(Runtime::Containerd, false, &Fake::new())
        .unwrap();
    let off = node.tree();
    let report = node
        .unconfigure(Runtime::Containerd, false, &Fake::new())
        .unwrap();
    assert_eq!(report.changes, []);
    assert_eq!(node.tree(), off);
}

#[test]
fn unconfigure_removes_what_configure_added_and_keeps_the_admins_edits() {
    let node = Node::new();
    node.containerd();
    let docker = put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    let before = node.tree();
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    // An edit made after `configure`.
    let edited = std::fs::read_to_string(&docker).unwrap().replace(
        "pull\", \"resolve\"]\n",
        "pull\", \"resolve\"]\n  skip_verify = true\n",
    );
    std::fs::write(&docker, &edited).unwrap();
    let report = node
        .unconfigure(Runtime::Containerd, false, &Fake::new())
        .unwrap();
    let after = node.tree();
    assert_eq!(
        String::from_utf8(after[&docker].0.clone()).unwrap(),
        DOCKER_IO.replace(
            "pull\", \"resolve\"]\n",
            "pull\", \"resolve\"]\n  skip_verify = true\n"
        )
    );
    assert!(
        !node.certs_d().join("_default").exists(),
        "the file configure made, and its directory"
    );
    assert!(!node.dir.path().join("var/lib/speculaire/mirror").exists());
    assert!(report.changes.len() >= 6, "{:?}", report.changes);
    // Without the edit, everything is as it was.
    std::fs::write(&docker, DOCKER_IO).unwrap();
    assert_eq!(
        node.tree().keys().collect::<Vec<_>>(),
        before.keys().collect::<Vec<_>>()
    );
}

#[test]
fn a_new_address_moves_the_entries_and_the_certificates_follow() {
    let mut node = Node::new();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    let ca_before = node.tree()[&node.dir.path().join("var/lib/speculaire/mirror/ca.crt")]
        .0
        .clone();
    node.settings.address = "127.0.0.2:7481".parse().unwrap();
    assert!(
        node.check(Runtime::Containerd)
            .iter()
            .any(|p| p.contains("hosts.toml") && p.contains("127.0.0.2:7481")),
        "check names the files that still point at the old address"
    );
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    let tree = node.tree();
    let docker =
        String::from_utf8(tree[&node.certs_d().join("docker.io/hosts.toml")].0.clone()).unwrap();
    assert!(
        docker.contains("127.0.0.2:7481") && !docker.contains("127.0.0.1:7480"),
        "{docker}"
    );
    assert_ne!(
        tree[&node.dir.path().join("var/lib/speculaire/mirror/ca.crt")].0,
        ca_before
    );
    assert_eq!(node.check(Runtime::Containerd), Vec::<String>::new());
    node.unconfigure(Runtime::Containerd, false, &Fake::new())
        .unwrap();
    let docker = std::fs::read_to_string(node.certs_d().join("docker.io/hosts.toml")).unwrap();
    assert_eq!(docker, DOCKER_IO);
}

#[test]
fn check_names_the_file_that_lacks_the_entry_or_the_certificate() {
    let node = Node::new();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO);
    // Before `configure`: the hosts.toml lacks the entry, `_default` is missing, and so are the certificates.
    let problems = node.check(Runtime::Containerd);
    assert_eq!(problems.len(), 3, "{problems:#?}");
    assert!(
        problems[0]
            .starts_with("/etc/containerd/certs.d/docker.io/hosts.toml: lacks the mirror entry"),
        "{problems:#?}"
    );
    assert!(
        problems[1].starts_with("/etc/containerd/certs.d/_default/hosts.toml: is missing"),
        "{problems:#?}"
    );
    assert!(
        problems[2].starts_with("/var/lib/speculaire/mirror/ca.crt: is missing"),
        "{problems:#?}"
    );

    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    assert_eq!(node.check(Runtime::Containerd), Vec::<String>::new());
    std::fs::write(node.certs_d().join("docker.io/hosts.toml"), DOCKER_IO).unwrap();
    let problems = node.check(Runtime::Containerd);
    assert_eq!(problems.len(), 1);
    assert!(
        problems[0].contains("docker.io/hosts.toml: lacks the mirror entry"),
        "{problems:#?}"
    );
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    std::fs::remove_file(node.dir.path().join("var/lib/speculaire/mirror/server.key")).unwrap();
    let problems = node.check(Runtime::Containerd);
    assert!(
        problems[0].starts_with("/var/lib/speculaire/mirror/server.key: is missing"),
        "{problems:#?}"
    );
    // A certificate for another address, and one that the CA did not sign.
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    let ca = node.dir.path().join("var/lib/speculaire/mirror/ca.crt");
    let other = Mirror::generate("127.0.0.1".parse().unwrap(), now()).unwrap();
    std::fs::write(&ca, other.ca()).unwrap();
    let problems = node.check(Runtime::Containerd);
    assert!(
        problems[0].contains("server.crt: is not signed by the CA"),
        "{problems:#?}"
    );
    // And configure repairs it.
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    assert_eq!(node.check(Runtime::Containerd), Vec::<String>::new());
}

#[test]
fn a_key_that_was_readable_by_others_ends_at_0600() {
    let node = Node::new();
    node.containerd();
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    let key = node.dir.path().join("var/lib/speculaire/mirror/server.key");
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o666)).unwrap();
    let report = node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    assert_eq!(report.changes, [Change::Updated(key.clone())]);
    assert_eq!(std::fs::metadata(&key).unwrap().mode() & 0o7777, 0o600);
}

#[test]
fn a_config_containerd_would_refuse_or_a_file_that_is_not_toml_changes_nothing() {
    let node = Node::new();
    put(
        &node.paths.containerd_config(),
        "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry.mirrors.\"docker.io\"]\n  endpoint = [\"https://m\"]\n",
    );
    let err = node
        .configure(Runtime::Containerd, &Fake::new())
        .unwrap_err();
    assert!(matches!(err, Error::LegacyMirrors(_)), "{err}");
    assert!(err.to_string().contains("config.toml"), "{err}");
    assert!(!node.dir.path().join("var").exists());

    let node = Node::new();
    node.containerd();
    put(&node.certs_d().join("docker.io/hosts.toml"), "[host\n");
    let err = node
        .configure(Runtime::Containerd, &Fake::new())
        .unwrap_err();
    assert!(matches!(err, Error::Edit { .. }), "{err}");
    assert!(err.to_string().contains("docker.io/hosts.toml"), "{err}");
    assert!(
        !node.dir.path().join("var").exists(),
        "no certificate was made"
    );
    assert!(!node.certs_d().join("_default").exists());
    let problems = check(Runtime::Containerd, &node.paths, &node.settings, now()).unwrap();
    assert!(
        problems
            .iter()
            .any(|p| p.path.ends_with("docker.io/hosts.toml")),
        "{problems:?}"
    );
}

#[test]
fn without_a_config_file_containerd_runs_on_its_defaults() {
    let node = Node::new();
    let docker = put(
        &node
            .dir
            .path()
            .join("etc/docker/certs.d/quay.io/hosts.toml"),
        "server = \"https://quay.io\"\n",
    );
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    assert!(
        node.dir
            .path()
            .join("etc/containerd/certs.d/_default/hosts.toml")
            .is_file()
    );
    assert!(
        std::fs::read_to_string(docker)
            .unwrap()
            .contains("[host.\"https://127.0.0.1:7480\"]")
    );
    assert_eq!(node.check(Runtime::Containerd), Vec::<String>::new());
}

#[test]
fn unconfigure_refuses_while_the_nri_validator_requires_the_plugin() {
    let node = Node::new();
    node.containerd();
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    let nri = "\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\n  enable = true\n  required_plugins = [\"speculaire\"]\n";
    let config = node.paths.containerd_config();
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, format!("{text}{nri}")).unwrap();
    let before = node.tree();
    let err = node
        .unconfigure(Runtime::Containerd, false, &Fake::new())
        .unwrap_err();
    assert!(
        matches!(
            err,
            Error::Required {
                runtime: Runtime::Containerd,
                ..
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("required_plugins"), "{err}");
    assert_eq!(node.tree(), before, "nothing was removed");
    // Another plugin is fine, and so is --force.
    std::fs::write(&config, text.clone() + &nri.replace("speculaire", "other")).unwrap();
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    node.unconfigure(Runtime::Containerd, false, &Fake::new())
        .unwrap();
    std::fs::write(&config, format!("{text}{nri}")).unwrap();
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    node.unconfigure(Runtime::Containerd, true, &Fake::new())
        .unwrap();
    assert!(!node.dir.path().join("var/lib/speculaire/mirror").exists());
}

// ---- CRI-O ----

const REGISTRIES_CONF: &str = "unqualified-search-registries = [\"docker.io\"]\n\n[[registry]]\nprefix = \"docker.io\"\nlocation = \"registry-1.docker.io\"\n[[registry.mirror]]\nlocation = \"mirror.corp:5000/dockerhub\"\n";

fn crio_node() -> (Node, Fake) {
    let node = Node::new();
    put(
        &node.dir.path().join("etc/containers/registries.conf"),
        REGISTRIES_CONF,
    );
    (node, Fake::new())
}

#[test]
fn crio_gets_a_drop_in_certificates_and_a_reload() {
    let (node, fake) = crio_node();
    let report = node.configure(Runtime::CriO, &fake).unwrap();
    let tree = node.tree();
    let dropin = &tree[&node.paths.crio_dropin()];
    insta::assert_snapshot!(
        "crio-node-dropin",
        String::from_utf8(dropin.0.clone()).unwrap()
    );
    let certs = node.paths.crio_certs().join("127.0.0.1:7480");
    for (name, mode) in [
        ("ca.crt", 0o644),
        ("client.cert", 0o644),
        ("client.key", 0o600),
    ] {
        assert_eq!(tree[&certs.join(name)].1, mode, "{name}");
    }
    // The client files are the parts of the combined PEM containerd would read.
    let pem = String::from_utf8(
        tree[&node.dir.path().join("var/lib/speculaire/mirror/client.pem")]
            .0
            .clone(),
    )
    .unwrap();
    let parts = format!(
        "{}{}",
        String::from_utf8(tree[&certs.join("client.cert")].0.clone()).unwrap(),
        String::from_utf8(tree[&certs.join("client.key")].0.clone()).unwrap()
    );
    assert_eq!(pem, parts);
    assert_eq!(fake.reloads.get(), 1);
    assert_eq!(report.notes, [""; 0]);
    assert_eq!(node.check(Runtime::CriO), Vec::<String>::new());

    let once = node.tree();
    let report = node.configure(Runtime::CriO, &fake).unwrap();
    assert_eq!(report.changes, []);
    assert_eq!(node.tree(), once);
    assert_eq!(
        fake.reloads.get(),
        2,
        "a reload that failed before must be able to run again"
    );
}

#[test]
fn crio_check_finds_a_later_file_that_replaces_the_entry_and_an_admin_edit() {
    let (node, fake) = crio_node();
    node.configure(Runtime::CriO, &fake).unwrap();
    let late = put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/999-admin.conf"),
        "[[registry]]\nprefix = \"docker.io\"\nlocation = \"registry-1.docker.io\"\n",
    );
    let problems = node.check(Runtime::CriO);
    assert!(
        problems.iter().any(|p| p.starts_with(
            "/etc/containers/registries.conf.d/99-speculaire.conf: the effective entry of docker.io does not have the mirror first"
        )),
        "{problems:#?}"
    );
    // `configure` cannot fix that, and says so.
    let report = node.configure(Runtime::CriO, &fake).unwrap();
    assert!(
        report
            .notes
            .iter()
            .any(|n| n.contains("effective entry of docker.io does not have the mirror first")),
        "{:#?}",
        report.notes
    );
    // The drop-in now copies the late file's entry: it is stale once that file goes.
    std::fs::remove_file(late).unwrap();
    assert_eq!(node.check(Runtime::CriO).len(), 2);
    node.configure(Runtime::CriO, &fake).unwrap();
    assert_eq!(node.check(Runtime::CriO), Vec::<String>::new());
    // The admin changes their own entry: the drop-in copied the old one.
    put(
        &node.dir.path().join("etc/containers/registries.conf"),
        &REGISTRIES_CONF.replace("mirror.corp:5000/dockerhub", "mirror2.corp:5000/dockerhub"),
    );
    let problems = node.check(Runtime::CriO);
    assert!(
        problems
            .iter()
            .all(|p| p.starts_with("/etc/containers/registries.conf.d/99-speculaire.conf: ")),
        "{problems:#?}"
    );
    assert!(
        problems
            .iter()
            .any(|p| p.contains("differs from what `speculaire configure` writes")),
        "{problems:#?}"
    );
    node.configure(Runtime::CriO, &fake).unwrap();
    assert_eq!(node.check(Runtime::CriO), Vec::<String>::new());
    // Without the drop-in the check says so once.
    std::fs::remove_file(node.paths.crio_dropin()).unwrap();
    let problems = node.check(Runtime::CriO);
    assert_eq!(problems.len(), 1, "{problems:#?}");
    assert!(
        problems[0].contains("99-speculaire.conf: is missing"),
        "{problems:#?}"
    );
}

#[test]
fn crio_unconfigure_reloads_before_the_certificates_go() {
    let (node, fake) = crio_node();
    node.configure(Runtime::CriO, &fake).unwrap();
    *fake.watch.borrow_mut() = Some(node.paths.crio_certs().join("127.0.0.1:7480/ca.crt"));
    fake.seen.borrow_mut().clear();
    let admin = put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/50-admin.conf"),
        "[[registry]]\nlocation = \"x.example\"\n",
    );
    node.unconfigure(Runtime::CriO, false, &fake).unwrap();
    assert_eq!(
        *fake.seen.borrow(),
        [true],
        "CRI-O reloaded while the certificates were still there"
    );
    let left: Vec<_> = node.tree().keys().cloned().collect();
    assert!(!node.paths.crio_dropin().exists());
    assert!(!node.paths.crio_certs().join("127.0.0.1:7480").exists());
    assert!(!node.dir.path().join("var/lib/speculaire/mirror").exists());
    assert!(
        left.contains(&admin)
            && left.contains(&node.dir.path().join("etc/containers/registries.conf"))
    );
    // Again: the reload runs, and nothing changes.
    let report = node.unconfigure(Runtime::CriO, false, &fake).unwrap();
    assert_eq!(report.changes, []);
    assert_eq!(fake.reloads.get(), 3);
}

#[test]
fn crio_unconfigure_refuses_while_the_validator_requires_the_plugin() {
    let (node, fake) = crio_node();
    node.configure(Runtime::CriO, &fake).unwrap();
    *fake.required.borrow_mut() = vec!["other".to_owned(), "speculaire".to_owned()];
    let before = node.tree();
    let err = node.unconfigure(Runtime::CriO, false, &fake).unwrap_err();
    assert!(
        err.to_string().contains("nri_validator_required_plugins"),
        "{err}"
    );
    assert_eq!(node.tree(), before);
    node.unconfigure(Runtime::CriO, true, &fake).unwrap();
    assert!(!node.paths.crio_dropin().exists());
}

#[test]
fn crio_a_new_address_leaves_no_certificates_of_the_old_one() {
    let (mut node, fake) = crio_node();
    node.configure(Runtime::CriO, &fake).unwrap();
    node.settings.address = "127.0.0.2:7481".parse().unwrap();
    let problems = node.check(Runtime::CriO);
    assert!(problems.len() >= 2, "{problems:#?}");
    node.configure(Runtime::CriO, &fake).unwrap();
    assert!(!node.paths.crio_certs().join("127.0.0.1:7480").exists());
    assert!(
        node.paths
            .crio_certs()
            .join("127.0.0.2:7481/ca.crt")
            .is_file()
    );
    let dropin = std::fs::read_to_string(node.paths.crio_dropin()).unwrap();
    assert!(
        dropin.contains("127.0.0.2:7481/registry-1.docker.io") && !dropin.contains("7480"),
        "{dropin}"
    );
    assert_eq!(node.check(Runtime::CriO), Vec::<String>::new());
    node.unconfigure(Runtime::CriO, false, &fake).unwrap();
    assert!(!node.paths.crio_certs().join("127.0.0.2:7481").exists());
}

#[test]
fn crio_a_failed_reload_is_an_error_and_a_rerun_reloads_again() {
    let (node, fake) = crio_node();
    fake.reload_fails.set(true);
    let err = node.configure(Runtime::CriO, &fake).unwrap_err();
    assert!(matches!(err, Error::Reload(_)), "{err}");
    assert!(node.paths.crio_dropin().is_file());
    fake.reload_fails.set(false);
    node.configure(Runtime::CriO, &fake).unwrap();
    assert_eq!(fake.reloads.get(), 2);
    fake.reload_fails.set(true);
    let err = node.unconfigure(Runtime::CriO, false, &fake).unwrap_err();
    assert!(matches!(err, Error::Reload(_)), "{err}");
    assert!(
        node.dir
            .path()
            .join("var/lib/speculaire/mirror/ca.crt")
            .is_file(),
        "the certificates stay while CRI-O may use them"
    );
}

#[test]
fn registries_that_are_left_out_are_noted_and_a_broken_registries_conf_is_an_error() {
    let (node, fake) = crio_node();
    put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/10-block.conf"),
        "[[registry]]\nprefix = \"evil.example\"\nlocation = \"evil.example\"\nblocked = true\n",
    );
    let report = node.configure(Runtime::CriO, &fake).unwrap();
    assert_eq!(
        report.notes,
        ["registry evil.example: not mirrored: blocked"]
    );
    put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/20-bad.conf"),
        "[[registry\n",
    );
    let err = node.configure(Runtime::CriO, &fake).unwrap_err();
    assert!(matches!(err, Error::Registries(_)), "{err}");
    assert!(err.to_string().contains("20-bad.conf"), "{err}");
}

#[test]
fn problems_and_changes_print_their_file() {
    let problem = Problem {
        path: PathBuf::from("/etc/x"),
        message: "is wrong".to_owned(),
    };
    assert_eq!(problem.to_string(), "/etc/x: is wrong");
    assert_eq!(
        Change::Removed(PathBuf::from("/a")).to_string(),
        "removed /a"
    );
    let system = System {
        containerd_socket: PathBuf::from("/nonexistent/containerd.sock"),
        crio_socket: PathBuf::from("/nonexistent/crio.sock"),
        systemctl: PathBuf::from("/nonexistent/systemctl"),
    };
    assert!(system.crio_nri().is_err());
    assert!(system.reload_crio().is_err());
}

/// A `systemctl` that records its arguments and exits with `status`.
fn fake_systemctl(dir: &Path, status: i32) -> System {
    use std::os::unix::fs::PermissionsExt;
    let script = dir.join("systemctl");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$@\" > '{}'\nexit {status}\n",
            dir.join("args").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    System {
        containerd_socket: dir.join("containerd.sock"),
        crio_socket: dir.join("crio.sock"),
        systemctl: script,
    }
}

#[test]
fn the_system_reloads_crio_with_systemctl_and_reports_its_failure() {
    let dir = tempfile::tempdir().unwrap();
    // A script just written can be busy while another test forks: try again.
    let run = |system: &System| {
        for _ in 0..50 {
            match system.reload_crio() {
                Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                other => return other,
            }
        }
        system.reload_crio()
    };
    let ok = fake_systemctl(dir.path(), 0);
    run(&ok).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("args")).unwrap(),
        "reload crio\n"
    );
    let failing = fake_systemctl(dir.path(), 3);
    let err = run(&failing).unwrap_err();
    assert!(err.to_string().contains("systemctl reload crio"), "{err}");
}

#[test]
fn own_cert_dirs_are_those_holding_the_ca_and_a_missing_certs_d_has_none() {
    let dir = tempfile::tempdir().unwrap();
    let certs = dir.path().join("certs.d");
    assert_eq!(own_cert_dirs(&certs, "ca").unwrap(), Vec::<PathBuf>::new());
    put(&certs.join("b:7480/ca.crt"), "ca");
    put(&certs.join("a:7480/ca.crt"), "ca");
    put(&certs.join("other/ca.crt"), "another ca");
    put(&certs.join("no-ca/client.key"), "x");
    assert_eq!(
        own_cert_dirs(&certs, "ca").unwrap(),
        [certs.join("a:7480"), certs.join("b:7480")]
    );
    let file = dir.path().join("file");
    put(&file, "");
    assert!(matches!(own_cert_dirs(&file, "ca"), Err(Error::Io { .. })));
}

#[test]
fn containerd_without_a_config_file_has_no_required_plugin_but_a_bad_config_stops_unconfigure() {
    let node = Node::new();
    node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    // No `config.toml`: containerd's defaults, and so no NRI validator.
    node.unconfigure(Runtime::Containerd, false, &Fake::new())
        .unwrap();
    assert!(!node.dir.path().join("var/lib/speculaire/mirror").exists());
    // A `config.toml` that cannot be read is not the same as none.
    std::fs::create_dir_all(node.paths.containerd_config()).unwrap();
    let err = node
        .unconfigure(Runtime::Containerd, false, &Fake::new())
        .unwrap_err();
    assert!(matches!(err, Error::Containerd { .. }), "{err}");
    let err = node
        .configure(Runtime::Containerd, &Fake::new())
        .unwrap_err();
    assert!(matches!(err, Error::Containerd { .. }), "{err}");
}

#[test]
fn a_missing_import_is_an_error_and_not_a_config_that_is_missing() {
    let node = Node::new();
    put(
        &node.paths.containerd_config(),
        "version = 2\nimports = [\"/nonexistent/conf.d/x.toml\"]\n",
    );
    let err = node
        .configure(Runtime::Containerd, &Fake::new())
        .unwrap_err();
    assert!(matches!(err, Error::Containerd { .. }), "{err}");
    assert!(err.to_string().contains("config.toml"), "{err}");
}

#[test]
fn directories_that_are_left_alone_are_noted() {
    let node = Node::new();
    node.containerd();
    put(&node.certs_d().join("private.example/ca.crt"), "pem");
    let report = node.configure(Runtime::Containerd, &Fake::new()).unwrap();
    assert_eq!(report.notes.len(), 1, "{:?}", report.notes);
    assert!(
        report.notes[0].contains("private.example: left alone"),
        "{:?}",
        report.notes
    );
}

#[test]
fn a_later_file_that_keeps_the_mirror_first_but_changes_the_entry_is_named_as_different() {
    let (node, fake) = crio_node();
    node.configure(Runtime::CriO, &fake).unwrap();
    put(
        &node
            .dir
            .path()
            .join("etc/containers/registries.conf.d/999-admin.conf"),
        "[[registry]]\nprefix = \"docker.io\"\nlocation = \"registry-1.docker.io\"\ninsecure = true\n[[registry.mirror]]\nlocation = \"127.0.0.1:7480/registry-1.docker.io\"\npull-from-mirror = \"all\"\n[[registry.mirror]]\nlocation = \"mirror.corp:5000/dockerhub\"\n",
    );
    let problems = node.check(Runtime::CriO);
    assert!(
        problems.iter().any(|p| p.contains(
            "the effective entry of docker.io differs from the admin's, with the mirror first"
        )),
        "{problems:#?}"
    );
}

// ---- preflight ----

impl Node {
    /// The problems of preflight, with the root of the node taken out of the paths.
    fn preflight(&self, runtime: Runtime, host: &Fake) -> Vec<String> {
        let root = self.dir.path().to_str().unwrap();
        preflight(runtime, &self.paths, &self.settings, host, now())
            .iter()
            .map(|p| p.to_string().replace(root, ""))
            .collect()
    }

    /// A node `configure` has been run on.
    fn configured(&self, runtime: Runtime) -> Fake {
        match runtime {
            Runtime::Containerd => self.containerd(),
            Runtime::CriO => {
                put(
                    &self
                        .paths
                        .context()
                        .root
                        .join("etc/containers/registries.conf"),
                    "unqualified-search-registries = [\"docker.io\"]\n",
                );
            }
        }
        let fake = Fake::new();
        if runtime == Runtime::CriO {
            *fake.version.borrow_mut() = Some(("cri-o".to_owned(), "1.37.2".to_owned()));
        }
        self.configure(runtime, &fake).unwrap();
        fake
    }

    fn containerd_toml(&self, text: &str) {
        put(&self.paths.containerd_config(), text);
    }
}

fn has(problems: &[String], parts: &[&str]) -> bool {
    problems
        .iter()
        .any(|problem| parts.iter().all(|part| problem.contains(part)))
}

#[test]
fn a_node_configure_has_run_on_has_no_problem_on_either_runtime() {
    for runtime in [Runtime::Containerd, Runtime::CriO] {
        let node = Node::new();
        let fake = node.configured(runtime);
        assert_eq!(
            node.preflight(runtime, &fake),
            Vec::<String>::new(),
            "{runtime}"
        );
        assert_eq!(
            check_all(runtime, &node.paths, &node.settings, &fake, now()).unwrap(),
            [],
            "{runtime}"
        );
    }
}

#[test]
fn missing_certificates_are_named_and_stop_startup() {
    let node = Node::new();
    let fake = node.configured(Runtime::Containerd);
    std::fs::remove_dir_all(node.dir.path().join("var/lib/speculaire/mirror")).unwrap();
    let problems = node.preflight(Runtime::Containerd, &fake);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        has(
            &problems,
            &[
                "/var/lib/speculaire/mirror/ca.crt",
                "run `speculaire configure`"
            ]
        ),
        "{problems:?}"
    );
}

#[test]
fn a_runtime_that_is_too_old_is_refused_with_the_version_it_reports() {
    let node = Node::new();
    for (runtime, name, old, ok) in [
        (Runtime::Containerd, "containerd", "v2.2.9", "v2.3.0"),
        (Runtime::Containerd, "containerd", "1.7.29", "2.3.0-rc.1"),
        (Runtime::CriO, "cri-o", "1.34.9", "1.35.0"),
    ] {
        let fake = node.configured(runtime);
        *fake.version.borrow_mut() = Some((name.to_owned(), old.to_owned()));
        let problems = node.preflight(runtime, &fake);
        assert!(
            has(
                &problems,
                &[
                    &format!("/run/{runtime}.sock"),
                    "is older than",
                    old.trim_start_matches('v')
                ]
            ),
            "{problems:?}"
        );
        *fake.version.borrow_mut() = Some((name.to_owned(), ok.to_owned()));
        assert_eq!(node.preflight(runtime, &fake), Vec::<String>::new(), "{ok}");
    }
    let fake = node.configured(Runtime::Containerd);
    *fake.version.borrow_mut() = Some(("containerd".to_owned(), "v2.2.9".to_owned()));
    assert!(has(
        &node.preflight(Runtime::Containerd, &fake),
        &["containerd 2.2.9 is older than 2.3.0"]
    ));
}

#[test]
fn a_runtime_that_answers_wrongly_or_not_at_all_is_a_problem_naming_its_socket() {
    let node = Node::new();
    let fake = node.configured(Runtime::Containerd);
    *fake.version.borrow_mut() = None;
    let problems = node.preflight(Runtime::Containerd, &fake);
    assert!(
        has(
            &problems,
            &[
                "/run/containerd.sock",
                "connection refused",
                "`runtime.containerd_socket`"
            ]
        ),
        "{problems:?}"
    );
    *fake.version.borrow_mut() = Some(("cri-o".to_owned(), "1.37.2".to_owned()));
    assert!(has(
        &node.preflight(Runtime::Containerd, &fake),
        &["answers as \"cri-o\", not containerd"]
    ));
    *fake.version.borrow_mut() = Some(("containerd".to_owned(), "Unknown".to_owned()));
    assert!(has(
        &node.preflight(Runtime::Containerd, &fake),
        &["\"Unknown\"", "no release"]
    ));
    let fake = node.configured(Runtime::CriO);
    *fake.version.borrow_mut() = None;
    assert!(has(
        &node.preflight(Runtime::CriO, &fake),
        &["/run/cri-o.sock", "`runtime.crio_socket`"]
    ));
}

#[test]
fn containerd_2_4_is_asked_for_what_its_image_service_runs_with() {
    let node = Node::new();
    let fake = node.configured(Runtime::Containerd);
    let exports = |discard: bool, path: &str| {
        Ok(Some(ImageExports {
            discard_unpacked_layers: discard,
            registry_config_path: path.to_owned(),
        }))
    };
    *fake.exports.borrow_mut() = exports(true, "/etc/containerd/certs.d");
    let problems = node.preflight(Runtime::Containerd, &fake);
    assert!(
        has(
            &problems,
            &[
                "/etc/containerd/config.toml",
                "`discard_unpacked_layers = true`",
                "set it to false"
            ]
        ),
        "{problems:?}"
    );
    *fake.exports.borrow_mut() = exports(false, "");
    let problems = node.preflight(Runtime::Containerd, &fake);
    assert!(
        has(
            &problems,
            &[
                "/etc/containerd/config.toml",
                "`config_path` is not set",
                "\"/etc/containerd/certs.d\""
            ]
        ),
        "{problems:?}"
    );
    *fake.exports.borrow_mut() = Ok(None);
    assert!(has(
        &node.preflight(Runtime::Containerd, &fake),
        &["/run/containerd.sock", "`io.containerd.cri.v1.images`"]
    ));
    *fake.exports.borrow_mut() = Err(());
    assert!(has(
        &node.preflight(Runtime::Containerd, &fake),
        &["/run/containerd.sock", "Unavailable"]
    ));
    // The config file says false, the running image service true: the running one counts.
    node.containerd_toml(
        "version = 3\n[plugins.'io.containerd.cri.v1.images']\ndiscard_unpacked_layers = false\n",
    );
    *fake.exports.borrow_mut() = exports(true, "/x");
    assert!(has(
        &node.preflight(Runtime::Containerd, &fake),
        &["`discard_unpacked_layers = true`"]
    ));
}

#[test]
fn containerd_2_3_has_its_image_settings_read_from_the_config_file() {
    let node = Node::new();
    let fake = node.configured(Runtime::Containerd);
    *fake.version.borrow_mut() = Some(("containerd".to_owned(), "v2.3.7".to_owned()));
    // The running image service is not asked: these exports would be refused.
    *fake.exports.borrow_mut() = Err(());
    assert_eq!(
        node.preflight(Runtime::Containerd, &fake),
        Vec::<String>::new()
    );
    for (text, key) in [
        (
            "version = 3\n[plugins.'io.containerd.cri.v1.images']\ndiscard_unpacked_layers = true\n",
            "`discard_unpacked_layers = true`",
        ),
        (
            "version = 2\n[plugins.'io.containerd.grpc.v1.cri'.containerd]\ndiscard_unpacked_layers = true\n[plugins.'io.containerd.grpc.v1.cri'.containerd.runtimes.runc]\nruntime_type = 'x'\n",
            "`discard_unpacked_layers = true`",
        ),
        (
            "version = 2\n[plugins.'io.containerd.grpc.v1.cri'.registry.mirrors.'docker.io']\nendpoint = ['https://m.io']\n",
            "`config_path` is not set",
        ),
    ] {
        node.containerd_toml(text);
        let problems = node.preflight(Runtime::Containerd, &fake);
        assert!(
            has(&problems, &["/etc/containerd/config.toml", key]),
            "{text}: {problems:?}"
        );
    }
    // Without a config file, containerd runs on its defaults: config_path set, nothing discarded.
    std::fs::remove_file(node.paths.containerd_config()).unwrap();
    assert_eq!(
        node.preflight(Runtime::Containerd, &fake),
        Vec::<String>::new()
    );
    // An invalid registry section is named; so is a config that is no TOML.
    node.containerd_toml("version = 3\n[plugins.'io.containerd.cri.v1.images'.registry]\nconfig_path = '/x'\n[plugins.'io.containerd.cri.v1.images'.registry.mirrors.'a.io']\nendpoint = ['https://m.io']\n");
    assert!(has(
        &node.preflight(Runtime::Containerd, &fake),
        &[
            "the registry section is invalid",
            "`mirrors` cannot be set when `config_path` is provided"
        ]
    ));
    node.containerd_toml("version = ");
    assert!(has(
        &node.preflight(Runtime::Containerd, &fake),
        &[
            "/etc/containerd/config.toml",
            "cannot read containerd's config"
        ]
    ));
}

#[test]
fn nri_that_is_off_or_closed_is_refused_naming_each_key() {
    let node = Node::new();
    let fake = node.configured(Runtime::Containerd);
    for (text, parts) in [
        (
            "version = 3\n[plugins.'io.containerd.nri.v1.nri']\ndisable = true\n",
            &[
                "`disable = true` in [plugins.'io.containerd.nri.v1.nri']",
                "set it to false",
            ][..],
        ),
        (
            "version = 3\n[plugins.'io.containerd.nri.v1.nri']\ndisable_connections = true\n",
            &[
                "`disable_connections = true` in [plugins.'io.containerd.nri.v1.nri']",
                "restart containerd",
            ],
        ),
        (
            "version = 3\ndisabled_plugins = ['io.containerd.nri.v1.nri']\n",
            &[
                "`io.containerd.nri.v1.nri` is in `disabled_plugins`",
                "remove it",
            ],
        ),
    ] {
        node.containerd_toml(text);
        let problems = node.preflight(Runtime::Containerd, &fake);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(
            has(&problems, &["/etc/containerd/config.toml", "(D54)"]),
            "{problems:?}"
        );
        assert!(has(&problems, parts), "{problems:?}");
    }
    node.containerd_toml("version = 3\ndisabled_plugins = ['io.containerd.nri.v1.nri']\n[plugins.'io.containerd.nri.v1.nri']\ndisable = true\ndisable_connections = true\n");
    assert_eq!(node.preflight(Runtime::Containerd, &fake).len(), 3);
}

#[test]
fn crios_nri_that_is_off_or_closed_and_a_missing_drop_in_are_refused() {
    let node = Node::new();
    let fake = node.configured(Runtime::CriO);
    fake.nri.set((false, false));
    let problems = node.preflight(Runtime::CriO, &fake);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        has(
            &problems,
            &[
                "/run/cri-o.sock",
                "`enable_nri = false` in [crio.nri]",
                "set it to true",
                "(D54, D64)"
            ]
        ),
        "{problems:?}"
    );
    fake.nri.set((true, true));
    assert!(has(
        &node.preflight(Runtime::CriO, &fake),
        &[
            "`nri_disable_connections = true` in [crio.nri]",
            "set it to false"
        ]
    ));
    fake.nri.set((false, true));
    assert_eq!(node.preflight(Runtime::CriO, &fake).len(), 2);
    fake.nri.set((true, false));
    fake.inspect_fails.set(true);
    assert!(has(
        &node.preflight(Runtime::CriO, &fake),
        &["/run/cri-o.sock", "CRI-O's inspect API answered"]
    ));
    fake.inspect_fails.set(false);
    std::fs::remove_file(node.paths.crio_dropin()).unwrap();
    let problems = node.preflight(Runtime::CriO, &fake);
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(
        has(
            &problems,
            &[
                "/etc/containers/registries.conf.d/99-speculaire.conf",
                "is missing",
                "run `speculaire configure`"
            ]
        ),
        "{problems:?}"
    );
}

#[test]
fn check_all_reports_what_check_and_preflight_both_find_once() {
    let node = Node::new();
    let fake = node.configured(Runtime::CriO);
    std::fs::remove_file(node.paths.crio_dropin()).unwrap();
    std::fs::remove_dir_all(node.dir.path().join("var/lib/speculaire/mirror")).unwrap();
    fake.nri.set((false, false));
    let all = check_all(Runtime::CriO, &node.paths, &node.settings, &fake, now()).unwrap();
    let root = node.dir.path().to_str().unwrap();
    let all: Vec<String> = all
        .iter()
        .map(|p| p.to_string().replace(root, ""))
        .collect();
    // The NRI key, the certificate, the drop-in: each once, though `check` finds the last two as well.
    assert_eq!(all.len(), 3, "{all:?}");
    assert!(
        has(&all, &["enable_nri"]) && has(&all, &["ca.crt"]) && has(&all, &["99-speculaire.conf"])
    );
    // A problem only `check` finds still shows up: a drop-in that differs.
    let node = Node::new();
    let fake = node.configured(Runtime::CriO);
    put(&node.paths.crio_dropin(), "# edited\n");
    let all = check_all(Runtime::CriO, &node.paths, &node.settings, &fake, now()).unwrap();
    assert!(
        all.iter().any(|p| p
            .message
            .contains("differs from what `speculaire configure` writes")),
        "{all:?}"
    );
}

#[test]
fn the_containerd_config_can_be_somewhere_else() {
    let node = Node::new();
    let elsewhere = node.dir.path().join("other/config.toml");
    let paths = Paths::under(node.dir.path()).with_containerd_config(&elsewhere);
    assert_eq!(paths.containerd_config(), elsewhere);
    assert_eq!(
        Paths::under(node.dir.path()).containerd_config(),
        node.dir.path().join("etc/containerd/config.toml")
    );
    assert_eq!(
        Paths::system().containerd_config(),
        PathBuf::from("/etc/containerd/config.toml")
    );
}
