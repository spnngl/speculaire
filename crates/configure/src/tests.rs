//! `configure`, `unconfigure` and `check` on a temporary tree standing for a node's root.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::time::Duration;

use speculaire_runtime::crio::Nri;

use super::*;

const NOW: Duration = Duration::from_hours(500_000);

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + NOW
}

/// What a test sets on the fake: CRI-O's NRI answer, whether a reload fails, and what exists at each reload.
struct Fake {
    required: RefCell<Vec<String>>,
    reload_fails: Cell<bool>,
    reloads: Cell<u32>,
    watch: RefCell<Option<PathBuf>>,
    seen: RefCell<Vec<bool>>,
}

impl Fake {
    fn new() -> Self {
        Self {
            required: RefCell::new(Vec::new()),
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
        Ok(Nri {
            enabled: true,
            disable_connections: false,
            required_plugins: self.required.borrow().clone(),
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
        Self {
            paths: Paths::under(dir.path()),
            dir,
            settings: Settings {
                address: "127.0.0.1:7480".parse().unwrap(),
                registries: ["docker.io", "registry.k8s.io"].map(str::to_owned).to_vec(),
            },
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
        crio_socket: PathBuf::from("/nonexistent/crio.sock"),
    };
    assert!(system.crio_nri().is_err());
}
