//! A node on a temporary tree, with a fake runtime listening on its socket and a `systemctl` that logs, for the tests
//! of what each runtime does to the files of its node.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use speculaire_fake_runtime::{Answers, Fake};

use crate::certificates;
use crate::detect::{Runtime, Sockets};
use crate::node::Node;
use crate::paths::Paths;
use crate::wiring::{Error, Problem, Report, Target};

const NOW: Duration = Duration::from_hours(500_000);

/// The time the tests make certificates at.
pub(crate) fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + NOW
}

/// Writes `text` at `path`, below directories that it makes.
pub(crate) fn put(path: &Path, text: &str) -> PathBuf {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
    path.to_owned()
}

/// A node of one runtime: its files below a temporary root, and its socket and `systemctl` in another directory.
pub(crate) struct Tree {
    /// The root of the node.
    pub(crate) dir: tempfile::TempDir,
    /// Where the sockets, `systemctl` and its files are.
    run: tempfile::TempDir,
    pub(crate) paths: Paths,
    pub(crate) target: Target,
    pub(crate) node: Node,
    fake: Option<Fake>,
}

impl Tree {
    /// A node whose runtime answers as a supported release.
    pub(crate) fn new(runtime: Runtime) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let run = tempfile::tempdir().unwrap();
        let sockets = Sockets {
            containerd: run.path().join("containerd.sock"),
            crio: run.path().join("cri-o.sock"),
        };
        let (socket, answers) = match runtime {
            Runtime::Containerd => (&sockets.containerd, Answers::containerd("v2.4.2")),
            Runtime::CriO => (&sockets.crio, Answers::crio("1.37.2")),
        };
        let fake = Fake::start(socket, answers).unwrap();
        let systemctl = systemctl(run.path());
        let paths = Paths::under(dir.path());
        Self {
            target: Target {
                address: "127.0.0.1:7480".parse().unwrap(),
                registries: ["docker.io", "registry.k8s.io"].map(str::to_owned).to_vec(),
                directory: dir.path().join("var/lib/speculaire/mirror"),
            },
            node: Node::new(runtime, &sockets, paths.clone(), None, systemctl),
            paths,
            fake: Some(fake),
            dir,
            run,
        }
    }

    /// The root of the node, for a text to strip from the paths.
    fn root(&self) -> &str {
        self.dir.path().to_str().unwrap()
    }

    /// `path` below the root of the node.
    pub(crate) fn at(&self, path: &str) -> PathBuf {
        self.paths.at(path)
    }

    pub(crate) fn certs_d(&self) -> PathBuf {
        self.at("/etc/containerd/certs.d")
    }

    pub(crate) fn containerd_config(&self) -> PathBuf {
        self.at("/etc/containerd/config.toml")
    }

    pub(crate) fn crio_dropin(&self) -> PathBuf {
        self.at("/etc/containers/registries.conf.d/99-speculaire.conf")
    }

    pub(crate) fn crio_certs(&self) -> PathBuf {
        self.at("/etc/containers/certs.d")
    }

    /// A containerd node as the e2e images are: `config_path` set, no `certs.d` content.
    pub(crate) fn containerd(&self) {
        put(
            &self.containerd_config(),
            &format!(
                "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"{}\"\n",
                self.certs_d().display()
            ),
        );
    }

    /// A CRI-O node whose admin has an entry of their own.
    pub(crate) fn crio(&self, registries_conf: &str) {
        put(&self.at("/etc/containers/registries.conf"), registries_conf);
    }

    /// Every file under the root, with its contents and mode.
    pub(crate) fn tree(&self) -> BTreeMap<PathBuf, (Vec<u8>, u32)> {
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

    pub(crate) fn configure(&self) -> Result<Report, Error> {
        self.node.wiring().configure(&self.target, now())
    }

    pub(crate) fn unconfigure(&self) -> Result<Report, Error> {
        self.node.wiring().unconfigure(&self.target)
    }

    /// What `check` finds, the certificates included, with the root of the node taken out of the paths.
    pub(crate) fn check(&self) -> Vec<String> {
        self.problems(&self.check_all().unwrap())
    }

    /// What `check` finds, the certificates included.
    pub(crate) fn check_all(&self) -> Result<Vec<Problem>, Error> {
        let mut problems = self.node.wiring().check(&self.target)?;
        problems.extend(certificates::check(&self.target, now()));
        Ok(problems)
    }

    /// What preflight finds, the certificates included, with the root of the node taken out of the paths and the
    /// directory of the sockets named `/run`.
    pub(crate) fn preflight(&self) -> Vec<String> {
        let mut problems = self.node.settings().preflight();
        problems.extend(certificates::check(&self.target, now()));
        self.problems(&problems)
    }

    fn problems(&self, problems: &[Problem]) -> Vec<String> {
        let run = self.run.path().to_str().unwrap();
        problems
            .iter()
            .map(|p| p.to_string().replace(self.root(), "").replace(run, "/run"))
            .collect()
    }

    /// A node `configure` has been run on.
    pub(crate) fn configured(runtime: Runtime) -> Self {
        let tree = Self::new(runtime);
        match runtime {
            Runtime::Containerd => tree.containerd(),
            Runtime::CriO => tree.crio("unqualified-search-registries = [\"docker.io\"]\n"),
        }
        tree.configure().unwrap();
        tree
    }

    /// Changes what the runtime answers.
    pub(crate) fn update(&self, change: impl FnOnce(&mut Answers)) {
        self.fake.as_ref().unwrap().update(change);
    }

    /// Stops the runtime: its socket is left behind, and refuses connections.
    pub(crate) fn stop(&mut self) {
        self.fake = None;
    }

    /// The `systemctl` of the node.
    pub(crate) fn systemctl(&self) -> PathBuf {
        self.run.path().join("systemctl")
    }

    /// What CRI-O's inspect API answers: `enable_nri`, `nri_disable_connections` and the required plugins.
    pub(crate) fn nri(&self, enabled: bool, disable_connections: bool, required: &[&str]) {
        let plugins = required
            .iter()
            .map(|p| format!("{p:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        self.update(|answers| {
            answers.crio_config = Some(format!(
                "[crio.nri]\nenable_nri = {enabled}\nnri_disable_connections = {disable_connections}\n\n[crio.nri.default_validator]\nnri_validator_required_plugins = [{plugins}]\n"
            ));
        });
    }

    /// What the runtime answers to `Version`.
    pub(crate) fn version(&self, name: &str, version: &str) {
        self.update(|answers| {
            answers.runtime_name = name.to_owned();
            answers.runtime_version = version.to_owned();
        });
    }

    /// Whether `systemctl` fails from now on.
    pub(crate) fn reload_fails(&self, fails: bool) {
        let marker = self.run.path().join("fails");
        if fails {
            std::fs::write(marker, "").unwrap();
        } else if marker.exists() {
            std::fs::remove_file(marker).unwrap();
        }
    }

    /// How many times `systemctl` ran, each with `reload crio`.
    pub(crate) fn reloads(&self) -> usize {
        let log = std::fs::read_to_string(self.run.path().join("log")).unwrap_or_default();
        assert!(log.lines().all(|line| line == "reload crio"), "{log}");
        log.lines().count()
    }

    /// Makes `systemctl` note, at each run, whether `path` exists.
    pub(crate) fn watch(&self, path: &Path) {
        std::fs::write(self.run.path().join("watch"), path.to_str().unwrap()).unwrap();
    }

    /// What `systemctl` noted of the watched path at each run: whether it existed.
    pub(crate) fn seen(&self) -> Vec<bool> {
        std::fs::read_to_string(self.run.path().join("seen"))
            .unwrap_or_default()
            .lines()
            .map(|line| line == "yes")
            .collect()
    }

    /// Forgets what `systemctl` noted.
    pub(crate) fn forget_seen(&self) {
        let _ = std::fs::remove_file(self.run.path().join("seen"));
    }
}

/// Whether every word of `parts` is in one of `problems`.
pub(crate) fn has(problems: &[String], parts: &[&str]) -> bool {
    problems
        .iter()
        .any(|problem| parts.iter().all(|part| problem.contains(part)))
}

/// A `systemctl` that logs its arguments, notes whether the watched path exists, and fails when told to.
fn systemctl(dir: &Path) -> PathBuf {
    let script = dir.join("systemctl");
    let at = |name: &str| dir.join(name).display().to_string();
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\necho \"$@\" >> '{log}'\nif [ -f '{watch}' ]; then if [ -e \"$(cat '{watch}')\" ]; then echo yes >> '{seen}'; else echo no >> '{seen}'; fi; fi\nif [ -f '{fails}' ]; then exit 3; fi\n",
            log = at("log"),
            watch = at("watch"),
            seen = at("seen"),
            fails = at("fails"),
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A script just written can be busy while another test forks: run it once, until it can run.
    for _ in 0..100 {
        match Command::new(&script).status() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(20));
            }
            other => {
                other.unwrap();
                break;
            }
        }
    }
    std::fs::remove_file(dir.join("log")).unwrap();
    script
}
