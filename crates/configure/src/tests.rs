//! The orchestration over a runtime that is a fake: what it does to the traits, and in which order. What a runtime
//! does to its files is tested in `speculaire-runtime`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use speculaire_fake_runtime::{Answers, Fake};
use speculaire_runtime::detect::{Runtime, Sockets};
use speculaire_runtime::paths::Paths;
use speculaire_runtime::settings::{Required, Settings};
use speculaire_runtime::wiring::{Error, Problem, Report, Target, Wiring};

use super::*;

fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_hours(500_000)
}

fn target() -> Target {
    Target {
        address: "127.0.0.1:7480".parse().unwrap(),
        registries: vec!["docker.io".to_owned()],
        directory: PathBuf::from("/nonexistent/mirror"),
    }
}

fn problem(path: &str, message: &str) -> Problem {
    Problem {
        path: PathBuf::from(path),
        message: message.to_owned(),
    }
}

/// A wiring that records what it was asked and answers `problems` to `check`.
#[derive(Default)]
struct FakeWiring {
    calls: Mutex<Vec<&'static str>>,
    problems: Vec<Problem>,
}

impl FakeWiring {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
}

impl Wiring for FakeWiring {
    fn configure(&self, target: &Target, at: SystemTime) -> Result<Report, Error> {
        assert_eq!(target.address, self::target().address);
        assert_eq!(at, now());
        self.calls.lock().unwrap().push("configure");
        Ok(Report {
            changes: Vec::new(),
            notes: vec!["configured".to_owned()],
        })
    }

    fn unconfigure(&self, _: &Target) -> Result<Report, Error> {
        self.calls.lock().unwrap().push("unconfigure");
        Ok(Report::default())
    }

    fn check(&self, _: &Target) -> Result<Vec<Problem>, Error> {
        self.calls.lock().unwrap().push("check");
        Ok(self.problems.clone())
    }
}

/// Settings that require `plugins`, or cannot be read, and find `problems` in preflight.
struct FakeSettings {
    plugins: Result<Vec<String>, ()>,
    problems: Vec<Problem>,
    asked: AtomicUsize,
}

impl FakeSettings {
    fn requiring(plugins: &[&str]) -> Self {
        Self {
            plugins: Ok(plugins.iter().map(|p| (*p).to_owned()).collect()),
            problems: Vec::new(),
            asked: AtomicUsize::new(0),
        }
    }
}

impl Settings for FakeSettings {
    fn required_plugins(&self) -> Result<Required, Error> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        match &self.plugins {
            Ok(plugins) => Ok(Required {
                runtime: "fake",
                key: "`required` of [fake]",
                plugins: plugins.clone(),
            }),
            Err(()) => Err(Error::Io {
                path: PathBuf::from("/fake/config"),
                source: std::io::Error::other("unreadable"),
            }),
        }
    }

    fn preflight(&self) -> Vec<Problem> {
        self.problems.clone()
    }
}

#[test]
fn configure_hands_the_target_and_the_time_to_the_wiring() {
    let wiring = FakeWiring::default();
    let report = configure(&wiring, &target(), now()).unwrap();
    assert_eq!(report.notes, ["configured"]);
    assert_eq!(wiring.calls(), ["configure"]);
}

#[test]
fn unconfigure_refuses_while_the_runtime_requires_the_plugin_and_removes_nothing() {
    let wiring = FakeWiring::default();
    let settings = FakeSettings::requiring(&["other", "speculaire"]);
    let err = unconfigure(&wiring, &settings, &target(), false).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Required {
                runtime: "fake",
                key: "`required` of [fake]"
            }
        ),
        "{err}"
    );
    let text = err.to_string();
    assert!(
        text.contains("`required` of [fake] names speculaire")
            && text.contains("restart fake")
            && text.contains("--force"),
        "{text}"
    );
    assert_eq!(wiring.calls(), Vec::<&str>::new(), "nothing was removed");
}

#[test]
fn unconfigure_goes_on_when_another_plugin_is_required_or_none() {
    for plugins in [&["other"][..], &[]] {
        let wiring = FakeWiring::default();
        let settings = FakeSettings::requiring(plugins);
        unconfigure(&wiring, &settings, &target(), false).unwrap();
        assert_eq!(wiring.calls(), ["unconfigure"]);
    }
}

#[test]
fn force_does_not_ask_what_the_runtime_requires() {
    let wiring = FakeWiring::default();
    let settings = FakeSettings::requiring(&["speculaire"]);
    unconfigure(&wiring, &settings, &target(), true).unwrap();
    assert_eq!(wiring.calls(), ["unconfigure"]);
    assert_eq!(settings.asked.load(Ordering::SeqCst), 0);
}

#[test]
fn settings_that_cannot_be_read_stop_unconfigure_unless_forced() {
    let wiring = FakeWiring::default();
    let settings = FakeSettings {
        plugins: Err(()),
        problems: Vec::new(),
        asked: AtomicUsize::new(0),
    };
    let err = unconfigure(&wiring, &settings, &target(), false).unwrap_err();
    assert!(matches!(err, Error::Io { .. }), "{err}");
    assert_eq!(wiring.calls(), Vec::<&str>::new());
    unconfigure(&wiring, &settings, &target(), true).unwrap();
    assert_eq!(wiring.calls(), ["unconfigure"]);
}

#[test]
fn check_adds_the_certificates_after_what_the_wiring_finds() {
    let wiring = FakeWiring {
        problems: vec![problem("/fake/hosts", "lacks the entry")],
        ..FakeWiring::default()
    };
    let problems = check(&wiring, &target(), now()).unwrap();
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert_eq!(problems[0], problem("/fake/hosts", "lacks the entry"));
    assert!(
        problems[1]
            .to_string()
            .starts_with("/nonexistent/mirror/ca.crt: is missing"),
        "{problems:?}"
    );
}

#[test]
fn preflight_adds_the_certificates_after_what_the_settings_find() {
    let settings = FakeSettings {
        problems: vec![problem("/fake/socket", "too old")],
        ..FakeSettings::requiring(&[])
    };
    let problems = preflight(&settings, &target(), now());
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert_eq!(problems[0], problem("/fake/socket", "too old"));
    assert!(problems[1].to_string().contains("ca.crt"), "{problems:?}");
}

#[test]
fn check_all_reports_what_check_and_preflight_both_find_once() {
    let both = problem("/fake/drop-in", "is missing");
    let wiring = FakeWiring {
        problems: vec![both.clone(), problem("/fake/drop-in", "differs")],
        ..FakeWiring::default()
    };
    let settings = FakeSettings {
        problems: vec![problem("/fake/socket", "too old"), both.clone()],
        ..FakeSettings::requiring(&[])
    };
    let all = check_all(&wiring, &settings, &target(), now()).unwrap();
    let lines: Vec<String> = all.iter().map(ToString::to_string).collect();
    // Preflight first, then what only `check` finds; the certificates, which both find, once.
    assert_eq!(lines.len(), 4, "{lines:?}");
    assert_eq!(lines[0], "/fake/socket: too old");
    assert_eq!(lines[1], "/fake/drop-in: is missing");
    assert!(lines[2].contains("ca.crt"), "{lines:?}");
    assert_eq!(lines[3], "/fake/drop-in: differs");
    assert_eq!(wiring.calls(), ["check"]);
}

// ---- with the real runtimes, on a temporary tree, where a runtime's own refusal is read ----

/// A node of `runtime` whose files are under `root`, and whose socket answers in `run`.
fn real(runtime: Runtime, root: &Path, run: &Path) -> (speculaire_runtime::Node, Fake, Target) {
    let sockets = Sockets {
        containerd: run.join("containerd.sock"),
        crio: run.join("cri-o.sock"),
    };
    let (socket, answers) = match runtime {
        Runtime::Containerd => (&sockets.containerd, Answers::containerd("v2.4.2")),
        Runtime::CriO => (&sockets.crio, Answers::crio("1.37.2")),
    };
    let fake = Fake::start(socket, answers).unwrap();
    let node = speculaire_runtime::Node::new(runtime, &sockets, Paths::under(root), None, "true");
    let target = Target {
        directory: root.join("var/lib/speculaire/mirror"),
        ..target()
    };
    (node, fake, target)
}

fn tree(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, Vec<u8>)>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

#[test]
fn containerd_unconfigure_refuses_while_the_nri_validator_requires_the_plugin() {
    let (root, run) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, _fake, target) = real(Runtime::Containerd, root.path(), run.path());
    let config = root.path().join("etc/containerd/config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    let base = format!(
        "version = 2\n[plugins.\"io.containerd.grpc.v1.cri\".registry]\n  config_path = \"{}\"\n",
        root.path().join("etc/containerd/certs.d").display()
    );
    let nri = "\n[plugins.\"io.containerd.nri.v1.nri\".default_validator]\n  enable = true\n  required_plugins = [\"speculaire\"]\n";
    std::fs::write(&config, &base).unwrap();
    configure(node.wiring(), &target, now()).unwrap();
    std::fs::write(&config, format!("{base}{nri}")).unwrap();
    let before = tree(root.path());
    let err = unconfigure(node.wiring(), node.settings(), &target, false).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Required {
                runtime: "containerd",
                ..
            }
        ),
        "{err}"
    );
    assert!(err.to_string().contains("required_plugins"), "{err}");
    assert_eq!(tree(root.path()), before, "nothing was removed");
    // Another plugin is fine, and so is --force.
    std::fs::write(&config, base.clone() + &nri.replace("speculaire", "other")).unwrap();
    configure(node.wiring(), &target, now()).unwrap();
    unconfigure(node.wiring(), node.settings(), &target, false).unwrap();
    std::fs::write(&config, format!("{base}{nri}")).unwrap();
    configure(node.wiring(), &target, now()).unwrap();
    unconfigure(node.wiring(), node.settings(), &target, true).unwrap();
    assert!(!root.path().join("var/lib/speculaire/mirror").exists());
}

#[test]
fn crio_unconfigure_refuses_while_the_validator_requires_the_plugin() {
    let (root, run) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (node, fake, target) = real(Runtime::CriO, root.path(), run.path());
    configure(node.wiring(), &target, now()).unwrap();
    fake.update(|answers| {
        answers.crio_config = Some(
            "[crio.nri.default_validator]\nnri_validator_required_plugins = [\"other\", \"speculaire\"]\n"
                .to_owned(),
        );
    });
    let before = tree(root.path());
    let err = unconfigure(node.wiring(), node.settings(), &target, false).unwrap_err();
    assert!(
        err.to_string().contains("nri_validator_required_plugins"),
        "{err}"
    );
    assert_eq!(tree(root.path()), before);
    unconfigure(node.wiring(), node.settings(), &target, true).unwrap();
    assert!(
        !root
            .path()
            .join("etc/containers/registries.conf.d/99-speculaire.conf")
            .exists()
    );
}
