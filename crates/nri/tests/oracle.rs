//! The plugin against NRI's own runtime side, `speculaire-oracle nri-runtime` (D29, D162), and its version inference
//! against NRI's, `speculaire-oracle nri-version` (D166). Without `SPECULAIRE_ORACLE` the oracle's tests skip, as in
//! `just check`; `just oracle` sets it.

#![expect(clippy::panic, reason = "a test file: its helpers report by panicking")]

use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use speculaire_nri::api::{Container, CreateContainerRequest, PodSandbox};
use speculaire_nri::version::{self, InferError};
use speculaire_nri::{
    Answer, Configuration, End, Handler, MuxError, NriVersion, REGISTRATION_TIMEOUT, serve,
};
use speculaire_oracle_harness::Oracle;
use speculaire_oracle_harness::nri::{
    self as oracle_nri, Create, Start, State, Verdict, VersionAnswer, VersionCase,
};
use tokio::time::Instant;

/// A plugin connects, registers and synchronizes well within this.
const SETTLE: Duration = Duration::from_secs(30);

fn oracle() -> Option<Oracle> {
    match Oracle::from_env() {
        Ok(Some(oracle)) => Some(oracle),
        Ok(None) => {
            eprintln!(
                "skipped: {} is not set (`just oracle` sets it)",
                speculaire_oracle_harness::ENV
            );
            None
        }
        Err(e) => panic!("{e}"),
    }
}

/// Records what it is given; rejects the containers named `reject`, holds those named `hold` past any deadline.
#[derive(Debug, Default)]
struct Recorder {
    configured: Mutex<Vec<Configuration>>,
    synchronized: Mutex<Vec<(Vec<PodSandbox>, Vec<Container>)>>,
    /// Each CreateContainer's deadline, from when the handler was called.
    deadlines: Mutex<Vec<Duration>>,
}

const REJECTION: &str = "speculaire: no verified signature";

impl Handler for Recorder {
    fn configure(&self, configuration: &Configuration) {
        self.configured
            .lock()
            .expect("no test panics holding it")
            .push(configuration.clone());
    }

    fn synchronize(&self, pods: Vec<PodSandbox>, containers: Vec<Container>) {
        self.synchronized
            .lock()
            .expect("no test panics holding it")
            .push((pods, containers));
    }

    fn create_container(
        &self,
        request: &CreateContainerRequest,
        deadline: Instant,
    ) -> impl Future<Output = Answer> + Send {
        self.deadlines
            .lock()
            .expect("no test panics holding it")
            .push(deadline - Instant::now());
        let name = request
            .container
            .as_ref()
            .map(|c| c.name.clone())
            .unwrap_or_default();
        async move {
            match name.as_str() {
                "reject" => Answer::Reject(REJECTION.to_owned()),
                _ => Answer::Allow,
            }
        }
    }

    fn overloaded(&self, _: &CreateContainerRequest) -> Answer {
        Answer::Reject("overloaded".to_owned())
    }
}

/// Runs the plugin on `socket` in a thread of its own, until its session ends.
fn plugin(
    socket: &Path,
    handler: &Arc<Recorder>,
    registration_timeout: Duration,
) -> JoinHandle<End> {
    let socket = socket.to_owned();
    let handler = Arc::clone(handler);
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime builds");
        runtime.block_on(async move {
            let (reader, writer) = tokio::net::UnixStream::connect(socket)
                .await
                .expect("the oracle listens")
                .into_split();
            serve(reader, writer, &*handler, registration_timeout).await
        })
    })
}

fn socket(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("nri.sock")
}

fn create(name: &str) -> Create {
    let pod = oracle_nri::Pod {
        id: "pod-0".to_owned(),
        name: "web".to_owned(),
        namespace: "default".to_owned(),
        ..oracle_nri::Pod::default()
    };
    let container = oracle_nri::Container {
        id: "container-0".to_owned(),
        name: name.to_owned(),
        ..oracle_nri::Container::default()
    };
    Create { pod, container }
}

#[test]
fn the_plugin_registers_collects_a_split_synchronize_and_answers_with_the_runtimes_timeouts() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    let mut start = Start::new(socket(&dir), "containerd", "v2.4.2");
    start.registration_timeout = Duration::from_secs(3);
    start.request_timeout = Duration::from_millis(1500);
    runtime.start(&start).unwrap();
    // 10 MiB of containers: over twice ttrpc's 4 MiB limit, so pkg/adaptation splits them in at least three.
    let state = State::padded(40, 400, 25 << 10);
    runtime.state(&state).unwrap();
    let recorder = Arc::new(Recorder::default());
    let session = plugin(&socket(&dir), &recorder, REGISTRATION_TIMEOUT);

    let report = runtime.wait(1, SETTLE).unwrap();
    let [registered] = &report.plugins[..] else {
        panic!("{report:?}")
    };
    assert_eq!(registered.name, "50-speculaire");
    assert_eq!(registered.events, ["CREATE_CONTAINER"]);
    assert!(registered.synchronize_requests >= 3, "{registered:?}");
    eprintln!(
        "the plugin took {} Synchronize requests",
        registered.synchronize_requests
    );
    {
        let synchronized = recorder.synchronized.lock().unwrap();
        let [(pods, containers)] = &synchronized[..] else {
            panic!("{} synchronizations", synchronized.len())
        };
        let ids = |ids: Vec<&str>| {
            (
                ids.len(),
                ids.into_iter().map(str::to_owned).collect::<BTreeSet<_>>(),
            )
        };
        let want_pods = ids(state.pods.iter().map(|p| p.id.as_str()).collect());
        let want_containers = ids(state.containers.iter().map(|c| c.id.as_str()).collect());
        assert_eq!(ids(pods.iter().map(|p| p.id.as_str()).collect()), want_pods);
        assert_eq!(
            ids(containers.iter().map(|c| c.id.as_str()).collect()),
            want_containers
        );
    }
    let configured = recorder.configured.lock().unwrap().clone();
    assert_eq!(
        configured,
        [Configuration {
            runtime_name: "containerd".to_owned(),
            runtime_version: "v2.4.2".to_owned(),
            nri_version: NriVersion::Announced("v0.12.3".to_owned()),
            registration_timeout: Duration::from_secs(3),
            request_timeout: Duration::from_millis(1500),
        }]
    );

    assert_eq!(runtime.create(&create("nginx")).unwrap(), Verdict::Allowed);
    match runtime.create(&create("reject")).unwrap() {
        Verdict::Rejected(e) => assert!(e.contains(REJECTION), "{e}"),
        Verdict::Allowed => panic!("the handler rejects this container"),
    }
    let deadlines = recorder.deadlines.lock().unwrap().clone();
    assert!(
        deadlines
            .iter()
            .all(|d| *d <= Duration::from_millis(1500) && *d > Duration::from_millis(1300)),
        "{deadlines:?}"
    );
    assert_eq!(runtime.close().unwrap(), 1);
    let end = session.join().unwrap();
    assert!(matches!(end, End::Closed), "{end}");
}

#[test]
fn the_plugin_infers_the_nri_version_cri_o_leaves_empty() {
    let Some(oracle) = oracle() else { return };
    for (runtime_version, nri_version) in [
        ("v1.35.10", NriVersion::Inferred("v0.11.0")),
        // CRI-O announces its version without a `v` (`internal/version/version.go:26` at v1.37.2), which neither NRI
        // nor the plugin infers from.
        (
            "1.35.10",
            NriVersion::Unknown {
                announced: String::new(),
                error: InferError::NoMatch("1.35.10".to_owned()),
            },
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut runtime = oracle.nri_runtime().unwrap();
        let mut start = Start::new(socket(&dir), "cri-o", runtime_version);
        start.nri_version = Some(String::new());
        runtime.start(&start).unwrap();
        let recorder = Arc::new(Recorder::default());
        let session = plugin(&socket(&dir), &recorder, REGISTRATION_TIMEOUT);
        runtime.wait(1, SETTLE).unwrap();
        assert_eq!(runtime.create(&create("nginx")).unwrap(), Verdict::Allowed);
        let configured = recorder.configured.lock().unwrap().clone();
        let [configuration] = &configured[..] else {
            panic!("{configured:?}")
        };
        assert_eq!(configuration.nri_version, nri_version);
        runtime.close().unwrap();
        session.join().unwrap();
    }
}

#[test]
fn the_registration_fails_after_its_timeout_when_the_runtime_does_not_answer() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    // The raw mode answers nothing on ConnID 2, where the plugin registers.
    runtime.raw(&socket(&dir), Duration::from_secs(5)).unwrap();
    let timeout = Duration::from_millis(500);
    let session = plugin(&socket(&dir), &Arc::default(), timeout);
    runtime.accept(SETTLE).unwrap();
    let end = session.join().unwrap();
    assert!(
        matches!(end, End::Registration(speculaire_nri::RegistrationError::Timeout(t)) if t == timeout),
        "{end}"
    );
}

#[test]
fn a_frame_over_the_maximum_payload_closes_the_trunk() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    runtime.raw(&socket(&dir), Duration::from_secs(5)).unwrap();
    let session = plugin(&socket(&dir), &Arc::default(), SETTLE);
    runtime.accept(SETTLE).unwrap();
    let written = runtime.oversize(1).unwrap();
    let end = session.join().unwrap();
    assert!(matches!(end, End::Lost(MuxError::Oversize(_))), "{end}");
    eprintln!(
        "the oracle wrote {} bytes: {:?}",
        written.bytes, written.error
    );
}

#[test]
fn with_conn_2_stalled_create_container_on_conn_1_is_answered() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    runtime.raw(&socket(&dir), Duration::from_secs(5)).unwrap();
    let recorder = Arc::new(Recorder::default());
    let session = plugin(&socket(&dir), &recorder, SETTLE);
    runtime.accept(SETTLE).unwrap();
    // The registration waits on ConnID 2, which the raw mode never answers.
    assert_eq!(runtime.create(&create("nginx")).unwrap(), Verdict::Allowed);
    match runtime.create(&create("reject")).unwrap() {
        Verdict::Rejected(e) => assert!(e.contains(REJECTION), "{e}"),
        Verdict::Allowed => panic!("the handler rejects this container"),
    }
    let stalled = runtime.report().unwrap().stalled.unwrap();
    assert!(stalled.frames >= 1, "{stalled:?}");
    runtime.close().unwrap();
    let end = session.join().unwrap();
    assert!(matches!(end, End::Closed), "{end}");
}

/// The listed tags, and the `justfile`'s runtime pins as `v` tags; each also as CRI-O announces it, without its `v`.
fn version_cases() -> Vec<VersionCase> {
    let listed = include_str!("versions.txt");
    let tags = listed
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| {
            let (runtime, tag) = line
                .split_once(' ')
                .unwrap_or_else(|| panic!("{line:?}: not `runtime tag`"));
            (runtime.to_owned(), tag.to_owned())
        });
    let pins = justfile_pins()
        .into_iter()
        .map(|(runtime, pin)| (runtime, format!("v{pin}")));
    let unique: BTreeSet<(String, String)> = tags.chain(pins).collect();
    let mut cases: Vec<VersionCase> = Vec::new();
    for (runtime, tag) in unique {
        let bare = tag.strip_prefix('v').unwrap_or(&tag).to_owned();
        cases.push(VersionCase {
            runtime: runtime.clone(),
            version: tag,
        });
        cases.push(VersionCase {
            runtime,
            version: bare,
        });
    }
    // What the port of Go's semver and of NRI's git suffix stripping must agree on.
    for (runtime, version) in [
        ("containerd", "v2.2.0-225-ge9dc15b7a.m"),
        ("containerd", "v2.2.1-3-gabc"),
        ("containerd", "v2.2.1-3-gxyz"),
        ("containerd", "v2.2.0-+3-g-1"),
        ("containerd", "v2.2.0-3-g-1"),
        ("containerd", "v2.2.0-3-g1.x"),
        ("containerd", "v2.2.1-rc.1"),
        ("containerd", "v2.2.1+build"),
        ("containerd", "v2.2.1-3-gabc+build"),
        ("containerd", "v2.2"),
        ("containerd", "v2"),
        ("containerd", "v2.2.01"),
        ("containerd", "v1.6.99"),
        ("containerd", "v1.7.0-rc.1"),
        ("containerd", ""),
        ("cri-o", "v1.26.4-0.1"),
        ("cri-o", "v1.27.0-rc.1"),
        ("cri-o", "v1.30.0-01"),
        ("docker", "v29.0.0"),
    ] {
        cases.push(VersionCase {
            runtime: runtime.to_owned(),
            version: version.to_owned(),
        });
    }
    cases
}

/// Each runtime pin of the `justfile`, as the runtime NRI names and the version.
fn justfile_pins() -> Vec<(String, String)> {
    let justfile = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../justfile"))
        .expect("the justfile is at the root");
    justfile
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(" := ")?;
            let runtime = if name.starts_with("containerd_") {
                "containerd"
            } else if name.starts_with("crio_") {
                "cri-o"
            } else {
                return None;
            };
            Some((runtime.to_owned(), value.trim_matches('"').to_owned()))
        })
        .collect()
}

#[test]
fn every_justfile_runtime_pin_is_listed() {
    let listed = include_str!("versions.txt");
    let pins = justfile_pins();
    assert!(pins.len() >= 5, "{pins:?}");
    for (runtime, pin) in pins {
        let line = format!("{runtime} v{pin}");
        assert!(
            listed.lines().any(|l| l == line),
            "add `{line}` to crates/nri/tests/versions.txt"
        );
    }
}

#[test]
fn the_nri_version_inferred_is_nris_for_every_listed_runtime_version() {
    let Some(oracle) = oracle() else { return };
    let cases = version_cases();
    let answers: Vec<VersionAnswer> = oracle.ask("nri-version", &cases).unwrap();
    assert_eq!(answers.len(), cases.len());
    for (case, answer) in cases.iter().zip(answers) {
        let ours = match version::infer(&case.runtime, &case.version) {
            Ok(nri) => VersionAnswer::NriVersion(nri.to_owned()),
            Err(e) => VersionAnswer::Error(e.to_string()),
        };
        assert_eq!(ours, answer, "{case:?}");
    }
    eprintln!("{} runtime versions agree", cases.len());
}
