//! The gate's registration against NRI's own runtime side, `speculaire-oracle nri-runtime` (D29, D41, D64). Without
//! `SPECULAIRE_ORACLE` the tests skip, as in `just check`; `just oracle` sets it.
//!
//! The tests share the process's metrics recorder and log subscriber, so they run one at a time.

#![expect(clippy::panic, reason = "a test file: its helpers report by panicking")]

use std::future::{self, Future};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use metrics_exporter_prometheus::PrometheusHandle;
use speculaire_agent::gate::Gate;
use speculaire_agent::status::Status;
use speculaire_agent::telemetry;
use speculaire_mirror::listed::Listed;
use speculaire_oracle_harness::Oracle;
use speculaire_oracle_harness::nri::Start;
use speculaire_runtime::Node;
use speculaire_runtime::detect::{Runtime, Sockets};
use speculaire_runtime::images::{Images, Update};
use speculaire_runtime::paths::Paths;
use tokio::sync::mpsc;

/// A plugin connects, registers and synchronizes well within this.
const SETTLE: Duration = Duration::from_secs(30);

/// How soon the gate registers again once the runtime is back: within its 1 s retry, and the registration.
const AGAIN: Duration = Duration::from_secs(2);

static SERIAL: Mutex<()> = Mutex::new(());

/// What the gate logs, for every test of the process.
static LOGS: OnceLock<Logs> = OnceLock::new();

/// The process's recorder.
static METRICS: OnceLock<PrometheusHandle> = OnceLock::new();

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

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl Logs {
    fn text(&self) -> String {
        let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

impl Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A runtime whose image list never comes: the gate registers without it.
struct Unlisted;

impl Images for Unlisted {
    fn follow(
        self: Arc<Self>,
        _: mpsc::Sender<Update>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'static>> {
        Box::pin(future::pending())
    }
}

/// A gate on `socket`, on a runtime of its own, with the process's recorder and logs.
struct Agent {
    runtime: tokio::runtime::Runtime,
    gate: Option<Gate>,
    status: Arc<Status>,
    metrics: PrometheusHandle,
    logs: Logs,
    _serial: MutexGuard<'static, ()>,
}

impl Agent {
    /// Starts the gate of a node that runs `runtime`, its mirror listening: `/readyz` waits for the gate alone.
    fn start(socket: &Path, runtime: Runtime) -> Self {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
        let logs = LOGS
            .get_or_init(|| {
                let logs = Logs::default();
                let writer = logs.clone();
                tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_writer(move || writer.clone())
                    .init();
                logs
            })
            .clone();
        let metrics = METRICS
            .get_or_init(|| telemetry::install().expect("the first recorder of the process"))
            .clone();
        let status = Arc::new(Status::new(metrics.clone(), false));
        status.mirror_listening();
        let tokio = tokio::runtime::Runtime::new().expect("a runtime builds");
        // A node with no runtime socket: containerd's image store stays empty.
        let root = socket.parent().expect("the socket is in a directory");
        let sockets = Sockets {
            containerd: root.join("containerd.sock"),
            crio: root.join("crio.sock"),
        };
        let node = Node::new(runtime, &sockets, Paths::under(root), None, "systemctl");
        let gate = {
            let _entered = tokio.enter();
            Gate::start(
                socket.to_owned(),
                runtime,
                node.identity(),
                Listed::follow(Arc::new(Unlisted)),
                Duration::from_millis(300),
                Arc::clone(&status),
            )
        };
        Self {
            runtime: tokio,
            gate: Some(gate),
            status,
            metrics,
            logs,
            _serial: serial,
        }
    }

    /// `speculaire_nri_connected`.
    fn connected(&self) -> bool {
        let text = self.metrics.render();
        match text
            .lines()
            .find_map(|line| line.strip_prefix("speculaire_nri_connected "))
        {
            Some("1") => true,
            Some("0") => false,
            other => panic!("speculaire_nri_connected is {other:?} in\n{text}"),
        }
    }

    /// The `speculaire_build_info` series, each as its labels and value.
    fn build_info(&self) -> Vec<String> {
        let mut series: Vec<String> = self
            .metrics
            .render()
            .lines()
            .filter_map(|line| line.strip_prefix("speculaire_build_info{"))
            .map(str::to_owned)
            .collect();
        // The exporter's order is a hash map's.
        series.sort();
        series
    }

    /// The `speculaire_identity_path` series at 1, each as its labels.
    fn identity_paths(&self) -> Vec<String> {
        self.metrics
            .render()
            .lines()
            .filter_map(|line| line.strip_prefix("speculaire_identity_path{"))
            .filter_map(|line| line.strip_suffix("} 1"))
            .map(str::to_owned)
            .collect()
    }

    /// Waits until the gate is registered or not, as `/readyz` and `speculaire_nri_connected` both say; returns how
    /// long that took.
    fn until_registered(&self, registered: bool, within: Duration) -> Duration {
        let start = Instant::now();
        while self.status.ready() != registered || self.connected() != registered {
            assert!(
                start.elapsed() < within,
                "registered is not {registered} within {within:?}: /readyz says {}, speculaire_nri_connected {}",
                self.status.ready(),
                self.connected()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        start.elapsed()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if let Some(gate) = self.gate.take() {
            self.runtime.block_on(gate.stop());
        }
    }
}

fn socket(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("nri.sock")
}

#[test]
fn the_gate_registers_again_at_once_and_within_2_s_of_a_runtime_that_comes_back() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let start = Start::new(socket(&dir), "containerd", "v2.4.2");
    let mut runtime = oracle.nri_runtime().unwrap();
    runtime.start(&start).unwrap();
    let agent = Agent::start(&socket(&dir), Runtime::Containerd);
    agent.until_registered(true, SETTLE);
    let report = runtime.wait(1, SETTLE).unwrap();
    assert_eq!(report.plugins[0].name, "50-speculaire");
    let version = env!("CARGO_PKG_VERSION");
    // The recorder is the process's: the series of the tests before are there too.
    let series = agent.build_info();
    for want in [
        format!(r#"version="{version}",runtime="",runtime_version="",nri_version=""}} 0"#),
        format!(
            r#"version="{version}",runtime="containerd",runtime_version="v2.4.2",nri_version="v0.12.3"}} 1"#
        ),
    ] {
        assert!(series.contains(&want), "{want} not in {series:?}");
    }

    // The runtime closes the connection: the gate registers again at once. Meanwhile `gate.wait` became half of
    // the oracle's 2 s request timeout: the new `Configure` logs both, and the gate stays registered (Q5).
    let too_long = "gate.wait is not below half of the request timeout";
    assert!(!agent.logs.text().contains(too_long));
    agent
        .gate
        .as_ref()
        .unwrap()
        .set_wait(Duration::from_secs(1));
    assert_eq!(runtime.close().unwrap(), 1);
    runtime.wait(1, AGAIN).unwrap();
    agent.until_registered(true, AGAIN);
    let logs = agent.logs.text();
    let line = logs
        .lines()
        .find(|l| l.contains(too_long))
        .unwrap_or_else(|| panic!("no {too_long:?} in\n{logs}"));
    assert!(
        line.contains("gate_wait=1s") && line.contains("request_timeout=2s"),
        "{line}"
    );

    // The runtime exits, and is away for a while: `/readyz` is 503 and the gauge 0 until it comes back, and the
    // gate warns once, not at each retry.
    let before = agent.logs.text().len();
    drop(runtime);
    agent.until_registered(false, SETTLE);
    std::thread::sleep(Duration::from_millis(2500));
    assert!(!agent.status.ready() && !agent.connected());
    let away = agent.logs.text().split_off(before);
    assert_eq!(away.matches("cannot connect to NRI").count(), 1, "{away}");
    let mut runtime = oracle.nri_runtime().unwrap();
    runtime.start(&start).unwrap();
    let again = agent.until_registered(true, AGAIN);
    runtime.wait(1, SETTLE).unwrap();
    eprintln!("registered again {again:?} after the runtime came back");
    assert_eq!(agent.build_info(), series);
}

#[test]
fn the_gate_reads_containerd_s_image_identity_from_nri_and_cri_o_s_from_its_image_id() {
    let Some(oracle) = oracle() else { return };
    // containerd 2.4 announces NRI v0.12.3, and 2.3 v0.12.0, whose `Container` names no image; CRI-O 1.35 and 1.36
    // announce no NRI version (D169, D170).
    for (runtime, name, version, nri_version, path) in [
        (Runtime::Containerd, "containerd", "v2.4.2", None, "nri"),
        (
            Runtime::Containerd,
            "containerd",
            "v2.3.7",
            Some("v0.12.0".to_owned()),
            "annotation",
        ),
        (
            Runtime::CriO,
            "cri-o",
            "1.36.7",
            Some(String::new()),
            "image_id",
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut start = Start::new(socket(&dir), name, version);
        start.nri_version = nri_version;
        let mut nri = oracle.nri_runtime().unwrap();
        nri.start(&start).unwrap();
        let agent = Agent::start(&socket(&dir), runtime);
        let before = agent.logs.text().len();
        agent.until_registered(true, SETTLE);
        nri.wait(1, SETTLE).unwrap();
        assert!(
            agent
                .identity_paths()
                .contains(&format!(r#"path="{path}""#)),
            "{name}: {:?}",
            agent.identity_paths()
        );
        let logs = agent.logs.text().split_off(before);
        assert_eq!(
            logs.contains("identity gap, D15"),
            path == "annotation",
            "{name} {version}: {logs}"
        );
    }
}

#[test]
fn containerd_upgraded_to_nri_v0_12_2_moves_the_gate_off_the_annotation() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut start = Start::new(socket(&dir), "containerd", "v2.3.7");
    start.nri_version = Some("v0.12.0".to_owned());
    let mut nri = oracle.nri_runtime().unwrap();
    nri.start(&start).unwrap();
    let agent = Agent::start(&socket(&dir), Runtime::Containerd);
    agent.until_registered(true, SETTLE);
    nri.wait(1, SETTLE).unwrap();
    assert!(
        agent
            .identity_paths()
            .contains(&r#"path="annotation""#.to_owned())
    );
    drop(nri);
    agent.until_registered(false, SETTLE);
    let mut start = Start::new(socket(&dir), "containerd", "v2.4.2");
    start.nri_version = None;
    let mut nri = oracle.nri_runtime().unwrap();
    nri.start(&start).unwrap();
    agent.until_registered(true, AGAIN);
    nri.wait(1, SETTLE).unwrap();
    let paths = agent.identity_paths();
    assert!(paths.contains(&r#"path="nri""#.to_owned()), "{paths:?}");
    assert!(
        !paths.contains(&r#"path="annotation""#.to_owned()),
        "{paths:?}"
    );
}

#[test]
fn a_runtime_that_is_not_the_nodes_is_refused_until_the_agent_restarts() {
    let Some(oracle) = oracle() else { return };
    let dir = tempfile::tempdir().unwrap();
    let mut runtime = oracle.nri_runtime().unwrap();
    runtime
        .start(&Start::new(socket(&dir), "cri-o", "1.37.2"))
        .unwrap();
    let agent = Agent::start(&socket(&dir), Runtime::Containerd);
    let refusal = "NRI's Configure names a runtime that is not the node's";
    let start = Instant::now();
    while !agent.logs.text().contains(refusal) {
        assert!(
            start.elapsed() < SETTLE,
            "no refusal in\n{}",
            agent.logs.text()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    // Past two retries, the gate has not connected again.
    std::thread::sleep(Duration::from_millis(2500));
    let report = runtime.report().unwrap();
    assert!(report.plugins.is_empty(), "{report:?}");
    assert!(!agent.status.ready() && !agent.connected());
    let logs = agent.logs.text();
    let refusals: Vec<&str> = logs.lines().filter(|l| l.contains(refusal)).collect();
    assert_eq!(refusals.len(), 1, "{logs}");
    assert!(
        refusals[0].contains("configured=\"cri-o\"")
            && refusals[0].contains("detected=\"containerd\""),
        "{}",
        refusals[0]
    );
}
