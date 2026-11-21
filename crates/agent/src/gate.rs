//! The gate's NRI plugin (D9, D41, D64): it registers with the runtime's NRI, again at once when the runtime closes the
//! connection, then every second until it succeeds. Each `CreateContainer` gets the [`decision`] of its image.

pub mod decision;

use std::future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use speculaire_mirror::listed::Listed;
use speculaire_nri::api::{Container, CreateContainerRequest, PodSandbox};
use speculaire_nri::{
    Answer, Configuration, End, Handler, NriVersion, REGISTRATION_TIMEOUT, serve,
};
use speculaire_runtime::detect::Runtime;
use speculaire_runtime::identity::NodeIdentity;
use tokio::net::UnixStream;
use tokio::sync::{Notify, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use self::decision::running::Running;
use self::decision::{Decider, Decision, Settings, Verifier};
use crate::config;
use crate::status::Status;
use crate::telemetry::{self, GATE_SECONDS, GATE_TOTAL, IDENTITY_PATH, NRI_CONNECTED, Versions};

/// How long the gate waits between two connections, unless the last one lasted longer (D41).
const RETRY: Duration = Duration::from_secs(1);

/// The gate's connection to the runtime's NRI, held while the agent serves.
pub struct Gate {
    settings: watch::Sender<Arc<Settings>>,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Gate {
    /// Connects to NRI's `socket` as the plugin of `runtime`, the node's, whose image identity path `identity` reads
    /// `listed` (D169, D170), and decides each container from the verdicts of `verifier` under `gate` (D172). Each
    /// `Configure` checks `gate.wait` against the runtime's request timeout (D41, D168). `status` follows the
    /// registration.
    #[must_use]
    pub fn start(
        socket: PathBuf,
        runtime: Runtime,
        (identity, listed): (NodeIdentity, Listed),
        verifier: Verifier,
        gate: &config::Gate,
        status: Arc<Status>,
    ) -> Self {
        exempted(gate);
        let (settings, read) = watch::channel(Arc::new(Settings::new(gate)));
        let (stop, stopped) = oneshot::channel();
        let decider = Arc::new(Decider::new(Arc::new(identity), verifier, read));
        let (synchronized, running) = watch::channel(Arc::default());
        let plugin = Plugin {
            runtime,
            decider: Arc::clone(&decider),
            status,
            versions: Mutex::new(Versions::default()),
            path: Mutex::new(None),
            refused: Notify::new(),
            synchronized,
        };
        let task = tokio::spawn(async move {
            // The list and containerd's image store outlive a connection, so a new one finds them already read. Once
            // the runtime's list ends, the last one read stays.
            let keep = async {
                listed
                    .each(|list| {
                        if let Some(list) = list {
                            decider.keep(list);
                        }
                    })
                    .await;
                future::pending::<()>().await;
            };
            tokio::select! {
                () = connect(socket, plugin, stopped) => {}
                () = keep => {}
                () = decider.identity().follow() => {}
                () = decider.watch_running(running) => {}
            }
        });
        Self {
            settings,
            stop,
            task,
        }
    }

    /// Takes the `[gate]` settings of a reload, which the next decision reads and the next `Configure` checks.
    pub fn set(&self, gate: &config::Gate) {
        self.settings.send_replace(Arc::new(Settings::new(gate)));
    }

    /// Closes the connection (D39 step 6).
    pub async fn stop(self) {
        // An error means the task already ended, which its join says.
        let _ = self.stop.send(());
        if let Err(err) = self.task.await {
            error!(%err, "the gate's NRI connection panicked");
        }
    }
}

/// Logs the exemptions of `gate` (D18).
fn exempted(gate: &config::Gate) {
    let exempt = &gate.exempt;
    let images: Vec<String> = exempt.images.iter().map(ToString::to_string).collect();
    info!(namespaces = ?exempt.namespaces, ?images, "the gate allows these namespaces and images unchecked");
}

/// Connects until `stop`, and plays the plugin on each connection.
async fn connect(socket: PathBuf, plugin: Plugin, mut stop: oneshot::Receiver<()>) {
    // `Delay`: a connection that lasted past `RETRY` is followed by one at once, a failed one by one after `RETRY`.
    let mut attempts = tokio::time::interval(RETRY);
    attempts.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Whether the failure to connect is already reported: a runtime that stays down warns once.
    let mut down = false;
    loop {
        tokio::select! {
            biased;
            _ = &mut stop => return,
            _ = attempts.tick() => {}
        }
        let stream = match UnixStream::connect(&socket).await {
            Ok(stream) => stream,
            Err(err) if down => {
                debug!(socket = %socket.display(), %err, "cannot connect to NRI");
                continue;
            }
            Err(err) => {
                warn!(socket = %socket.display(), %err, "cannot connect to NRI: trying again every second");
                down = true;
                continue;
            }
        };
        down = false;
        let (reader, writer) = stream.into_split();
        // Leaving the select drops the session, which closes the connection.
        let end = tokio::select! {
            biased;
            _ = &mut stop => return,
            () = plugin.refused.notified() => None,
            end = serve(reader, writer, &plugin, REGISTRATION_TIMEOUT) => Some(end),
        };
        plugin.registered(false);
        match end {
            // D64: a runtime that is not the node's stays refused until the agent restarts.
            None => {
                // An error means the gate was dropped, which also means stop.
                let _ = stop.await;
                return;
            }
            Some(end @ (End::Shutdown | End::Closed)) => info!(%end, "registering with NRI again"),
            Some(end) => warn!(%end, "registering with NRI again"),
        }
    }
}

/// The plugin's handler.
struct Plugin {
    /// The node's runtime, which `Configure` must name (D64).
    runtime: Runtime,
    /// Decides each container, through the image identity the node's runtime gives (D169, D172).
    decider: Arc<Decider>,
    status: Arc<Status>,
    /// The versions `speculaire_build_info` names: empty until the first `Configure` (D61, D168).
    versions: Mutex<Versions>,
    /// The path `speculaire_identity_path` names: none until the first `Configure` (D170).
    path: Mutex<Option<&'static str>>,
    /// Notified when `Configure` names a runtime that is not the node's.
    refused: Notify,
    /// The containers of the latest `Synchronize` (D175).
    synchronized: watch::Sender<Arc<Vec<Running>>>,
}

impl Plugin {
    /// Records whether the plugin is registered, for `/readyz` and `speculaire_nri_connected`.
    fn registered(&self, registered: bool) {
        self.status.nri_registered(registered);
        metrics::gauge!(NRI_CONNECTED).set(u8::from(registered));
    }

    /// Moves `speculaire_build_info` to `versions`, setting the series it named before to 0 (D168).
    fn name(&self, versions: Versions) {
        let mut named = self
            .versions
            .lock()
            .expect("no thread panics holding the versions");
        if *named != versions {
            telemetry::build_info(&named).set(0);
            telemetry::build_info(&versions).set(1);
            *named = versions;
        }
    }

    /// Chooses the identity path by NRI's version, and moves `speculaire_identity_path` to it, setting the series it
    /// named before to 0 (D170). On `annotation`, warns of the gap D15 accepts.
    fn choose_path(&self, nri_version: &NriVersion, named: &str) {
        let path = self.decider.identity().configure(nri_version);
        let mut chosen = self.path.lock().expect("no thread panics holding the path");
        if let Some(before) = chosen.replace(path) {
            metrics::gauge!(IDENTITY_PATH, "path" => before).set(0);
        }
        metrics::gauge!(IDENTITY_PATH, "path" => path).set(1);
        if path == "annotation" {
            warn!(
                nri_version = named,
                "NRI below v0.12.2 names no image: the gate identifies a container's image by the name containerd \
                 annotates it with, and rejects the container when its snapshot does not rest on that image's layers. \
                 An image retagged after the pull to one of the same layers and another config passes as the old one \
                 (identity gap, D15)"
            );
        }
    }
}

impl Handler for Plugin {
    fn configure(&self, configuration: &Configuration) {
        let runtime = self.runtime.name();
        if configuration.runtime_name != runtime {
            error!(
                configured = configuration.runtime_name,
                detected = runtime,
                "NRI's Configure names a runtime that is not the node's: the gate closes its connection and registers \
                 again only when the agent restarts"
            );
            self.refused.notify_one();
            return;
        }
        let versions = Versions {
            runtime,
            runtime_version: configuration.runtime_version.clone(),
            nri_version: match &configuration.nri_version {
                NriVersion::Announced(version) => version.clone(),
                NriVersion::Inferred(version) => (*version).to_owned(),
                // CRI-O 1.35 and 1.36 announce none, and NRI cannot infer it from their versions (D64).
                NriVersion::Unknown { .. } => String::new(),
            },
        };
        info!(
            runtime,
            runtime_version = versions.runtime_version,
            nri_version = versions.nri_version,
            "registered with NRI"
        );
        let wait = self.decider.settings().wait;
        let timeout = configuration.request_timeout;
        if wait.saturating_mul(2) >= timeout {
            error!(
                gate_wait = ?wait,
                request_timeout = ?timeout,
                "gate.wait is not below half of the request timeout NRI's Configure gives: a container whose verdict is \
                 pending may outlast the runtime's wait (D41)"
            );
        }
        self.choose_path(&configuration.nri_version, &versions.nri_version);
        self.name(versions);
        self.registered(true);
    }

    // The gate is ready without it (Q4).
    fn synchronize(&self, pods: Vec<PodSandbox>, containers: Vec<Container>) {
        self.synchronized
            .send_replace(Arc::new(Running::listed(pods, containers)));
    }

    async fn create_container(
        &self,
        request: &CreateContainerRequest,
        deadline: Instant,
    ) -> Answer {
        let started = Instant::now();
        let settings = self.decider.settings();
        let decision = self.decider.decide(request, &settings, deadline).await;
        let path = self.decider.identity().path();
        metrics::histogram!(GATE_SECONDS, "path" => path).record(started.elapsed());
        answer(&decision, &settings)
    }

    fn overloaded(&self, request: &CreateContainerRequest) -> Answer {
        let settings = self.decider.settings();
        answer(&self.decider.overloaded(request, &settings), &settings)
    }
}

/// The answer `decision` gets under `settings`, counted under `speculaire_gate_total`.
fn answer(decision: &Decision, settings: &Settings) -> Answer {
    let stale = if decision.stale() { "true" } else { "false" };
    let mode = settings.mode.name();
    metrics::counter!(GATE_TOTAL, "mode" => mode, "result" => decision.result(), "stale" => stale)
        .increment(1);
    decision.answer(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_reload_swaps_the_settings_the_next_decision_reads() {
        let gate = config::Gate::default();
        let (settings, read) = watch::channel(Arc::new(Settings::new(&gate)));
        let (stop, _) = oneshot::channel();
        let gate = Gate {
            settings,
            stop,
            task: tokio::spawn(async {}),
        };
        assert_eq!(read.borrow().mode, config::Mode::Audit);
        let reloaded =
            config::parse("[gate]\nmode = \"enforce\"\nwait = 0.1\n").expect("the settings parse");
        gate.set(&reloaded.gate);
        assert_eq!(read.borrow().mode, config::Mode::Enforce);
        assert_eq!(read.borrow().wait, Duration::from_millis(100));
    }
}
