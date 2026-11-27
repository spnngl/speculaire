//! The chart's uninstall hook (D211). Its `DaemonSet` runs `unconfigure` in an init container on every node, then
//! [`sleep`], which keeps the pod ready; its wait pod runs [`wait_daemonset`], which follows that `DaemonSet` through the
//! Kubernetes API until every pod is ready, and names the node of each whose init container failed.

use std::fmt::Write as _;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt as _, Limited};
use secrecy::{ExposeSecret as _, SecretString};
use serde::Deserialize;
use speculaire_registry::{Client, Request};
use speculaire_runtime::registries::{Credentials, Endpoint, Tls};
use tokio::signal::unix::{SignalKind, signal};

/// Where the kubelet mounts the pod's service account token, the cluster CA and the namespace.
const ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";
/// How often the API is asked.
const POLL: Duration = Duration::from_secs(1);
/// The largest answer read: the namespace's pods.
const MAX_BODY: usize = 16 << 20;

/// Does nothing until SIGTERM or SIGINT: as a container's PID 1, it is sent no signal it has no handler for.
///
/// # Errors
///
/// When the signal handlers cannot be installed.
pub fn sleep() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(async {
        let mut terminate = signal(SignalKind::terminate()).context("handling SIGTERM")?;
        let mut interrupt = signal(SignalKind::interrupt()).context("handling SIGINT")?;
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        Ok(())
    })
}

/// Waits until every pod of each `DaemonSet` of `names`, in this pod's namespace, is ready, asking the API server as this
/// pod's service account, and writes each change of progress to `out`.
///
/// # Errors
///
/// At the first poll that finds an init container failed, naming its node, the container and its message; or at
/// `timeout`, naming each pod not ready, its node and why; or when the service account cannot be read.
pub fn wait_daemonset(
    names: &[String],
    timeout: Duration,
    out: &mut impl std::io::Write,
) -> anyhow::Result<()> {
    let api = Api::in_cluster()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(api.wait(names, timeout, out))
}

/// The API server, as the pod's service account.
pub(crate) struct Api {
    client: Client,
    endpoint: Endpoint,
    namespace: String,
}

impl Api {
    /// The API server the kubelet names to every pod, trusted with the cluster CA, and the pod's namespace.
    fn in_cluster() -> anyhow::Result<Self> {
        let env = |name: &str| {
            std::env::var(name).with_context(|| format!("{name} is not set: not in a pod"))
        };
        let host = env("KUBERNETES_SERVICE_HOST")?;
        let port = env("KUBERNETES_SERVICE_PORT")?;
        let read = |file: &str| {
            let path = format!("{ACCOUNT}/{file}");
            std::fs::read(&path).with_context(|| format!("reading {path}"))
        };
        let token =
            String::from_utf8(read("token")?).context("the service account token is not UTF-8")?;
        let token = SecretString::from(token.trim().to_owned());
        let namespace = String::from_utf8(read("namespace")?)
            .context("the service account namespace is not UTF-8")?;
        let authority = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let endpoint = Endpoint {
            root: String::new(),
            tls: Tls {
                roots: vec![Bytes::from(read("ca.crt")?)],
                ..Tls::default()
            },
            ..Endpoint::new(true, authority)
        };
        Ok(Self::new(endpoint, &token, namespace.trim().to_owned()))
    }

    /// The API server at `endpoint`, as the bearer of `token`, in `namespace`.
    pub(crate) fn new(mut endpoint: Endpoint, token: &SecretString, namespace: String) -> Self {
        endpoint.headers.push((
            "Authorization".to_owned(),
            SecretString::from(format!("Bearer {}", token.expose_secret())),
        ));
        Self {
            client: Client::new(),
            endpoint,
            namespace,
        }
    }

    /// [`wait_daemonset`] with this server.
    pub(crate) async fn wait(
        &self,
        names: &[String],
        timeout: Duration,
        out: &mut impl std::io::Write,
    ) -> anyhow::Result<()> {
        let deadline = Instant::now() + timeout;
        let mut lines = vec![String::new(); names.len()];
        loop {
            let mut done = true;
            let mut failed = Vec::new();
            for (name, last) in names.iter().zip(&mut lines) {
                // The API server may be away a moment: an error is waited on like a pod, and the deadline bounds both.
                let progress = self.progress(name).await;
                let line = match &progress {
                    Ok(progress) => format!("{name}: {progress}"),
                    Err(e) => format!("{name}: {e:#}"),
                };
                // A failure is the error, written once.
                let failure = matches!(progress, Ok(Progress::Failed(_)));
                if line != *last && !failure {
                    writeln!(out, "{line}")?;
                }
                *last = line;
                match progress {
                    Ok(Progress::Done) => {}
                    Ok(Progress::Failed(_)) => {
                        failed.push(last.as_str());
                        done = false;
                    }
                    _ => done = false,
                }
            }
            if !failed.is_empty() {
                anyhow::bail!("{}", failed.join("; "));
            }
            if done {
                return Ok(());
            }
            if Instant::now() >= deadline {
                anyhow::bail!(
                    "not ready within {} s: {}",
                    timeout.as_secs(),
                    lines.join("; ")
                );
            }
            tokio::time::sleep(POLL).await;
        }
    }
    /// Where the `DaemonSet` `name` stands now.
    async fn progress(&self, name: &str) -> anyhow::Result<Progress> {
        let namespace = &self.namespace;
        let daemonset = self
            .get(&format!(
                "/apis/apps/v1/namespaces/{namespace}/daemonsets/{name}"
            ))
            .await?;
        let daemonset = DaemonSet::parse(&daemonset)?;
        let pods = Pods::parse(
            &self
                .get(&format!("/api/v1/namespaces/{namespace}/pods"))
                .await?,
        )?;
        Ok(Progress::of(&daemonset, &pods))
    }

    /// The body of a 200 to `GET path`.
    async fn get(&self, path: &str) -> anyhow::Result<Bytes> {
        let request = Request {
            method: Method::GET,
            path: path.to_owned(),
            repository: String::new(),
            headers: Vec::new(),
        };
        let response = self
            .client
            .send(&self.endpoint, &Credentials::Anonymous, &request)
            .await?;
        let status = response.status;
        let body = Limited::new(response.body, MAX_BODY)
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("GET {path}: {e}"))?
            .to_bytes();
        if status != StatusCode::OK {
            // The API server's `Status` names the missing object or permission; it holds no secret.
            let reason = String::from_utf8_lossy(&body[..body.len().min(512)]).into_owned();
            anyhow::bail!("GET {path}: {status}: {reason}");
        }
        Ok(body)
    }
}

/// Where a `DaemonSet`'s pods stand.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// The controller saw the latest spec, and every pod it schedules is ready.
    Done,
    /// `ready` of `desired` pods are ready; for each other one, its node and what it waits on.
    Waiting {
        /// The pods ready.
        ready: i64,
        /// The pods the controller schedules.
        desired: i64,
        /// `<node>: <reason>`, by node.
        pending: Vec<String>,
    },
    /// Pods that are not ready because an init container failed: `<node>: <container> failed: <message>`, by node.
    Failed(Vec<String>),
}

impl Progress {
    /// Where the pods of `daemonset` among `pods` stand.
    #[must_use]
    pub fn of(daemonset: &DaemonSet, pods: &Pods) -> Self {
        let mut pending = Vec::new();
        let mut failed = Vec::new();
        let owned = pods.items.iter().filter(|pod| {
            pod.metadata
                .owner_references
                .iter()
                .any(|owner| owner.uid == daemonset.metadata.uid)
        });
        for pod in owned.filter(|pod| !pod.ready()) {
            let node = pod.spec.node_name.as_deref().unwrap_or("(unscheduled)");
            match pod.failure() {
                Some(failure) => failed.push(format!("{node}: {failure}")),
                None => pending.push(format!("{node}: {}", pod.waiting_on())),
            }
        }
        failed.sort_unstable();
        pending.sort_unstable();
        let status = &daemonset.status;
        if !failed.is_empty() {
            Self::Failed(failed)
        } else if status.observed_generation >= daemonset.metadata.generation
            && status.number_ready == status.desired_number_scheduled
        {
            Self::Done
        } else {
            Self::Waiting {
                ready: status.number_ready,
                desired: status.desired_number_scheduled,
                pending,
            }
        }
    }
}

impl std::fmt::Display for Progress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Done => f.write_str("every pod is ready"),
            Self::Waiting {
                ready,
                desired,
                pending,
            } => {
                write!(f, "{ready} of {desired} pods ready")?;
                if !pending.is_empty() {
                    write!(f, "; waiting on {}", pending.join("; "))?;
                }
                Ok(())
            }
            Self::Failed(failed) => f.write_str(&failed.join("; ")),
        }
    }
}

/// What [`Progress`] reads of a `DaemonSet`.
#[derive(Debug, Deserialize)]
pub struct DaemonSet {
    metadata: Metadata,
    #[serde(default)]
    status: DaemonSetStatus,
}

impl DaemonSet {
    /// A `DaemonSet` as the API server answers it.
    ///
    /// # Errors
    ///
    /// When `body` is not one.
    pub fn parse(body: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(body).context("the DaemonSet")
    }
}

#[derive(Debug, Deserialize)]
struct Metadata {
    uid: String,
    #[serde(default)]
    generation: i64,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct DaemonSetStatus {
    observed_generation: i64,
    desired_number_scheduled: i64,
    number_ready: i64,
}

/// What [`Progress`] reads of a list of pods.
#[derive(Debug, Deserialize)]
pub struct Pods {
    items: Vec<Pod>,
}

impl Pods {
    /// A `PodList` as the API server answers it.
    ///
    /// # Errors
    ///
    /// When `body` is not one.
    pub fn parse(body: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(body).context("the pod list")
    }
}

#[derive(Debug, Deserialize)]
struct Pod {
    #[serde(default)]
    metadata: PodMetadata,
    #[serde(default)]
    spec: PodSpec,
    #[serde(default)]
    status: PodStatus,
}

impl Pod {
    /// Whether its `Ready` condition is true.
    fn ready(&self) -> bool {
        self.status
            .conditions
            .iter()
            .any(|c| c.kind == "Ready" && c.status == "True")
    }

    /// `<container> failed: <message>` of the first init container whose last run failed.
    fn failure(&self) -> Option<String> {
        self.status.init_container_statuses.iter().find_map(|c| {
            [&c.state, &c.last_state]
                .into_iter()
                .find_map(|state| state.terminated.as_ref().filter(|t| t.exit_code != 0))
                .map(|t| format!("{} failed: {}", c.name, t.why()))
        })
    }

    /// The reason of the first container waiting, init containers first, else the phase.
    fn waiting_on(&self) -> String {
        let status = &self.status;
        status
            .init_container_statuses
            .iter()
            .chain(&status.container_statuses)
            .find_map(|c| {
                c.state
                    .waiting
                    .as_ref()
                    .map(|w| format!("{} {}", c.name, w.reason))
            })
            .unwrap_or_else(|| status.phase.clone())
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PodMetadata {
    owner_references: Vec<Owner>,
}

#[derive(Debug, Deserialize)]
struct Owner {
    uid: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PodSpec {
    node_name: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PodStatus {
    phase: String,
    conditions: Vec<Condition>,
    init_container_statuses: Vec<ContainerStatus>,
    container_statuses: Vec<ContainerStatus>,
}

#[derive(Debug, Deserialize)]
struct Condition {
    #[serde(rename = "type")]
    kind: String,
    status: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ContainerStatus {
    name: String,
    state: State,
    last_state: State,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct State {
    waiting: Option<Waiting>,
    terminated: Option<Terminated>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Waiting {
    reason: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Terminated {
    exit_code: i32,
    reason: String,
    message: String,
}

impl Terminated {
    /// Its message, which `FallbackToLogsOnError` fills with the log's end, else its reason and exit code.
    fn why(&self) -> String {
        let message = self.message.trim();
        if message.is_empty() {
            let mut why = self.reason.clone();
            let _ = write!(why, " (exit code {})", self.exit_code);
            why.trim_start().to_owned()
        } else {
            message.replace('\n', " ")
        }
    }
}

#[cfg(test)]
mod tests;
