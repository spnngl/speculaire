//! The cluster the e2e suites run against, made by `just e2e-up <runtime> <version> [<kubernetes minor>]` (D27, D63).
//!
//! Suites live in `tests/`, each test `#[ignore]`d so that `just check` builds them without a cluster;
//! `just e2e-test` runs them with `--ignored`. They drive the cluster through `kubectl` and `docker exec`:
//! kind names each node's container after the node.
//!
//! The peer harness (D94): `just e2e-up` also starts the cluster's [`upstream`] registry and its reflectors'
//! [`balancer`]; [`node`] stops, slows and corrupts a node for the peer suites, and [`reflector`] calls a reflector.

use std::fmt;
use std::process::Command;

pub mod balancer;
pub mod node;
pub mod reflector;
pub mod registry;
pub mod upstream;

/// The image of the suites' plain pods, pinned by digest; Renovate moves it (renovate.json5, which skips `tests/`).
pub const TEST_IMAGE: &str = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec";

/// The CRI runtime of every node of the cluster (D63).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Runtime {
    /// containerd, with a node image of `e2e/node/containerd/`.
    Containerd,
    /// CRI-O, with a node image of `e2e/node/crio/`.
    Crio,
}

impl Runtime {
    /// The prefix of the node's `containerRuntimeVersion`, as kubelet reports it.
    #[must_use]
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Containerd => "containerd",
            Self::Crio => "cri-o",
        }
    }
}

/// The addresses of the cluster's nodes, which `SPECULAIRE_E2E_IP_FAMILY` picks (D94).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpFamily {
    /// IPv4 only.
    Ipv4,
    /// IPv4 and IPv6; the load balancer and `reflector.members` are on IPv6.
    Dual,
}

/// The cluster named by `just e2e-test` in the `SPECULAIRE_E2E_*` variables.
pub struct Cluster {
    name: String,
    context: String,
    family: IpFamily,
    runtime: Runtime,
    release: String,
    kubernetes: String,
}

impl Cluster {
    /// Reads the cluster from the environment `just e2e-test` sets.
    ///
    /// # Panics
    ///
    /// When a variable is missing: the suites run only through `just e2e-test`.
    #[must_use]
    #[expect(
        clippy::panic,
        reason = "a suite run outside `just e2e-test` is a usage error, reported by name"
    )]
    pub fn from_env() -> Self {
        let var = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| {
                panic!("{name} is unset: run the suites with just e2e <runtime> <version>")
            })
        };
        let runtime = match var("SPECULAIRE_E2E_RUNTIME").as_str() {
            "containerd" => Runtime::Containerd,
            "crio" => Runtime::Crio,
            other => panic!("SPECULAIRE_E2E_RUNTIME is {other:?}, not containerd or crio"),
        };
        let family = match var("SPECULAIRE_E2E_IP_FAMILY").as_str() {
            "ipv4" => IpFamily::Ipv4,
            "dual" => IpFamily::Dual,
            other => panic!("SPECULAIRE_E2E_IP_FAMILY is {other:?}, not ipv4 or dual"),
        };
        let name = var("SPECULAIRE_E2E_CLUSTER");
        Self {
            context: format!("kind-{name}"),
            name,
            family,
            runtime,
            release: var("SPECULAIRE_E2E_RELEASE"),
            kubernetes: var("SPECULAIRE_E2E_KUBERNETES"),
        }
    }

    /// The runtime every node runs.
    #[must_use]
    pub fn runtime(&self) -> Runtime {
        self.runtime
    }

    /// The addresses of its nodes.
    #[must_use]
    pub fn ip_family(&self) -> IpFamily {
        self.family
    }

    /// The nodes whose agents are reflectors: the control plane and the first worker (D94).
    #[must_use]
    pub fn reflectors(&self) -> [String; 2] {
        [
            format!("{}-control-plane", self.name),
            format!("{}-worker", self.name),
        ]
    }

    /// The runtime release the node image runs, such as `2.4.2` or `1.37.2`.
    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }

    /// The Kubernetes minor of the node image, such as `1.37`.
    #[must_use]
    pub fn kubernetes(&self) -> &str {
        &self.kubernetes
    }

    /// Runs `kubectl` against the cluster's context and returns its stdout.
    ///
    /// # Errors
    ///
    /// When `kubectl` cannot start or exits non-zero.
    pub fn kubectl(&self, args: &[&str]) -> Result<String, Failure> {
        run(Command::new("kubectl")
            .arg("--context")
            .arg(&self.context)
            .args(args))
    }

    /// Runs a command in a node's container and returns its stdout.
    ///
    /// # Errors
    ///
    /// When `docker` cannot start or the command exits non-zero.
    pub fn exec(&self, node: &str, command: &[&str]) -> Result<String, Failure> {
        run(Command::new("docker").arg("exec").arg(node).args(command))
    }

    /// Runs a command in a node's container and returns its exit status and output, whatever the status.
    ///
    /// # Errors
    ///
    /// When `docker` cannot start.
    pub fn exec_output(&self, node: &str, command: &[&str]) -> Result<Output, Failure> {
        let mut docker = Command::new("docker");
        docker.arg("exec").arg(node).args(command);
        let out = docker.output().map_err(|e| Failure {
            command: format!("{docker:?}"),
            detail: e.to_string(),
        })?;
        Ok(Output {
            success: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }

    /// Every node with its `Ready` condition and versions.
    ///
    /// # Errors
    ///
    /// When `kubectl` fails.
    pub fn nodes(&self) -> Result<Vec<Node>, Failure> {
        let out = self.kubectl(&[
            "get",
            "nodes",
            "-o",
            concat!(
                r"jsonpath={range .items[*]}{.metadata.name} ",
                r#"{.status.conditions[?(@.type=="Ready")].status} "#,
                r#"{.status.nodeInfo.containerRuntimeVersion} {.status.nodeInfo.kubeletVersion} "#,
                r#"{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}"#,
            ),
        ])?;
        Ok(out
            .lines()
            .filter_map(|line| {
                let mut fields = line.split(' ');
                Some(Node {
                    name: fields.next()?.to_owned(),
                    ready: fields.next()? == "True",
                    runtime: fields.next()?.to_owned(),
                    kubelet: fields.next()?.to_owned(),
                    address: fields.next()?.to_owned(),
                    ipv6: fields.next().map(str::to_owned),
                })
            })
            .collect())
    }
}

/// What a command run in a node left: its exit status and both streams.
#[derive(Debug)]
pub struct Output {
    /// Whether it exited with status 0.
    pub success: bool,
    /// What it wrote to stdout.
    pub stdout: String,
    /// What it wrote to stderr.
    pub stderr: String,
}

/// A node of the cluster, as `kubectl get nodes` reports it.
#[derive(Debug)]
pub struct Node {
    /// The node name, which is also its container's name.
    pub name: String,
    /// Whether its `Ready` condition is `True`.
    pub ready: bool,
    /// Its `containerRuntimeVersion`, such as `cri-o://1.37.2`.
    pub runtime: String,
    /// Its `kubeletVersion`, such as `v1.37.0`.
    pub kubelet: String,
    /// Its first `InternalIP`, on kind's Docker network: IPv4 on both families.
    pub address: String,
    /// Its second `InternalIP`, IPv6, on a dual-stack cluster.
    pub ipv6: Option<String>,
}

/// A command that could not start or exited non-zero.
pub struct Failure {
    pub(crate) command: String,
    pub(crate) detail: String,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.command, self.detail)
    }
}

// `unwrap` in a test prints `Debug`: the same text as `Display`, with stderr unescaped.
impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Failure {}

pub(crate) fn run(command: &mut Command) -> Result<String, Failure> {
    let shown = format!("{command:?}");
    let out = command.output().map_err(|e| Failure {
        command: shown.clone(),
        detail: e.to_string(),
    })?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(Failure {
            command: shown,
            detail: format!(
                "{}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ),
        })
    }
}
