//! The cluster the e2e suites run against, made by `just e2e-up <minor>` (D27).
//!
//! Suites live in `tests/`, each test `#[ignore]`d so that `just check` builds them without a cluster;
//! `just e2e-test <minor>` runs them with `--ignored`. They drive the cluster through `kubectl` and `docker exec`:
//! kind names each node's container after the node.

use std::fmt;
use std::process::Command;

/// The image of the suites' plain pods, pinned by digest; Renovate moves it (renovate.json5, which skips `tests/`).
pub const TEST_IMAGE: &str = "docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec";

/// The cluster named by `just e2e-test` in `SPECULAIRE_E2E_CLUSTER` and `SPECULAIRE_E2E_CONTAINERD`.
pub struct Cluster {
    context: String,
    containerd: String,
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
            std::env::var(name)
                .unwrap_or_else(|_| panic!("{name} is unset: run the suites with just e2e <minor>"))
        };
        Self {
            context: format!("kind-{}", var("SPECULAIRE_E2E_CLUSTER")),
            containerd: var("SPECULAIRE_E2E_CONTAINERD"),
        }
    }

    /// The containerd release the node image runs, such as `2.4.2`.
    #[must_use]
    pub fn containerd(&self) -> &str {
        &self.containerd
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

    /// Every node with its `Ready` condition.
    ///
    /// # Errors
    ///
    /// When `kubectl` fails.
    pub fn nodes(&self) -> Result<Vec<Node>, Failure> {
        let out = self.kubectl(&[
            "get",
            "nodes",
            "-o",
            r#"jsonpath={range .items[*]}{.metadata.name} {.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}"#,
        ])?;
        Ok(out
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(name, ready)| Node {
                name: name.to_owned(),
                ready: ready == "True",
            })
            .collect())
    }
}

/// A node of the cluster, as `kubectl get nodes` reports it.
#[derive(Debug)]
pub struct Node {
    /// The node name, which is also its container's name.
    pub name: String,
    /// Whether its `Ready` condition is `True`.
    pub ready: bool,
}

/// A command that could not start or exited non-zero.
pub struct Failure {
    command: String,
    detail: String,
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

fn run(command: &mut Command) -> Result<String, Failure> {
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
