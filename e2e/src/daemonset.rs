//! The node helpers' bodies when the agents are the chart's pods (D208).
//!
//! A pod's log goes with the pod: before a helper ends an agent's container, it follows the container's log to its end
//! and appends the lines to a file on the node, `KEPT`, which [`Cluster::agent_logs`] reads before the running container's.
//! The helpers ask the node's runtime, through `crictl`, for the running container and its log: the API server learns
//! of a container's start a second or so after the container serves.

use std::io::{BufRead as _, BufReader, Write as _};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;

use crate::logs::{Entry, Log};
use crate::registry::fail;
use crate::{Cluster, Failure, run};

/// The namespace `just e2e-up` installs the chart in.
pub const NAMESPACE: &str = "speculaire";
/// The chart's release, which names its `ConfigMap`, and its `DaemonSet`s with `-agent` and `-reflector`.
pub const RELEASE: &str = "speculaire";
/// The node label on which the chart's `DaemonSet`s drop the node's pod: the stop of [`Cluster::stop_agent`].
const OPT_OUT: &str = "speculaire.spnngl.github.io/disabled";
/// The node's directory of [`KEPT`] and [`EXIT`].
const DIR: &str = "/var/log/speculaire-e2e";
/// The lines of the node's ended agent containers, oldest first, as `crictl logs --timestamps` printed them.
const KEPT: &str = "/var/log/speculaire-e2e/agent.log";
/// The exit code of the node's last ended agent container, which [`Cluster::wait_stopped`] reads.
const EXIT: &str = "/var/log/speculaire-e2e/exit";
/// The shell command that sets `pod` to the ID of the node's ready agent pod other than `$old`, if any.
const POD: &str =
    "pod=$(crictl pods --quiet --state ready --namespace speculaire | grep -vx \"$old\" | head -1)";
/// The shell command that sets `id` to the ID of the node's running agent container, if any.
const RUNNING: &str = "id=$(crictl ps --quiet --state running --namespace speculaire --name '^(agent|reflector)$' | head -1)";
/// The shell filter that keeps a container's lines from `crictl logs --timestamps ID 2>&1`: they start with their
/// time, while `crictl`'s own errors, on the same stderr as the agent's lines, do not.
const LINES: &str = "grep --line-buffered -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T'";

/// The name of a node's agent pod.
struct Pod {
    name: String,
}

impl Cluster {
    /// The node's agent pod that is not being deleted, if any.
    fn pod(&self, node: &str) -> Result<Option<Pod>, Failure> {
        let field = format!("spec.nodeName={node}");
        let pods = self.kubectl(&[
            "get",
            "pods",
            "--namespace",
            NAMESPACE,
            "--field-selector",
            &field,
            "--output",
            "json",
        ])?;
        let pods: Value = serde_json::from_str(&pods).map_err(|e| fail(node, &e))?;
        Ok(pods
            .get("items")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|pod| pod.pointer("/metadata/deletionTimestamp").is_none())
            .find_map(|pod| pod.pointer("/metadata/name")?.as_str())
            .map(|name| Pod {
                name: name.to_owned(),
            }))
    }

    /// Labels the node out of the chart's `DaemonSet`s, waits until its agent has ended and its pod's sandbox has
    /// stopped, and returns when the agent began stopping: the time it logged `stopping`, else the node's clock before
    /// the label.
    ///
    /// The kubelet stops the sandbox right after the containers, and removes the pod up to a second later, which the
    /// helper does not wait for: the `DaemonSet` starts the next pod once this one has gone, and then the node's only
    /// ready sandbox is the next pod's, which [`Cluster::pod_live`] waits for.
    pub(crate) fn pod_stop(&self, node: &str) -> Result<SystemTime, Failure> {
        let began = self.clock(node)?;
        let lines = self.end(node, || self.label(node, true))?;
        self.sh(
            node,
            "for _ in $(seq 600); do
               [ -z \"$(crictl pods --quiet --state ready --namespace speculaire)\" ] && exit
               sleep 0.05
             done
             echo 'the pod sandbox is still ready after 30 s' >&2
             exit 1",
        )?;
        Ok(lines
            .iter()
            .filter_map(|line| Entry::from_pod(line).ok())
            .find(|(_, entry)| entry.message == "stopping")
            .map_or(began, |(_, entry)| entry.at))
    }

    /// Checks that the node's last stopped agent exited by itself, with 0, within the chart's grace period.
    pub(crate) fn pod_stopped(&self, node: &str) -> Result<(), Failure> {
        let code = self.sh(node, &format!("cat {EXIT}"))?;
        match code.trim() {
            "0" => Ok(()),
            other => Err(fail(node, &format!("the agent exited with {other}"))),
        }
    }

    /// Labels the node back into the chart's `DaemonSet`s, starts a new pod unless an agent runs, and waits until the
    /// agent is ready.
    pub(crate) fn pod_start(&self, node: &str) -> Result<(), Failure> {
        let running = self.pod_pid(node)?.is_some();
        if !running && let Some(pod) = self.pod(node)? {
            // Its agent failed or was killed, and the helper that saw it end kept its logs.
            self.delete_pod(&pod, true)?;
        }
        self.label(node, false)?;
        if !running {
            self.pod_live(node, "")?;
        }
        self.wait_ready(node)
    }

    /// Kills the node's agent with `SIGKILL`, which the kubelet starts again in the same pod.
    pub(crate) fn pod_kill(&self, node: &str) -> Result<(), Failure> {
        let pid = self
            .pod_pid(node)?
            .ok_or_else(|| fail(node, &"no agent runs to kill"))?;
        self.end(node, || {
            self.sh(node, &format!("kill -KILL {pid}")).map(drop)
        })
        .map(drop)
    }

    /// Deletes the node's agent pod, or labels the node back in, and returns once the next pod's agent runs; empties the
    /// agent's logs first unless `keep`.
    ///
    /// # Errors
    ///
    /// When the next agent, or its init container, fails, or the agent does not run within 120 s.
    pub(crate) fn pod_restart(&self, node: &str, keep: bool) -> Result<(), Failure> {
        // The `DaemonSet` starts the next pod once this one is deleted, before the kubelet has cleaned it up: waiting
        // for its agent to end, then telling its sandbox from the next pod's, saves that cleanup's seconds.
        let old = self.sh(node, &format!("old=\n{POD}\necho \"$pod\""))?;
        if let Some(pod) = self.pod(node)? {
            self.end(node, || self.delete_pod(&pod, false))?;
        }
        if !keep {
            self.sh(node, &format!("rm -f {KEPT} {EXIT}"))?;
        }
        self.label(node, false)?;
        self.pod_live(node, old.trim())
    }

    /// Waits until the agent of the node's new pod, any but the sandbox `old`, runs: it answers `/livez`, the chart's
    /// startup probe. An agent that fails first has its logs kept and its node labelled out, as systemd leaves a failed
    /// unit stopped.
    ///
    /// # Errors
    ///
    /// When the pod's agent, or its init container, fails, or the agent does not run within 120 s.
    fn pod_live(&self, node: &str, old: &str) -> Result<(), Failure> {
        // In a new pod, an ended agent container failed.
        let check = format!(
            "old={old}
             curl -sf -o /dev/null http://127.0.0.1:7482/livez && echo live && exit
             {POD}
             [ -z \"$pod\" ] || crictl ps --all --quiet --state exited --pod \"$pod\" | while read -r id; do
               crictl inspect --output go-template --template '{{{{.status.metadata.name}}}} exited {{{{.status.exitCode}}}} ({{{{.status.reason}}}})' \"$id\"
             done | grep -v '^configure exited 0 '
             true"
        );
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            let out = self.sh(node, &check)?;
            match out.trim() {
                "live" => return Ok(()),
                "" if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
                "" => return Err(fail(node, &"the agent does not run after 120 s")),
                failed => {
                    let failed = fail(node, &format!("the agent's pod failed: {failed}"));
                    // `crictl ps` lists the newest first.
                    self.sh(
                        node,
                        &format!(
                            "mkdir -p {DIR}
                             old={old}
                             {POD}
                             [ -z \"$pod\" ] || crictl ps --all --quiet --state exited --pod \"$pod\" --name '^(agent|reflector)$' \
                               | tac | while read -r id; do crictl logs --timestamps \"$id\" 2>&1 | {LINES} >>{KEPT}; done
                             true"
                        ),
                    )?;
                    self.pod_stop(node)?;
                    return Err(failed);
                }
            }
        }
    }

    /// The PID of the node's running agent, as the node sees it.
    pub(crate) fn pod_pid(&self, node: &str) -> Result<Option<u32>, Failure> {
        let pid = self.sh(
            node,
            &format!(
                "{RUNNING}
                 [ -z \"$id\" ] || crictl inspect --output go-template --template '{{{{.info.pid}}}}' \"$id\""
            ),
        )?;
        // An ended container's PID is 0.
        match pid.trim() {
            "" | "0" => Ok(None),
            pid => pid.parse().map(Some).map_err(|e| fail(node, &e)),
        }
    }

    /// The node's agent logs of kind `log` since `since`, taken to the second: its ended containers' first, then the
    /// running one's.
    pub(crate) fn pod_logs(
        &self,
        node: &str,
        since: Option<SystemTime>,
        log: Log,
    ) -> Result<Vec<Entry>, Failure> {
        // The agent logs to stderr, which `crictl logs` prints to its own.
        let lines = self.sh(
            node,
            &format!(
                "cat {KEPT} 2>/dev/null
                 {RUNNING}
                 [ -z \"$id\" ] || crictl logs --timestamps \"$id\" 2>&1 | {LINES} || true"
            ),
        )?;
        let since = since.map(|since| {
            let secs = since
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
        });
        lines
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| Entry::from_pod(line).map_err(|e| fail(&format!("the logs of {node}"), &e)))
            .filter(|parsed| match parsed {
                Ok((kind, entry)) => *kind == log && since.is_none_or(|since| entry.at >= since),
                Err(_) => true,
            })
            .map(|parsed| parsed.map(|(_, entry)| entry))
            .collect()
    }

    /// Runs `helm` with `args` in [`NAMESPACE`], and returns its stdout.
    ///
    /// # Errors
    ///
    /// When `helm` cannot start or exits non-zero.
    pub fn helm(&self, args: &[&str]) -> Result<String, Failure> {
        run(Command::new("helm")
            .args(["--kube-context", &self.context, "--namespace", NAMESPACE])
            .args(args))
    }

    /// Deletes `pod`, and waits until it has gone if `wait`.
    fn delete_pod(&self, pod: &Pod, wait: bool) -> Result<(), Failure> {
        self.kubectl(&[
            "delete",
            "pod",
            &pod.name,
            "--namespace",
            NAMESPACE,
            &format!("--wait={wait}"),
        ])
        .map(drop)
    }

    /// Follows the log of the node's running agent container while `act` ends it, appends the log's lines to
    /// [`KEPT`], writes the container's exit code to [`EXIT`], and returns the lines.
    pub(crate) fn end(
        &self,
        node: &str,
        act: impl FnOnce() -> Result<(), Failure>,
    ) -> Result<Vec<String>, Failure> {
        let id = self.sh(node, &format!("rm -f {EXIT}\n{RUNNING}\necho \"$id\""))?;
        let id = id.trim();
        if id.is_empty() {
            return act().map(|()| Vec::new());
        }
        // `crictl logs --follow` ends once it finds the container ended, which it checks on a change in the log's
        // directory or else every second: once the agent's process has gone, touching the log tells it at once. The
        // runtime records the exit code a little after.
        let mut follow = Command::new("docker");
        follow.args(["exec", node, "sh", "-c"]).arg(format!(
            "pid=$(crictl inspect --output go-template --template '{{{{.info.pid}}}}' {id})
             log=$(crictl inspect --output go-template --template '{{{{.status.logPath}}}}' {id})
             (while kill -0 \"$pid\" 2>/dev/null; do sleep 0.05; done
              while touch -c \"$log\"; do sleep 0.05; done) >/dev/null 2>&1 &
             crictl logs --follow --timestamps {id} 2>&1 | {LINES}
             kill $! 2>/dev/null
             for _ in $(seq 100); do
               state=$(crictl inspect --output go-template --template '{{{{.status.state}}}} {{{{.status.exitCode}}}}' {id}) || break
               [ \"${{state%% *}}\" = CONTAINER_EXITED ] && mkdir -p {DIR} && echo \"${{state#* }}\" >{EXIT} && break
               sleep 0.05
             done
             true"
        ));
        let follow = Lines::spawn(follow)?;
        // Up to the first line, the follow may not have opened the log yet.
        let first = follow.next(Instant::now() + Duration::from_secs(10));
        act()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        let lines: Vec<String> = first
            .into_iter()
            .chain(std::iter::from_fn(|| follow.next(deadline)))
            .collect();
        let mut append = Command::new("docker")
            .args(["exec", "-i", node, "sh", "-c"])
            .arg(format!("mkdir -p {DIR} && cat >>{KEPT}"))
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| fail(node, &e))?;
        if let Some(mut stdin) = append.stdin.take() {
            for line in &lines {
                writeln!(stdin, "{line}").map_err(|e| fail(node, &e))?;
            }
        }
        let status = append.wait().map_err(|e| fail(node, &e))?;
        if !status.success() {
            return Err(fail(node, &format!("appending to {KEPT}: {status}")));
        }
        Ok(lines)
    }

    /// Labels the node out of the chart's `DaemonSet`s, or back in.
    fn label(&self, node: &str, out: bool) -> Result<(), Failure> {
        let label = if out {
            format!("{OPT_OUT}=true")
        } else {
            format!("{OPT_OUT}-")
        };
        self.kubectl(&["label", "node", node, &label, "--overwrite"])
            .map(drop)
    }
}

/// The lines a command prints, read as it prints them; the command is killed when this drops.
struct Lines {
    child: Child,
    lines: Receiver<String>,
}

impl Lines {
    fn spawn(mut command: Command) -> Result<Self, Failure> {
        let shown = format!("{command:?}");
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| fail(&shown, &e))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| fail(&shown, &"no stdout"))?;
        let (send, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Ok(Self { child, lines })
    }

    /// The next line; `None` once the command has ended or at `deadline`.
    fn next(&self, deadline: Instant) -> Option<String> {
        self.lines
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .ok()
    }
}

impl Drop for Lines {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
