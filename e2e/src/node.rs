//! What the suites do to a node (D94): stop, start, restart, reload or kill its agent, slow its network, cut it off from
//! a host, corrupt a blob it serves, and read its metrics, logs and audit events.
//!
//! The suites act on the agent only through these helpers, which alone run `systemctl` and `journalctl` on it, except
//! the suites of the unit itself (D195).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use prost::Message as _;

use crate::logs::Entry;
use crate::registry::{docker, fail};
use crate::upstream::Digest;
use crate::{Cluster, Failure, Runtime};

/// The verification policy the agent reads by default (D8).
pub const POLICY: &str = "/etc/speculaire/policy.yaml";
/// The trusted root each node pins: the one recorded with the Sigstore fixtures (D141).
pub const TRUSTED_ROOT: &str = "/etc/speculaire/trusted_root.json";

/// A shell function `state` that prints the agent's `/readyz` status and `speculaire_nri_connected` as one line: `200 1`
/// when registered, `000 ` before the listener opens.
pub const STATE: &str = "state() { echo \"$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7482/readyz) \
                         $(curl -s http://127.0.0.1:7482/metrics | sed -n 's/^speculaire_nri_connected //p')\"; }";

/// See [`TRUSTED_ROOT`].
const RECORDED_ROOT: &str = include_str!("../../fixtures/sigstore/trusted_root.json");

impl Cluster {
    /// Pins the fixtures' recorded trusted root on `node`, at [`TRUSTED_ROOT`].
    ///
    /// # Errors
    ///
    /// When the node's command fails.
    pub fn pin(&self, node: &str) -> Result<(), Failure> {
        self.write(node, TRUSTED_ROOT, RECORDED_ROOT)
    }

    /// Writes `policy`, YAML ending in a newline, to [`POLICY`] on `node`.
    ///
    /// # Errors
    ///
    /// When the node's command fails.
    pub fn policy(&self, node: &str, policy: &str) -> Result<(), Failure> {
        self.write(node, POLICY, policy)
    }

    /// The file a node serves its peers `digest` from (D67): in containerd's content store, or in the agent's blob
    /// cache on CRI-O.
    #[must_use]
    pub fn blob_path(&self, digest: &Digest) -> String {
        let blobs = match self.runtime {
            Runtime::Containerd => {
                "/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256"
            }
            Runtime::Crio => "/var/lib/speculaire/blobs/blobs/sha256",
        };
        format!("{blobs}/{}", digest.hex())
    }

    pub(crate) fn sh(&self, node: &str, script: &str) -> Result<String, Failure> {
        self.exec(node, &["sh", "-c", script])
    }

    /// Writes `text` to the node's file `path`, and makes its directory.
    pub(crate) fn write(&self, node: &str, path: &str, text: &str) -> Result<(), Failure> {
        let dir = path.rsplit_once('/').map_or("/", |(dir, _)| dir);
        self.sh(
            node,
            &format!(
                "mkdir -p {dir} && cat >{path} <<'SPECULAIRE_E2E_EOF'\n{text}SPECULAIRE_E2E_EOF\n"
            ),
        )
        .map(drop)
    }

    /// Resets every TCP connection the node opens to `host`, a container on kind's network, until the guard drops: a
    /// pull from it fails at once.
    ///
    /// # Errors
    ///
    /// When `docker inspect` or `iptables` fails.
    pub fn reject(&self, node: &str, host: &str) -> Result<Rules<'_>, Failure> {
        self.reject_to(node, host, None)
    }

    /// Resets every TCP connection the node opens to `port` of `host`, a container on kind's network, until the guard
    /// drops.
    ///
    /// # Errors
    ///
    /// When `docker inspect` or `iptables` fails.
    pub fn reject_port(&self, node: &str, host: &str, port: u16) -> Result<Rules<'_>, Failure> {
        self.reject_to(node, host, Some(port))
    }

    /// Resets every TCP connection the node opens off loopback to port 80 or 443 until the guard drops: no upstream,
    /// the test ones on kind's network nor the internet's, can be reached, and peers and reflectors still can.
    ///
    /// # Errors
    ///
    /// When `iptables` fails.
    pub fn reject_upstreams(&self, node: &str) -> Result<Rules<'_>, Failure> {
        let rules = ["iptables", "ip6tables"]
            .into_iter()
            .flat_map(|tables| {
                [80, 443].map(|port| {
                    let rule = format!(
                        "OUTPUT ! -o lo -p tcp --dport {port} -j REJECT --reject-with tcp-reset"
                    );
                    (tables, rule)
                })
            })
            .collect();
        Rules::insert(self, node, rules)
    }

    fn reject_to(&self, node: &str, host: &str, port: Option<u16>) -> Result<Rules<'_>, Failure> {
        let port = port
            .map(|port| format!(" --dport {port}"))
            .unwrap_or_default();
        let rules = addresses(host)?
            .into_iter()
            .map(|address| {
                let tables = if address.is_ipv6() {
                    "ip6tables"
                } else {
                    "iptables"
                };
                let rule =
                    format!("OUTPUT -d {address} -p tcp{port} -j REJECT --reject-with tcp-reset");
                (tables, rule)
            })
            .collect();
        Rules::insert(self, node, rules)
    }

    /// Stops the node's agent, as an admin does, and returns the node's clock when the stop began.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails.
    pub fn stop_agent(&self, node: &str) -> Result<SystemTime, Failure> {
        self.scrape(node)?;
        let began = self.sh(node, "date +%s%N; systemctl stop speculaire")?;
        nanos(node, &began)
    }

    /// Stops the node's agent and runs `script` in the same `docker exec`, so that no other request of the kubelet's
    /// reaches the runtime between the two; returns what `script` printed.
    ///
    /// # Errors
    ///
    /// When the stop or `script` fails.
    pub fn stop_agent_then(&self, node: &str, script: &str) -> Result<String, Failure> {
        self.scrape(node)?;
        self.sh(node, &format!("systemctl stop speculaire\n{script}"))
    }

    /// Begins stopping the node's agent and returns once it stops, while it drains (D39).
    ///
    /// # Errors
    ///
    /// When the agent is not stopping within 2 s.
    pub fn stop_agent_no_wait(&self, node: &str) -> Result<(), Failure> {
        self.scrape(node)?;
        self.sh(
            node,
            "systemctl stop --no-block speculaire
             for _ in $(seq 100); do [ \"$(systemctl is-active speculaire)\" = deactivating ] && exit 0; sleep 0.02; done
             echo 'the agent is not stopping after 2 s' >&2; exit 1",
        )
        .map(drop)
    }

    /// Waits until the node's agent has stopped, and checks that it exited by itself within the stop timeout.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails, or the agent was killed or failed.
    pub fn wait_stopped(&self, node: &str) -> Result<(), Failure> {
        let result = self.sh(
            node,
            "while [ \"$(systemctl is-active speculaire)\" = deactivating ]; do sleep 0.1; done
             systemctl show -p Result --value speculaire",
        )?;
        match result.trim() {
            "success" => Ok(()),
            other => Err(fail(
                node,
                &format!("the agent stopped with result {other}"),
            )),
        }
    }

    /// Starts the node's agent and waits until it is ready.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails, or the agent is not ready within 120 s.
    pub fn start_agent(&self, node: &str) -> Result<(), Failure> {
        self.sh(
            node,
            "systemctl reset-failed speculaire; systemctl start speculaire",
        )?;
        self.wait_ready(node)
    }

    /// Kills the node's agent with `SIGKILL`; systemd starts it again (`Restart=on-failure`).
    ///
    /// # Errors
    ///
    /// When `systemctl` fails.
    pub fn kill_agent(&self, node: &str) -> Result<(), Failure> {
        self.scrape(node)?;
        self.sh(node, "systemctl kill --signal=SIGKILL speculaire")
            .map(drop)
    }

    /// Restarts the node's agent, keeping its logs, and returns once it runs: [`Cluster::wait_ready`] waits for it to
    /// register.
    ///
    /// # Errors
    ///
    /// When the agent fails to start.
    pub fn restart_agent(&self, node: &str) -> Result<(), Failure> {
        self.scrape(node)?;
        self.sh(
            node,
            "systemctl reset-failed speculaire; systemctl restart speculaire",
        )
        .map(drop)
    }

    /// Sends the node's agent `SIGHUP`, on which it reads its files again (D30, D91, D95, D154).
    ///
    /// # Errors
    ///
    /// When the agent does not run.
    pub fn reload_agent(&self, node: &str) -> Result<(), Failure> {
        self.sh(node, "systemctl reload speculaire").map(drop)
    }

    /// The PID of the node's agent, as the node sees it; `None` when no agent runs.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails.
    pub fn agent_pid(&self, node: &str) -> Result<Option<u32>, Failure> {
        let pid = self.sh(node, "systemctl show -p MainPID --value speculaire")?;
        let pid: u32 = pid.trim().parse().map_err(|e| fail(node, &e))?;
        Ok((pid != 0).then_some(pid))
    }

    /// The node's clock now.
    ///
    /// # Errors
    ///
    /// When `date` fails.
    pub fn clock(&self, node: &str) -> Result<SystemTime, Failure> {
        nanos(node, &self.sh(node, "date +%s%N")?)
    }

    /// The entries of the node's agent logs since `since`, a time of the node's clock taken to the second, or since
    /// they were emptied; oldest first, audit events aside.
    ///
    /// # Errors
    ///
    /// When `journalctl` fails, or an entry does not parse.
    pub fn agent_logs(&self, node: &str, since: Option<SystemTime>) -> Result<Vec<Entry>, Failure> {
        let since = since.map_or_else(String::new, |since| {
            let secs = since
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!(" --since @{secs}")
        });
        self.journal(
            node,
            &format!("journalctl -q -t speculaire --no-pager -o json{since}"),
        )
    }

    /// The audit events of the node's agent, oldest first (D37, D173).
    ///
    /// # Errors
    ///
    /// When `journalctl` fails, or an event does not parse.
    pub fn audit(&self, node: &str) -> Result<Vec<Entry>, Failure> {
        self.journal(node, "journalctl -q -t speculaire-audit --no-pager -o json")
    }

    fn journal(&self, node: &str, command: &str) -> Result<Vec<Entry>, Failure> {
        self.sh(node, command)?
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| {
                Entry::from_journal(line).map_err(|e| fail(&format!("the journal of {node}"), &e))
            })
            .collect()
    }

    /// Empties the node's agent logs and restarts the agent, which writes its start entries again: `unit.rs` asserts the
    /// logs hold no warning, and a kill leaves some.
    ///
    /// # Errors
    ///
    /// When the agent is not ready within 120 s.
    pub fn reset_agent(&self, node: &str) -> Result<(), Failure> {
        self.restart_with_empty_logs(node)?;
        self.wait_ready(node)
    }

    /// Stops the node's agent, empties its logs and starts the agent, without waiting for it.
    ///
    /// The agent stops first: one still running may write a warning between the vacuum and its stop, such as a
    /// discovery failing on an upstream the test has just removed. The vacuum keeps an archived file whose last entry
    /// is younger than its limit: at `1s`, the file just rotated, with the agent's last events, could stay.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails to start the agent.
    pub fn restart_with_empty_logs(&self, node: &str) -> Result<(), Failure> {
        self.scrape(node)?;
        self.sh(
            node,
            "systemctl stop speculaire; journalctl --rotate && journalctl --vacuum-time=1us; systemctl reset-failed speculaire; systemctl start speculaire",
        )
        .map(drop)
    }

    /// Waits until the node's agent answers `/readyz`.
    ///
    /// # Errors
    ///
    /// When it does not within 120 s.
    pub fn wait_ready(&self, node: &str) -> Result<(), Failure> {
        let deadline = Instant::now() + Duration::from_secs(120);
        while !self
            .exec_output(
                node,
                &[
                    "curl",
                    "-sf",
                    "-o",
                    "/dev/null",
                    "http://127.0.0.1:7482/readyz",
                ],
            )?
            .success
        {
            if Instant::now() > deadline {
                return Err(fail(node, &"the agent is not ready after 120 s"));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Ok(())
    }

    /// Waits until the node's agent streams to every reflector, so that its lookups and announcements reach them all.
    ///
    /// An agent whose dials to a stopped reflector failed waits up to 60 s before the next (D33), then 5 s for the dial:
    /// 90 s covers both.
    ///
    /// # Errors
    ///
    /// When the agent does not answer `/metrics`, or some stream is still down after 90 s.
    pub fn wait_connected(&self, node: &str) -> Result<(), Failure> {
        let series = self
            .reflectors()
            .map(|member| format!("speculaire_reflector_connected{{member=\"{member}\"}}"));
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let metrics = self.metrics(node)?;
            let connected = series.each_ref().map(|series| metrics.get(series));
            if connected.iter().all(|up| *up == Some(1.0)) {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(fail(
                    node,
                    &format!("not streaming to every reflector after 90 s: {connected:?}"),
                ));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Runs `command` on the node in the background, and returns each change of the agent's [`STATE`] from before
    /// the command until the agent is registered again after being away, or 30 s, as `<ms since the command> <state>`.
    ///
    /// # Errors
    ///
    /// When the node's command fails.
    pub fn watch(&self, node: &str, command: &str) -> Result<Vec<String>, Failure> {
        // Polled on the node: a registration takes milliseconds, less than an exec from the host.
        let changes = self.sh(
            node,
            &format!(
                "{STATE}
                 last=$(state); echo \"0 $last\"; away=0
                 start=$(date +%s%N); end=$((start + 30000000000))
                 {command} &
                 while [ \"$(date +%s%N)\" -lt \"$end\" ]; do
                     s=$(state)
                     if [ \"$s\" != \"$last\" ]; then echo \"$((($(date +%s%N) - start) / 1000000)) $s\"; last=$s; fi
                     if [ \"$s\" = '200 1' ]; then [ $away = 1 ] && break; else away=1; fi
                     sleep 0.02
                 done
                 wait"
            ),
        )?;
        Ok(changes.lines().map(str::to_owned).collect())
    }

    /// Restarts the node's runtime, waits until it answers again, and returns the agent's changes of state, as
    /// [`Cluster::watch`] does.
    ///
    /// # Errors
    ///
    /// When the node's command fails, or the runtime does not answer within 90 s.
    pub fn restart_runtime(&self, node: &str) -> Result<Vec<String>, Failure> {
        let changes = self.watch(node, &format!("systemctl restart {}", self.runtime.unit()))?;
        self.wait_runtime(node)?;
        Ok(changes)
    }

    /// Waits until the node's runtime answers, so that kubelet and the next suite find it.
    ///
    /// # Errors
    ///
    /// When it does not within 90 s.
    pub fn wait_runtime(&self, node: &str) -> Result<(), Failure> {
        let check = match self.runtime {
            Runtime::Containerd => "crictl version",
            Runtime::Crio => "crictl version && crio status config | grep -q nri",
        };
        let deadline = Instant::now() + Duration::from_secs(90);
        while !self.exec_output(node, &["sh", "-c", check])?.success {
            if Instant::now() > deadline {
                return Err(fail(node, &"the runtime is not back after 90 s"));
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Ok(())
    }

    /// Waits until the creation of `pod`'s container fails with a message that holds `reason`, then deletes the pod, and
    /// returns the message.
    ///
    /// # Errors
    ///
    /// When `kubectl` fails, or no such failure shows within 90 s.
    pub fn rejected(&self, namespace: &str, pod: &str, reason: &str) -> Result<String, Failure> {
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut state = String::new();
        while Instant::now() < deadline {
            state = self.kubectl(&[
                "get",
                "pod",
                "-n",
                namespace,
                pod,
                "-o",
                r#"jsonpath={.status.containerStatuses[0].state.waiting.reason}{"\n"}{.status.containerStatuses[0].state.waiting.message}"#,
            ])?;
            if let Some(("CreateContainerError", message)) = state.split_once('\n')
                && message.contains(reason)
            {
                let message = message.to_owned();
                self.kubectl(&[
                    "delete",
                    "pod",
                    "-n",
                    namespace,
                    pod,
                    "--now",
                    "--timeout=60s",
                ])?;
                return Ok(message);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        Err(fail(
            pod,
            &format!("no creation error holding {reason:?}, last {state:?}"),
        ))
    }

    /// Puts `tc netem <args>`, such as `delay 200ms` or `loss 100%`, on what leaves the node through kind's network.
    ///
    /// # Errors
    ///
    /// When `tc` fails; the host's kernel needs `sch_netem`.
    pub fn netem(&self, node: &str, args: &str) -> Result<Netem<'_>, Failure> {
        // `replace`: a killed run may have left one.
        self.sh(
            node,
            &format!("tc qdisc replace dev eth0 root netem {args}"),
        )?;
        Ok(Netem {
            cluster: self,
            node: node.to_owned(),
        })
    }

    /// Changes the first byte of the blob the node serves its peers as `digest`, keeping its size.
    ///
    /// # Errors
    ///
    /// When the node holds no such blob.
    pub fn corrupt_blob(&self, node: &str, digest: &Digest) -> Result<(), Failure> {
        let path = self.blob_path(digest);
        // `x`, or `y` when the byte is `x`.
        self.sh(
            node,
            &format!(
                "test -f {path} || {{ echo 'no blob {digest}' >&2; exit 1; }}; c=x; [ \"$(head -c 1 {path})\" != x ] || c=y; printf $c | dd of={path} bs=1 count=1 conv=notrunc 2>/dev/null"
            ),
        )
        .map(drop)
    }

    /// The node's metrics, as its agent serves them now.
    ///
    /// # Errors
    ///
    /// When the agent does not answer.
    pub fn metrics(&self, node: &str) -> Result<Metrics, Failure> {
        self.exec(node, &["curl", "-sf", "http://127.0.0.1:7482/metrics"])
            .map(Metrics)
    }

    /// The node's metrics as its agent serves them now in the protobuf exposition, the only one with native histograms
    /// (D34); `None` when the agent does not answer.
    ///
    /// # Errors
    ///
    /// When `docker` cannot start.
    pub fn exposition(&self, node: &str) -> Result<Option<Vec<u8>>, Failure> {
        let mut docker = Command::new("docker");
        docker.args([
            "exec",
            node,
            "curl",
            "-sf",
            "-H",
            "Accept: application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited",
            "http://127.0.0.1:7482/metrics",
        ]);
        let out = docker.output().map_err(|e| Failure {
            command: format!("{docker:?}"),
            detail: e.to_string(),
        })?;
        Ok(out.status.success().then_some(out.stdout))
    }

    /// Adds the node's metrics in the protobuf exposition to the leg's scrapes, one file each, for the catalog check
    /// (D182); nothing when the agent does not answer or `just e2e-test` named no directory. Each helper that stops the
    /// agent calls it first (D195).
    ///
    /// # Errors
    ///
    /// When `docker` cannot start, or the file cannot be written.
    pub fn scrape(&self, node: &str) -> Result<(), Failure> {
        static SCRAPES: AtomicU64 = AtomicU64::new(0);
        let Some(dir) = &self.scrapes else {
            return Ok(());
        };
        let Some(exposition) = self.exposition(node)? else {
            return Ok(());
        };
        let since = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = dir.join(format!(
            "{node}-{since}-{}.pb",
            SCRAPES.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(dir)
            .and_then(|()| std::fs::write(&path, exposition))
            .map_err(|e| fail(&path.display().to_string(), &e))
    }

    /// The series of the native histogram `name` whose labels include `label`, summed, as the node's agent serves them
    /// now; empty when it has none.
    ///
    /// # Errors
    ///
    /// When the agent does not answer, or its answer does not parse.
    pub fn histogram(
        &self,
        node: &str,
        name: &str,
        label: (&str, &str),
    ) -> Result<Native, Failure> {
        let metrics = format!("the metrics of {node}");
        let exposition = self
            .exposition(node)?
            .ok_or_else(|| fail(&metrics, &"the agent does not answer"))?;
        Native::decode(&exposition, name, Some(label)).map_err(|detail| fail(&metrics, &detail))
    }
}

/// The names of the metric families in `exposition`, an agent's `/metrics` in the protobuf exposition.
///
/// # Errors
///
/// When `exposition` does not parse.
pub fn families(mut exposition: &[u8]) -> Result<Vec<String>, String> {
    let mut names = Vec::new();
    while !exposition.is_empty() {
        let family =
            Family::decode_length_delimited(&mut exposition).map_err(|err| err.to_string())?;
        names.push(family.name);
    }
    Ok(names)
}

/// A native histogram of non-negative samples: its count, and the count of each bucket by index (D34).
#[derive(Clone, Debug, Default)]
pub struct Native {
    /// The samples.
    pub count: u64,
    /// The schema: the bucket of index `i` holds the samples above `2^((i - 1) / 2^schema)` up to `2^(i / 2^schema)`.
    schema: Option<i32>,
    /// The samples in the zero bucket.
    zero: u64,
    /// The samples of each positive bucket.
    buckets: BTreeMap<i32, u64>,
}

impl Native {
    /// The series of the native histogram `name` in `exposition`, an agent's `/metrics` in the protobuf exposition,
    /// summed: those whose labels include `label`, or all of them without one. Empty when it has none.
    ///
    /// # Errors
    ///
    /// When `exposition` does not parse, or holds histograms of two schemas.
    pub fn decode(
        mut exposition: &[u8],
        name: &str,
        label: Option<(&str, &str)>,
    ) -> Result<Self, String> {
        let mut native = Self::default();
        while !exposition.is_empty() {
            let family =
                Family::decode_length_delimited(&mut exposition).map_err(|err| err.to_string())?;
            if family.name != name {
                continue;
            }
            let histograms = family
                .metric
                .iter()
                .filter(|metric| {
                    label.is_none_or(|label| {
                        metric
                            .label
                            .iter()
                            .any(|pair| (pair.name.as_str(), pair.value.as_str()) == label)
                    })
                })
                .filter_map(|metric| metric.histogram.as_ref());
            for histogram in histograms {
                native.add(histogram)?;
            }
        }
        Ok(native)
    }

    /// The samples recorded after `before`, an earlier reading of the same histogram; `None` when `before` holds a
    /// sample this does not, as when the agent restarted in between and its histograms started empty.
    #[must_use]
    pub fn since(&self, before: &Self) -> Option<Self> {
        let Some(schema) = before.schema else {
            return Some(self.clone());
        };
        if self.schema != Some(schema) {
            return None;
        }
        let mut buckets = self.buckets.clone();
        for (index, count) in &before.buckets {
            let after = buckets.entry(*index).or_default();
            *after = after.checked_sub(*count)?;
        }
        Some(Self {
            count: self.count.checked_sub(before.count)?,
            schema: self.schema,
            zero: self.zero.checked_sub(before.zero)?,
            buckets,
        })
    }

    /// Adds the samples of `other`.
    ///
    /// # Errors
    ///
    /// When the two have different schemas.
    pub fn merge(&mut self, other: &Self) -> Result<(), &'static str> {
        let Some(schema) = other.schema else {
            return Ok(());
        };
        if *self.schema.get_or_insert(schema) != schema {
            return Err("histograms of two schemas");
        }
        self.count += other.count;
        self.zero += other.zero;
        for (index, count) in &other.buckets {
            *self.buckets.entry(*index).or_default() += count;
        }
        Ok(())
    }

    /// Adds the buckets of `histogram`, whose spans give each first index after the previous span's end and whose
    /// deltas give each count after the previous one.
    fn add(&mut self, histogram: &Histogram) -> Result<(), &'static str> {
        if *self.schema.get_or_insert(histogram.schema) != histogram.schema {
            return Err("histograms of two schemas");
        }
        self.count += histogram.sample_count;
        self.zero += histogram.zero_count;
        let mut deltas = histogram.positive_delta.iter();
        let (mut index, mut count) = (0_i32, 0_i64);
        for span in &histogram.positive_span {
            index += span.offset;
            for _ in 0..span.length {
                count += deltas.next().ok_or("fewer deltas than buckets")?;
                let count = u64::try_from(count).map_err(|_| "a negative bucket count")?;
                *self.buckets.entry(index).or_default() += count;
                index += 1;
            }
        }
        Ok(())
    }

    /// The upper bound of the bucket that holds the `percent`th percentile of the samples, in the samples' unit: no
    /// sample of that rank is above it. 0 when the zero bucket holds it or there are no samples.
    #[must_use]
    pub fn percentile(&self, percent: u64) -> f64 {
        let rank = (self.count * percent).div_ceil(100);
        let mut seen = self.zero;
        if seen >= rank {
            return 0.0;
        }
        let base = 2_f64.powf(2_f64.powi(-self.schema.unwrap_or_default()));
        for (index, count) in &self.buckets {
            seen += count;
            if seen >= rank {
                return base.powi(*index);
            }
        }
        f64::INFINITY
    }
}

/// The time `date +%s%N` printed first on `node`.
fn nanos(node: &str, date: &str) -> Result<SystemTime, Failure> {
    let nanos = date
        .lines()
        .next()
        .and_then(|line| line.trim().parse().ok())
        .ok_or_else(|| fail(node, &format!("no time in {date:?}")))?;
    Ok(SystemTime::UNIX_EPOCH + Duration::from_nanos(nanos))
}

/// Every address of `container`, a node or a registry, on kind's network, in both families: on a dual-stack cluster, a
/// node may resolve a name to either.
///
/// # Errors
///
/// When `docker inspect` fails, or prints an address that does not parse.
pub fn addresses(container: &str) -> Result<Vec<IpAddr>, Failure> {
    docker(&[
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}",
        container,
    ])?
    .split_whitespace()
    .map(|address| {
        address.parse().map_err(|e| {
            fail(
                &format!("the addresses of {container}"),
                &format!("{address:?}: {e}"),
            )
        })
    })
    .collect()
}

/// What [`Cluster::histogram`] and [`families`] read of a `MetricFamily` of Prometheus' `metrics.proto`.
#[derive(Clone, PartialEq, prost::Message)]
struct Family {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(message, repeated, tag = "4")]
    metric: Vec<Series>,
}

/// A `Metric`: its labels and its histogram.
#[derive(Clone, PartialEq, prost::Message)]
struct Series {
    #[prost(message, repeated, tag = "1")]
    label: Vec<LabelPair>,
    #[prost(message, optional, tag = "7")]
    histogram: Option<Histogram>,
}

/// A `LabelPair`.
#[derive(Clone, PartialEq, prost::Message)]
struct LabelPair {
    #[prost(string, tag = "1")]
    name: String,
    #[prost(string, tag = "2")]
    value: String,
}

/// A native `Histogram`: its count of samples, its zero bucket and its positive buckets.
#[derive(Clone, PartialEq, prost::Message)]
struct Histogram {
    #[prost(uint64, tag = "1")]
    sample_count: u64,
    #[prost(sint32, tag = "5")]
    schema: i32,
    #[prost(uint64, tag = "7")]
    zero_count: u64,
    #[prost(message, repeated, tag = "12")]
    positive_span: Vec<Span>,
    #[prost(sint64, repeated, tag = "13")]
    positive_delta: Vec<i64>,
}

/// A `BucketSpan`: `length` buckets from `offset` after the previous span's end, or from index 0 for the first.
#[derive(Clone, PartialEq, prost::Message)]
struct Span {
    #[prost(sint32, tag = "1")]
    offset: i32,
    #[prost(uint32, tag = "2")]
    length: u32,
}

/// `iptables` rules of a node, each with its command (`iptables` or `ip6tables`), deleted when this drops.
pub struct Rules<'a> {
    cluster: &'a Cluster,
    node: String,
    inserted: Vec<(&'static str, String)>,
}

impl<'a> Rules<'a> {
    /// Inserts each rule the node does not have yet.
    pub(crate) fn insert(
        cluster: &'a Cluster,
        node: &str,
        rules: Vec<(&'static str, String)>,
    ) -> Result<Self, Failure> {
        let mut guard = Self {
            cluster,
            node: node.to_owned(),
            inserted: Vec::new(),
        };
        for (tables, rule) in rules {
            guard
                .run(tables, "-C", &rule)
                .or_else(|_| guard.run(tables, "-I", &rule))?;
            guard.inserted.push((tables, rule));
        }
        Ok(guard)
    }

    /// Checks (`-C`), inserts (`-I`) or deletes (`-D`) `rule`.
    fn run(&self, tables: &str, command: &str, rule: &str) -> Result<String, Failure> {
        self.cluster
            .sh(&self.node, &format!("{tables} -w {command} {rule}"))
    }
}

impl Drop for Rules<'_> {
    fn drop(&mut self) {
        for (tables, rule) in &self.inserted {
            let _ = self.run(tables, "-D", rule);
        }
    }
}

/// A `tc netem` qdisc on a node, removed when this drops.
pub struct Netem<'a> {
    cluster: &'a Cluster,
    node: String,
}

impl Netem<'_> {
    /// Replaces the qdisc's `args`, such as a rate with `loss 100%`, in one step.
    ///
    /// # Errors
    ///
    /// When `tc` fails.
    pub fn change(&self, args: &str) -> Result<(), Failure> {
        self.cluster
            .sh(
                &self.node,
                &format!("tc qdisc replace dev eth0 root netem {args}"),
            )
            .map(drop)
    }
}

impl Drop for Netem<'_> {
    fn drop(&mut self) {
        let _ = self.cluster.sh(&self.node, "tc qdisc del dev eth0 root");
    }
}

/// What an agent's `/metrics` answered, in the Prometheus text format.
pub struct Metrics(String);

impl Metrics {
    /// The value of `series`, written as the agent writes it, such as
    /// `speculaire_mirror_requests_total{kind="blob",result="served"}`; `None` when the agent has not written it.
    #[must_use]
    pub fn get(&self, series: &str) -> Option<f64> {
        self.0.lines().find_map(|line| {
            let (name, value) = line.rsplit_once(' ')?;
            (name == series).then(|| value.parse().ok()).flatten()
        })
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use prost::Message as _;

    use super::{Family, Histogram, LabelPair, Native, Series, Span};

    #[test]
    fn the_percentile_is_the_upper_bound_of_the_bucket_of_its_rank_across_spans_and_series() {
        // Schema 0: the bucket of index i ends at 2^i. Buckets -1 and 0 hold 1 and 2 samples, then bucket 2 holds 3.
        let histogram = Histogram {
            sample_count: 7,
            schema: 0,
            zero_count: 1,
            positive_span: vec![
                Span {
                    offset: -1,
                    length: 2,
                },
                Span {
                    offset: 1,
                    length: 1,
                },
            ],
            positive_delta: vec![1, 1, 1],
        };
        let mut native = Native::default();
        native.add(&histogram).unwrap();
        native.add(&histogram).unwrap();
        assert_eq!(native.count, 14);
        assert_eq!(native.percentile(10), 0.0);
        assert_eq!(native.percentile(20), 0.5);
        assert_eq!(native.percentile(50), 1.0);
        assert_eq!(native.percentile(99), 4.0);
        let other = Histogram {
            schema: 3,
            ..histogram
        };
        assert!(native.add(&other).is_err());
    }

    #[test]
    fn the_samples_since_a_reading_are_the_difference_and_none_after_a_restart() {
        // Schema 0: one sample in bucket 0, up to 1, then two more in bucket 2, up to 4.
        let mut before = Native::default();
        before
            .add(&Histogram {
                sample_count: 1,
                schema: 0,
                zero_count: 0,
                positive_span: vec![Span {
                    offset: 0,
                    length: 1,
                }],
                positive_delta: vec![1],
            })
            .unwrap();
        let mut after = Native::default();
        after
            .add(&Histogram {
                sample_count: 3,
                schema: 0,
                zero_count: 0,
                positive_span: vec![
                    Span {
                        offset: 0,
                        length: 1,
                    },
                    Span {
                        offset: 1,
                        length: 1,
                    },
                ],
                positive_delta: vec![1, 1],
            })
            .unwrap();
        let since = after.since(&before).unwrap();
        assert_eq!(since.count, 2);
        assert_eq!(since.percentile(1), 4.0);
        assert_eq!(after.since(&Native::default()).unwrap().count, 3);
        assert!(before.since(&after).is_none());

        let mut set = since.clone();
        set.merge(&before).unwrap();
        assert_eq!(set.count, 3);
        assert_eq!(set.percentile(34), 4.0);
        assert_eq!(set.percentile(33), 1.0);
    }

    #[test]
    fn the_exposition_gives_the_sum_of_the_named_histogram_over_the_series_with_the_label() {
        // One sample in bucket 0 per series: two series of `gate`, one of them labelled, and one of `other`.
        let histogram = Histogram {
            sample_count: 1,
            schema: 0,
            zero_count: 0,
            positive_span: vec![Span {
                offset: 0,
                length: 1,
            }],
            positive_delta: vec![1],
        };
        let series = |label: Vec<LabelPair>| Series {
            label,
            histogram: Some(histogram.clone()),
        };
        let path = LabelPair {
            name: "path".to_owned(),
            value: "nri".to_owned(),
        };
        let mut exposition = Vec::new();
        for family in [
            Family {
                name: "other".to_owned(),
                metric: vec![series(Vec::new())],
            },
            Family {
                name: "gate".to_owned(),
                metric: vec![series(vec![path]), series(Vec::new())],
            },
        ] {
            family.encode_length_delimited(&mut exposition).unwrap();
        }
        assert_eq!(Native::decode(&exposition, "gate", None).unwrap().count, 2);
        let labelled = Native::decode(&exposition, "gate", Some(("path", "nri"))).unwrap();
        assert_eq!(labelled.count, 1);
        assert_eq!(Native::decode(&exposition, "none", None).unwrap().count, 0);
        assert!(Native::decode(&exposition[1..], "gate", None).is_err());
    }

    /// Every `.rs` file under `dir`.
    fn sources(dir: &Path, into: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("the e2e crate's directories read") {
            let path = entry.expect("the e2e crate's directories read").path();
            if path.is_dir() {
                sources(&path, into);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                into.push(path);
            }
        }
    }

    /// Outside these helpers and the suites of the unit itself, `systemctl` and `journalctl` act on the runtime only, on
    /// lines that name it (D195): an agent run as a `DaemonSet` has no unit.
    #[test]
    fn the_suites_act_on_the_agent_only_through_the_node_helpers() {
        const SYSTEMD_ONLY: [&str; 6] = [
            "src/node.rs",
            "tests/operations.rs",
            "tests/preflight.rs",
            "tests/unit.rs",
            "tests/unit_reload.rs",
            "tests/unit_restart.rs",
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        sources(&root.join("src"), &mut files);
        sources(&root.join("tests"), &mut files);
        let mut found = Vec::new();
        for path in files {
            let name = path
                .strip_prefix(root)
                .expect("under the crate")
                .to_string_lossy()
                .replace('\\', "/");
            if SYSTEMD_ONLY.contains(&name.as_str()) {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("the source reads");
            for (number, line) in text.lines().enumerate() {
                let systemd = line.contains("systemctl") || line.contains("journalctl");
                let runtime = ["crio", "{unit}", ".unit()"]
                    .iter()
                    .any(|named| line.contains(named));
                if systemd && !runtime {
                    found.push(format!("{name}:{}: {}", number + 1, line.trim()));
                }
            }
        }
        assert!(
            found.is_empty(),
            "use the node helpers:\n{}",
            found.join("\n")
        );
    }
}
