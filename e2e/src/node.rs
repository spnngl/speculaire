//! What the suites do to a node (D94): stop, start or kill its agent, slow its network, cut it off from a host, corrupt
//! a blob it serves, and read its metrics and audit events.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use prost::Message as _;

use crate::reflector::unhex;
use crate::registry::{docker, fail};
use crate::upstream::Digest;
use crate::{Cluster, Failure, Runtime};

/// The verification policy the agent reads by default (D8).
pub const POLICY: &str = "/etc/speculaire/policy.yaml";
/// The trusted root each node pins: the one recorded with the Sigstore fixtures (D141).
pub const TRUSTED_ROOT: &str = "/etc/speculaire/trusted_root.json";

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

    /// Stops the node's agent, as an admin does.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails.
    pub fn stop_agent(&self, node: &str) -> Result<(), Failure> {
        self.sh(node, "systemctl stop speculaire").map(drop)
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
        self.sh(node, "systemctl kill --signal=SIGKILL speculaire")
            .map(drop)
    }

    /// Empties the node's journal and restarts its agent, which writes its start entries again: `unit.rs` asserts the
    /// journal holds no warning, and a kill leaves some.
    ///
    /// # Errors
    ///
    /// When the agent is not ready within 120 s.
    pub fn reset_agent(&self, node: &str) -> Result<(), Failure> {
        self.restart_with_empty_journal(node)?;
        self.wait_ready(node)
    }

    /// Stops the node's agent, empties its journal and starts the agent, without waiting for it.
    ///
    /// The agent stops first: one still running may write a warning between the vacuum and its stop, such as a
    /// discovery failing on an upstream the test has just removed. The vacuum keeps an archived file whose last entry
    /// is younger than its limit: at `1s`, the file just rotated, with the agent's last events, could stay.
    ///
    /// # Errors
    ///
    /// When `systemctl` fails to start the agent.
    pub fn restart_with_empty_journal(&self, node: &str) -> Result<(), Failure> {
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

    /// The audit events in the node's journal, oldest first, as `journalctl -t speculaire-audit -o json` gives them:
    /// each the record of its journal fields, such as `F_EVENT` (D37, D173).
    ///
    /// # Errors
    ///
    /// When `journalctl` fails, or a line is no JSON object.
    pub fn audit(
        &self,
        node: &str,
    ) -> Result<Vec<serde_json::Map<String, serde_json::Value>>, Failure> {
        let journal = self.sh(node, "journalctl -q -t speculaire-audit --no-pager -o json")?;
        journal
            .lines()
            .filter(|line| !line.is_empty())
            .map(|line| match serde_json::from_str(line) {
                Ok(serde_json::Value::Object(record)) => Ok(record),
                _ => Err(fail(&format!("the audit journal of {node}"), &line)),
            })
            .collect()
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

    /// The series of the native histogram `name` whose labels include `label`, summed, as the node's agent serves them
    /// now in the protobuf exposition, the only one with native histograms (D34); empty when it has none.
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
        let hex = self.sh(
            node,
            "curl -sf -H 'Accept: application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited' http://127.0.0.1:7482/metrics | od -An -v -tx1 | tr -d ' \\n'",
        )?;
        let unparsable = |detail: &str| fail(&format!("the metrics of {node}"), &detail);
        let bytes = unhex(hex.trim()).ok_or_else(|| unparsable("not hex"))?;
        let mut rest = bytes.as_slice();
        let mut native = Native::default();
        while !rest.is_empty() {
            let family = Family::decode_length_delimited(&mut rest)
                .map_err(|err| unparsable(&err.to_string()))?;
            if family.name != name {
                continue;
            }
            let histograms = family
                .metric
                .iter()
                .filter(|metric| {
                    metric
                        .label
                        .iter()
                        .any(|pair| (pair.name.as_str(), pair.value.as_str()) == label)
                })
                .filter_map(|metric| metric.histogram.as_ref());
            for histogram in histograms {
                native.add(histogram).map_err(unparsable)?;
            }
        }
        Ok(native)
    }
}

/// A native histogram of non-negative samples: its count, and the count of each bucket by index (D34).
#[derive(Debug, Default)]
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

/// What [`Cluster::histogram`] reads of a `MetricFamily` of Prometheus' `metrics.proto`.
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
    use super::{Histogram, Native, Span};

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
}
