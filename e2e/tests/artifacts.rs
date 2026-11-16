//! Artifact discovery (D118): a pull of the signed test image puts its Sigstore bundles and its `.sig` manifest, with
//! their blobs, in the node's artifact store, fetched from the upstream it was pulled from with the node's own
//! registry config only (D17).
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::sleep;
use std::time::{Duration, Instant};

use e2e::Cluster;
use e2e::registry::PASSWORD;
use e2e::upstream::{Digest, Kind, Request, SIGNED, Upstream};
use serde_json::Value;

/// The tests share the worker's agent and image list: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

const CONFIG: &str = "/etc/speculaire/config.toml";
const STORE: &str = "/var/lib/speculaire/artifacts";

/// The repository of [`SIGNED`].
const REPOSITORY: &str = "e2e/signed";

/// How long after a pull the store must hold the image's artifacts.
const WITHIN: Duration = Duration::from_secs(10);

/// What discovery must keep of [`SIGNED`]: its digest, and each artifact's manifest with the blobs it names.
struct Expected {
    root: Digest,
    artifacts: Vec<(String, Vec<String>)>,
}

impl Expected {
    /// Read from the plain upstream, where `regctl` copied the image with its referrers and tags (D112).
    fn read(cluster: &Cluster) -> Self {
        let plain = cluster.upstream(Kind::Plain);
        let root = plain.digest(SIGNED).unwrap();
        let name = format!("{}/{REPOSITORY}", plain.address());
        let get = |reference: &str| -> Value {
            let body = plain
                .regctl(&format!(
                    "regctl manifest get --format raw-body {name}{reference}"
                ))
                .unwrap();
            serde_json::from_str(&body).unwrap()
        };
        let blobs = |manifest: &Value| -> Vec<String> {
            std::iter::once(&manifest["config"])
                .chain(manifest["layers"].as_array().unwrap())
                .map(|descriptor| descriptor["digest"].as_str().unwrap().to_owned())
                .collect()
        };
        let fallback = get(&format!(":sha256-{}", root.hex()));
        let mut artifacts: Vec<(String, Vec<String>)> = fallback["manifests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|listed| {
                let digest = listed["digest"].as_str().unwrap().to_owned();
                let manifest = get(&format!("@{digest}"));
                (digest, blobs(&manifest))
            })
            .collect();
        assert_eq!(artifacts.len(), 3, "{fallback}");
        let sig = format!(":sha256-{}.sig", root.hex());
        let digest = plain
            .regctl(&format!("regctl image digest {name}{sig}"))
            .unwrap()
            .trim()
            .to_owned();
        artifacts.push((digest, blobs(&get(&sig))));
        Self { root, artifacts }
    }

    /// Every digest the store must hold.
    fn digests(&self) -> impl Iterator<Item = &String> {
        self.artifacts
            .iter()
            .flat_map(|(manifest, blobs)| std::iter::once(manifest).chain(blobs))
    }
}

/// The worker no reflector runs on (D94), and its agent's config to put back when the test ends: restarting its agent
/// leaves the reflectors' holders as the other suites expect them.
struct Worker {
    cluster: Cluster,
    name: String,
    config_changed: bool,
}

impl Worker {
    fn new() -> Self {
        let cluster = Cluster::from_env();
        let reflectors = cluster.reflectors();
        let name = cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .find(|name| !reflectors.contains(name))
            .expect("a node no reflector runs on");
        Self {
            cluster,
            name,
            config_changed: false,
        }
    }

    fn sh(&self, script: &str) -> String {
        let output = self
            .cluster
            .exec_output(&self.name, &["sh", "-c", script])
            .unwrap();
        assert!(output.success, "{script}: {output:?}");
        output.stdout
    }

    /// Sets the agent's `log.filter`; the agent restarts at the next [`Self::forget`].
    fn log_filter(&mut self, filter: &str) {
        if !self.config_changed {
            self.sh(&format!("cp {CONFIG} {CONFIG}.e2e"));
            self.config_changed = true;
        }
        self.sh(&format!(
            "sed -i 's/^filter = .*/filter = \"{filter}\"/' {CONFIG}"
        ));
    }

    /// Removes the signed image from the runtime under every upstream's name, and its artifacts and record from the
    /// store, then restarts the agent: it discovers the image again once it is listed.
    fn forget(&self, expected: &Expected) {
        let files: Vec<String> = expected
            .digests()
            .chain(std::iter::once(&expected.root.to_string()))
            .map(|digest| {
                let hex = digest.trim_start_matches("sha256:");
                format!("{STORE}/blobs/sha256/{hex} {STORE}/roots/sha256/{hex}.json")
            })
            .collect();
        self.cluster.stop_agent(&self.name).unwrap();
        self.sh(&format!("{}; rm -f {}", self.rmi(), files.join(" ")));
        self.cluster.start_agent(&self.name).unwrap();
    }

    /// The script that removes the signed image from the runtime, under each upstream's name.
    fn rmi(&self) -> String {
        let names: Vec<String> = Kind::ALL
            .iter()
            .map(|kind| format!("{}/{SIGNED}", self.cluster.upstream(*kind).address()))
            .collect();
        format!(
            "for image in {}; do crictl rmi $image >/dev/null 2>&1; done; true",
            names.join(" ")
        )
    }

    /// Pulls the signed image from `upstream`, and waits until the store holds every artifact of `expected`: how
    /// long that took after the pull.
    fn pull(&self, upstream: &Upstream, expected: &Expected) -> Duration {
        self.sh(&format!("crictl pull {}/{SIGNED}", upstream.address()));
        let start = Instant::now();
        let test = expected
            .digests()
            .map(|digest| {
                format!(
                    "test -f {STORE}/blobs/sha256/{}",
                    digest.trim_start_matches("sha256:")
                )
            })
            .collect::<Vec<_>>()
            .join(" && ");
        while !self
            .cluster
            .exec_output(&self.name, &["sh", "-c", &test])
            .unwrap()
            .success
        {
            assert!(
                start.elapsed() < WITHIN,
                "the store lacks some of {:?}: {}",
                expected.artifacts,
                self.sh(&format!(
                    "ls -R {STORE}; journalctl -u speculaire --no-pager -o cat | tail -n 30"
                ))
            );
            sleep(Duration::from_millis(200));
        }
        start.elapsed()
    }

    /// The sum of `speculaire_artifact_fetches_total` over the series whose labels include each of `labels`.
    fn fetches(&self, labels: &[&str]) -> f64 {
        self.sh("curl -sf http://127.0.0.1:7482/metrics")
            .lines()
            .filter(|line| {
                line.starts_with("speculaire_artifact_fetches_total{")
                    && labels.iter().all(|label| line.contains(label))
            })
            .filter_map(|line| line.rsplit_once(' ')?.1.parse::<f64>().ok())
            .sum()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let restore = if self.config_changed {
            format!("mv {CONFIG}.e2e {CONFIG}; ")
        } else {
            String::new()
        };
        // The journal stays: `configure.rs` reads CRI-O's entries in it, and a graceful stop writes no warning.
        let script = format!(
            "{restore}{}; systemctl reset-failed speculaire; systemctl restart speculaire",
            self.rmi()
        );
        let _ = self.cluster.exec_output(&self.name, &["sh", "-c", &script]);
        if !std::thread::panicking() {
            self.cluster.wait_ready(&self.name).unwrap();
        }
    }
}

/// The agent's requests to `upstream` since the `seen` first entries of its log, but the challenges.
fn agent_requests(upstream: &Upstream, seen: usize) -> Vec<Request> {
    upstream
        .requests()
        .unwrap()
        .into_iter()
        .skip(seen)
        .filter(|r| r.user_agent.starts_with("speculaire/") && r.status != 401)
        .collect()
}

/// The index of the first request of `requests` with `method`, `path` and `status`.
fn position(requests: &[Request], method: &str, path: &str, status: u16) -> usize {
    let found = requests
        .iter()
        .position(|r| r.method == method && r.path == path && r.status == status);
    assert!(
        found.is_some(),
        "no {method} {path} answered {status} in {requests:?}"
    );
    found.unwrap()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_pull_from_the_private_upstream_keeps_its_bundles_and_sig_with_the_nodes_credentials() {
    let _serial = serial();
    let worker = Worker::new();
    let expected = Expected::read(&worker.cluster);
    let private = worker.cluster.upstream(Kind::Private);
    worker.forget(&expected);
    let seen = private.requests().unwrap().len();
    let label = format!("upstream=\"{}\"", private.address());
    let before = worker.fetches(&[&label, "result=\"ok\""]);

    let took = worker.pull(&private, &expected);
    println!("artifacts kept {} ms after the pull", took.as_millis());

    let requests = agent_requests(&private, seen);
    let hex = expected.root.hex();
    let manifests = format!("/v2/{REPOSITORY}/manifests");
    let order = [
        position(
            &requests,
            "GET",
            &format!("/v2/{REPOSITORY}/referrers/{}", expected.root),
            404,
        ),
        position(&requests, "HEAD", &format!("{manifests}/sha256-{hex}"), 200),
        position(&requests, "GET", &format!("{manifests}/sha256-{hex}"), 200),
        position(
            &requests,
            "HEAD",
            &format!("{manifests}/sha256-{hex}.sig"),
            200,
        ),
        position(
            &requests,
            "GET",
            &format!("{manifests}/sha256-{hex}.sig"),
            200,
        ),
    ];
    assert!(order.is_sorted(), "{requests:?}");
    assert!(
        requests.iter().all(|r| !r.path.contains(".att")),
        "{requests:?}"
    );
    // The fetches count under the private upstream's own name: the node's registry config names it (D50).
    assert!(
        worker.fetches(&[&label, "result=\"ok\""]) >= before + 9.0,
        "{label}: {before} then {}",
        worker.fetches(&[&label, "result=\"ok\""])
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn at_trace_the_journal_holds_no_secret_of_the_private_upstream() {
    let _serial = serial();
    let mut worker = Worker::new();
    let expected = Expected::read(&worker.cluster);
    let private = worker.cluster.upstream(Kind::Private);
    worker.log_filter("trace");
    worker.forget(&expected);
    let since = worker.sh("date '+%Y-%m-%d %H:%M:%S'");

    worker.pull(&private, &expected);

    let journal = worker.sh(&format!(
        "journalctl -u speculaire --no-pager -o cat --since '{}'",
        since.trim()
    ));
    assert!(
        journal.contains("upstream request"),
        "the journal holds no trace event"
    );
    for secret in [PASSWORD, "Basic ", "eyJ"] {
        assert!(
            !journal.contains(secret),
            "the journal holds a secret ({} bytes of it matched)",
            secret.len()
        );
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn fetches_from_a_host_the_registry_config_does_not_name_count_as_other() {
    let _serial = serial();
    let worker = Worker::new();
    let expected = Expected::read(&worker.cluster);
    let public = worker.cluster.upstream(Kind::Public);
    worker.forget(&expected);
    let other = ["upstream=\"other\"", "result=\"ok\""];
    let before = worker.fetches(&other);

    worker.pull(&public, &expected);

    assert!(
        worker.fetches(&other) >= before + 9.0,
        "{before} then {}",
        worker.fetches(&other)
    );
    let own = format!("upstream=\"{}\"", public.address());
    assert_eq!(worker.fetches(&[&own]), 0.0);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn with_the_referrers_api_no_fallback_tag_is_asked() {
    let _serial = serial();
    let worker = Worker::new();
    let expected = Expected::read(&worker.cluster);
    let zot = worker.cluster.upstream(Kind::Referrers);
    worker.forget(&expected);
    let seen = zot.requests().unwrap().len();

    worker.pull(&zot, &expected);

    let requests = agent_requests(&zot, seen);
    position(
        &requests,
        "GET",
        &format!("/v2/{REPOSITORY}/referrers/{}", expected.root),
        200,
    );
    let fallback = format!("/v2/{REPOSITORY}/manifests/sha256-{}", expected.root.hex());
    assert!(requests.iter().all(|r| r.path != fallback), "{requests:?}");
}
