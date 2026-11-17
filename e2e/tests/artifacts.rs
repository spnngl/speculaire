//! Artifact discovery (D121): a pull of the signed test image puts its Sigstore bundles and its `.sig` manifest, with
//! their blobs, in the node's artifact store, fetched from the upstream it was pulled from with the node's own
//! registry config only (D17). Another node reads them, and their referrers, from the node's peer API (D124), and a
//! node cut off from upstream discovers them there (D126). The store keeps only what the images listed name (D131).
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::sleep;
use std::time::{Duration, Instant};

use e2e::Cluster;
use e2e::balancer::PORT;
use e2e::node::Rules;
use e2e::reflector::KUBELET;
use e2e::registry::PASSWORD;
use e2e::upstream::{Digest, Kind, Request, SIGNED, UNSIGNED, Upstream};
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

/// A second signed image on zot, made by [`push_collected`]: an image of its own with one Sigstore bundle.
const COLLECTED: &str = "e2e/collected:1";

/// The empty config every Sigstore bundle names (D124), so both signed images.
const EMPTY: &str = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// How long after a blob is stored or deleted every reflector must tell it (D131).
const ANNOUNCED_WITHIN: Duration = Duration::from_secs(2);

/// How long after a pull the store must hold the image's artifacts.
const WITHIN: Duration = Duration::from_secs(10);

/// The peer API's port when `peer.address` is `"auto"` (D36).
const PEER_PORT: u16 = 7481;

/// The predicate types of the bundles of [`SIGNED`]: its signature, its SLSA provenance and its SPDX document.
const PREDICATES: [&str; 3] = [
    "https://sigstore.dev/cosign/sign/v1",
    "https://slsa.dev/provenance/v1",
    "https://spdx.dev/Document",
];

/// The loopback mirror (D14), and the directory of its client certificate.
const MIRROR: &str = "https://127.0.0.1:7480";
const MIRROR_DIR: &str = "/var/lib/speculaire/mirror";

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

    /// A node other than the worker: a reflector names no node to itself.
    fn other(&self) -> String {
        self.cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .find(|name| *name != self.name)
            .expect("a second node")
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

    /// The script that removes [`COLLECTED`] from the runtime.
    fn rmi_collected(&self) -> String {
        let zot = self.cluster.upstream(Kind::Referrers);
        format!(
            "crictl rmi {}/{COLLECTED} >/dev/null 2>&1; true",
            zot.address()
        )
    }

    /// The time on the nodes' clock, in nanoseconds since the epoch, after `script` ran.
    fn stamped(&self, script: &str) -> u64 {
        self.sh(&format!("{script}; date +%s%N"))
            .lines()
            .last()
            .and_then(|line| line.trim().parse().ok())
            .unwrap()
    }

    /// Pulls the signed image from `upstream`, and waits until the store holds every artifact of `expected`: how
    /// long that took after the pull.
    fn pull(&self, upstream: &Upstream, expected: &Expected) -> Duration {
        let _alone = self.alone();
        self.sh(&format!("crictl pull {}/{SIGNED}", upstream.address()));
        holds(&self.cluster, &self.name, expected, Instant::now())
    }

    /// Cuts the worker off from the other nodes' peer APIs while the rules live: discovery asks upstream once peers
    /// list nothing (D126).
    fn alone(&self) -> Vec<Rules<'_>> {
        self.cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .filter(|name| *name != self.name)
            .map(|other| {
                self.cluster
                    .reject_port(&self.name, &other, PEER_PORT)
                    .unwrap()
            })
            .collect()
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
            "{restore}{}; {}; systemctl reset-failed speculaire; systemctl restart speculaire",
            self.rmi(),
            self.rmi_collected()
        );
        let _ = self.cluster.exec_output(&self.name, &["sh", "-c", &script]);
        if !std::thread::panicking() {
            self.cluster.wait_ready(&self.name).unwrap();
        }
    }
}

/// Waits until the store of `node` holds every artifact of `expected`, [`WITHIN`] after `start` at most: how long after
/// `start` it did.
fn holds(cluster: &Cluster, node: &str, expected: &Expected, start: Instant) -> Duration {
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
    while !cluster
        .exec_output(node, &["sh", "-c", &test])
        .unwrap()
        .success
    {
        assert!(
            start.elapsed() < WITHIN,
            "{node}'s store lacks some of {:?}: {}",
            expected.artifacts,
            cluster
                .exec(
                    node,
                    &[
                        "sh",
                        "-c",
                        &format!(
                            "ls -R {STORE}; journalctl -u speculaire --no-pager -o cat | tail -n 30"
                        ),
                    ],
                )
                .unwrap()
        );
        sleep(Duration::from_millis(200));
    }
    start.elapsed()
}

/// Waits until every reflector names `holder` to `asker` for the root of `expected` and each of its artifacts' manifests,
/// which `holder`'s store announces with their blobs (D124). A reflector that restarted learns them again only once
/// `holder`'s stream to it is back.
fn wait_held(cluster: &Cluster, asker: &str, holder: &str, expected: &Expected) {
    let manifests = expected
        .artifacts
        .iter()
        .map(|(manifest, _)| manifest.parse().unwrap());
    for digest in std::iter::once(expected.root.clone()).chain(manifests) {
        told(
            cluster,
            asker,
            holder,
            &digest,
            true,
            Duration::from_secs(30),
        );
    }
}

/// Waits until every reflector tells `asker` whether `holder` holds `digest`, as `held` says.
///
/// Fails after `within`. Returns when the last reflector told, in nanoseconds since the epoch on the nodes' clock.
fn told(
    cluster: &Cluster,
    asker: &str,
    holder: &str,
    digest: &Digest,
    held: bool,
    within: Duration,
) -> u64 {
    let deadline = Instant::now() + within;
    let mut last = 0;
    for reflector in cluster.reflectors() {
        let address = SocketAddr::new(cluster.family_address(&reflector).unwrap(), PORT);
        let stamp = loop {
            let (holders, stamp) = cluster.lookup_stamped(asker, address, digest).unwrap();
            if holders.iter().any(|h| h.node == holder) == held {
                break stamp;
            }
            assert!(
                Instant::now() < deadline,
                "{digest}: reflector {reflector} does not tell that {holder} holds it: {held}"
            );
            sleep(Duration::from_millis(100));
        };
        last = last.max(stamp);
    }
    last
}

/// Waits until `node`'s store has recorded `root`: the manifest and blobs of each artifact recorded.
fn recorded(cluster: &Cluster, node: &str, root: &Digest) -> Vec<(Digest, Vec<Digest>)> {
    let start = Instant::now();
    let path = format!("{STORE}/roots/sha256/{}.json", root.hex());
    let text = loop {
        let output = cluster.exec_output(node, &["cat", &path]).unwrap();
        if output.success {
            break output.stdout;
        }
        assert!(start.elapsed() < WITHIN, "{node} has not recorded {root}");
        sleep(Duration::from_millis(200));
    };
    let record: Value = serde_json::from_str(&text).unwrap();
    let digest = |value: &Value| -> Digest { value.as_str().unwrap().parse().unwrap() };
    record["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|artifact| {
            let blobs = artifact["blobs"].as_array().unwrap();
            (
                digest(&artifact["manifest"]),
                blobs.iter().map(digest).collect(),
            )
        })
        .collect()
}

/// Pushes [`COLLECTED`] to `zot`, new, with a Sigstore bundle as referrer: its root. It is [`UNSIGNED`] with a label of
/// its own, so another config: CRI-O names an image by its config, and would merge two that share one.
fn push_collected(zot: &Upstream) -> Digest {
    let name = zot.address();
    let bundle = "application/vnd.dev.sigstore.bundle.v0.3+json";
    zot.regctl(&format!(
        "regctl image copy {name}/{UNSIGNED} {name}/{COLLECTED} >/dev/null \
         && regctl image mod --replace --label dev.speculaire.e2e.run=$(date +%s%N) {name}/{COLLECTED} >/dev/null \
         && printf '{{\"e2e\":\"collected\"}}' >/tmp/bundle.json \
         && regctl artifact put --subject {name}/{COLLECTED} --artifact-type {bundle} \
            --file /tmp/bundle.json --file-media-type {bundle} >/dev/null"
    ))
    .unwrap();
    zot.digest(COLLECTED).unwrap()
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

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn the_tags_of_an_unsigned_image_get_a_head_and_never_a_get() {
    let _serial = serial();
    let worker = Worker::new();
    let plain = worker.cluster.upstream(Kind::Plain);
    let root = plain.digest(UNSIGNED).unwrap();
    let image = format!("{}/{UNSIGNED}", plain.address());
    // Forgotten, so that it is discovered again once listed.
    worker.cluster.stop_agent(&worker.name).unwrap();
    worker.sh(&format!(
        "crictl rmi {image} >/dev/null 2>&1; rm -f {STORE}/roots/sha256/{}.json",
        root.hex()
    ));
    worker.cluster.start_agent(&worker.name).unwrap();
    let seen = plain.requests().unwrap().len();

    let alone = worker.alone();
    worker.sh(&format!("crictl pull {image}"));
    let fallback = format!("/v2/e2e/unsigned/manifests/sha256-{}", root.hex());
    let sig = format!("{fallback}.sig");
    let start = Instant::now();
    let requests = loop {
        let requests = agent_requests(&plain, seen);
        if requests.iter().any(|r| r.path == sig) {
            break requests;
        }
        assert!(
            start.elapsed() < WITHIN,
            "no request for {sig}: {requests:?}"
        );
        sleep(Duration::from_millis(200));
    };
    drop(alone);
    worker.sh(&format!("crictl rmi {image}"));

    // Docker Hub counts a `GET` of a manifest against the pull limit, not a `HEAD` (D38).
    position(&requests, "HEAD", &fallback, 404);
    position(&requests, "HEAD", &sig, 404);
    assert!(
        requests
            .iter()
            .all(|r| r.method == "HEAD" || (r.path != fallback && r.path != sig)),
        "{requests:?}"
    );
}

/// An answer of the peer API: its status, its `OCI-Filters-Applied` header, the SHA-256 of its body, and its body when
/// asked for.
struct Answer {
    status: String,
    filters: String,
    sha256: String,
    body: String,
}

/// A `GET` of `path` from `reader` on the peer API at `address`, with kubelet's certificate as another agent would:
/// the peer API presents a kubelet client certificate, which has no name to check, hence `-k` (D16).
fn peer_get(
    cluster: &Cluster,
    reader: &str,
    address: SocketAddr,
    path: &str,
    body: bool,
) -> Answer {
    let cat = if body { r#"; cat "$dir/b""# } else { "" };
    let script = format!(
        r#"set -e; dir=$(mktemp -d); trap 'rm -rf "$dir"' EXIT
code=$(curl -sSg -k --max-time 10 --cert {KUBELET} -D "$dir/h" -o "$dir/b" -w "%{{http_code}}" "https://{address}{path}")
filters=$(tr -d "\r" < "$dir/h" | sed -n "s/^oci-filters-applied: //Ip")
echo "$code|$filters|$(sha256sum < "$dir/b" | cut -d" " -f1)"{cat}"#
    );
    let output = cluster.exec_output(reader, &["sh", "-c", &script]).unwrap();
    assert!(output.success, "{path}: {output:?}");
    let (line, body) = output.stdout.split_once('\n').unwrap();
    let fields: Vec<&str> = line.split('|').collect();
    Answer {
        status: fields[0].to_owned(),
        filters: fields[1].to_owned(),
        sha256: fields[2].to_owned(),
        body: body.to_owned(),
    }
}

/// The digest, `artifactType` and predicate type of each descriptor of the referrers index `answer` holds.
fn referrers(answer: &Answer) -> BTreeSet<(String, String, String)> {
    let index: Value = serde_json::from_str(&answer.body).unwrap();
    index["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|listed| {
            let field = |pointer: &str| {
                listed
                    .pointer(pointer)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            (
                field("/digest"),
                field("/artifactType"),
                field("/annotations/dev.sigstore.bundle.predicateType"),
            )
        })
        .collect()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn another_node_reads_the_referrers_and_artifacts_a_node_discovered_from_its_peer_api() {
    let _serial = serial();
    let worker = Worker::new();
    let cluster = &worker.cluster;
    let expected = Expected::read(cluster);
    let reader = worker.other();
    worker.forget(&expected);
    worker.pull(&cluster.upstream(Kind::Plain), &expected);
    let address = SocketAddr::new(cluster.family_address(&worker.name).unwrap(), PEER_PORT);
    let path = format!("/v2/{REPOSITORY}/referrers/{}", expected.root);

    // The root's record follows its blobs, and the peer API opens once the agent has announced.
    let start = Instant::now();
    let all = loop {
        let answer = peer_get(cluster, &reader, address, &path, true);
        if answer.status == "200" && referrers(&answer).len() == expected.artifacts.len() {
            break answer;
        }
        assert!(
            start.elapsed() < WITHIN,
            "{} {}",
            answer.status,
            answer.body
        );
        sleep(Duration::from_millis(200));
    };
    assert_eq!(all.filters, "", "{}", all.body);
    let listed = referrers(&all);
    let (sig, _) = expected.artifacts.last().unwrap();
    let bundle = "application/vnd.dev.sigstore.bundle.v0.3+json";
    let mut bundles = BTreeSet::new();
    for (digest, artifact_type, predicate) in &listed {
        if digest == sig {
            assert_eq!(
                artifact_type,
                "application/vnd.dev.cosign.simplesigning.v1+json"
            );
        } else {
            assert_eq!(artifact_type, bundle, "{}", all.body);
            bundles.insert(predicate.as_str());
        }
    }
    assert_eq!(bundles, BTreeSet::from(PREDICATES), "{}", all.body);
    let digests: BTreeSet<&String> = listed.iter().map(|(digest, ..)| digest).collect();
    let manifests: BTreeSet<&String> = expected
        .artifacts
        .iter()
        .map(|(manifest, _)| manifest)
        .collect();
    assert_eq!(digests, manifests);

    let filtered = peer_get(
        cluster,
        &reader,
        address,
        &format!("{path}?artifactType=application/vnd.dev.sigstore.bundle.v0.3%2Bjson"),
        true,
    );
    assert_eq!(
        (filtered.status.as_str(), filtered.filters.as_str()),
        ("200", "artifactType")
    );
    assert_eq!(referrers(&filtered).len(), 3, "{}", filtered.body);
    // A manifest no artifact is about.
    let none = peer_get(
        cluster,
        &reader,
        address,
        &format!("/v2/{REPOSITORY}/referrers/{sig}"),
        true,
    );
    assert_eq!((none.status.as_str(), none.filters.as_str()), ("200", ""));
    assert!(referrers(&none).is_empty(), "{}", none.body);

    // Every artifact manifest and every blob it names, by digest from any repository.
    for (manifest, blobs) in &expected.artifacts {
        let paths = std::iter::once(format!("/v2/any/manifests/{manifest}"))
            .chain(blobs.iter().map(|blob| format!("/v2/any/blobs/{blob}")));
        for (path, digest) in paths.zip(std::iter::once(manifest).chain(blobs)) {
            let answer = peer_get(cluster, &reader, address, &path, false);
            assert_eq!(answer.status, "200", "{path}");
            assert_eq!(format!("sha256:{}", answer.sha256), *digest, "{path}");
        }
    }

    // The runtime still finds no referrers on its loopback mirror (D85).
    let mirror = worker.sh(&format!(
        "curl -s -o /dev/null -w '%{{http_code}}' --cacert {MIRROR_DIR}/ca.crt --cert {MIRROR_DIR}/client.pem {MIRROR}{path}"
    ));
    assert_eq!(mirror.trim(), "404");
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_node_cut_off_from_upstream_gets_every_artifact_from_the_node_that_discovered_them() {
    let _serial = serial();
    // B restarts its agent: the worker no reflector runs on. A is any other node.
    let b = Worker::new();
    let cluster = &b.cluster;
    let expected = Expected::read(cluster);
    let zot = cluster.upstream(Kind::Referrers);
    let seen = zot.requests().unwrap().len();
    let a = b.other();
    let reference = format!("{}/{SIGNED}", zot.address());
    let pull = cluster
        .exec_output(&a, &["crictl", "pull", &reference])
        .unwrap();
    assert!(pull.success, "{a}: {pull:?}");
    holds(cluster, &a, &expected, Instant::now());
    // B forgets the image and its artifacts, and pulls it straight from upstream while its agent is stopped.
    b.forget(&expected);
    cluster.stop_agent(&b.name).unwrap();
    b.sh(&format!("crictl pull {reference}"));
    // B discovers once, right after its agent starts (D126): every reflector must name A by then.
    wait_held(cluster, &b.name, &a, &expected);

    let (took, peer, asked) = {
        let _rejected = cluster.reject(&b.name, zot.address()).unwrap();
        let before = zot.requests().unwrap().len();
        let start = Instant::now();
        cluster.start_agent(&b.name).unwrap();
        let took = holds(cluster, &b.name, &expected, start);
        let asked = agent_requests(&zot, before);
        (
            took,
            b.fetches(&["source=\"peer\"", "result=\"ok\""]),
            asked,
        )
    };
    println!(
        "B held every artifact {} ms after its agent started",
        took.as_millis()
    );

    // The counters start with the agent: each artifact digest came from a peer. Other images B lists may count upstream.
    let digests: BTreeSet<&String> = expected.digests().collect();
    assert!(
        peer >= f64::from(u32::try_from(digests.len()).unwrap()),
        "{peer} from peers, {} digests",
        digests.len()
    );
    assert!(asked.is_empty(), "{asked:?}");
    // No node ever asks for the `.att` tag (D43).
    let att = format!("sha256-{}.att", expected.root.hex());
    let requests: Vec<Request> = zot.requests().unwrap().into_iter().skip(seen).collect();
    assert!(
        requests.iter().all(|r| !r.path.ends_with(&att)),
        "{requests:?}"
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_stored_artifact_is_announced_and_withdrawn_with_its_image_within_2_s() {
    let _serial = serial();
    let worker = Worker::new();
    let cluster = &worker.cluster;
    let reader = worker.other();
    let expected = Expected::read(cluster);
    worker.forget(&expected);
    worker.pull(&cluster.upstream(Kind::Referrers), &expected);
    let manifest: Digest = expected.artifacts[0].0.parse().unwrap();

    // A blob is linked into place once written: its time is when the store kept it.
    let stored = worker.stamped(&format!(
        "date -r {STORE}/blobs/sha256/{} +%s%N",
        manifest.hex()
    ));
    let announced = told(cluster, &reader, &worker.name, &manifest, true, WITHIN);
    let removed = worker.stamped(&worker.rmi());
    let withdrawn = told(cluster, &reader, &worker.name, &manifest, false, WITHIN);
    let ms = |from: u64, to: u64| to.saturating_sub(from) / 1_000_000;
    println!(
        "every reflector named the worker {} ms after it stored an artifact, and no longer {} ms after the image's removal",
        ms(stored, announced),
        ms(removed, withdrawn)
    );
    let within = u64::try_from(ANNOUNCED_WITHIN.as_millis()).unwrap();
    assert!(ms(stored, announced) <= within);
    assert!(ms(removed, withdrawn) <= within);

    // Deleted before withdrawn. The empty config may stay: another image the worker lists may name it.
    let left: Vec<&String> = expected
        .digests()
        .filter(|digest| *digest != EMPTY)
        .filter(|digest| {
            let hex = digest.trim_start_matches("sha256:");
            worker
                .cluster
                .exec_output(
                    &worker.name,
                    &["test", "-e", &format!("{STORE}/blobs/sha256/{hex}")],
                )
                .unwrap()
                .success
        })
        .collect();
    assert!(left.is_empty(), "{left:?}");
    let record = format!("{STORE}/roots/sha256/{}.json", expected.root.hex());
    worker.sh(&format!("test ! -e {record}"));
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_blob_two_images_name_stays_and_a_restart_collects_the_image_removed_meanwhile() {
    let _serial = serial();
    let worker = Worker::new();
    let cluster = &worker.cluster;
    let name = worker.name.as_str();
    let reader = worker.other();
    let expected = Expected::read(cluster);
    let zot = cluster.upstream(Kind::Referrers);
    worker.forget(&expected);
    let root = push_collected(&zot);
    worker.pull(&zot, &expected);
    worker.sh(&format!("crictl pull {}/{COLLECTED}", zot.address()));
    let artifacts = recorded(cluster, name, &root);
    let empty: Digest = EMPTY.parse().unwrap();
    assert!(expected.digests().any(|digest| digest == EMPTY));
    assert_eq!(artifacts.len(), 1, "{artifacts:?}");
    assert!(artifacts[0].1.contains(&empty), "{artifacts:?}");
    let own: Vec<Digest> = std::iter::once(artifacts[0].0.clone())
        .chain(
            artifacts[0]
                .1
                .iter()
                .filter(|blob| **blob != empty)
                .cloned(),
        )
        .collect();
    let signed: Vec<Digest> = expected
        .artifacts
        .iter()
        .map(|(manifest, _)| manifest.parse().unwrap())
        .collect();
    for digest in own.iter().chain(&signed).chain([&empty]) {
        told(cluster, &reader, name, digest, true, WITHIN);
    }

    // Removing the signed image keeps the empty config, which the other still names.
    worker.sh(&worker.rmi());
    for digest in &signed {
        told(cluster, &reader, name, digest, false, WITHIN);
    }
    worker.sh(&format!("test -f {STORE}/blobs/sha256/{}", empty.hex()));
    told(cluster, &reader, name, &empty, true, Duration::ZERO);

    // The signed image comes back; the other leaves while the agent is stopped.
    worker.pull(&zot, &expected);
    recorded(cluster, name, &expected.root);
    cluster.stop_agent(name).unwrap();
    worker.sh(&worker.rmi_collected());
    let start = Instant::now();
    cluster.start_agent(name).unwrap();
    let kept: Vec<&Digest> = signed.iter().chain([&empty]).collect();
    let reflectors: Vec<SocketAddr> = cluster
        .reflectors()
        .iter()
        .map(|r| SocketAddr::new(cluster.family_address(r).unwrap(), PORT))
        .collect();
    loop {
        let mut all_kept = true;
        for reflector in &reflectors {
            for digest in &own {
                let holders = cluster.lookup(&reader, *reflector, digest).unwrap();
                assert!(
                    holders.iter().all(|h| h.node != name),
                    "{reflector} names {name} for {digest}, of an image removed while its agent was stopped"
                );
            }
            for digest in &kept {
                let holders = cluster.lookup(&reader, *reflector, digest).unwrap();
                all_kept &= holders.iter().any(|h| h.node == name);
            }
        }
        if all_kept {
            break;
        }
        assert!(
            start.elapsed() < WITHIN,
            "the store's artifacts are not announced"
        );
        sleep(Duration::from_millis(100));
    }
    println!(
        "every reflector named the worker for its stored artifacts {} ms after its agent started",
        start.elapsed().as_millis()
    );
    for digest in &own {
        worker.sh(&format!("test ! -e {STORE}/blobs/sha256/{}", digest.hex()));
    }
    worker.sh(&format!(
        "test ! -e {STORE}/roots/sha256/{}.json",
        root.hex()
    ));
}
