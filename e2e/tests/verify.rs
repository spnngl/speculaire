//! The gate's verification (D8) against the recorded Sigstore fixtures (D141), which `just e2e-up` pushes to zot and
//! to the plain upstream, with their trusted root pinned on every node.
//!
//! The suite runs in the IPv4 pass only (D141): what it checks does not depend on the address family.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::BTreeSet;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::sleep;
use std::time::{Duration, Instant};

use e2e::node::{POLICY, Rules, TRUSTED_ROOT};
use e2e::upstream::{FIXTURES, Kind, Upstream};
use e2e::{Cluster, IpFamily};
use serde_json::Value;
use speculaire_artifacts::store::Artifact;
use speculaire_artifacts::testing::{self, Layout};

const STORE: &str = "/var/lib/speculaire/artifacts";

/// The peer API's port when `peer.address` is `"auto"` (D36).
const PEER_PORT: u16 = 7481;

/// How long after its pull a fixture's record may take.
const WITHIN: Duration = Duration::from_secs(30);

/// The config blob of every Sigstore bundle, the test image's too: it stays in the store.
const EMPTY: &str = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// The media type of an image index.
const INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// An artifact as the store records it: target, manifest, kind and blobs.
type Recorded = (String, String, String, Vec<String>);

/// A fixture case as a node can pull it.
struct Case {
    name: String,
    layout: Layout,
    /// Whether its root is an image index, which the store keeps.
    index: bool,
}

impl Case {
    /// Every case, but the image indexes on an arm64 node: they hold `linux/amd64` alone.
    fn pullable() -> Vec<Self> {
        testing::cases()
            .into_iter()
            .map(|name| {
                let layout = Layout::open(&name);
                let root: Value = serde_json::from_slice(&layout.blob(layout.root())).unwrap();
                let index = root["mediaType"] == INDEX;
                Self {
                    name,
                    layout,
                    index,
                }
            })
            .filter(|case| cfg!(target_arch = "x86_64") || !case.index)
            .collect()
    }

    /// What discovery must record: the artifacts recorded with the case.
    fn expected(&self) -> BTreeSet<Recorded> {
        self.layout.artifacts().iter().map(recorded).collect()
    }

    /// What the store keeps of the case, but [`EMPTY`]: every artifact's manifest and blobs, and the root if an index.
    fn digests(&self) -> Vec<String> {
        let artifacts = self.layout.artifacts();
        let manifests = artifacts
            .iter()
            .flat_map(|artifact| std::iter::once(&artifact.manifest).chain(&artifact.blobs));
        self.index
            .then(|| self.layout.root())
            .into_iter()
            .chain(manifests)
            .map(ToString::to_string)
            .filter(|digest| digest != EMPTY)
            .collect()
    }
}

fn recorded(artifact: &Artifact) -> Recorded {
    let kind = serde_json::to_value(artifact.kind).unwrap();
    (
        artifact.target.to_string(),
        artifact.manifest.to_string(),
        kind.as_str().unwrap().to_owned(),
        artifact.blobs.iter().map(ToString::to_string).collect(),
    )
}

/// The tests share the worker and its agent: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

/// The example policy file, of no fixture's repository.
const EXAMPLE_POLICY: &str = include_str!("../../packaging/policy.yaml");

/// The node the suite pulls on, which no reflector runs on. Dropping it removes the fixtures and the policy file, and
/// restarts its agent.
struct Worker {
    cluster: Cluster,
    name: String,
    _serial: MutexGuard<'static, ()>,
}

impl Worker {
    fn new() -> Self {
        let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
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
            _serial: serial,
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

    /// Removes every case from the runtime, and its artifacts and record from the store, then restarts the agent.
    fn forget(&self, cases: &[Case]) {
        let files: Vec<String> = cases
            .iter()
            .flat_map(|case| {
                let root = format!("{STORE}/roots/sha256/{}.json", hex(case.layout.root()));
                let blobs = case
                    .digests()
                    .into_iter()
                    .map(|digest| format!("{STORE}/blobs/sha256/{}", hex(&digest)));
                std::iter::once(root).chain(blobs)
            })
            .collect();
        self.cluster.stop_agent(&self.name).unwrap();
        self.sh(&format!(
            "{}; rm -f {}",
            rmi(&self.cluster),
            files.join(" ")
        ));
        self.cluster.start_agent(&self.name).unwrap();
    }

    /// Cuts the worker off from the other nodes' peer APIs while the rules live: discovery asks upstream (D126).
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

    /// Waits until the store has recorded `case`'s root, and returns the record.
    fn recorded(&self, case: &Case, start: Instant) -> BTreeSet<Recorded> {
        let path = format!("{STORE}/roots/sha256/{}.json", hex(case.layout.root()));
        let text = loop {
            let output = self
                .cluster
                .exec_output(&self.name, &["cat", &path])
                .unwrap();
            if output.success {
                break output.stdout;
            }
            assert!(
                start.elapsed() < WITHIN,
                "{} has not recorded {}",
                self.name,
                case.name
            );
            sleep(Duration::from_millis(200));
        };
        let record: Value = serde_json::from_str(&text).unwrap();
        let text = |value: &Value| value.as_str().unwrap().to_owned();
        record["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|artifact| {
                (
                    text(&artifact["target"]),
                    text(&artifact["manifest"]),
                    text(&artifact["kind"]),
                    artifact["blobs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(text)
                        .collect(),
                )
            })
            .collect()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let script = format!(
            "{}; rm -f {POLICY}; systemctl reset-failed speculaire; systemctl restart speculaire",
            rmi(&self.cluster)
        );
        let _ = self.cluster.exec_output(&self.name, &["sh", "-c", &script]);
        if !std::thread::panicking() {
            self.cluster.wait_ready(&self.name).unwrap();
        }
    }
}

/// The script that removes every case from the runtime, under zot's name and the plain upstream's.
fn rmi(cluster: &Cluster) -> String {
    let names: Vec<String> = [Kind::Referrers, Kind::Plain]
        .iter()
        .flat_map(|kind| {
            let host = cluster.upstream(*kind).address().to_owned();
            testing::cases()
                .into_iter()
                .map(move |case| format!("{host}/{FIXTURES}:{case}"))
        })
        .collect();
    format!(
        "for image in {}; do crictl rmi $image >/dev/null 2>&1; done; true",
        names.join(" ")
    )
}

/// Asserts that the agent read every recorded fallback tag and `.sig` tag of `cases` from `plain`, which has no
/// referrers API.
fn assert_fallback_and_sig_tags_read(plain: &Upstream, cases: &[Case]) {
    let read: BTreeSet<String> = plain
        .requests()
        .unwrap()
        .into_iter()
        .filter(|r| r.user_agent.starts_with("speculaire/") && r.method == "GET" && r.status == 200)
        .map(|r| r.path)
        .collect();
    for case in cases {
        let tags = case.layout.tags().iter().map(|(tag, _)| tag);
        for tag in tags.filter(|tag| {
            tag.strip_prefix("sha256-")
                .is_some_and(|rest| matches!(rest.split_once('.'), None | Some((_, "sig"))))
        }) {
            let path = format!("/v2/{FIXTURES}/manifests/{tag}");
            assert!(read.contains(&path), "{}: no GET of {path}", case.name);
        }
    }
}

fn hex(digest: &impl ToString) -> String {
    digest.to_string().trim_start_matches("sha256:").to_owned()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_policy_file_outside_the_subset_stops_the_agent_which_starts_on_the_example() {
    if Cluster::from_env().ip_family() == IpFamily::Dual {
        return;
    }
    let worker = Worker::new();
    let refused = EXAMPLE_POLICY.replacen(
        "    keyless:\n",
        "    keyless:\n      url: https://fulcio.example\n",
        1,
    );
    assert_ne!(refused, EXAMPLE_POLICY);
    worker.cluster.policy(&worker.name, &refused).unwrap();
    let since = worker.sh("date '+%Y-%m-%d %H:%M:%S'");
    let restart = worker
        .cluster
        .exec_output(&worker.name, &["systemctl", "restart", "speculaire"])
        .unwrap();
    assert!(!restart.success, "the agent started on a refused policy");
    let journal = worker.sh(&format!(
        "journalctl -u speculaire --no-pager -o cat --since '{}'",
        since.trim()
    ));
    let reason = format!(
        "the policy file {POLICY}: document 1, spec.authorities[0].keyless.url: unknown field `url`"
    );
    assert!(journal.contains(&reason), "no {reason:?} in:\n{journal}");

    worker.cluster.policy(&worker.name, EXAMPLE_POLICY).unwrap();
    worker.cluster.start_agent(&worker.name).unwrap();
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn discovery_records_every_fixture_from_zot_and_from_the_plain_upstreams_fallback_and_sig_tags() {
    if Cluster::from_env().ip_family() == IpFamily::Dual {
        return;
    }
    let worker = Worker::new();
    let recorded =
        std::fs::read_to_string(format!("{}/trusted_root.json", testing::FIXTURES)).unwrap();
    assert!(
        worker.sh(&format!("cat {TRUSTED_ROOT}")) == recorded,
        "{TRUSTED_ROOT} is not pinned"
    );
    let cases = Case::pullable();
    for kind in [Kind::Referrers, Kind::Plain] {
        let host = worker.cluster.upstream(kind).address().to_owned();
        worker.forget(&cases);
        let _alone = worker.alone();
        let start = Instant::now();
        let pulls: Vec<String> = cases
            .iter()
            .map(|case| format!("crictl pull {host}/{FIXTURES}:{} >/dev/null", case.name))
            .collect();
        worker.sh(&pulls.join(" && "));

        for case in &cases {
            assert_eq!(
                worker.recorded(case, start),
                case.expected(),
                "{} from {kind:?}",
                case.name
            );
        }
        let files: Vec<String> = cases
            .iter()
            .flat_map(Case::digests)
            .map(|digest| format!("{STORE}/blobs/sha256/{}", hex(&digest)))
            .collect();
        let missing = worker.sh(&format!(
            "for file in {}; do test -f $file || echo $file; done",
            files.join(" ")
        ));
        assert_eq!(missing, "", "from {kind:?}");
        if kind == Kind::Plain {
            assert_fallback_and_sig_tags_read(&worker.cluster.upstream(kind), &cases);
        }
        eprintln!(
            "verify: {} fixtures recorded from {kind:?} in {:.1} s",
            cases.len(),
            start.elapsed().as_secs_f64()
        );
    }
}
