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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use e2e::node::{POLICY, Rules, TRUSTED_ROOT};
use e2e::upstream::{FIXTURES, Kind, UNSIGNED, Upstream};
use e2e::{Cluster, IpFamily, Runtime};
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
fn the_agent_holds_the_pinned_trust_root_until_after_now() {
    if Cluster::from_env().ip_family() == IpFamily::Dual {
        return;
    }
    let worker = Worker::new();
    let expiry = worker
        .cluster
        .metrics(&worker.name)
        .unwrap()
        .get("speculaire_trust_root_expiry_timestamp_seconds");
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert!(
        expiry.is_some_and(|expiry| expiry > now.as_secs_f64()),
        "{expiry:?}"
    );
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

/// The workflow that signed the keyless fixtures.
const SAN: &str =
    "https://github.com/spnngl/speculaire/.github/workflows/fixtures.yml@refs/heads/main";

/// A node other than the worker that pulled a fixture through its mirror, then forgot its artifacts, its agent stopped:
/// it serves the image and not its artifacts until its agent discovers them again. Dropping it removes the fixtures and
/// starts its agent.
struct Holder<'a> {
    cluster: &'a Cluster,
    name: String,
    /// Where its store records the fixture's root.
    record: String,
}

impl<'a> Holder<'a> {
    /// Pulls `case` as `reference` on a node other than `worker`, and forgets its artifacts: its agent stays stopped.
    /// On CRI-O, a node serves only the manifests its relay served (D66), so the pull goes through the mirror.
    fn pull(worker: &'a Worker, case: &Case, reference: &str) -> Self {
        let cluster = &worker.cluster;
        let name = cluster
            .nodes()
            .unwrap()
            .into_iter()
            .map(|n| n.name)
            .find(|name| *name != worker.name)
            .expect("a second node");
        let record = format!("{STORE}/roots/sha256/{}.json", hex(case.layout.root()));
        let script = format!("{}; crictl pull {reference} >/dev/null", rmi(cluster));
        let output = cluster.exec_output(&name, &["sh", "-c", &script]).unwrap();
        assert!(output.success, "{script}: {output:?}");
        let holder = Self {
            cluster,
            name,
            record,
        };
        until(
            &|| format!("{} never discovered {reference}", holder.name),
            &mut || holder.recorded(),
        );
        cluster.stop_agent(&holder.name).unwrap();
        let blobs: Vec<String> = case
            .digests()
            .into_iter()
            .map(|digest| format!("{STORE}/blobs/sha256/{}", hex(&digest)))
            .collect();
        let script = format!("rm -f {} {}", holder.record, blobs.join(" "));
        let output = cluster
            .exec_output(&holder.name, &["sh", "-c", &script])
            .unwrap();
        assert!(output.success, "{script}: {output:?}");
        holder
    }

    /// Whether its store recorded the fixture's root.
    fn recorded(&self) -> bool {
        self.cluster
            .exec_output(&self.name, &["test", "-f", &self.record])
            .unwrap()
            .success
    }
}

impl Drop for Holder<'_> {
    fn drop(&mut self) {
        let _ = self
            .cluster
            .exec_output(&self.name, &["sh", "-c", &rmi(self.cluster)]);
        let _ = self.cluster.start_agent(&self.name);
    }
}

/// The worker's agent journal since `since`, a time as `date '+%Y-%m-%d %H:%M:%S'` gives it.
fn journal(worker: &Worker, since: &str) -> String {
    worker.sh(&format!(
        "journalctl -u speculaire --no-pager -o cat --since '{since}'"
    ))
}

/// Waits until `done` holds, at most [`WITHIN`], and returns when it did; `what` names it otherwise.
fn until(what: &dyn Fn() -> String, done: &mut dyn FnMut() -> bool) -> Instant {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < WITHIN, "{}", what());
        sleep(Duration::from_millis(200));
    }
    Instant::now()
}

/// Waits until the worker's journal since `since` holds `line`.
fn logged(worker: &Worker, since: &str, line: &str) -> Instant {
    until(
        &|| format!("no {line:?} in:\n{}", journal(worker, since)),
        &mut || journal(worker, since).contains(line),
    )
}

/// A policy named `fixtures` over the fixtures at `host`, which the workflow that recorded them signs.
fn fixtures_policy(host: &str) -> String {
    format!(
        "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: fixtures\nspec:\n  \
         images:\n  - glob: {host}/{FIXTURES}\n  authorities:\n  - keyless:\n      identities:\n      - issuer: \
         https://token.actions.githubusercontent.com\n        subject: {SAN}\n"
    )
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn an_image_whose_artifacts_no_source_serves_is_unverifiable_until_a_peer_discovers_them() {
    if Cluster::from_env().ip_family() == IpFamily::Dual {
        return;
    }
    // A is the worker; zot serves the keyless fixture and its bundle.
    let worker = Worker::new();
    let cluster = &worker.cluster;
    let case = Case::pullable()
        .into_iter()
        .find(|case| case.name == "keyless")
        .expect("the keyless fixture");
    let root = case.layout.root().to_string();
    let host = cluster.upstream(Kind::Referrers).address().to_owned();
    let reference = format!("{host}/{FIXTURES}:keyless");
    cluster
        .policy(&worker.name, &fixtures_policy(&host))
        .unwrap();
    worker.forget(std::slice::from_ref(&case));
    let b = Holder::pull(&worker, &case, &reference);
    let since = worker.sh("date '+%Y-%m-%d %H:%M:%S'");
    let since = since.trim();
    let unverifiable = {
        // B starts without upstreams: it discovers nothing. A pulls from B once a reflector names B.
        let _b_alone = cluster.reject_upstreams(&b.name).unwrap();
        cluster.start_agent(&b.name).unwrap();
        let _a_alone = cluster.reject_upstreams(&worker.name).unwrap();
        let pull = ["crictl", "pull", reference.as_str()];
        until(
            &|| format!("{} never pulled from {}", worker.name, b.name),
            &mut || cluster.exec_output(&worker.name, &pull).unwrap().success,
        );
        let line = format!("verdict of {root} under fixtures: unverifiable: artifacts unreachable");
        let unverifiable = logged(&worker, since, &line);
        let metrics = cluster.metrics(&worker.name).unwrap();
        assert_eq!(
            metrics.get(r#"speculaire_verdicts{state="unverifiable"}"#),
            Some(1.0)
        );
        assert!(!b.recorded(), "{} discovered without upstreams", b.name);
        unverifiable
    };

    // B discovers from zot as its agent starts again, and announces: A's next try finds the artifacts at B.
    cluster.stop_agent(&b.name).unwrap();
    cluster.start_agent(&b.name).unwrap();
    let discovered = until(
        &|| format!("{} has not discovered {root}", b.name),
        &mut || b.recorded(),
    );
    let allowed = logged(
        &worker,
        since,
        &format!("verdict of {root} under fixtures: allow"),
    );
    // The try after `discovered` comes at most one wait later, and a wait is at most 10 s more than the time since
    // the first verdict (D151); 5 s more for the polls and A's discovery.
    let waited = discovered - unverifiable;
    assert!(
        allowed - discovered <= waited + Duration::from_secs(15),
        "allowed {:?} after B discovered, {waited:?} after unverifiable",
        allowed - discovered
    );
    eprintln!(
        "verify: unverifiable to allow {:.1} s, B discovered to A allowed {:.1} s",
        (allowed - unverifiable).as_secs_f64(),
        (allowed - discovered).as_secs_f64()
    );
}

/// The loopback mirror (D14), and the directory of its client certificate.
const MIRROR: &str = "https://127.0.0.1:7480";
const MIRROR_DIR: &str = "/var/lib/speculaire/mirror";

/// The worker's agent config.
const CONFIG: &str = "/etc/speculaire/config.toml";

/// Sets the worker's `artifacts.grace` to `secs` while it lives, the agent restarted by the caller: dropping it sets
/// the default back, for the [`Worker`] dropped after it to restart the agent.
struct Grace<'a>(&'a Worker);

impl<'a> Grace<'a> {
    fn set(worker: &'a Worker, secs: u64) -> Self {
        worker.sh(&format!(
            "sed -i 's/^#grace = 600$/grace = {secs}/' {CONFIG} && grep -q '^grace = {secs}$' {CONFIG}"
        ));
        Self(worker)
    }
}

impl Drop for Grace<'_> {
    fn drop(&mut self) {
        let script = format!("sed -i 's/^grace = [0-9]*$/#grace = 600/' {CONFIG}");
        let _ = self
            .0
            .cluster
            .exec_output(&self.0.name, &["sh", "-c", &script]);
    }
}

/// The time of the first line of the worker's journal since `since` that holds `line`, logged already, in seconds
/// since the epoch.
fn logged_at(worker: &Worker, since: &str, line: &str) -> f64 {
    let journal = worker.sh(&format!(
        "journalctl -u speculaire --no-pager -o short-unix --since '{since}'"
    ));
    let found = journal.lines().find(|logged| logged.contains(line));
    found
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_pull_by_tag_is_verified_from_its_manifest_fetch_before_the_runtime_lists_the_image() {
    if Cluster::from_env().ip_family() == IpFamily::Dual {
        return;
    }
    let worker = Worker::new();
    let cluster = &worker.cluster;
    let case = Case::pullable()
        .into_iter()
        .find(|case| case.name == "keyless")
        .expect("the keyless fixture");
    let root = case.layout.root().to_string();
    let host = cluster.upstream(Kind::Referrers).address().to_owned();
    let reference = format!("{host}/{FIXTURES}:keyless");
    cluster
        .policy(&worker.name, &fixtures_policy(&host))
        .unwrap();
    worker.forget(std::slice::from_ref(&case));
    cluster.wait_ready(&worker.name).unwrap();
    let since = worker.sh("date '+%Y-%m-%d %H:%M:%S'");
    let since = since.trim();

    // The pull returns once the runtime lists the image.
    let pulled: f64 = worker
        .sh(&format!(
            "crictl pull {reference} >/dev/null && date +%s.%N"
        ))
        .trim()
        .parse()
        .unwrap();
    let line = format!("verdict of {root} under fixtures: allow");
    logged(&worker, since, &line);
    let allowed = logged_at(&worker, since, &line);
    let metrics = cluster.metrics(&worker.name).unwrap();
    let manifest =
        metrics.get(r#"speculaire_verifications_total{result="allow",trigger="manifest"}"#);
    assert!(
        manifest >= Some(1.0),
        "verifications under manifest: {manifest:?}"
    );
    eprintln!(
        "verify: verdict {:.3} s before the pull returned",
        pulled - allowed
    );
    assert!(
        allowed <= pulled,
        "verdict {:.3} s after the pull returned",
        allowed - pulled
    );
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_manifest_fetched_and_never_pulled_keeps_its_artifacts_through_a_restart_until_its_grace_ends()
{
    const GRACE: u64 = 20;
    if Cluster::from_env().ip_family() == IpFamily::Dual {
        return;
    }
    let worker = Worker::new();
    let cluster = &worker.cluster;
    let case = Case::pullable()
        .into_iter()
        .find(|case| case.name == "keyless")
        .expect("the keyless fixture");
    let root = case.layout.root().to_string();
    let host = cluster.upstream(Kind::Referrers).address().to_owned();
    let _grace = Grace::set(&worker, GRACE);
    worker.forget(std::slice::from_ref(&case));
    cluster.wait_ready(&worker.name).unwrap();

    // containerd names the registry in `ns`, CRI-O first in the path (D66).
    let path = match cluster.runtime() {
        Runtime::Containerd => format!("/v2/{FIXTURES}/manifests/{root}?ns={host}"),
        Runtime::Crio => format!("/v2/{host}/{FIXTURES}/manifests/{root}"),
    };
    let fetched = Instant::now();
    worker.sh(&format!(
        "curl -s -o /dev/null --cacert {MIRROR_DIR}/ca.crt --cert {MIRROR_DIR}/client.pem \
         -H 'Accept: {INDEX}, application/vnd.oci.image.manifest.v1+json' '{MIRROR}{path}'"
    ));
    let expected = case.expected();
    assert_eq!(worker.recorded(&case, fetched), expected);

    // A restart lists the images again, and collects: the grace, kept on disk, keeps the root.
    cluster.stop_agent(&worker.name).unwrap();
    cluster.start_agent(&worker.name).unwrap();
    cluster.wait_ready(&worker.name).unwrap();
    // The first listing comes within a second of the start; it is collected at once.
    sleep(Duration::from_secs(3));
    let record = format!("{STORE}/roots/sha256/{}.json", hex(case.layout.root()));
    let blobs: Vec<String> = case
        .digests()
        .into_iter()
        .map(|digest| format!("{STORE}/blobs/sha256/{}", hex(&digest)))
        .collect();
    let held = || {
        cluster
            .exec_output(&worker.name, &["test", "-f", &record])
            .unwrap()
            .success
    };
    assert!(held(), "{root} collected within its grace");

    // Collected as its grace ends, blobs too.
    let collected = until(&|| format!("{root} kept after its grace"), &mut || !held());
    let left = worker.sh(&format!("ls {} 2>/dev/null; true", blobs.join(" ")));
    assert_eq!(left.trim(), "", "blobs kept after the grace");
    let after = collected - fetched;
    assert!(
        after >= Duration::from_secs(GRACE - 1),
        "collected {after:?} after the fetch"
    );
    eprintln!(
        "verify: collected {:.1} s after the fetch",
        after.as_secs_f64()
    );
}

/// Waits until the worker's journal since `since` holds an error `message` whose fields hold `reason`.
fn logged_error(worker: &Worker, since: &str, message: &str, reason: &str) {
    // `-o verbose` shows the fields.
    let errors = || {
        worker.sh(&format!(
            "journalctl -u speculaire -p err --no-pager -o verbose --since '{since}'"
        ))
    };
    until(&|| format!("no {reason:?} in:\n{}", errors()), &mut || {
        let errors = errors();
        errors.contains(&format!("MESSAGE={message}")) && errors.contains(reason)
    });
}

/// Sets the worker's `config.poll_interval` to `secs` while it lives, the agent restarted or sent SIGHUP by the caller:
/// dropping it sets the default back, for the [`Worker`] dropped after it to restart the agent.
struct PollInterval<'a>(&'a Worker);

impl<'a> PollInterval<'a> {
    fn set(worker: &'a Worker, secs: u64) -> Self {
        worker.sh(&format!(
            "sed -i 's/^#\\{{0,1\\}}poll_interval = [0-9]*$/poll_interval = {secs}/' {CONFIG} && \
             grep -q '^poll_interval = {secs}$' {CONFIG}"
        ));
        Self(worker)
    }
}

impl Drop for PollInterval<'_> {
    fn drop(&mut self) {
        let script = format!("sed -i 's/^poll_interval = [0-9]*$/#poll_interval = 10/' {CONFIG}");
        let _ = self
            .0
            .cluster
            .exec_output(&self.0.name, &["sh", "-c", &script]);
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_changed_policy_verifies_again_on_sighup_or_a_poll_and_a_refused_one_keeps_the_verdicts() {
    if Cluster::from_env().ip_family() == IpFamily::Dual {
        return;
    }
    let worker = Worker::new();
    let cluster = &worker.cluster;
    let case = Case::pullable()
        .into_iter()
        .find(|case| case.name == "keyless")
        .expect("the keyless fixture");
    let root = case.layout.root().to_string();
    let host = cluster.upstream(Kind::Referrers).address().to_owned();
    let reference = format!("{host}/{FIXTURES}:keyless");
    let signed = fixtures_policy(&host);
    // The keyless fixture holds no provenance.
    let attested = format!(
        "{signed}    attestations:\n    - name: provenance\n      predicateType: https://slsa.dev/provenance/v1\n"
    );
    let refused = signed.replacen(
        "  - keyless:\n",
        "  - keyless:\n      url: https://fulcio.example\n",
        1,
    );
    cluster.policy(&worker.name, &signed).unwrap();
    // No poll until SIGHUP sets a shorter interval.
    let poll = PollInterval::set(&worker, 3600);
    worker.forget(std::slice::from_ref(&case));
    cluster.wait_ready(&worker.name).unwrap();
    let since = worker.sh("date '+%Y-%m-%d %H:%M:%S'");
    let since = since.trim();
    let verdicts = |verdict: &str| {
        journal(&worker, since)
            .matches(&format!("verdict of {root} under fixtures: {verdict}"))
            .count()
    };
    let wait = |verdict: &str, count: usize| {
        until(
            &|| {
                format!(
                    "not {count} {verdict} verdicts in:\n{}",
                    journal(&worker, since)
                )
            },
            &mut || verdicts(verdict) == count,
        )
    };
    let hangup = || worker.sh("systemctl kill -s HUP speculaire");
    let reloaded = || {
        cluster
            .metrics(&worker.name)
            .unwrap()
            .get("speculaire_config_reload_failures_total")
            .unwrap_or(0.0)
    };
    worker.sh(&format!("crictl pull {reference} >/dev/null"));
    wait("allow", 1);

    // SIGHUP alone.
    cluster.policy(&worker.name, &attested).unwrap();
    let changed = Instant::now();
    hangup();
    let rejected = wait("rejected", 1);
    eprintln!(
        "verify: rejected {:.1} s after SIGHUP",
        (rejected - changed).as_secs_f64()
    );
    let reverified = cluster
        .metrics(&worker.name)
        .unwrap()
        .get(r#"speculaire_verifications_total{result="rejected",trigger="reverify"}"#);
    assert_eq!(reverified, Some(1.0));

    // A refused file keeps the policy and the verdicts, and counts once.
    let failures = reloaded();
    drop(poll);
    let poll = PollInterval::set(&worker, 1);
    cluster.policy(&worker.name, &refused).unwrap();
    hangup();
    logged_error(
        &worker,
        since,
        "the policy file reload failed; the previous one stays in use",
        &format!(
            "the policy file {POLICY}: document 1, spec.authorities[0].keyless.url: unknown field `url`"
        ),
    );
    sleep(Duration::from_secs(3));
    assert_eq!(reloaded(), failures + 1.0);
    assert_eq!((verdicts("allow"), verdicts("rejected")), (1, 1));
    let metrics = cluster.metrics(&worker.name).unwrap();
    assert_eq!(
        metrics.get(r#"speculaire_verdicts{state="rejected"}"#),
        Some(1.0)
    );

    // A poll alone, each second now.
    cluster.policy(&worker.name, &signed).unwrap();
    wait("allow", 2);
    cluster.policy(&worker.name, &attested).unwrap();
    let changed = Instant::now();
    let rejected = wait("rejected", 2);
    eprintln!(
        "verify: rejected {:.1} s after the write, polled each second",
        (rejected - changed).as_secs_f64()
    );
    drop(poll);
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn speculaire_verify_on_a_node_allows_a_signed_fixture_and_exits_1_for_an_unsigned_image() {
    if Cluster::from_env().ip_family() == IpFamily::Dual {
        return;
    }
    let worker = Worker::new();
    let cluster = &worker.cluster;
    let zot = cluster.upstream(Kind::Referrers);
    let host = zot.address().to_owned();
    let keyless = Case::pullable()
        .into_iter()
        .find(|case| case.name == "keyless")
        .expect("the keyless fixture");
    let unsigned = zot.digest(UNSIGNED).unwrap();
    let name = UNSIGNED.split_once(':').expect("a tag").0;
    let policy = fixtures_policy(&host).replace(
        &format!("  - glob: {host}/{FIXTURES}\n"),
        &format!("  - glob: {host}/{FIXTURES}\n  - glob: {host}/{name}\n"),
    );
    cluster.policy(&worker.name, &policy).unwrap();
    // The agent is not asked: the command discovers on its own (D156).
    let verify = |image: String| worker.sh(&format!("speculaire verify {image}; echo \"exit $?\""));

    let allowed = verify(format!("{host}/{FIXTURES}@{}", keyless.layout.root()));
    assert!(allowed.starts_with("allow\n"), "{allowed}");
    assert!(
        allowed.contains(&format!("pass: {SAN} (issuer ")),
        "{allowed}"
    );
    assert!(allowed.ends_with("exit 0\n"), "{allowed}");

    let rejected = verify(format!("{host}/{name}@{unsigned}"));
    assert!(
        rejected.starts_with("rejected: no signature\n"),
        "{rejected}"
    );
    assert!(rejected.ends_with("exit 1\n"), "{rejected}");
}
