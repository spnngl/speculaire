//! Prewarm end to end (D51, D181, D185, D186, D188): an image written into both reflectors' `prewarm.images` reaches
//! every node, only its seeds get its blobs from upstream, and each agent pulls it once, through a reflector's restart
//! and a seed that can reach nothing. On containerd, each agent pins the image until no list names it, which keeps it
//! through image garbage collection; on CRI-O, where none is pinned, a pod that needs it once removed gets it from
//! peers (D191). On the IPv4 pass only, as the verify suite (D141): neither the seeds' pick nor
//! the waves depend on the family.
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use e2e::node::addresses;
use e2e::prewarm::Prewarm;
use e2e::upstream::{Digest, Image, Kind, Upstream};
use e2e::{Cluster, IpFamily, Runtime};

/// The tests write the same reflectors' config: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

const PEER_PORT: u16 = 7481;
/// How long after the write every node holds the image, the reflectors polling their config every second (§ M7,
/// question 9).
const WITHIN: Duration = Duration::from_secs(30);
/// The size of each image's one layer.
const SIZE: u64 = 1 << 20;
/// `prewarm.seed_timeout`, but in the case of the seed that reaches nothing.
const SEED_TIMEOUT: u64 = 300;
/// How long after the write that unlists an image every node unpins it (D191).
const UNPINNED: Duration = Duration::from_secs(10);

const PULLED: &str = r#"speculaire_prewarm_pulls_total{result="ok"}"#;
const FAILED: &str = r#"speculaire_prewarm_pulls_total{result="failed"}"#;
const DROPPED: &str = r#"speculaire_prewarm_pulls_total{result="dropped"}"#;
const SENT_SEED: &str = r#"speculaire_reflector_prewarm_sent_total{stage="seed"}"#;
const SENT_RELEASE: &str = r#"speculaire_reflector_prewarm_sent_total{stage="release"}"#;
const TIMED_OUT: &str = r#"speculaire_reflector_prewarm_rounds_total{release="timeout"}"#;

/// The cluster on the IPv4 pass, with its nodes' names; `None` on the dual-stack pass.
fn cluster() -> Option<(Cluster, Vec<String>, MutexGuard<'static, ()>)> {
    let cluster = Cluster::from_env();
    if cluster.ip_family() == IpFamily::Dual {
        return None;
    }
    let serial = SERIAL.lock().unwrap_or_else(PoisonError::into_inner);
    let nodes = cluster
        .nodes()
        .unwrap()
        .into_iter()
        .map(|node| node.name)
        .collect();
    Some((cluster, nodes, serial))
}

/// The 2 seeds of `reference` among `nodes`, as each reflector picks them (D181).
fn seeds(reference: &str, nodes: &[String]) -> BTreeSet<String> {
    speculaire_reflect::seeds(
        reference,
        nodes.iter().map(String::as_str),
        NonZeroU32::new(2).unwrap(),
    )
    .map(str::to_owned)
    .collect()
}

/// A repository no run pushed yet, `e2e/prewarm-<case>-…`, whose image `<upstream>/<repository>:1` has seeds that
/// `fit`.
fn repository(
    upstream: &Upstream,
    case: &str,
    nodes: &[String],
    fit: impl Fn(&BTreeSet<String>) -> bool,
) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // With 3 nodes and 2 seeds, each fit holds for a third of the names at least: 1000 tries all miss with odds
    // below (2/3)^1000.
    (0..1000)
        .map(|n| format!("e2e/prewarm-{case}-{nanos}-{n}"))
        .find(|repository| {
            fit(&seeds(
                &format!("{}/{repository}:1", upstream.address()),
                nodes,
            ))
        })
        .unwrap()
}

/// The counter `series` of the node's agent, 0 before it counts.
fn counter(cluster: &Cluster, node: &str, series: &str) -> u64 {
    let value = cluster
        .metrics(node)
        .unwrap()
        .get(series)
        .unwrap_or_default();
    value.to_string().parse().unwrap()
}

/// Waits until `done`, at most `within`; `what` says what did not happen.
fn wait(within: Duration, what: &dyn Fn() -> String, done: &mut dyn FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() < within, "after {within:?}: {}", what());
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Waits until the runtime of each of `nodes` lists `reference`, at most [`WITHIN`] after `since`; how long after
/// `since` the last did.
fn held(cluster: &Cluster, nodes: &[&str], reference: &str, since: Instant) -> Duration {
    for node in nodes {
        let within = WITHIN.saturating_sub(since.elapsed());
        let what = || format!("{node} does not hold {reference}");
        wait(within, &what, &mut || {
            cluster.lists(node, reference).unwrap()
        });
    }
    since.elapsed()
}

/// How many records of the node's agent have every field of `matches`, across its restarts.
fn journal(cluster: &Cluster, node: &str, matches: &[&str]) -> usize {
    let mut command = vec![
        "journalctl",
        "-q",
        "-u",
        "speculaire",
        "--no-pager",
        "-o",
        "cat",
    ];
    command.extend_from_slice(matches);
    cluster.exec(node, &command).unwrap().lines().count()
}

/// How many times the node's agent logged that it prewarmed `reference`, across its restarts.
fn prewarmed(cluster: &Cluster, node: &str, reference: &str) -> usize {
    journal(
        cluster,
        node,
        &["MESSAGE=prewarmed", &format!("F_IMAGE={reference}")],
    )
}

/// How many times the node's agent opened a stream to a reflector, across its restarts.
fn streams(cluster: &Cluster, node: &str) -> usize {
    journal(cluster, node, &["MESSAGE=reflector stream up"])
}

/// The blob `GET`s without `Range` upstream answered for `image` after its first `since` requests, by the node they
/// came from.
fn blob_gets(
    cluster: &Cluster,
    upstream: &Upstream,
    image: &Image,
    nodes: &[String],
    since: usize,
) -> BTreeMap<String, Vec<Digest>> {
    let by_address: Vec<_> = nodes
        .iter()
        .map(|node| (node, addresses(node).unwrap()))
        .collect();
    let mut gets: BTreeMap<String, Vec<Digest>> = BTreeMap::new();
    for request in upstream.requests().unwrap().into_iter().skip(since) {
        // The log has no `Range`: the full answer is a 200, a range's a 206.
        let Some(digest) = request
            .blob()
            .filter(|digest| request.status == 200 && image.blobs.contains(digest))
        else {
            continue;
        };
        let (node, _) = by_address
            .iter()
            .find(|(_, addresses)| addresses.contains(&request.client))
            .unwrap_or_else(|| {
                unreachable!(
                    "{request:?} comes from no node of {}",
                    cluster.reflectors()[0]
                )
            });
        gets.entry((*node).clone()).or_default().push(digest);
    }
    gets
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn an_image_written_into_prewarm_images_is_held_everywhere_within_30_s_with_its_blobs_from_upstream_to_its_seeds_alone()
 {
    let Some((cluster, nodes, _serial)) = cluster() else {
        return;
    };
    let upstream = cluster.upstream(Kind::Plain);
    let prewarm = cluster.prewarm().unwrap();
    let image = upstream
        .push(&repository(&upstream, "held", &nodes, |_| true), SIZE)
        .unwrap();
    let seeds = seeds(&image.reference, &nodes);
    let before: Vec<u64> = nodes
        .iter()
        .map(|node| counter(&cluster, node, PULLED))
        .collect();

    let written = prewarm.write(&[&image.reference], SEED_TIMEOUT).unwrap();
    let all: Vec<&str> = nodes.iter().map(String::as_str).collect();
    let took = held(&cluster, &all, &image.reference, written);
    eprintln!(
        "{}: every node holds it {took:?} after the write, seeds {seeds:?}",
        image.reference
    );

    for (node, before) in nodes.iter().zip(before) {
        let pulled = || counter(&cluster, node, PULLED);
        let what = || format!("{node} counts {} pulls, not {}", pulled(), before + 1);
        wait(Duration::from_secs(5), &what, &mut || pulled() > before);
        assert_eq!(pulled(), before + 1, "{node}");
    }
    let gets = blob_gets(&cluster, &upstream, &image, &nodes, 0);
    let getters: BTreeSet<&String> = gets.keys().collect();
    assert!(
        !getters.is_empty() && getters.iter().all(|node| seeds.contains(*node)),
        "{gets:?}, seeds {seeds:?}"
    );
    let got: BTreeSet<&Digest> = gets.values().flatten().collect();
    assert_eq!(got, image.blobs.iter().collect(), "{gets:?}");
    if cluster.runtime() == Runtime::Crio {
        // The relay keeps what it fetches in the blob cache (D67). A node resolves the tag upstream or from a seed
        // that announced it (D123), as the seed's announce and its own pull fall.
        for (node, digests) in &gets {
            for digest in digests {
                let path = cluster.blob_path(digest);
                let kept = cluster.exec_output(node, &["test", "-f", &path]).unwrap();
                assert!(kept.success, "{node} has no {path}");
            }
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_reflector_restarted_mid_wave_leaves_the_other_to_release_and_resends_nothing_an_agent_pulls_twice()
 {
    let Some((cluster, nodes, _serial)) = cluster() else {
        return;
    };
    let [restarted, other] = cluster.reflectors();
    let upstream = cluster.upstream(Kind::Plain);
    let prewarm = cluster.prewarm().unwrap();
    // The restarted reflector's own agent is no seed: a restart cuts its pull, and its stream opens again after the
    // other reflector sent the seeds the image (D186).
    let image = upstream
        .push(
            &repository(&upstream, "restart", &nodes, |seeds| {
                !seeds.contains(&restarted)
            }),
            SIZE,
        )
        .unwrap();
    let reference = image.reference.as_str();
    let (seeded, released) = (
        counter(&cluster, &restarted, SENT_SEED),
        counter(&cluster, &other, SENT_RELEASE),
    );
    // The seeds pull slowly until the restarted agent streams to the other reflector again: its round, which comes
    // after the seeds', finds it streaming. A release before the restart would cut its pull, and leave it to the
    // restarted reflector's next wave.
    let slow: Vec<_> = seeds(reference, &nodes)
        .iter()
        .map(|seed| cluster.netem(seed, "delay 2s").unwrap())
        .collect();

    let up = streams(&cluster, &restarted);
    let written = prewarm.write(&[reference], SEED_TIMEOUT).unwrap();
    let what = || format!("{restarted} sent no seed {reference}");
    wait(WITHIN, &what, &mut || {
        counter(&cluster, &restarted, SENT_SEED) > seeded
    });
    cluster
        .exec(&restarted, &["systemctl", "restart", "speculaire"])
        .unwrap();
    let restart = Instant::now();
    cluster.wait_ready(&restarted).unwrap();
    let what = || format!("{restarted} streams to no reflector since its restart");
    wait(WITHIN, &what, &mut || {
        streams(&cluster, &restarted) >= up + 2
    });
    drop(slow);
    let all: Vec<&str> = nodes.iter().map(String::as_str).collect();
    let took = held(&cluster, &all, reference, written);
    eprintln!(
        "{reference}: every node holds it {took:?} after the write, {restarted} restarted mid-wave"
    );
    assert!(counter(&cluster, &other, SENT_RELEASE) > released);

    // The restarted reflector's wave starts 60 s after it (D186): it sends every agent the image, each drops it.
    let dropped: Vec<u64> = nodes
        .iter()
        .map(|node| counter(&cluster, node, DROPPED))
        .collect();
    let sent =
        || counter(&cluster, &restarted, SENT_SEED) + counter(&cluster, &restarted, SENT_RELEASE);
    let what = || {
        format!(
            "{restarted} sent {reference} {} times since its restart",
            sent()
        )
    };
    wait(
        Duration::from_secs(90).saturating_sub(restart.elapsed()),
        &what,
        &mut || sent() >= 3,
    );
    eprintln!(
        "{reference}: {restarted} sent it again {:?} after its restart",
        restart.elapsed()
    );
    for (node, dropped) in nodes.iter().zip(dropped) {
        let what = || format!("{node} dropped no second {reference}");
        wait(Duration::from_secs(5), &what, &mut || {
            counter(&cluster, node, DROPPED) > dropped
        });
        assert_eq!(prewarmed(&cluster, node, reference), 1, "{node}");
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn a_seed_that_reaches_neither_upstream_nor_peers_holds_its_round_until_seed_timeout_and_pulls_on_its_retry()
 {
    let Some((cluster, nodes, _serial)) = cluster() else {
        return;
    };
    let reflectors = cluster.reflectors();
    let blocked = nodes
        .iter()
        .find(|node| !reflectors.contains(node))
        .unwrap()
        .clone();
    let upstream = cluster.upstream(Kind::Plain);
    let prewarm = cluster.prewarm().unwrap();
    // A seed that is no reflector: both reflectors still resolve the image.
    let image = upstream
        .push(
            &repository(&upstream, "timeout", &nodes, |seeds| {
                seeds.contains(&blocked)
            }),
            SIZE,
        )
        .unwrap();
    let reference = image.reference.as_str();
    let seeds = seeds(reference, &nodes);
    let released = nodes
        .iter()
        .find(|node| !seeds.contains(*node))
        .unwrap()
        .as_str();
    let others: Vec<&str> = nodes
        .iter()
        .map(String::as_str)
        .filter(|node| *node != blocked)
        .collect();
    let timed_out: Vec<u64> = reflectors
        .iter()
        .map(|reflector| counter(&cluster, reflector, TIMED_OUT))
        .collect();
    let failed = counter(&cluster, &blocked, FAILED);
    // Streaming to the reflectors still: a seed is picked among the agents streaming (D181).
    let mut rules = vec![cluster.reject_upstreams(&blocked).unwrap()];
    for node in &others {
        rules.push(cluster.reject_port(&blocked, node, PEER_PORT).unwrap());
    }

    let written = prewarm.write(&[reference], 10).unwrap();
    let late = held(&cluster, &[released], reference, written);
    let took = held(&cluster, &others, reference, written);
    eprintln!(
        "{reference}: {released} holds it {late:?} after the write, every node but {blocked} {took:?}"
    );
    assert!(
        late >= Duration::from_secs(10),
        "{released} was sent it before prewarm.seed_timeout: {late:?}"
    );
    // Each reflector runs its own wave, which may start a poll and a resolution later.
    for (reflector, before) in reflectors.iter().zip(timed_out) {
        let what = || format!("{reflector} timed no round out");
        wait(Duration::from_secs(5), &what, &mut || {
            counter(&cluster, reflector, TIMED_OUT) > before
        });
    }
    assert!(counter(&cluster, &blocked, FAILED) > failed);
    assert!(!cluster.lists(&blocked, reference).unwrap());

    // Each reflector's list retries the pull at once, and the second failure doubles the backoff to 60 s (D188): the
    // next retry comes at most 60 s after the unblock.
    drop(rules);
    let unblocked = Instant::now();
    let what = || format!("{blocked} does not hold {reference}");
    wait(Duration::from_secs(70), &what, &mut || {
        cluster.lists(&blocked, reference).unwrap()
    });
    eprintln!(
        "{reference}: {blocked} holds it {:?} after it was unblocked",
        unblocked.elapsed()
    );
    assert_eq!(prewarmed(&cluster, &blocked, reference), 1);
}

/// The node that is no reflector: a case removes its images, and its agent pins as any other.
fn worker(cluster: &Cluster, nodes: &[String]) -> String {
    let reflectors = cluster.reflectors();
    nodes
        .iter()
        .find(|node| !reflectors.contains(node))
        .unwrap()
        .clone()
}

/// Waits until whether the runtime of `node` pins `reference` is `pinned`, at most `within`.
fn pins(cluster: &Cluster, node: &str, reference: &str, pinned: bool, within: Duration) {
    let what = || {
        let state = if pinned { "does not pin" } else { "still pins" };
        format!("{node} {state} {reference}")
    };
    wait(within, &what, &mut || {
        cluster.pinned(node).unwrap().contains(reference) == pinned
    });
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_containerd_a_prewarmed_image_is_pinned_through_image_collection_and_unpinned_within_10_s_once_unlisted()
 {
    let Some((cluster, nodes, _serial)) = cluster() else {
        return;
    };
    if cluster.runtime() != Runtime::Containerd {
        return;
    }
    let begun = Instant::now();
    let node = worker(&cluster, &nodes);
    let upstream = cluster.upstream(Kind::Plain);
    let prewarm = cluster.prewarm().unwrap();
    let image = upstream
        .push(&repository(&upstream, "pinned", &nodes, |_| true), SIZE)
        .unwrap();
    let reference = image.reference.as_str();
    let control = upstream
        .push(&repository(&upstream, "control", &nodes, |_| true), SIZE)
        .unwrap();
    cluster
        .exec(&node, &["crictl", "pull", &control.reference])
        .unwrap();
    // containerd's config pins the sandbox image, and kind its own: the agent leaves those.
    let others = cluster.pinned(&node).unwrap();
    assert!(
        others
            .iter()
            .any(|tag| tag.starts_with("registry.k8s.io/pause:")),
        "{others:?}"
    );

    let written = prewarm.write(&[reference], SEED_TIMEOUT).unwrap();
    let all: Vec<&str> = nodes.iter().map(String::as_str).collect();
    held(&cluster, &all, reference, written);
    for node in &nodes {
        pins(&cluster, node, reference, true, Duration::from_secs(5));
    }
    cluster.prune(&node).unwrap();
    assert!(cluster.lists(&node, reference).unwrap());
    assert!(!cluster.lists(&node, &control.reference).unwrap());

    let unlisted = prewarm.write(&[], SEED_TIMEOUT).unwrap();
    for node in &nodes {
        let within = UNPINNED.saturating_sub(unlisted.elapsed());
        pins(&cluster, node, reference, false, within);
    }
    eprintln!(
        "{reference}: unpinned everywhere {:?} after the write, the case took {:?}",
        unlisted.elapsed(),
        begun.elapsed()
    );
    assert_eq!(cluster.pinned(&node).unwrap(), others);
}

/// Deletes the pod, even when the test fails.
/// What the CRI-O case leaves, taken off however it ends: its image shares the layers of `TEST_IMAGE`, which CRI-O
/// would then not fetch for the suites that follow.
struct Leftovers<'a> {
    cluster: &'a Cluster,
    prewarm: &'a Prewarm<'a>,
    nodes: &'a [String],
    pod: &'static str,
    image: &'a str,
}

impl Drop for Leftovers<'_> {
    fn drop(&mut self) {
        let _ = self.prewarm.write(&[], SEED_TIMEOUT);
        let _ = self
            .cluster
            .kubectl(&["delete", "pod", self.pod, "--now", "--timeout=60s"]);
        for node in self.nodes {
            let _ = self.cluster.exec(node, &["crictl", "rmi", self.image]);
        }
    }
}

#[test]
#[ignore = "needs a kind cluster: just e2e <runtime> <version>"]
fn on_crio_a_prewarmed_image_is_not_pinned_and_once_removed_its_pod_starts_with_no_blob_from_upstream()
 {
    let Some((cluster, nodes, _serial)) = cluster() else {
        return;
    };
    if cluster.runtime() != Runtime::Crio {
        return;
    }
    let begun = Instant::now();
    let node = worker(&cluster, &nodes);
    let upstream = cluster.upstream(Kind::Plain);
    let prewarm = cluster.prewarm().unwrap();
    let image = upstream
        .push_runnable(&repository(&upstream, "unpinned", &nodes, |_| true), SIZE)
        .unwrap();
    let reference = image.reference.as_str();

    let written = prewarm.write(&[reference], SEED_TIMEOUT).unwrap();
    let all: Vec<&str> = nodes.iter().map(String::as_str).collect();
    held(&cluster, &all, reference, written);
    assert!(!cluster.pinned(&node).unwrap().contains(reference));
    cluster.prune(&node).unwrap();
    assert!(!cluster.lists(&node, reference).unwrap());

    // The peers hold every blob, and the node's blob cache too (D67): only the manifests come from upstream.
    let since = upstream.requests().unwrap().len();
    let leftovers = Leftovers {
        cluster: &cluster,
        prewarm: &prewarm,
        nodes: &nodes,
        pod: "e2e-prewarm-unpinned",
        image: reference,
    };
    let _ = cluster.kubectl(&[
        "delete",
        "pod",
        leftovers.pod,
        "--ignore-not-found",
        "--wait",
    ]);
    let overrides = format!(r#"{{"spec":{{"nodeName":"{node}"}}}}"#);
    cluster
        .kubectl(&[
            "run",
            leftovers.pod,
            "--image",
            reference,
            "--image-pull-policy=IfNotPresent",
            "--restart=Never",
            &format!("--overrides={overrides}"),
            "--command",
            "--",
            "sleep",
            "3600",
        ])
        .unwrap();
    cluster
        .kubectl(&[
            "wait",
            "--for=condition=Ready",
            &format!("pod/{}", leftovers.pod),
            "--timeout=120s",
        ])
        .unwrap();
    let gets = blob_gets(&cluster, &upstream, &image, &nodes, since);
    assert!(!gets.contains_key(&node), "{gets:?}");
    eprintln!("{reference}: the case took {:?}", begun.elapsed());
}
