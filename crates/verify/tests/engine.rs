//! The verdict engine over the recorded fixtures of step 01, offline, with discovery scripted (D20, D151).

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use metrics_exporter_prometheus::PrometheusBuilder;
use speculaire_artifacts::Store;
use speculaire_artifacts::discover::{Error, Reason};
use speculaire_artifacts::follow::{Found, roots};
use speculaire_artifacts::testing::{FIXTURES, Fixture};
use speculaire_oci::reference::Digest;
use speculaire_runtime::images::{Image, List, RepoDigest, Update};
use speculaire_verify::engine::{Discover, RETRY_FIRST, RETRY_MAX};
use speculaire_verify::{
    Absent, Engine, Held, Key, MatchHash, Policies, Signatures, TrustRoot, Verdict, Verdicts,
};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::time::Instant;

/// The workflow that signed every keyless case.
const SAN: &str =
    "https://github.com/spnngl/speculaire/.github/workflows/fixtures.yml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";
/// `sbom.max_size`'s default (D12).
const MAX_SIZE: u64 = 64 << 20;

/// A discovery whose answers the test sets, noting when it is asked.
struct Scripted {
    store: Arc<Store>,
    /// Whether a discovery finds the artifacts.
    finds: bool,
    discovered: Mutex<Vec<Instant>>,
    again: Mutex<Vec<Instant>>,
    /// Upstream answers once the test adds a permit.
    upstream: Semaphore,
    /// How many times verification read the store.
    reads: AtomicUsize,
}

impl Scripted {
    fn answer(&self, asked: &Mutex<Vec<Instant>>) -> Result<(), Error> {
        asked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Instant::now());
        if self.finds {
            Ok(())
        } else {
            Err(unreachable())
        }
    }
}

impl Discover for Scripted {
    fn store(&self) -> &Store {
        self.reads.fetch_add(1, Ordering::Relaxed);
        &self.store
    }

    fn discover(&self, _: &Digest, _: &[String]) -> impl Future<Output = Result<(), Error>> + Send {
        std::future::ready(self.answer(&self.discovered))
    }

    fn again(&self, _: &Digest, _: &[String]) -> impl Future<Output = Result<(), Error>> + Send {
        let answer = self.answer(&self.again);
        async move {
            let _answers = self.upstream.acquire().await;
            answer
        }
    }
}

fn unreachable() -> Error {
    Error::Unverifiable {
        reason: Reason::Unreachable,
        retry_at: Instant::now() + Duration::from_mins(10),
    }
}

/// A running engine.
struct Run {
    found: mpsc::UnboundedSender<Found>,
    verdicts: Arc<Verdicts>,
    discovery: Arc<Scripted>,
}

impl Run {
    fn start(store: &Arc<Store>, policies: Policies, finds: bool, trust: Held) -> Self {
        let discovery = Arc::new(Scripted {
            store: Arc::clone(store),
            finds,
            discovered: Mutex::default(),
            again: Mutex::default(),
            upstream: Semaphore::new(0),
            reads: AtomicUsize::new(0),
        });
        let engine = Engine::new(
            Arc::clone(&discovery),
            policies,
            Signatures::new(MAX_SIZE),
            watch::channel(trust).1,
        );
        let verdicts = Arc::clone(engine.verdicts());
        let (found, told) = mpsc::unbounded_channel();
        tokio::spawn(engine.run(told));
        Self {
            found,
            verdicts,
            discovery,
        }
    }

    /// Lists `list`, and tells that the discovery of `root` ended as `discovered` says.
    fn listed(&self, list: &List, root: &Digest, discovered: Result<(), Error>) {
        self.found
            .send(Found::Listed(roots(list)))
            .expect("the engine runs");
        let root = root.clone();
        self.found
            .send(Found::Ended { root, discovered })
            .expect("the engine runs");
    }

    /// The verdict of `key` once it is no longer pending, waiting 10 s at most.
    async fn verdict(&self, key: Key<'_>) -> Verdict {
        for _ in 0..200 {
            let verdict = self.verdicts.get(key);
            if verdict != Verdict::Pending {
                return verdict;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Verdict::Pending
    }
}

/// One policy per `(name, image glob, subject)`, each a keyless authority from GitHub Actions.
fn policies(policies: &[(&str, &str, &str)]) -> Policies {
    let text = policies
        .iter()
        .map(|(name, glob, subject)| {
            format!(
                "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: {name}\nspec:\n  \
                 images:\n  - glob: \"{glob}\"\n  authorities:\n  - keyless:\n      identities:\n      - issuer: \
                 {ISSUER}\n        subject: {subject}\n"
            )
        })
        .collect::<Vec<_>>()
        .join("---\n");
    Policies::parse(&text).expect("the test policies parse")
}

fn hash(policies: &Policies, names: &[&str]) -> MatchHash {
    MatchHash::of(
        policies
            .iter()
            .filter(|policy| names.contains(&policy.name())),
    )
}

fn pinned() -> Arc<TrustRoot> {
    let root = TrustRoot::load(&Path::new(FIXTURES).join("trusted_root.json"))
        .expect("the recorded trusted root parses");
    Arc::new(root)
}

/// The image list of `images`, each an ID and its `(repository, manifest digest)` pairs.
fn list(images: &[(&Digest, &[(&str, &Digest)])]) -> List {
    let images = images
        .iter()
        .map(|(id, repo_digests)| Image {
            id: (*id).clone(),
            repo_digests: repo_digests
                .iter()
                .map(|(repository, digest)| RepoDigest {
                    repository: (*repository).to_owned(),
                    digest: (*digest).clone(),
                })
                .collect(),
            tags: Vec::new(),
        })
        .collect();
    let mut list = List::default();
    list.apply(Update::Listing(images));
    list
}

fn digest(byte: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{byte:02x}").repeat(32)))
        .expect("a test digest parses")
}

#[tokio::test]
async fn a_digest_under_two_names_has_a_verdict_per_hash_of_the_policies_each_name_matches() {
    let fixture = Fixture::load("keyless").await;
    let root = &fixture.root;
    let policies = policies(&[("a", "reg.test/a", SAN), ("b", "reg.test/b", SAN)]);
    // containerd lists an image per name, CRI-O one image with a repository digest per name (D65).
    let (a, b) = (digest(1), digest(2));
    let containerd = list(&[(&a, &[("reg.test/a", root)]), (&b, &[("reg.test/b", root)])]);
    let crio = list(&[(&a, &[("reg.test/a", root), ("reg.test/b", root)])]);

    for list in [containerd, crio] {
        let run = Run::start(&fixture.store, policies.clone(), true, Ok(pinned()));
        run.listed(&list, root, Ok(()));

        for names in [["a"], ["b"]] {
            let key = Key {
                image: root,
                policies: hash(&policies, &names),
                root: Some(pinned().hash()),
            };
            assert_eq!(run.verdict(key).await, Verdict::Allow, "{names:?}");
        }
        let both = Key {
            image: root,
            policies: hash(&policies, &["a", "b"]),
            root: Some(pinned().hash()),
        };
        assert_eq!(run.verdicts.get(both), Verdict::Pending);
    }
}

#[tokio::test]
async fn a_rejection_asks_upstream_once_and_stays_when_upstream_adds_nothing() {
    let fixture = Fixture::load("keyless").await;
    let root = &fixture.root;
    let policies = policies(&[("a", "reg.test/a", "https://example.test/another")]);
    let list = list(&[(&digest(1), &[("reg.test/a", root)])]);
    let run = Run::start(&fixture.store, policies.clone(), true, Ok(pinned()));
    let key = Key {
        image: root,
        policies: hash(&policies, &["a"]),
        root: Some(pinned().hash()),
    };

    run.listed(&list, root, Ok(()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        run.verdicts.get(key),
        Verdict::Pending,
        "while upstream is asked"
    );
    run.discovery.upstream.add_permits(1);
    let rejected = run.verdict(key).await;
    run.found
        .send(Found::Ended {
            root: root.clone(),
            discovered: Ok(()),
        })
        .expect("the engine runs");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let Verdict::Rejected { reason } = rejected else {
        panic!("{rejected:?} is no rejection");
    };
    assert_eq!(
        &*reason,
        "identity mismatch: signed by https://github.com/spnngl/speculaire/.github/workflows/fixtures.yml@refs/heads/main (issuer https://token.actions.githubusercontent.com)"
    );
    assert_eq!(run.verdicts.get(key), Verdict::Rejected { reason });
    assert_eq!(
        run.discovery
            .again
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn an_unverifiable_key_is_tried_again_after_10_s_doubling_up_to_5_min() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = Arc::new(Store::open(dir.path()).expect("the store opens"));
    let policies = policies(&[("a", "reg.test/a", SAN)]);
    let root = digest(10);
    let list = list(&[(&digest(1), &[("reg.test/a", &root)])]);
    let run = Run::start(&store, policies.clone(), false, Ok(pinned()));
    let start = Instant::now();

    run.listed(&list, &root, Err(unreachable()));
    // The image list's own discovery failing again does not pace the engine's tries.
    tokio::time::sleep(Duration::from_secs(5)).await;
    run.found
        .send(Found::Ended {
            root: root.clone(),
            discovered: Err(unreachable()),
        })
        .expect("the engine runs");
    tokio::time::sleep(Duration::from_secs(995)).await;

    let tried: Vec<u64> = run
        .discovery
        .discovered
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|at| at.duration_since(start).as_secs())
        .collect();
    assert_eq!(tried, [10, 30, 70, 150, 310, 610, 910]);
    let key = Key {
        image: &root,
        policies: hash(&policies, &["a"]),
        root: Some(pinned().hash()),
    };
    let Verdict::Unverifiable { reason, retry_at } = run.verdicts.get(key) else {
        panic!("not unverifiable");
    };
    assert_eq!(&*reason, "artifacts unreachable");
    assert_eq!(retry_at, start + Duration::from_secs(910) + RETRY_MAX);
    assert_eq!(RETRY_FIRST, Duration::from_secs(10));
}

#[tokio::test]
async fn without_a_trust_root_a_key_is_unverifiable_under_no_root_hash() {
    let fixture = Fixture::load("keyless").await;
    let root = &fixture.root;
    let policies = policies(&[("a", "reg.test/a", SAN)]);
    let list = list(&[(&digest(1), &[("reg.test/a", root)])]);
    let run = Run::start(
        &fixture.store,
        policies.clone(),
        true,
        Err(Absent::new("TUF unreachable")),
    );

    run.listed(&list, root, Ok(()));

    let key = Key {
        image: root,
        policies: hash(&policies, &["a"]),
        root: None,
    };
    let verdict = run.verdict(key).await;
    assert_eq!(
        verdict.to_string(),
        "unverifiable: trust root: TUF unreachable"
    );
}

#[test]
fn a_rejection_is_final_for_its_key_and_a_verdict_under_another_root_replaces_its_own() {
    let verdicts = Verdicts::default();
    let image = digest(1);
    let policies = policies(&[("a", "reg.test/a", SAN)]);
    let key = Key {
        image: &image,
        policies: hash(&policies, &["a"]),
        root: Some(pinned().hash()),
    };
    let rejected = Verdict::Rejected {
        reason: "no signature".into(),
    };

    assert_eq!(verdicts.keep(key, rejected.clone()), Some(Verdict::Pending));
    assert_eq!(verdicts.keep(key, Verdict::Allow), None);
    assert_eq!(verdicts.get(key), rejected);
    let other = Key { root: None, ..key };
    assert_eq!(verdicts.keep(other, Verdict::Allow), Some(rejected));
    assert_eq!(verdicts.get(key), Verdict::Pending);
    assert_eq!(verdicts.get(other), Verdict::Allow);
}

#[tokio::test]
async fn a_key_follows_the_names_listed_and_its_verdict_leaves_with_its_root() {
    let fixture = Fixture::load("keyless").await;
    let root = &fixture.root;
    let policies = policies(&[("a", "reg.test/a", SAN), ("b", "reg.test/b", SAN)]);
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    // The engine runs on this thread: the test's runtime has one.
    let _recorder = metrics::set_default_local_recorder(&recorder);
    let run = Run::start(&fixture.store, policies.clone(), true, Ok(pinned()));
    let key = |names: &[&str]| Key {
        image: root,
        policies: hash(&policies, names),
        root: Some(pinned().hash()),
    };
    let settle = || tokio::time::sleep(Duration::from_millis(200));
    let reads = || run.discovery.reads.load(Ordering::Relaxed);

    run.listed(
        &list(&[(&digest(1), &[("reg.test/a", root)])]),
        root,
        Ok(()),
    );
    assert_eq!(run.verdict(key(&["a"])).await, Verdict::Allow);
    let rendered = handle.render();
    for wanted in [
        r#"speculaire_verifications_total{result="allow",trigger="event"} 1"#,
        r#"speculaire_verdicts{state="allow"} 1"#,
        r#"speculaire_verdicts{state="pending"} 0"#,
    ] {
        assert!(rendered.contains(wanted), "{wanted} in {rendered}");
    }

    // Another root listed leaves this one's verdict as it is, and verifies nothing again.
    let before = reads();
    let other = list(&[
        (&digest(1), &[("reg.test/a", root)]),
        (&digest(2), &[("reg.test/c", &digest(20))]),
    ]);
    run.found
        .send(Found::Listed(roots(&other)))
        .expect("the engine runs");
    settle().await;
    assert_eq!(run.verdicts.get(key(&["a"])), Verdict::Allow);
    assert_eq!(reads(), before);

    // Listed under another name, the root has the key of the policies that name matches, and only that one.
    let renamed = list(&[(&digest(1), &[("reg.test/b", root)])]);
    run.found
        .send(Found::Listed(roots(&renamed)))
        .expect("the engine runs");
    assert_eq!(run.verdict(key(&["b"])).await, Verdict::Allow);
    assert_eq!(run.verdicts.get(key(&["a"])), Verdict::Pending);

    run.found
        .send(Found::Listed(roots(&List::default())))
        .expect("the engine runs");
    settle().await;
    assert_eq!(run.verdicts.get(key(&["b"])), Verdict::Pending);
}

#[tokio::test(start_paused = true)]
async fn a_rate_limit_sets_the_next_try_no_sooner_than_the_backoff_gives() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let store = Arc::new(Store::open(dir.path()).expect("the store opens"));
    let policies = policies(&[("a", "reg.test/a", SAN)]);
    let (soon, late) = (digest(10), digest(11));
    let list = list(&[
        (&digest(1), &[("reg.test/a", &soon)]),
        (&digest(2), &[("reg.test/a", &late)]),
    ]);
    let run = Run::start(&store, policies.clone(), false, Ok(pinned()));
    let start = Instant::now();
    let limited = |after| Error::Unverifiable {
        reason: Reason::RateLimited {
            host: "reg.test".to_owned(),
        },
        retry_at: start + Duration::from_secs(after),
    };

    run.listed(&list, &soon, Err(limited(1)));
    run.found
        .send(Found::Ended {
            root: late.clone(),
            discovered: Err(limited(60)),
        })
        .expect("the engine runs");
    tokio::time::sleep(Duration::from_millis(100)).await;

    for (root, after) in [(&soon, 10), (&late, 60)] {
        let key = Key {
            image: root,
            policies: hash(&policies, &["a"]),
            root: Some(pinned().hash()),
        };
        assert_eq!(
            run.verdicts.get(key),
            Verdict::Unverifiable {
                reason: "upstream rate limited: reg.test".into(),
                retry_at: start + Duration::from_secs(after),
            }
        );
    }
}
