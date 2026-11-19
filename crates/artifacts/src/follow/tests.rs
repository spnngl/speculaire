//! The image list as the trigger of discovery, with registry config that names no source of anything.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures_util::future::BoxFuture;
use speculaire_oci::platform::Host;
use speculaire_runtime::images::{Image, RepoDigest, Update};
use speculaire_runtime::registries::{
    Error as ConfigError, Reference, Registries, Reloaded, Source,
};
use tokio::sync::oneshot;

use super::*;
use crate::discover::{Limits, Local};
use crate::store::{Artifact, Kind, Store};

fn digest(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
}

fn image(id: u8, repo_digests: &[(&str, u8)]) -> Image {
    Image {
        id: digest(id),
        repo_digests: repo_digests
            .iter()
            .map(|(repository, n)| RepoDigest {
                repository: (*repository).to_owned(),
                digest: digest(*n),
            })
            .collect(),
        tags: Vec::new(),
    }
}

/// An image list whose updates the test sends.
struct Scripted(Mutex<Option<mpsc::Receiver<Update>>>);

impl Images for Scripted {
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
        let mut script = self.0.lock().unwrap().take().unwrap();
        Box::pin(async move {
            while let Some(update) = script.recv().await {
                if updates.send(update).await.is_err() {
                    return;
                }
            }
        })
    }
}

/// Registry config that has no source of any name, and logs each name asked; as the node's content, it holds nothing
/// and counts the manifests asked, one per discovery. The manifest of the root in `2`, if any, comes only once its
/// receiver does: its discovery runs until then.
#[derive(Default)]
struct Asked(
    Mutex<Vec<String>>,
    AtomicUsize,
    Mutex<Option<(Digest, oneshot::Receiver<()>)>>,
);

impl Local for Asked {
    fn manifest<'a>(
        &'a self,
        root: &'a Digest,
        _: u64,
    ) -> Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>> {
        self.1.fetch_add(1, Ordering::Relaxed);
        let mut stalled = self.2.lock().unwrap();
        if stalled.as_ref().is_some_and(|(stalled, _)| stalled == root)
            && let Some((_, released)) = stalled.take()
        {
            return Box::pin(async move {
                let _ = released.await;
                None
            });
        }
        Box::pin(std::future::ready(None))
    }
}

impl Registries for Asked {
    fn sources(&self, name: &str, _: Reference<'_>) -> Result<Vec<Source>, ConfigError> {
        self.0.lock().unwrap().push(name.to_owned());
        Ok(Vec::new())
    }

    fn configured(&self, _: &str) -> bool {
        false
    }

    fn poll(&self) -> Option<Result<Reloaded, ConfigError>> {
        None
    }

    fn reload(&self) -> Result<Reloaded, ConfigError> {
        Ok(Reloaded::default())
    }
}

#[test]
fn each_root_has_the_names_the_list_gives_it_once_each() {
    let mut list = List::default();
    list.apply(Update::Listing(vec![image(
        1,
        &[
            ("reg.test/a", 10),
            ("reg.test/b", 10),
            ("reg.test/a", 10),
            ("reg.test/a", 11),
        ],
    )]));
    let roots = roots(&list);
    assert_eq!(roots[&digest(10)], ["reg.test/a", "reg.test/b"]);
    assert_eq!(roots[&digest(11)], ["reg.test/a"]);
    assert_eq!(roots.len(), 2);
}

/// Follows the list the returned sender scripts, with `store`, from `linked` on, the latest reflector stream up at
/// `last_up`, logging in `asked` each name a root is asked under.
fn start(
    store: Arc<Store>,
    asked: &Arc<Asked>,
    linked: impl Future<Output = ()> + Send + 'static,
    last_up: Option<Instant>,
) -> (mpsc::Sender<Update>, tokio::task::JoinHandle<()>) {
    let (script, followed, _) = start_found(store, asked, linked, last_up);
    (script, followed)
}

/// As [`start`], with what verification is told.
fn start_found(
    store: Arc<Store>,
    asked: &Arc<Asked>,
    linked: impl Future<Output = ()> + Send + 'static,
    last_up: Option<Instant>,
) -> (
    mpsc::Sender<Update>,
    tokio::task::JoinHandle<()>,
    mpsc::UnboundedReceiver<Found>,
) {
    let unlinked = speculaire_mirror::fetch::Fetcher::new(
        std::path::PathBuf::new(),
        speculaire_mirror::fetch::Settings {
            stall_timeout: std::time::Duration::from_secs(1),
            deny_ttl: std::time::Duration::from_secs(1),
            resolve_tags: false,
        },
    );
    let discovery = Arc::new(Discovery::new(
        store,
        Arc::clone(asked) as Arc<dyn Local>,
        unlinked,
        Arc::clone(asked) as Arc<dyn Registries>,
        "127.0.0.1:7480".to_owned(),
        Host::current(),
        Limits::new(1024),
    ));
    let (script, receiver) = mpsc::channel(4);
    let (found, told) = mpsc::unbounded_channel();
    let followed = tokio::spawn(follow(
        discovery,
        Arc::new(Scripted(Mutex::new(Some(receiver)))),
        linked,
        watch::channel(last_up).1,
        found,
    ));
    (script, followed, told)
}

#[tokio::test(start_paused = true)]
async fn verification_is_told_the_roots_listed_then_each_discovery_and_each_root_recorded() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    store.record(&digest(10), &[]).await.unwrap();
    let asked = Arc::new(Asked::default());
    let (script, followed, mut told) = start_found(store, &asked, std::future::ready(()), None);
    let listing = Update::Listing(vec![
        image(1, &[("reg.test/old", 10)]),
        image(2, &[("reg.test/new", 20)]),
    ]);

    let settle = || tokio::time::sleep(Duration::from_millis(10));

    script.send(listing.clone()).await.unwrap();
    settle().await;
    script.send(listing).await.unwrap();
    settle().await;
    script
        .send(Update::Listed(image(2, &[("reg.test/other", 20)])))
        .await
        .unwrap();
    settle().await;
    drop(script);
    followed.await.unwrap();

    let mut found = Vec::new();
    while let Ok(event) = told.try_recv() {
        found.push(match event {
            Found::Listed(roots) => {
                let mut roots: Vec<_> = roots.into_iter().collect();
                roots.sort_by_key(|(root, _)| root.to_string());
                format!("{roots:?}")
            }
            Found::Ended { root, discovered } => {
                format!("{root} {:?}", discovered.map_err(|e| e.to_string()))
            }
        });
    }
    let listed = |names: [(u8, &str); 2]| {
        format!(
            "{:?}",
            names.map(|(n, name)| (digest(n), vec![name.to_owned()]))
        )
    };
    assert_eq!(
        found,
        [
            listed([(10, "reg.test/old"), (20, "reg.test/new")]),
            format!("{} Ok(())", digest(10)),
            format!(
                "{} Err(\"unverifiable: artifacts unreachable\")",
                digest(20)
            ),
            listed([(10, "reg.test/old"), (20, "reg.test/other")]),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn the_roots_of_an_image_just_listed_go_beside_a_listing_s_discovery_which_does_not_run_twice()
 {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let asked = Arc::new(Asked::default());
    let (release, released) = oneshot::channel();
    *asked.2.lock().unwrap() = Some((digest(10), released));
    let (script, followed) = start(store, &asked, std::future::ready(()), None);
    let settle = || tokio::time::sleep(Duration::from_millis(10));
    let discoveries = || asked.1.load(Ordering::Relaxed);

    script
        .send(Update::Listing(vec![
            image(1, &[("reg.test/a", 10)]),
            image(2, &[("reg.test/b", 20)]),
        ]))
        .await
        .unwrap();
    settle().await;
    assert_eq!(discoveries(), 1, "10 is being discovered");
    script
        .send(Update::Listed(image(3, &[("reg.test/pulled", 30)])))
        .await
        .unwrap();
    settle().await;
    assert_eq!(*asked.0.lock().unwrap(), ["reg.test/pulled"]);

    // An image just listed whose root is being discovered waits for that discovery.
    script
        .send(Update::Listed(image(4, &[("reg.test/a", 10)])))
        .await
        .unwrap();
    settle().await;
    assert_eq!(discoveries(), 2);

    release.send(()).unwrap();
    settle().await;
    assert_eq!(
        *asked.0.lock().unwrap(),
        ["reg.test/pulled", "reg.test/a", "reg.test/b"]
    );

    drop(script);
    followed.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_recorded_root_is_skipped_and_a_failed_one_is_tried_again_at_its_retry_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    store.record(&digest(10), &[]).await.unwrap();
    let asked = Arc::new(Asked::default());
    let (script, followed) = start(store, &asked, std::future::ready(()), None);
    let listing = || {
        Update::Listing(vec![
            image(1, &[("reg.test/old", 10)]),
            image(2, &[("reg.test/new", 20)]),
        ])
    };
    let settle = || tokio::time::sleep(Duration::from_millis(10));

    script.send(listing()).await.unwrap();
    settle().await;
    assert_eq!(*asked.0.lock().unwrap(), ["reg.test/new"]);

    script.send(listing()).await.unwrap();
    settle().await;
    assert_eq!(asked.0.lock().unwrap().len(), 1);

    // No listing is needed: the retry time wakes the root.
    tokio::time::advance(RETRY).await;
    settle().await;
    assert_eq!(*asked.0.lock().unwrap(), ["reg.test/new", "reg.test/new"]);

    script.send(listing()).await.unwrap();
    settle().await;
    assert_eq!(asked.0.lock().unwrap().len(), 2);

    drop(script);
    followed.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_root_found_nowhere_just_after_a_stream_came_up_is_tried_again_soon_three_times() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let asked = Arc::new(Asked::default());
    let (script, followed) = start(store, &asked, std::future::ready(()), Some(Instant::now()));
    let settle = || tokio::time::sleep(Duration::from_millis(10));
    let asks = |name: &str| {
        asked
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|n| *n == name)
            .count()
    };

    // A discovery that starts FRESH after the stream came up is tried again soon; one that starts later waits RETRY.
    tokio::time::advance(FRESH).await;
    script
        .send(Update::Listed(image(1, &[("reg.test/fresh", 10)])))
        .await
        .unwrap();
    settle().await;
    script
        .send(Update::Listed(image(2, &[("reg.test/late", 20)])))
        .await
        .unwrap();
    settle().await;
    assert_eq!((asks("reg.test/fresh"), asks("reg.test/late")), (1, 1));

    for tries in 1..=TRIES {
        tokio::time::advance(SOON).await;
        settle().await;
        assert_eq!(asks("reg.test/fresh"), 1 + usize::from(tries));
    }
    tokio::time::advance(SOON).await;
    settle().await;
    assert_eq!(asks("reg.test/fresh"), 1 + usize::from(TRIES));
    assert_eq!(asks("reg.test/late"), 1);

    // Then the root waits RETRY, as the other did.
    tokio::time::advance(RETRY).await;
    settle().await;
    assert_eq!(asks("reg.test/fresh"), 2 + usize::from(TRIES));
    assert_eq!(asks("reg.test/late"), 2);

    drop(script);
    followed.await.unwrap();
}

#[test]
fn a_refusal_keeps_its_retry_time_even_just_after_a_stream_came_up() {
    let now = Instant::now();
    let mut soon = Soon {
        last_up: watch::channel(Some(now)).1,
        left: HashMap::from([(digest(10), TRIES)]),
    };
    let refused = Error::Unverifiable {
        reason: Reason::RateLimited {
            host: "reg.test".to_owned(),
        },
        retry_at: now + RETRY,
    };
    assert_eq!(soon.next(&digest(10), now, &refused), None);
    assert!(soon.left.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_root_the_store_fails_is_tried_again_after_the_retry_time() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    // A directory where the root's blob would be: reading it fails.
    let root = digest(20);
    std::fs::create_dir_all(dir.path().join("blobs/sha256").join(root.encoded())).unwrap();
    let asked = Arc::new(Asked::default());
    let (script, followed) = start(store, &asked, std::future::ready(()), None);
    let listing = || Update::Listing(vec![image(2, &[("reg.test/new", 20)])]);
    let settle = || tokio::time::sleep(Duration::from_millis(10));
    let discoveries = || asked.1.load(Ordering::Relaxed);

    script.send(listing()).await.unwrap();
    settle().await;
    assert_eq!(discoveries(), 1);
    script.send(listing()).await.unwrap();
    settle().await;
    assert_eq!(discoveries(), 1);

    tokio::time::advance(RETRY).await;
    settle().await;
    assert_eq!(discoveries(), 2);
    // The store failed before any source was asked.
    assert!(asked.0.lock().unwrap().is_empty());

    drop(script);
    followed.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_root_that_leaves_the_list_is_collected_and_discovered_again_when_it_comes_back() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let bundle = speculaire_oci::hash::of("sha256", b"bundle").unwrap();
    store.keep(&bundle, b"bundle").await.unwrap();
    let artifact = Artifact {
        target: digest(10),
        manifest: bundle.clone(),
        kind: Kind::Bundle,
        blobs: Vec::new(),
    };
    store.record(&digest(10), &[artifact]).await.unwrap();
    store.record(&digest(20), &[]).await.unwrap();
    let asked = Arc::new(Asked::default());
    let (script, followed) = start(Arc::clone(&store), &asked, std::future::ready(()), None);
    let settle = || tokio::time::sleep(Duration::from_millis(10));

    script
        .send(Update::Listing(vec![
            image(1, &[("reg.test/a", 10)]),
            image(2, &[("reg.test/b", 20)]),
        ]))
        .await
        .unwrap();
    settle().await;
    assert!(store.contains(&bundle));
    assert!(asked.0.lock().unwrap().is_empty());

    // No listing: the image's removal alone collects its root.
    script.send(Update::Removed(digest(1))).await.unwrap();
    settle().await;
    assert!(!store.contains(&bundle));
    assert_eq!(store.recorded(&digest(10)).await.unwrap(), None);
    assert!(store.recorded(&digest(20)).await.unwrap().is_some());

    script
        .send(Update::Listed(image(1, &[("reg.test/a", 10)])))
        .await
        .unwrap();
    settle().await;
    assert_eq!(*asked.0.lock().unwrap(), ["reg.test/a"]);

    // A root listed since the last collection is collected too once it leaves.
    store.record(&digest(10), &[]).await.unwrap();
    script.send(Update::Removed(digest(1))).await.unwrap();
    settle().await;
    assert_eq!(store.recorded(&digest(10)).await.unwrap(), None);

    // The last root to leave is collected too.
    script.send(Update::Removed(digest(2))).await.unwrap();
    settle().await;
    assert_eq!(store.recorded(&digest(20)).await.unwrap(), None);

    drop(script);
    followed.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_root_that_leaves_the_list_while_another_is_discovered_is_collected_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let bundle = speculaire_oci::hash::of("sha256", b"bundle").unwrap();
    store.keep(&bundle, b"bundle").await.unwrap();
    let artifact = Artifact {
        target: digest(10),
        manifest: bundle.clone(),
        kind: Kind::Bundle,
        blobs: Vec::new(),
    };
    store.record(&digest(10), &[artifact]).await.unwrap();
    let asked = Arc::new(Asked::default());
    let (release, released) = oneshot::channel();
    *asked.2.lock().unwrap() = Some((digest(20), released));
    let (script, followed) = start(Arc::clone(&store), &asked, std::future::ready(()), None);
    let settle = || tokio::time::sleep(Duration::from_millis(10));

    script
        .send(Update::Listing(vec![
            image(1, &[("reg.test/a", 10)]),
            image(2, &[("reg.test/b", 20)]),
        ]))
        .await
        .unwrap();
    settle().await;
    assert_eq!(asked.1.load(Ordering::Relaxed), 1, "20 is being discovered");
    script.send(Update::Removed(digest(1))).await.unwrap();
    settle().await;
    assert!(!store.contains(&bundle));
    assert_eq!(store.recorded(&digest(10)).await.unwrap(), None);

    // The root being discovered leaves too: its record, written as its discovery ends, goes once it has ended.
    store.record(&digest(20), &[]).await.unwrap();
    script.send(Update::Removed(digest(2))).await.unwrap();
    settle().await;
    assert!(store.recorded(&digest(20)).await.unwrap().is_some());
    release.send(()).unwrap();
    settle().await;
    assert_eq!(store.recorded(&digest(20)).await.unwrap(), None);

    drop(script);
    followed.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_pulled_root_that_leaves_the_list_is_collected_while_the_backlog_lane_discovers() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let asked = Arc::new(Asked::default());
    let (_release, released) = oneshot::channel();
    *asked.2.lock().unwrap() = Some((digest(20), released));
    let (script, followed) = start(Arc::clone(&store), &asked, std::future::ready(()), None);
    let settle = || tokio::time::sleep(Duration::from_millis(10));

    script
        .send(Update::Listing(vec![image(2, &[("reg.test/b", 20)])]))
        .await
        .unwrap();
    settle().await;
    script
        .send(Update::Listed(image(3, &[("reg.test/pulled", 30)])))
        .await
        .unwrap();
    settle().await;
    assert_eq!(
        *asked.0.lock().unwrap(),
        ["reg.test/pulled"],
        "30's discovery ended while 20's runs"
    );
    // What 30's discovery would have recorded, had a source served it.
    let bundle = speculaire_oci::hash::of("sha256", b"bundle").unwrap();
    store.keep(&bundle, b"bundle").await.unwrap();
    let artifact = Artifact {
        target: digest(30),
        manifest: bundle.clone(),
        kind: Kind::Bundle,
        blobs: Vec::new(),
    };
    store.record(&digest(30), &[artifact]).await.unwrap();

    // 20's discovery still runs: it holds nothing of 30's.
    script.send(Update::Removed(digest(3))).await.unwrap();
    settle().await;
    assert_eq!(store.recorded(&digest(30)).await.unwrap(), None);
    assert!(!store.contains(&bundle));

    drop(script);
    followed.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_store_is_collected_from_the_first_listing_and_discovery_waits_for_the_link() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let orphan = speculaire_oci::hash::of("sha256", b"orphan").unwrap();
    store.keep(&orphan, b"orphan").await.unwrap();
    let asked = Arc::new(Asked::default());
    let (link, linked) = tokio::sync::oneshot::channel::<()>();
    let (script, followed) = start(
        Arc::clone(&store),
        &asked,
        async move {
            let _ = linked.await;
        },
        None,
    );
    let settle = || tokio::time::sleep(Duration::from_millis(10));

    settle().await;
    assert!(
        store.contains(&orphan),
        "no collection before the first listing"
    );
    script
        .send(Update::Listing(vec![image(1, &[("reg.test/a", 10)])]))
        .await
        .unwrap();
    settle().await;
    assert!(!store.contains(&orphan));
    assert!(asked.0.lock().unwrap().is_empty());

    link.send(()).unwrap();
    settle().await;
    assert_eq!(*asked.0.lock().unwrap(), ["reg.test/a"]);

    drop(script);
    followed.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn each_listing_collects_the_store_even_when_no_root_left() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let asked = Arc::new(Asked::default());
    let (script, followed) = start(Arc::clone(&store), &asked, std::future::ready(()), None);
    let settle = || tokio::time::sleep(Duration::from_millis(10));
    script
        .send(Update::Listing(vec![image(1, &[("reg.test/a", 10)])]))
        .await
        .unwrap();
    settle().await;
    let orphan = speculaire_oci::hash::of("sha256", b"orphan").unwrap();
    store.keep(&orphan, b"orphan").await.unwrap();

    // Sent together, the listing comes in behind the image, with the updates already queued.
    script
        .send(Update::Listed(image(2, &[("reg.test/b", 20)])))
        .await
        .unwrap();
    script
        .send(Update::Listing(vec![
            image(1, &[("reg.test/a", 10)]),
            image(2, &[("reg.test/b", 20)]),
        ]))
        .await
        .unwrap();
    settle().await;
    assert!(!store.contains(&orphan));

    drop(script);
    followed.await.unwrap();
}
