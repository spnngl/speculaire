use std::sync::Arc;
use std::time::{Duration, Instant};

use containerd_client::events::ContentCreate;
use containerd_client::services::v1::{ImageCreate, ImageDelete, ImageUpdate};
use containerd_client::types::Envelope;
use speculaire_fake_runtime::{Answers, Fake};
use speculaire_oci::reference::Digest;

use super::{Event, SETTLE, Store, event};
use crate::containerd::Containerd;
use crate::paths::Paths;

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

fn envelope(namespace: &str, topic: &str, event: &impl prost::Name) -> Envelope {
    Envelope {
        timestamp: None,
        namespace: namespace.to_owned(),
        topic: topic.to_owned(),
        event: Some(containerd_client::to_any(event)),
    }
}

fn created(name: &str) -> Envelope {
    let event = ImageCreate {
        name: name.to_owned(),
        ..ImageCreate::default()
    };
    envelope("k8s.io", "/images/create", &event)
}

fn updated(name: &str) -> Envelope {
    let event = ImageUpdate {
        name: name.to_owned(),
        ..ImageUpdate::default()
    };
    envelope("k8s.io", "/images/update", &event)
}

fn deleted(name: &str) -> Envelope {
    let event = ImageDelete {
        name: name.to_owned(),
    };
    envelope("k8s.io", "/images/delete", &event)
}

#[test]
fn image_events_of_the_cri_namespace_name_their_image() {
    assert_eq!(event(&created("a")), Some(Event::Changed("a".to_owned())));
    assert_eq!(event(&updated("b")), Some(Event::Changed("b".to_owned())));
    assert_eq!(event(&deleted("c")), Some(Event::Deleted("c".to_owned())));
    let mut elsewhere = created("a");
    elsewhere.namespace = "default".to_owned();
    assert_eq!(event(&elsewhere), None);
    let content = envelope("k8s.io", "/content/create", &ContentCreate::default());
    assert_eq!(event(&content), None);
}

/// A fake containerd holding `images`, and a store kept from it.
struct Kept {
    fake: Fake,
    store: Arc<Store>,
    keeper: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Kept {
    fn drop(&mut self) {
        self.keeper.abort();
    }
}

fn keep(images: &[(&str, char)]) -> Kept {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let mut answers = Answers::containerd("2.3.7");
    answers.image_store = images
        .iter()
        .map(|&(name, c)| (name.to_owned(), digest(c)))
        .collect();
    let fake = Fake::start(&socket, answers).unwrap();
    let containerd = Containerd::new(Paths::under(dir.path()), &socket, None);
    let store = Arc::new(Store::default());
    let kept = Arc::clone(&store);
    let keeper = tokio::spawn(async move { containerd.keep(&kept).await });
    Kept {
        fake,
        store,
        keeper,
        _dir: dir,
    }
}

impl Kept {
    /// Waits up to `within` for `name` to target `target`, and says how long it took.
    async fn shows(&self, name: &str, target: Option<char>, within: Duration) -> Duration {
        let target = target.map(|c| Digest::parse(&digest(c)).unwrap());
        let start = Instant::now();
        while self.store.get(name) != target {
            assert!(
                start.elapsed() < within,
                "{name} targets {:?}, not {target:?}, after {within:?}",
                self.store.get(name)
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        start.elapsed()
    }

    /// Waits for a live subscription, then for the listing that follows it to settle.
    async fn subscribed(&self) {
        let start = Instant::now();
        while self.fake.subscribers() == 0 {
            assert!(start.elapsed() < Duration::from_secs(5), "no subscription");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        tokio::time::sleep(SETTLE + Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn the_store_holds_every_image_listed() {
    let kept = keep(&[
        ("docker.io/library/busybox:1.37", 'a'),
        ("registry.k8s.io/pause:3.10", 'b'),
    ]);
    kept.shows(
        "docker.io/library/busybox:1.37",
        Some('a'),
        Duration::from_secs(5),
    )
    .await;
    let mut names = kept.store.names();
    names.sort();
    assert_eq!(
        names,
        [
            "docker.io/library/busybox:1.37",
            "registry.k8s.io/pause:3.10"
        ]
    );
    assert_eq!(
        kept.store.get("registry.k8s.io/pause:3.10"),
        Some(Digest::parse(&digest('b')).unwrap())
    );
    assert_eq!(kept.store.get("busybox:1.37"), None);
}

#[tokio::test]
async fn an_image_created_while_listing_shows_once_listed_again() {
    let kept = keep(&[("docker.io/library/busybox:1.37", 'a')]);
    kept.shows(
        "docker.io/library/busybox:1.37",
        Some('a'),
        Duration::from_secs(5),
    )
    .await;
    kept.fake.update(|answers| {
        answers
            .image_store
            .push(("docker.io/library/nginx:1".to_owned(), digest('c')));
    });
    kept.shows("docker.io/library/nginx:1", Some('c'), SETTLE * 3)
        .await;
}

#[tokio::test]
async fn create_retag_and_delete_each_show_within_a_second() {
    let name = "docker.io/library/busybox:1.37";
    let kept = keep(&[]);
    kept.subscribed().await;

    kept.fake.update(|answers| {
        answers.image_store.push((name.to_owned(), digest('a')));
    });
    kept.fake.publish(created(name));
    let create = kept.shows(name, Some('a'), Duration::from_secs(1)).await;

    kept.fake
        .update(|answers| answers.image_store[0].1 = digest('b'));
    kept.fake.publish(updated(name));
    let retag = kept.shows(name, Some('b'), Duration::from_secs(1)).await;

    kept.fake.update(|answers| answers.image_store.clear());
    kept.fake.publish(deleted(name));
    let delete = kept.shows(name, None, Duration::from_secs(1)).await;
    eprintln!("create {create:?}, retag {retag:?}, delete {delete:?}");
}

#[tokio::test]
async fn an_update_of_an_image_gone_since_removes_it_without_a_relist() {
    let name = "docker.io/library/busybox:1.37";
    let kept = keep(&[(name, 'a')]);
    kept.subscribed().await;
    kept.fake.update(|answers| answers.image_store.clear());
    kept.fake.publish(updated(name));
    // A relist would come only after a lost subscription, `RETRY` later.
    kept.shows(name, None, Duration::from_millis(500)).await;
}

#[tokio::test]
async fn an_image_whose_get_fails_is_kept_until_listed_again() {
    let name = "docker.io/library/busybox:1.37";
    let kept = keep(&[(name, 'a')]);
    kept.subscribed().await;
    kept.fake
        .update(|answers| answers.image_get_unavailable = true);
    kept.fake.publish(updated(name));
    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        assert_eq!(
            kept.store.get(name),
            Some(Digest::parse(&digest('a')).unwrap())
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn an_image_created_while_the_events_were_cut_is_found_after() {
    let kept = keep(&[("docker.io/library/busybox:1.37", 'a')]);
    kept.subscribed().await;
    kept.fake.cut();
    kept.fake.update(|answers| {
        answers
            .image_store
            .push(("docker.io/library/nginx:1".to_owned(), digest('c')));
    });
    kept.shows(
        "docker.io/library/nginx:1",
        Some('c'),
        Duration::from_secs(5),
    )
    .await;
}

#[tokio::test]
async fn a_late_or_restarted_containerd_is_waited_for_and_listed() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let containerd = Containerd::new(Paths::under(dir.path()), &socket, None);
    let store = Arc::new(Store::default());
    let kept = Arc::clone(&store);
    let keeper = tokio::spawn(async move { containerd.keep(&kept).await });
    let shows = async |name: &str, c: char| {
        let target = Some(Digest::parse(&digest(c)).unwrap());
        let start = Instant::now();
        while store.get(name) != target {
            assert!(start.elapsed() < Duration::from_secs(5), "{name} not shown");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let start = |name: &str, c: char| {
        let mut answers = Answers::containerd("2.3.7");
        answers.image_store = vec![(name.to_owned(), digest(c))];
        Fake::start(&socket, answers).unwrap()
    };

    // No containerd yet: it is waited for.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let fake = start("docker.io/library/busybox:1.37", 'a');
    shows("docker.io/library/busybox:1.37", 'a').await;
    // A non-image event is passed over.
    fake.publish(envelope(
        "default",
        "/images/create",
        &ImageCreate::default(),
    ));

    // containerd restarts with another image.
    drop(fake);
    std::fs::remove_file(&socket).unwrap();
    let _fake = start("docker.io/library/nginx:1", 'b');
    shows("docker.io/library/nginx:1", 'b').await;
    assert_eq!(store.names(), ["docker.io/library/nginx:1"]);
    keeper.abort();
}

#[test]
fn a_store_holds_the_images_it_is_built_from() {
    let store: Store = [("a".to_owned(), Digest::parse(&digest('a')).unwrap())]
        .into_iter()
        .collect();
    assert_eq!(store.get("a"), Some(Digest::parse(&digest('a')).unwrap()));
    assert_eq!(store.get("b"), None);
}
