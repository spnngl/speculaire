use std::time::Duration;

use speculaire_fake_runtime::{Answers, Fake};
use tokio::sync::mpsc;

use super::*;

const A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn digest(text: &str) -> Digest {
    Digest::parse(text).unwrap()
}

fn listed(id: &str, repo_digests: &[&str]) -> (String, Vec<String>, Vec<String>) {
    (
        id.to_owned(),
        Vec::new(),
        repo_digests.iter().map(|&text| text.to_owned()).collect(),
    )
}

fn image(id: &str, repo_digests: &[(&str, &str)]) -> Image {
    Image {
        id: digest(id),
        repo_digests: repo_digests
            .iter()
            .map(|&(repository, text)| RepoDigest {
                repository: repository.to_owned(),
                digest: digest(text),
            })
            .collect(),
        tags: Vec::new(),
    }
}

async fn next(updates: &mut mpsc::Receiver<Update>) -> Update {
    tokio::time::timeout(Duration::from_secs(5), updates.recv())
        .await
        .expect("an update comes")
        .expect("the follower goes on")
}

#[test]
fn an_image_reads_its_id_with_or_without_algorithm_its_repo_digests_and_tags() {
    let hex = A.trim_start_matches("sha256:");
    let crio = ListedImage {
        id: hex.to_owned(),
        repo_tags: vec![
            "docker.io/library/busybox:1".to_owned(),
            "busybox".to_owned(),
            format!("busybox@{B}"),
        ],
        repo_digests: vec![
            format!("docker.io/library/busybox@{B}"),
            "no-digest".to_owned(),
            "docker.io/library/busybox@sha256:short".to_owned(),
        ],
    };
    let want = Image {
        tags: vec![Tagged::parse("busybox:1").unwrap()],
        ..image(A, &[("docker.io/library/busybox", B)])
    };
    assert_eq!(Image::from_listed(&crio), Some(want.clone()));
    let containerd = ListedImage {
        id: A.to_owned(),
        ..crio
    };
    assert_eq!(Image::from_listed(&containerd), Some(want));
    let bad = ListedImage {
        id: "sha256:nope".to_owned(),
        ..ListedImage::default()
    };
    assert_eq!(Image::from_listed(&bad), None);
}

#[test]
fn a_repo_digest_splits_at_its_last_at_sign() {
    let read = RepoDigest::parse(&format!("host:5000/a@b/c@{A}")).unwrap();
    assert_eq!(read.repository, "host:5000/a@b/c");
    assert_eq!(read.digest, digest(A));
    assert_eq!(RepoDigest::parse(A), None);
}

#[test]
fn changes_name_the_removed_then_the_new_and_the_changed() {
    let mut known: HashMap<Digest, Image> = [image(A, &[("r", B)]), image(B, &[])]
        .into_iter()
        .map(|image| (image.id.clone(), image))
        .collect();
    let changed = image(B, &[("r", C)]);
    let added = image(C, &[]);
    let mut got = changes(&mut known, vec![changed.clone(), added.clone()]);
    assert_eq!(got.remove(0), Update::Removed(digest(A)));
    got.sort_by_key(|update| format!("{update:?}"));
    let mut want = vec![Update::Listed(changed), Update::Listed(added)];
    want.sort_by_key(|update| format!("{update:?}"));
    assert_eq!(got, want);
    assert_eq!(known.len(), 2);
    let same = known.values().cloned().collect();
    assert_eq!(changes(&mut known, same), Vec::new());
}

#[test]
fn a_list_follows_its_updates() {
    let mut list = List::default();
    list.apply(Update::Listing(vec![image(A, &[]), image(B, &[])]));
    list.apply(Update::Removed(digest(A)));
    list.apply(Update::Listed(image(B, &[("r", C)])));
    list.apply(Update::Listed(image(C, &[])));
    let mut ids: Vec<&Image> = list.images().collect();
    ids.sort_by_key(|image| image.id.to_string());
    assert_eq!(ids, [&image(B, &[("r", C)]), &image(C, &[])]);
    list.apply(Update::Listing(Vec::new()));
    assert_eq!(list.images().count(), 0);
}

/// A hint reads the list and sends what changed; when the hints stop, the whole list comes again, so a change made
/// while nobody watched is not missed.
#[tokio::test]
async fn hints_send_changes_and_a_lost_watch_sends_the_list_again() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("runtime.sock");
    let mut answers = Answers::crio("1.37.0");
    answers.images = vec![listed(A, &[])];
    let fake = Fake::start(&socket, answers).unwrap();
    let (hints, mut watching) = mpsc::channel::<mpsc::Sender<()>>(4);
    let (ends, ended) = mpsc::channel::<()>(4);
    let ended = std::sync::Arc::new(tokio::sync::Mutex::new(ended));
    let (sender, mut updates) = mpsc::channel(16);
    let follower = tokio::spawn({
        let socket = socket.clone();
        async move {
            follow(
                &socket,
                &sender,
                Duration::from_secs(3600),
                "fake",
                |hint| {
                    let hints = hints.clone();
                    let ended = std::sync::Arc::clone(&ended);
                    async move {
                        hints.send(hint).await.unwrap();
                        ended.lock().await.recv().await;
                        Lost::Ended
                    }
                },
            )
            .await;
        }
    });
    assert_eq!(
        next(&mut updates).await,
        Update::Listing(vec![image(A, &[])])
    );
    let hint = watching.recv().await.unwrap();

    fake.update(|answers| answers.images = vec![listed(B, &[])]);
    hint.send(()).await.unwrap();
    let mut got = vec![next(&mut updates).await, next(&mut updates).await];
    got.sort_by_key(|update| format!("{update:?}"));
    assert_eq!(
        got,
        vec![Update::Listed(image(B, &[])), Update::Removed(digest(A))]
    );

    // A change no hint tells of, then the watch ends: the list comes again whole.
    fake.update(|answers| answers.images = vec![listed(C, &[])]);
    ends.send(()).await.unwrap();
    assert_eq!(
        next(&mut updates).await,
        Update::Listing(vec![image(C, &[])])
    );
    let _again = watching.recv().await.unwrap();

    drop(updates);
    tokio::time::timeout(Duration::from_secs(5), follower)
        .await
        .expect("the follower ends with its reader")
        .unwrap();
}

/// The whole list comes every interval, whatever the hints say.
#[tokio::test]
async fn the_list_comes_whole_every_interval() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("runtime.sock");
    let fake = Fake::start(&socket, Answers::crio("1.37.0")).unwrap();
    let (sender, mut updates) = mpsc::channel(16);
    let follower = tokio::spawn(async move {
        follow(
            &socket,
            &sender,
            Duration::from_millis(50),
            "fake",
            |_hint| std::future::pending(),
        )
        .await;
    });
    assert_eq!(next(&mut updates).await, Update::Listing(Vec::new()));
    fake.update(|answers| answers.images = vec![listed(A, &[])]);
    loop {
        if next(&mut updates).await == Update::Listing(vec![image(A, &[])]) {
            break;
        }
    }
    follower.abort();
}

/// An image made before the watch holds its subscription comes [`super::SETTLE`] after the start, without a hint.
#[tokio::test]
async fn a_change_before_the_first_hint_comes_once_the_watch_settled() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("runtime.sock");
    let fake = Fake::start(&socket, Answers::crio("1.37.0")).unwrap();
    let (sender, mut updates) = mpsc::channel(16);
    let follower = tokio::spawn(async move {
        follow(
            &socket,
            &sender,
            Duration::from_secs(3600),
            "fake",
            |_hint| std::future::pending(),
        )
        .await;
    });
    assert_eq!(next(&mut updates).await, Update::Listing(Vec::new()));
    fake.update(|answers| answers.images = vec![listed(A, &[])]);
    assert_eq!(next(&mut updates).await, Update::Listed(image(A, &[])));
    follower.abort();
}

/// A runtime that cannot be asked sends nothing, and the follower tries again until it answers.
#[tokio::test]
async fn an_unreachable_runtime_is_asked_again() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("runtime.sock");
    let (sender, mut updates) = mpsc::channel(16);
    let follower = tokio::spawn({
        let socket = socket.clone();
        async move {
            follow(
                &socket,
                &sender,
                Duration::from_secs(3600),
                "fake",
                |_hint| std::future::pending(),
            )
            .await;
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(updates.try_recv().is_err());
    let mut answers = Answers::crio("1.37.0");
    answers.images = vec![listed(A, &[])];
    let _fake = Fake::start(&socket, answers).unwrap();
    assert_eq!(
        next(&mut updates).await,
        Update::Listing(vec![image(A, &[])])
    );
    follower.abort();
}
