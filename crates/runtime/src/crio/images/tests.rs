use std::sync::Arc;
use std::time::Duration;

use speculaire_fake_runtime::{Answers, Fake};
use speculaire_oci::reference::Digest;
use tokio::sync::mpsc;

use super::CriO;
#[cfg(target_os = "linux")]
use crate::images::Lost;
use crate::images::{Image, Images, Update};
use crate::paths::Paths;

fn image(hex: &str) -> Image {
    Image {
        id: Digest::parse(&format!("sha256:{hex}")).unwrap(),
        repo_digests: Vec::new(),
    }
}

async fn next(updates: &mut mpsc::Receiver<Update>) -> Update {
    tokio::time::timeout(Duration::from_secs(5), updates.recv())
        .await
        .expect("an update comes")
        .expect("the follower goes on")
}

/// The list comes first; on Linux, `images.json` replaced in the directory CRI-O's config names sends what changed.
#[tokio::test]
async fn the_list_comes_then_each_replaced_images_json_hints() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("crio.sock");
    let images = dir.path().join("var/lib/containers/storage/overlay-images");
    std::fs::create_dir_all(&images).unwrap();
    let a = "a".repeat(64);
    let mut answers = Answers::crio("1.37.0");
    answers.crio_config = Some(
        "[crio]\nroot = \"/var/lib/containers/storage\"\nstorage_driver = \"overlay\"\n".to_owned(),
    );
    answers.images = vec![(a.clone(), Vec::new(), Vec::new())];
    let fake = Fake::start(&socket, answers).unwrap();
    let crio = Arc::new(CriO::new(Paths::under(dir.path()), &socket, "systemctl"));
    let (sender, mut updates) = mpsc::channel(4);
    let follower = tokio::spawn(crio.follow(sender));
    assert_eq!(next(&mut updates).await, Update::Listing(vec![image(&a)]));

    if cfg!(target_os = "linux") {
        let b = "b".repeat(64);
        fake.update(|answers| answers.images.push((b.clone(), Vec::new(), Vec::new())));
        // The watch may start after the listing: replace the file until the change comes.
        let replaced = loop {
            std::fs::write(images.join("images.json.tmp"), "[]").unwrap();
            std::fs::rename(images.join("images.json.tmp"), images.join("images.json")).unwrap();
            if let Ok(Some(update)) =
                tokio::time::timeout(Duration::from_millis(200), updates.recv()).await
            {
                break update;
            }
        };
        assert_eq!(replaced, Update::Listed(image(&b)));
    }

    drop(updates);
    tokio::time::timeout(Duration::from_secs(5), follower)
        .await
        .expect("the follower ends with its reader")
        .unwrap();
}

/// What the watch of `directory` comes to within 5 s, with `act` run once it started and its hints counted.
#[cfg(target_os = "linux")]
async fn watched(directory: &std::path::Path, act: impl FnOnce()) -> (Option<Lost>, usize) {
    let (hint, mut hints) = mpsc::channel(1);
    let watching = tokio::task::spawn_blocking({
        let directory = directory.to_owned();
        move || super::watch_blocking(&directory, &hint)
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    act();
    let mut count = 0;
    let lost = tokio::time::timeout(Duration::from_secs(5), async {
        let mut watching = std::pin::pin!(watching);
        loop {
            tokio::select! {
                lost = &mut watching => break lost.unwrap(),
                Some(()) = hints.recv() => count += 1,
            }
        }
    })
    .await
    .ok();
    while hints.try_recv().is_ok() {
        count += 1;
    }
    (lost, count)
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn images_json_written_in_place_hints_and_the_directory_removed_ends_the_watch() {
    let dir = tempfile::tempdir().unwrap();
    let images = dir.path().join("overlay-images");
    std::fs::create_dir(&images).unwrap();
    let (lost, hints) = watched(&images, || {
        std::fs::write(images.join("other.json"), "[]").unwrap();
        std::fs::write(images.join("images.json"), "[]").unwrap();
        std::thread::sleep(Duration::from_millis(100));
        std::fs::remove_dir_all(&images).unwrap();
    })
    .await;
    assert!(matches!(lost, Some(Lost::Ended)), "{lost:?}");
    assert_eq!(hints, 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_path_that_is_no_directory_is_unreachable() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("images.json");
    std::fs::write(&file, "[]").unwrap();
    let (lost, _) = watched(&file, || {}).await;
    assert!(matches!(lost, Some(Lost::Unreachable(_))), "{lost:?}");
}
