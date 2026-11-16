use std::sync::Arc;
use std::time::Duration;

use speculaire_fake_runtime::{Answers, Fake};
use speculaire_oci::reference::Digest;
use tokio::sync::mpsc;

use super::CriO;
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
