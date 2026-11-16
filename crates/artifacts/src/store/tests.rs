//! The artifact store on a temporary directory.

use metrics_exporter_prometheus::PrometheusBuilder;

use super::*;

fn digest_of(bytes: &[u8]) -> Digest {
    speculaire_oci::hash::of("sha256", bytes).unwrap()
}

#[tokio::test]
async fn a_blob_is_kept_once_when_it_matches_its_digest_and_counted_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let digest = digest_of(b"{}");
    assert!(!store.contains(&digest));
    assert_eq!(store.read(&digest).await.unwrap(), None);
    store.keep(&digest, b"{}").await.unwrap();
    store.keep(&digest, b"{}").await.unwrap();
    assert!(store.contains(&digest));
    assert_eq!(store.read(&digest).await.unwrap(), Some(b"{}".to_vec()));
    assert_eq!(store.bytes(), 2);
    assert!(
        dir.path()
            .join("blobs/sha256")
            .join(digest.encoded())
            .is_file()
    );
}

#[tokio::test]
async fn a_blob_that_does_not_match_its_digest_is_refused_and_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let digest = digest_of(b"{}");
    let refused = store.keep(&digest, b"{ }").await;
    assert!(matches!(refused, Err(Error::Mismatch(_))), "{refused:?}");
    assert!(!store.contains(&digest));
    assert_eq!(store.bytes(), 0);
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
}

#[tokio::test]
async fn a_writer_dropped_before_its_commit_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let digest = digest_of(b"{}");
    let mut writer = store.writer(&digest).await.unwrap();
    writer.write(b"{").await.unwrap();
    assert_eq!(writer.written(), 1);
    drop(writer);
    assert!(!store.contains(&digest));
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
}

#[tokio::test]
async fn opening_again_clears_parts_and_counts_the_blobs_held() {
    let dir = tempfile::tempdir().unwrap();
    let digest = digest_of(b"layer");
    Store::open(dir.path())
        .unwrap()
        .keep(&digest, b"layer")
        .await
        .unwrap();
    std::fs::write(dir.path().join("tmp/1-0.part"), b"half").unwrap();
    let store = Store::open(dir.path()).unwrap();
    assert_eq!(store.bytes(), 5);
    assert!(store.contains(&digest));
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
}

#[tokio::test]
async fn a_record_is_read_back_and_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let root = digest_of(b"root");
    assert_eq!(store.recorded(&root).await.unwrap(), None);
    let artifact = Artifact {
        target: root.clone(),
        manifest: digest_of(b"manifest"),
        kind: Kind::Bundle,
        blobs: vec![digest_of(b"{}"), digest_of(b"bundle")],
    };
    store
        .record(&root, std::slice::from_ref(&artifact))
        .await
        .unwrap();
    assert_eq!(
        store.recorded(&root).await.unwrap(),
        Some(vec![artifact.clone()])
    );
    store.record(&root, &[]).await.unwrap();
    assert_eq!(store.recorded(&root).await.unwrap(), Some(Vec::new()));
}

#[tokio::test]
async fn a_record_that_is_no_record_is_an_error_naming_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let root = digest_of(b"root");
    let path = dir
        .path()
        .join("roots/sha256")
        .join(format!("{}.json", root.encoded()));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        r#"{"artifacts":[{"target":"x","manifest":"y","kind":"bundle","blobs":[]}]}"#,
    )
    .unwrap();
    let error = store.recorded(&root).await.unwrap_err();
    assert!(
        error.to_string().contains(&path.display().to_string()),
        "{error}"
    );
}

#[tokio::test]
async fn a_blob_or_record_that_is_there_but_unreadable_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let digest = digest_of(b"{}");
    std::fs::create_dir_all(store.path(&digest)).unwrap();
    std::fs::create_dir_all(store.record_path(&digest)).unwrap();
    assert!(store.read(&digest).await.is_err());
    assert!(store.recorded(&digest).await.is_err());
}

#[tokio::test]
async fn a_commit_whose_part_is_gone_is_an_error_and_holds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let digest = digest_of(b"{}");
    let mut writer = store.writer(&digest).await.unwrap();
    writer.write(b"{}").await.unwrap();
    std::fs::remove_file(&writer.path).unwrap();
    assert!(writer.commit(&store).await.is_err());
    assert!(!store.contains(&digest));
    assert_eq!(store.bytes(), 0);
}

#[tokio::test]
async fn the_store_bytes_gauge_follows_each_blob_kept() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _local = ::metrics::set_default_local_recorder(&recorder);
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let gauge = || {
        handle
            .render()
            .lines()
            .find_map(|line| line.strip_prefix("speculaire_artifact_store_bytes "))
            .map(str::to_owned)
    };
    assert_eq!(gauge().as_deref(), Some("0"));
    store.keep(&digest_of(b"{}"), b"{}").await.unwrap();
    assert_eq!(gauge().as_deref(), Some("2"));
    store.keep(&digest_of(b"abc"), b"abc").await.unwrap();
    assert_eq!(gauge().as_deref(), Some("5"));
}

#[tokio::test]
async fn the_referrers_of_a_target_are_the_manifests_recorded_about_it_each_once_across_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let (index, platform) = (digest_of(b"index"), digest_of(b"platform"));
    let artifact = |target: &Digest, manifest: &[u8]| Artifact {
        target: target.clone(),
        manifest: digest_of(manifest),
        kind: Kind::Bundle,
        blobs: Vec::new(),
    };
    // Two roots may share an artifact: an index and the platform manifest pulled by its own digest.
    let shared = artifact(&platform, b"bundle");
    store
        .record(&index, &[artifact(&index, b"sbom"), shared.clone()])
        .await
        .unwrap();
    store
        .record(&platform, &[shared, artifact(&platform, b"sig")])
        .await
        .unwrap();
    let mut about = store.referrers(&platform);
    about.sort_by_key(ToString::to_string);
    let mut expected = vec![digest_of(b"bundle"), digest_of(b"sig")];
    expected.sort_by_key(ToString::to_string);
    assert_eq!(about, expected);
    assert_eq!(store.referrers(&index), [digest_of(b"sbom")]);
    assert_eq!(store.referrers(&digest_of(b"other")), []);

    // A record that is no record, and a file that names no root, are left out of a reopened store.
    let roots = dir.path().join("roots/sha256");
    std::fs::write(
        roots.join(format!("{}.json", digest_of(b"bad").encoded())),
        "[]",
    )
    .unwrap();
    std::fs::write(roots.join("x.json"), "{\"artifacts\":[]}").unwrap();
    std::fs::write(dir.path().join("roots/stray"), "").unwrap();
    store.record(&platform, &[]).await.unwrap();
    let reopened = Store::open(dir.path()).unwrap();
    // The index still records the shared one.
    assert_eq!(reopened.referrers(&platform), [digest_of(b"bundle")]);
    assert_eq!(reopened.referrers(&index), [digest_of(b"sbom")]);
}

#[tokio::test]
async fn the_store_serves_the_blobs_it_holds() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    let digest = digest_of(b"{}");
    store.keep(&digest, b"{}").await.unwrap();
    let blob = Content::open(&store, &digest).await.unwrap().unwrap();
    assert_eq!(blob.read_all(10).await.unwrap(), &b"{}"[..]);
    assert!(
        Content::open(&store, &digest_of(b"x"))
            .await
            .unwrap()
            .is_none()
    );
    // A file where the directory of an algorithm should be: there, but unreadable.
    std::fs::write(dir.path().join("blobs/sha512"), "").unwrap();
    let sha512 = speculaire_oci::hash::of("sha512", b"{}").unwrap();
    assert!(Content::open(&store, &sha512).await.is_err());
}

#[tokio::test]
async fn a_follower_gets_the_blobs_held_then_each_blob_kept() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let (first, second) = (digest_of(b"{}"), digest_of(b"abc"));
    store.keep(&first, b"{}").await.unwrap();
    // A file that is no digest is no blob.
    std::fs::write(dir.path().join("blobs/sha256/x"), "").unwrap();
    std::fs::write(dir.path().join("blobs/stray"), "").unwrap();
    let (updates, mut received) = mpsc::channel(8);
    let followed = tokio::spawn(Arc::clone(&store).follow(updates));
    assert_eq!(
        received.recv().await,
        Some(Update::Listing([first.clone()].into()))
    );
    // A blob kept again is no change.
    store.keep(&first, b"{}").await.unwrap();
    store.keep(&second, b"abc").await.unwrap();
    assert_eq!(
        received.recv().await,
        Some(Update::Change(Change::Added(second)))
    );
    drop(received);
    followed.await.unwrap();
}

#[tokio::test]
async fn a_store_that_cannot_be_listed_announces_none_then_the_blobs_kept() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    std::fs::remove_dir_all(dir.path().join("blobs")).unwrap();
    let (updates, mut received) = mpsc::channel(8);
    let followed = tokio::spawn(Arc::clone(&store).follow(updates));
    assert_eq!(received.recv().await, Some(Update::Listing(HashSet::new())));
    let digest = digest_of(b"{}");
    store.keep(&digest, b"{}").await.unwrap();
    assert_eq!(
        received.recv().await,
        Some(Update::Change(Change::Added(digest)))
    );
    drop(received);
    followed.await.unwrap();
}

#[tokio::test]
async fn a_follower_that_missed_changes_gets_a_listing_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let (updates, mut received) = mpsc::channel(1);
    let followed = tokio::spawn(Arc::clone(&store).follow(updates));
    assert_eq!(received.recv().await, Some(Update::Listing(HashSet::new())));
    // More blobs than the backlog holds while the follower waits on a full channel, which has taken two.
    let mut kept = HashSet::new();
    for i in 0..BACKLOG + 8 {
        let bytes = i.to_string();
        let digest = digest_of(bytes.as_bytes());
        store.keep(&digest, bytes.as_bytes()).await.unwrap();
        kept.insert(digest);
    }
    let listing = loop {
        match received.recv().await.unwrap() {
            Update::Listing(listing) => break listing,
            Update::Change(_) => {}
        }
    };
    assert_eq!(listing, kept);
    drop(received);
    followed.await.unwrap();
}

#[tokio::test]
async fn a_follower_whose_receiver_is_gone_stops() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    let (updates, received) = mpsc::channel(1);
    drop(received);
    store.follow(updates).await;
}
