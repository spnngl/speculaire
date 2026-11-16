//! The artifact store on a temporary directory.

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
