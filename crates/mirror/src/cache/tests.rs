//! The blob cache on a temporary directory.

use std::collections::HashSet;

use bytes::Bytes;
use futures_util::TryStreamExt as _;

use super::*;

fn digest(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
}

async fn keep(cache: &Cache, digest: &Digest, bytes: &[u8]) {
    let mut writer = cache.writer().await.unwrap();
    writer.write(bytes).await.unwrap();
    assert_eq!(writer.written(), bytes.len() as u64);
    writer.commit(cache, digest).await.unwrap();
}

async fn read(cache: &Cache, digest: &Digest) -> Option<Vec<u8>> {
    let blob = cache.open(digest).await.unwrap()?;
    let size = blob.size();
    let chunks: Vec<Bytes> = blob
        .stream(0, size)
        .await
        .unwrap()
        .try_collect()
        .await
        .unwrap();
    Some(chunks.concat())
}

#[tokio::test]
async fn a_blob_kept_is_served_by_its_digest_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::open(dir.path(), 1 << 20).unwrap();
    assert_eq!(cache.size(), 0);
    assert!(read(&cache, &digest(1)).await.is_none());
    keep(&cache, &digest(1), b"hello").await;
    assert!(cache.contains(&digest(1)));
    assert_eq!(cache.size(), 5);
    assert_eq!(read(&cache, &digest(1)).await.unwrap(), b"hello");
    // The file is where D67 puts it, and nothing is left in tmp/.
    let hex = digest(1).encoded().to_owned();
    assert_eq!(
        std::fs::read(dir.path().join("blobs/sha256").join(hex)).unwrap(),
        b"hello"
    );
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
    // Keeping the same digest again counts it once.
    keep(&cache, &digest(1), b"hello").await;
    assert_eq!(cache.size(), 5);
    assert_eq!(cache.digests(), [digest(1)]);
}

#[tokio::test]
async fn a_writer_that_is_not_committed_leaves_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::open(dir.path(), 1 << 20).unwrap();
    let mut writer = cache.writer().await.unwrap();
    writer.write(b"partial").await.unwrap();
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        1
    );
    drop(writer);
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
    assert_eq!(cache.size(), 0);
}

#[tokio::test]
async fn opening_again_deletes_leftovers_and_counts_what_was_kept() {
    let dir = tempfile::tempdir().unwrap();
    {
        let cache = Cache::open(dir.path(), 1 << 20).unwrap();
        keep(&cache, &digest(1), b"one").await;
        keep(&cache, &digest(2), b"three").await;
    }
    std::fs::write(dir.path().join("tmp/9-9.part"), b"left by a killed agent").unwrap();
    // Not ours: a stray file and a directory with another name are neither counted nor deleted.
    std::fs::write(dir.path().join("blobs/sha256/not-a-digest"), b"x").unwrap();
    std::fs::create_dir_all(dir.path().join("blobs/other")).unwrap();
    std::fs::write(dir.path().join("blobs/stray"), b"x").unwrap();
    let cache = Cache::open(dir.path(), 1 << 20).unwrap();
    assert_eq!(
        std::fs::read_dir(dir.path().join("tmp")).unwrap().count(),
        0
    );
    assert_eq!(cache.size(), 8);
    let mut held = cache.digests();
    held.sort_by_key(ToString::to_string);
    assert_eq!(held, [digest(1), digest(2)]);
    assert!(dir.path().join("blobs/sha256/not-a-digest").exists());
    assert_eq!(read(&cache, &digest(2)).await.unwrap(), b"three");
}

#[tokio::test]
async fn above_the_bound_the_least_recently_served_blob_goes_first() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::open(dir.path(), 25).unwrap();
    for n in 1..=3 {
        keep(&cache, &digest(n), &[n; 10]).await;
    }
    // 30 bytes against 25: serving the first makes the second the oldest.
    assert!(read(&cache, &digest(1)).await.is_some());
    assert!(cache.over());
    let evicted = cache.evict(&HashSet::new());
    assert_eq!(evicted, [digest(2)]);
    assert_eq!(cache.size(), 20);
    assert!(!cache.contains(&digest(2)));
    assert!(read(&cache, &digest(2)).await.is_none());
    assert!(read(&cache, &digest(1)).await.is_some());
    assert!(!cache.over());
    // Within the bound, nothing goes.
    assert_eq!(cache.evict(&HashSet::new()).len(), 0);
}

#[tokio::test]
async fn protected_blobs_go_last_and_only_when_nothing_else_is_left() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::open(dir.path(), 15).unwrap();
    for n in 1..=3 {
        keep(&cache, &digest(n), &[n; 10]).await;
    }
    // The oldest two are protected: the newest, unprotected, goes first even though it is the most recently kept.
    let protected = HashSet::from([digest(1), digest(2)]);
    assert_eq!(cache.evict(&protected), [digest(3), digest(1)]);
    assert_eq!(cache.digests(), [digest(2)]);
    // A bound of zero evicts what is protected too.
    cache.set_max_size(0);
    assert_eq!(cache.max_size(), 0);
    assert_eq!(cache.evict(&protected), [digest(2)]);
    assert_eq!(cache.size(), 0);
}

#[tokio::test]
async fn a_blob_deleted_behind_the_cache_is_forgotten_at_the_next_read() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Cache::open(dir.path(), 1 << 20).unwrap();
    keep(&cache, &digest(1), b"one").await;
    keep(&cache, &digest(2), b"two").await;
    std::fs::remove_file(dir.path().join("blobs/sha256").join(digest(1).encoded())).unwrap();
    assert!(read(&cache, &digest(1)).await.is_none());
    assert!(!cache.contains(&digest(1)));
    assert_eq!(cache.size(), 3);
    // One whose size changed is not the blob that was kept.
    std::fs::write(
        dir.path().join("blobs/sha256").join(digest(2).encoded()),
        b"longer",
    )
    .unwrap();
    assert!(read(&cache, &digest(2)).await.is_none());
    assert_eq!(cache.size(), 0);
}

#[tokio::test]
async fn the_order_of_service_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let cache = Cache::open(dir.path(), 1 << 20).unwrap();
        for n in 1..=3 {
            keep(&cache, &digest(n), &[n; 10]).await;
        }
        // Make the times distinct and old, then serve the first: its time moves to now.
        for (n, age) in [(1, 300), (2, 200), (3, 100)] {
            let file = std::fs::File::options()
                .write(true)
                .open(dir.path().join("blobs/sha256").join(digest(n).encoded()))
                .unwrap();
            file.set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(age))
                .unwrap();
        }
        assert!(read(&cache, &digest(1)).await.is_some());
    }
    let cache = Cache::open(dir.path(), 25).unwrap();
    assert_eq!(cache.evict(&HashSet::new()), [digest(2)]);
}
