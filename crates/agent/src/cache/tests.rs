use std::time::Duration;

use speculaire_oci::reference::Digest;
use speculaire_verify::{Absent, Key, Verdict};
use tokio::time::Instant;

use super::*;
use crate::capture::Capture;

fn digest(byte: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{byte:02x}").repeat(32))).expect("a digest")
}

/// Caches at `path` with no policy and no trust root.
fn caches(path: PathBuf) -> Caches {
    Caches {
        path,
        verdicts: Arc::default(),
        signatures: Arc::new(Signatures::new(0)),
        policies: watch::channel(Arc::new(Policies::default())).1,
        trust: watch::channel(Err(Absent::new("none in this test"))).1,
    }
}

fn keep(caches: &Caches, byte: u8) {
    let key = Key {
        image: &digest(byte),
        policies: caches.match_hash(),
        root: None,
    };
    caches.verdicts.keep(key, Verdict::Allow);
}

#[tokio::test(start_paused = true)]
async fn constant_change_saves_at_most_once_a_second_and_a_stop_saves_once_more() {
    let verdicts = Verdicts::default();
    let (stop, stopped) = oneshot::channel();
    let mut saves = Vec::new();
    let start = Instant::now();
    let changing = async {
        for byte in 0..=u8::MAX {
            verdicts.keep(
                Key {
                    image: &digest(byte),
                    policies: MatchHash::of([]),
                    root: None,
                },
                Verdict::Allow,
            );
            sleep(Duration::from_millis(20)).await;
        }
        stop.send(()).expect("the saver runs");
    };
    let saving = async {
        let mut pace = Pace::new(&verdicts, stopped);
        loop {
            let tick = pace.next().await;
            saves.push(start.elapsed());
            if let Tick::Last = tick {
                break;
            }
        }
    };
    tokio::join!(changing, saving);
    // 256 changes over 5.12 s: one save at the first, one a second after each save, and one at the stop.
    assert_eq!(saves.len(), 7, "{saves:?}");
    let (_, paced) = saves.split_last().expect("saves were made");
    for pair in paced.windows(2) {
        assert!(pair[1].saturating_sub(pair[0]) >= PERIOD, "{saves:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn no_change_saves_only_at_the_stop() {
    let verdicts = Verdicts::default();
    let (stop, stopped) = oneshot::channel();
    let stopping = async {
        sleep(Duration::from_secs(10)).await;
        stop.send(()).expect("the saver runs");
    };
    let mut pace = Pace::new(&verdicts, stopped);
    let ((), tick) = tokio::join!(stopping, pace.next());
    assert!(matches!(tick, Tick::Last));
}

#[tokio::test]
async fn a_stopped_saver_leaves_a_file_the_next_start_loads() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("cache.bin");
    let before = caches(path.clone());
    let saver = before.clone().save();
    keep(&before, 1);
    keep(&before, 2);
    saver.stop().await;
    let after = caches(path);
    after.load();
    let key = Key {
        image: &digest(2),
        policies: after.match_hash(),
        root: None,
    };
    let lookup = after.verdicts.get(key);
    assert_eq!((lookup.verdict, lookup.stale), (Verdict::Allow, false));
}

/// The mode of `dir`'s permission bits.
fn mode(dir: &Path) -> u32 {
    std::fs::metadata(dir)
        .expect("the directory exists")
        .permissions()
        .mode()
        & 0o7777
}

#[tokio::test]
async fn a_cache_directory_made_0755_ends_0700_and_its_file_loads() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let run = dir.path().join("run");
    let path = run.join("cache.bin");
    let before = caches(path.clone());
    before.load();
    assert_eq!(mode(&run), PRIVATE);
    let saver = before.clone().save();
    keep(&before, 1);
    saver.stop().await;
    std::fs::set_permissions(&run, Permissions::from_mode(0o755)).expect("chmod 0755");
    let after = caches(path);
    after.load();
    assert_eq!(mode(&run), PRIVATE);
    let key = Key {
        image: &digest(1),
        policies: after.match_hash(),
        root: None,
    };
    assert_eq!(after.verdicts.get(key).verdict, Verdict::Allow);
}

#[test]
fn a_private_or_narrower_directory_keeps_its_mode() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    for kept in [PRIVATE, 0o500] {
        std::fs::set_permissions(dir.path(), Permissions::from_mode(kept)).expect("chmod");
        assert_eq!(make_private(dir.path()).expect("a directory"), Made::Kept);
        assert_eq!(mode(dir.path()), kept);
    }
    for wider in [0o710, 0o701, 0o1700] {
        std::fs::set_permissions(dir.path(), Permissions::from_mode(wider)).expect("chmod");
        assert_eq!(
            make_private(dir.path()).expect("a directory"),
            Made::Narrowed(wider)
        );
        assert_eq!(mode(dir.path()), PRIVATE);
    }
}

#[tokio::test]
async fn a_failed_write_warns_once_until_one_succeeds() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let mut caches = caches(dir.path().join("missing/cache.bin"));
    let capture = Capture::default();
    let _guard = capture.install();
    let mut failing = false;
    let bytes = caches.write(Vec::new(), &mut failing).await;
    assert!(failing);
    let bytes = caches.write(bytes, &mut failing).await;
    assert!(failing);
    caches.path = dir.path().join("cache.bin");
    caches.write(bytes, &mut failing).await;
    assert!(!failing);
    assert!(caches.path.is_file());
    assert_eq!(capture.warnings().len(), 1, "{:?}", capture.warnings());
}

#[tokio::test]
async fn a_file_that_cannot_be_read_is_discarded_with_a_warning() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    // A directory in place of the file: reading it fails.
    let path = dir.path().join("cache.bin");
    std::fs::create_dir(&path).expect("a directory");
    let capture = Capture::default();
    let _guard = capture.install();
    caches(path).load();
    let warnings = capture.warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let cause = warnings[0]["cause"].as_str().unwrap_or_default();
    assert!(cause.starts_with("it cannot be read"), "{cause}");
}
