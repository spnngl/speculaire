use containerd_client::tonic::Code;
use speculaire_fake_runtime::{Answers, Fake, Snapshot};
use speculaire_oci::reference::Digest;

use super::Error;
use crate::containerd::Containerd;
use crate::paths::Paths;

const CHAIN: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn chain() -> Digest {
    Digest::parse(CHAIN).unwrap()
}

/// Whether a snapshot carries the ID mapping labels of a user-namespaced container.
#[derive(Clone, Copy)]
enum Ids {
    Kept,
    Mapped,
}

/// A fake containerd holding `snapshots` (key, parent, IDs), and a client of it.
fn snapshots(snapshots: &[(&str, &str, Ids)]) -> (Fake, Containerd, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let mut answers = Answers::containerd("2.3.7");
    answers.snapshots = snapshots
        .iter()
        .map(|&(key, parent, ids)| Snapshot {
            key: key.to_owned(),
            parent: parent.to_owned(),
            labels: match ids {
                Ids::Kept => Vec::new(),
                Ids::Mapped => vec![(
                    "containerd.io/snapshot/uidmapping".to_owned(),
                    "0:65536:65536".to_owned(),
                )],
            },
        })
        .collect();
    let fake = Fake::start(&socket, answers).unwrap();
    let containerd = Containerd::new(Paths::under(dir.path()), &socket, None);
    (fake, containerd, dir)
}

#[tokio::test]
async fn a_container_rests_on_its_parent_after_one_stat() {
    let (fake, containerd, _dir) = snapshots(&[("container", CHAIN, Ids::Kept)]);
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), CHAIN);
    assert_eq!(fake.stats(), 1);
}

#[tokio::test]
async fn a_container_on_another_parent_rests_on_it() {
    let (fake, containerd, _dir) = snapshots(&[("container", "elsewhere", Ids::Kept)]);
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), "elsewhere");
    assert_eq!(fake.stats(), 1);
}

#[tokio::test]
async fn a_remapped_container_rests_on_its_grandparent_after_two_stats() {
    let (fake, containerd, _dir) = snapshots(&[
        ("container", "remapped", Ids::Mapped),
        ("remapped", CHAIN, Ids::Kept),
    ]);
    let base = containerd
        .snapshot_base("native", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), CHAIN);
    assert_eq!(fake.stats(), 2);
}

#[tokio::test]
async fn a_mapped_container_on_a_snapshotter_that_maps_ids_rests_on_its_parent() {
    let (fake, containerd, _dir) = snapshots(&[("container", CHAIN, Ids::Mapped)]);
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), CHAIN);
    assert_eq!(fake.stats(), 1);
}

#[tokio::test]
async fn a_snapshot_without_parent_or_record_has_no_base() {
    let (_fake, containerd, _dir) = snapshots(&[("scratch", "", Ids::Kept)]);
    let base = containerd
        .snapshot_base("overlayfs", "scratch", &chain())
        .await;
    assert!(matches!(base, Err(Error::NoParent(key)) if key == "scratch"));
    let base = containerd
        .snapshot_base("overlayfs", "missing", &chain())
        .await;
    assert!(matches!(base, Err(Error::Stat(status)) if status.code() == Code::NotFound));
}

#[tokio::test]
async fn no_containerd_has_no_base() {
    let dir = tempfile::tempdir().unwrap();
    let containerd = Containerd::new(Paths::under(dir.path()), dir.path().join("none.sock"), None);
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert!(matches!(base, Err(Error::Unreachable)));
}

#[tokio::test]
async fn a_restarted_containerd_is_reached_again_after_one_failed_stat() {
    let (fake, containerd, dir) = snapshots(&[("container", CHAIN, Ids::Kept)]);
    let socket = dir.path().join("containerd.sock");
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), CHAIN);
    drop(fake);
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert!(matches!(base, Err(Error::Stat(_))));

    std::fs::remove_file(&socket).unwrap();
    let mut answers = Answers::containerd("2.3.7");
    answers.snapshots = vec![Snapshot {
        key: "container".to_owned(),
        parent: CHAIN.to_owned(),
        labels: Vec::new(),
    }];
    let _fake = Fake::start(&socket, answers).unwrap();
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), CHAIN);
}
