use std::time::Duration;

use containerd_client::events::{SnapshotCommit, SnapshotPrepare, SnapshotRemove};
use containerd_client::tonic::Code;
use containerd_client::types::Envelope;
use speculaire_fake_runtime::{Answers, Fake, Snapshot};
use speculaire_oci::reference::Digest;

use super::{Error, PREPARED, Prepared};
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

/// A fake containerd holding `snapshots` (key, parent, IDs) in `snapshotter`, and a client of it.
fn snapshots(
    snapshotter: &str,
    snapshots: &[(&str, &str, Ids)],
) -> (Fake, Containerd, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let mut answers = Answers::containerd("2.3.7");
    answers.snapshots = snapshots
        .iter()
        .map(|&(key, parent, ids)| Snapshot {
            snapshotter: snapshotter.to_owned(),
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
    let (fake, containerd, _dir) = snapshots("overlayfs", &[("container", CHAIN, Ids::Kept)]);
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), CHAIN);
    assert_eq!(fake.stats(), 1);
}

#[tokio::test]
async fn a_container_on_another_parent_rests_on_it() {
    let (fake, containerd, _dir) = snapshots("overlayfs", &[("container", "elsewhere", Ids::Kept)]);
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), "elsewhere");
    assert_eq!(fake.stats(), 1);
}

#[tokio::test]
async fn a_remapped_container_rests_on_its_grandparent_after_two_stats() {
    let (fake, containerd, _dir) = snapshots(
        "native",
        &[
            ("container", "remapped", Ids::Mapped),
            ("remapped", CHAIN, Ids::Kept),
        ],
    );
    let base = containerd
        .snapshot_base("native", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), CHAIN);
    assert_eq!(fake.stats(), 2);
}

#[tokio::test]
async fn a_mapped_container_on_a_snapshotter_that_maps_ids_rests_on_its_parent() {
    let (fake, containerd, _dir) = snapshots("overlayfs", &[("container", CHAIN, Ids::Mapped)]);
    let base = containerd
        .snapshot_base("overlayfs", "container", &chain())
        .await;
    assert_eq!(base.unwrap(), CHAIN);
    assert_eq!(fake.stats(), 1);
}

#[tokio::test]
async fn a_snapshot_without_parent_or_record_has_no_base() {
    let (_fake, containerd, _dir) = snapshots("overlayfs", &[("scratch", "", Ids::Kept)]);
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
    let (fake, containerd, dir) = snapshots("overlayfs", &[("container", CHAIN, Ids::Kept)]);
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
        snapshotter: "overlayfs".to_owned(),
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

/// containerd's envelope of `event`, under `topic` in `namespace`.
fn envelope(namespace: &str, topic: &str, event: &impl prost::Name) -> Envelope {
    Envelope {
        timestamp: None,
        namespace: namespace.to_owned(),
        topic: topic.to_owned(),
        event: Some(containerd_client::to_any(event)),
    }
}

fn prepare(key: &str, parent: &str) -> Envelope {
    let event = SnapshotPrepare {
        key: key.to_owned(),
        parent: parent.to_owned(),
        snapshotter: "overlayfs".to_owned(),
    };
    envelope("k8s.io", "/snapshot/prepare", &event)
}

#[test]
fn a_prepared_snapshot_rests_on_its_digest_parent_until_committed_or_removed() {
    let prepared = Prepared::default();
    let other = Digest::parse(&CHAIN.replace('c', "d")).unwrap();
    prepared.apply(&prepare("container", CHAIN));
    assert!(prepared.rests_on("overlayfs", "container", &chain()));
    assert!(
        !prepared.rests_on("native", "container", &chain()),
        "another snapshotter"
    );
    assert!(
        !prepared.rests_on("overlayfs", "container", &other),
        "another parent"
    );
    assert!(
        !prepared.rests_on("overlayfs", "other", &chain()),
        "another key"
    );

    let removed = SnapshotRemove {
        key: "container".to_owned(),
        snapshotter: "overlayfs".to_owned(),
    };
    prepared.apply(&envelope("k8s.io", "/snapshot/remove", &removed));
    assert!(!prepared.rests_on("overlayfs", "container", &chain()));

    prepared.apply(&prepare("extract", CHAIN));
    let committed = SnapshotCommit {
        key: "extract".to_owned(),
        name: "layer".to_owned(),
        snapshotter: "overlayfs".to_owned(),
    };
    prepared.apply(&envelope("k8s.io", "/snapshot/commit", &committed));
    assert!(!prepared.rests_on("overlayfs", "extract", &chain()));

    // A remapped copy is no digest: `Stat` reads what it rests on. So is a re-preparation on one.
    prepared.apply(&prepare("container", CHAIN));
    prepared.apply(&prepare("container", &format!("{CHAIN}-remapped")));
    assert!(!prepared.rests_on("overlayfs", "container", &chain()));

    let elsewhere = SnapshotPrepare {
        key: "container".to_owned(),
        parent: CHAIN.to_owned(),
        snapshotter: "overlayfs".to_owned(),
    };
    prepared.apply(&envelope("default", "/snapshot/prepare", &elsewhere));
    assert!(
        !prepared.rests_on("overlayfs", "container", &chain()),
        "another namespace"
    );
}

#[test]
fn past_the_bound_the_prepared_snapshots_are_dropped() {
    let prepared = Prepared::default();
    for key in 0..PREPARED {
        prepared.apply(&prepare(&key.to_string(), CHAIN));
    }
    assert!(prepared.rests_on("overlayfs", "0", &chain()));
    prepared.apply(&prepare("last", CHAIN));
    assert!(!prepared.rests_on("overlayfs", "0", &chain()));
    assert!(prepared.rests_on("overlayfs", "last", &chain()));
}

#[tokio::test]
async fn the_prepared_snapshots_follow_containerd_s_events_from_each_subscription() {
    let (fake, containerd, _dir) = snapshots("overlayfs", &[]);
    let prepared = Prepared::default();
    prepared.apply(&prepare("before", CHAIN));
    tokio::select! {
        () = containerd.keep_prepared(&prepared) => panic!("following ends only when the agent stops"),
        () = async {
            while fake.subscribers() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            fake.publish(prepare("container", CHAIN));
            while !prepared.rests_on("overlayfs", "container", &chain()) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        } => {}
    }
    assert!(
        !prepared.rests_on("overlayfs", "before", &chain()),
        "what came before the subscription is dropped"
    );
    assert_eq!(fake.stats(), 0);
}
