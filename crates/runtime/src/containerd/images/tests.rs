use std::sync::Arc;
use std::time::Duration;

use containerd_client::events::ContentCreate;
use containerd_client::types::Envelope;
use speculaire_fake_runtime::{Answers, Fake};
use speculaire_oci::reference::Digest;
use tokio::sync::mpsc;

use super::{Containerd, hints};
use crate::images::{Image, Images, Update};
use crate::paths::Paths;

/// An event on `topic` in `namespace`: hints read no payload, so any will do.
fn envelope(namespace: &str, topic: &str) -> Envelope {
    Envelope {
        timestamp: None,
        namespace: namespace.to_owned(),
        topic: topic.to_owned(),
        event: Some(containerd_client::to_any(&ContentCreate::default())),
    }
}

#[test]
fn image_events_of_the_cri_namespace_hint() {
    for topic in ["/images/create", "/images/update", "/images/delete"] {
        assert!(hints(&envelope("k8s.io", topic)), "{topic}");
        assert!(!hints(&envelope("default", topic)), "{topic}");
    }
    assert!(!hints(&envelope("k8s.io", "/content/create")));
}

#[tokio::test]
async fn the_list_is_what_the_cri_lists() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let id = format!("sha256:{}", "a".repeat(64));
    let mut answers = Answers::containerd("2.4.2");
    answers.images = vec![(id.clone(), Vec::new(), Vec::new())];
    let _fake = Fake::start(&socket, answers).unwrap();
    let containerd = Arc::new(Containerd::new(Paths::under(dir.path()), &socket, None));
    let (sender, mut updates) = mpsc::channel(4);
    let follower = tokio::spawn(containerd.follow(sender));
    let first = tokio::time::timeout(Duration::from_secs(5), updates.recv())
        .await
        .unwrap();
    let image = Image {
        id: Digest::parse(&id).unwrap(),
        repo_digests: Vec::new(),
    };
    assert_eq!(first, Some(Update::Listing(vec![image])));
    drop(updates);
    tokio::time::timeout(Duration::from_secs(5), follower)
        .await
        .expect("the follower ends with its reader")
        .unwrap();
}
