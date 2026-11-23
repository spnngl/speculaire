//! Pins through [`Pull`](crate::pull::Pull) on a fake containerd, and none on CRI-O.

use std::collections::HashMap;

use containerd_client::services::v1::Image;
use containerd_client::types::Descriptor;
use speculaire_oci::reference::Reference;

use super::{MARK, PINNED, update};
use crate::detect::Runtime;
use crate::fixture::Tree;

const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn reference(text: &str) -> Reference {
    Reference::parse_docker_ref(text).expect("a reference")
}

/// A containerd node holding `names`, with `labels` on each.
fn holding(names: &[(&str, &[(&str, &str)])]) -> Tree {
    let tree = Tree::new(Runtime::Containerd);
    tree.update(|answers| {
        for (name, labels) in names {
            answers
                .image_store
                .push(((*name).to_owned(), DIGEST.to_owned()));
            answers.image_labels.insert(
                (*name).to_owned(),
                labels
                    .iter()
                    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                    .collect(),
            );
        }
    });
    tree
}

/// The labels of `name` on the fake.
fn labels(tree: &Tree, name: &str) -> HashMap<String, String> {
    tree.answers()
        .image_labels
        .get(name)
        .cloned()
        .unwrap_or_default()
}

fn pinned_by_the_agent() -> HashMap<String, String> {
    [PINNED, MARK]
        .map(|key| (key.to_owned(), "pinned".to_owned()))
        .into()
}

const APP: &str = "registry.test/team/app:1.0";
const PAUSE: &str = "registry.k8s.io/pause:3.10";

#[tokio::test]
async fn a_pin_is_marked_and_an_unpin_takes_only_a_marked_pin_off() {
    let tree = holding(&[
        (APP, &[("io.cri-containerd.image", "managed")]),
        (PAUSE, &[(PINNED, "pinned")]),
    ]);
    let pull = tree.node.pull();
    assert!(pull.pin(&reference(APP)).await.unwrap());
    assert!(
        pull.pin(&reference(APP)).await.unwrap(),
        "pinned by the agent already"
    );
    let mut wanted = pinned_by_the_agent();
    wanted.insert("io.cri-containerd.image".to_owned(), "managed".to_owned());
    assert_eq!(labels(&tree, APP), wanted);
    // Pinned by the CRI config: neither marked nor unpinned.
    assert!(!pull.pin(&reference(PAUSE)).await.unwrap());
    assert_eq!(
        labels(&tree, PAUSE),
        [(PINNED.to_owned(), "pinned".to_owned())].into()
    );
    assert_eq!(pull.marked().await.unwrap(), [reference(APP)]);
    pull.unpin(&reference(PAUSE)).await.unwrap();
    assert_eq!(
        labels(&tree, PAUSE),
        [(PINNED.to_owned(), "pinned".to_owned())].into()
    );
    pull.unpin(&reference(APP)).await.unwrap();
    assert_eq!(
        labels(&tree, APP),
        [("io.cri-containerd.image".to_owned(), "managed".to_owned())].into()
    );
    assert_eq!(pull.marked().await.unwrap(), []);
    // An image containerd lacks has nothing to pin or unpin.
    assert!(!pull.pin(&reference("registry.test/gone:1")).await.unwrap());
    pull.unpin(&reference("registry.test/gone:1"))
        .await
        .unwrap();
}

#[tokio::test]
async fn marked_names_only_references_with_the_mark() {
    let tree = holding(&[
        (APP, &[(PINNED, "pinned"), (MARK, "pinned")]),
        // containerd names an image by its ID too; the agent marks none.
        (DIGEST, &[(PINNED, "pinned"), (MARK, "pinned")]),
        ("registry.test/team/other:1.0", &[(MARK, "no")]),
    ]);
    assert_eq!(tree.node.pull().marked().await.unwrap(), [reference(APP)]);
}

#[tokio::test]
async fn a_runtime_that_does_not_answer_is_an_error() {
    let mut tree = holding(&[(APP, &[])]);
    tree.stop();
    let pull = tree.node.pull();
    for err in [
        pull.pin(&reference(APP)).await.unwrap_err(),
        pull.unpin(&reference(APP)).await.unwrap_err(),
        pull.marked().await.unwrap_err(),
    ] {
        assert!(err.to_string().contains("containerd.sock"), "{err}");
    }
}

/// Only `NotFound` means the image is gone, between the agent's `Get` and its `Update` too; any other answer is an
/// error.
#[tokio::test]
async fn only_not_found_means_the_image_is_gone() {
    let tree = holding(&[(APP, &[])]);
    let socket = tree.node.socket();
    let target = Some(Descriptor {
        digest: DIGEST.to_owned(),
        ..Descriptor::default()
    });
    let gone = Image {
        name: "registry.test/gone:1".to_owned(),
        target,
        ..Image::default()
    };
    update(socket, gone, "pinned").await.unwrap();
    let untargeted = Image {
        name: APP.to_owned(),
        ..Image::default()
    };
    let err = update(socket, untargeted, "pinned").await.unwrap_err();
    assert!(err.to_string().contains("Update"), "{err}");
    tree.update(|answers| answers.image_get_unavailable = true);
    let err = tree.node.pull().pin(&reference(APP)).await.unwrap_err();
    assert!(err.to_string().contains("Get"), "{err}");
}

/// CRI-O pins only from its config, so the agent asks it nothing (D65).
#[tokio::test]
async fn crio_pins_nothing() {
    let mut tree = Tree::new(Runtime::CriO);
    tree.stop();
    let pull = tree.node.pull();
    assert!(!pull.pin(&reference(APP)).await.unwrap());
    pull.unpin(&reference(APP)).await.unwrap();
    assert_eq!(pull.marked().await.unwrap(), []);
}
