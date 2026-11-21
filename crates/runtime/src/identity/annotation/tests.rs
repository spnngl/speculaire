//! The `annotation` path against a fake containerd: blobs in its content directory, snapshots in its snapshot service.

use std::path::Path;
use std::time::Duration;

use serde_json::json;
use speculaire_fake_runtime::{Answers, Fake, Snapshot};
use speculaire_oci::hash;
use speculaire_oci::referrers::{INDEX, MANIFEST};

use super::*;
use crate::paths::Paths;

const NAME: &str = "reg.test/app:1";
const CONTAINER: &str = "c0ffee";
const UIDMAPPING: &str = "containerd.io/snapshot/uidmapping";

/// An image's blobs: the index `target` names an amd64 and an arm64 image, whose layers differ.
struct Image {
    target: Digest,
    blobs: Vec<(Digest, Vec<u8>)>,
    /// The chain IDs of the amd64 and the arm64 image.
    amd64: Digest,
    arm64: Digest,
}

fn blob(blobs: &mut Vec<(Digest, Vec<u8>)>, value: &serde_json::Value) -> Digest {
    let bytes = serde_json::to_vec(value).unwrap();
    let digest = hash::of("sha256", &bytes).unwrap();
    blobs.push((digest.clone(), bytes));
    digest
}

fn image() -> Image {
    let mut blobs = Vec::new();
    let mut platform = |arch: &str, layer: u8| {
        let diff_id = format!("sha256:{}", format!("{layer:02x}").repeat(32));
        let config = blob(
            &mut blobs,
            &json!({"architecture": arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": [diff_id]}}),
        );
        let manifest = blob(
            &mut blobs,
            &json!({
                "schemaVersion": 2,
                "mediaType": MANIFEST,
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config.to_string(), "size": 1},
                "layers": [],
            }),
        );
        let chain = chain::chain_id(&[Digest::parse(&diff_id).unwrap()]).unwrap();
        (manifest, chain)
    };
    let (amd64_manifest, amd64) = platform("amd64", 0xa);
    let (arm64_manifest, arm64) = platform("arm64", 0xb);
    let entry = |digest: &Digest, arch: &str| json!({"mediaType": MANIFEST, "digest": digest.to_string(), "size": 1, "platform": {"os": "linux", "architecture": arch}});
    let target = blob(
        &mut blobs,
        &json!({
            "schemaVersion": 2,
            "mediaType": INDEX,
            "manifests": [entry(&arm64_manifest, "arm64"), entry(&amd64_manifest, "amd64")],
        }),
    );
    Image {
        target,
        blobs,
        amd64,
        arm64,
    }
}

/// The digest of `image`'s amd64 manifest, as its index lists it.
fn amd64_manifest(image: &Image) -> Digest {
    let index = &image
        .blobs
        .iter()
        .find(|(digest, _)| *digest == image.target)
        .unwrap()
        .1;
    let index: serde_json::Value = serde_json::from_slice(index).unwrap();
    Digest::parse(index["manifests"][1]["digest"].as_str().unwrap()).unwrap()
}

fn amd64() -> Host {
    Host {
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        variant: String::new(),
    }
}

fn put(root: &Path, blobs: &[(Digest, Vec<u8>)]) {
    let dir = root.join("var/lib/containerd/io.containerd.content.v1.content/blobs/sha256");
    std::fs::create_dir_all(&dir).unwrap();
    for (digest, bytes) in blobs {
        std::fs::write(dir.join(digest.encoded()), bytes).unwrap();
    }
}

fn snapshot(key: &str, parent: &str, mapped: bool) -> Snapshot {
    Snapshot {
        key: key.to_owned(),
        parent: parent.to_owned(),
        labels: if mapped {
            vec![(UIDMAPPING.to_owned(), "0:65536:65536".to_owned())]
        } else {
            Vec::new()
        },
    }
}

/// A fake containerd holding `snapshots` and `image`'s blobs, and the path on it of an amd64 node whose image store
/// names `image` [`NAME`].
fn node(image: &Image, snapshots: Vec<Snapshot>) -> (Fake, Annotation, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let mut answers = Answers::containerd("2.3.7");
    answers.snapshots = snapshots;
    let fake = Fake::start(&socket, answers).unwrap();
    put(dir.path(), &image.blobs);
    let containerd = Containerd::new(Paths::under(dir.path()), &socket, None);
    let mut annotation = Annotation::new(containerd, amd64());
    annotation.store = [("reg.test/app:1".to_owned(), image.target.clone())]
        .into_iter()
        .collect();
    (fake, annotation, dir)
}

fn container(name: Option<&str>) -> Container {
    Container {
        id: CONTAINER.to_owned(),
        annotations: name
            .map(|name| (IMAGE_NAME.to_owned(), name.to_owned()))
            .into_iter()
            .collect(),
        ..Container::default()
    }
}

#[tokio::test]
async fn a_container_on_its_image_s_layers_is_identified_by_the_image_s_target_after_one_stat() {
    let image = image();
    let (fake, annotation, _dir) = node(
        &image,
        vec![snapshot(CONTAINER, &image.amd64.to_string(), false)],
    );
    let container = container(Some(NAME));
    let identified = annotation.identify(&container).await;
    assert_eq!(
        identified,
        Identified::Listed {
            digest: image.target.clone(),
            name: NAME
        }
    );
    assert_eq!(fake.stats(), 1);
}

#[tokio::test]
async fn a_container_on_another_image_s_layers_is_a_mismatch() {
    let image = image();
    let (_fake, annotation, _dir) = node(
        &image,
        vec![snapshot(CONTAINER, &image.arm64.to_string(), false)],
    );
    assert_eq!(
        annotation.identify(&container(Some(NAME))).await,
        Identified::Mismatched
    );
}

#[tokio::test]
async fn a_user_namespaced_container_is_checked_on_its_grandparent_in_two_stats() {
    let image = image();
    for (grandparent, want) in [
        (
            &image.amd64,
            Identified::Listed {
                digest: image.target.clone(),
                name: NAME,
            },
        ),
        (&image.arm64, Identified::Mismatched),
    ] {
        let (fake, annotation, _dir) = node(
            &image,
            vec![
                snapshot(CONTAINER, "remapped", true),
                snapshot("remapped", &grandparent.to_string(), true),
            ],
        );
        assert_eq!(annotation.identify(&container(Some(NAME))).await, want);
        assert_eq!(fake.stats(), 2);
    }
}

#[tokio::test]
async fn the_name_is_normalised_as_containerd_names_its_images() {
    let image = image();
    let (_fake, mut annotation, _dir) = node(
        &image,
        vec![snapshot(CONTAINER, &image.amd64.to_string(), false)],
    );
    annotation.store = [(
        "docker.io/library/app:latest".to_owned(),
        image.target.clone(),
    )]
    .into_iter()
    .collect();
    for name in [
        "app",
        "library/app",
        "docker.io/library/app:latest",
        "index.docker.io/library/app",
    ] {
        let container = container(Some(name));
        assert!(
            matches!(
                annotation.identify(&container).await,
                Identified::Listed { .. }
            ),
            "{name}"
        );
    }
}

#[tokio::test]
async fn each_missing_link_is_its_own_unverifiable_reason() {
    let image = image();
    let (_fake, annotation, dir) = node(&image, Vec::new());
    assert_eq!(
        annotation.identify(&container(None)).await,
        Identified::Unknown(MISSING)
    );
    assert_eq!(
        annotation.identify(&container(Some("Not A Name"))).await,
        Identified::Unknown(MISSING)
    );
    assert_eq!(
        annotation
            .identify(&container(Some("reg.test/app:2")))
            .await,
        Identified::Unknown(NOT_STORED)
    );
    assert_eq!(
        annotation.identify(&container(Some(NAME))).await,
        Identified::Unknown(NO_SNAPSHOT),
        "the container has no snapshot"
    );
    std::fs::remove_dir_all(dir.path().join("var/lib/containerd")).unwrap();
    annotation.chains().clear();
    assert_eq!(
        annotation.identify(&container(Some(NAME))).await,
        Identified::Unknown(NO_CHAIN),
        "the image's blobs are gone"
    );
}

#[tokio::test]
async fn an_image_s_chain_id_is_read_once() {
    let image = image();
    let (_fake, mut annotation, dir) = node(
        &image,
        vec![snapshot(CONTAINER, &image.amd64.to_string(), false)],
    );
    // The image's amd64 manifest is a second target of the same chain ID.
    annotation.store = [
        (NAME.to_owned(), image.target.clone()),
        ("reg.test/app:2".to_owned(), amd64_manifest(&image)),
    ]
    .into_iter()
    .collect();
    let containers = [container(Some(NAME)), container(Some("reg.test/app:2"))];
    for container in &containers {
        assert!(matches!(
            annotation.identify(container).await,
            Identified::Listed { .. }
        ));
    }
    std::fs::remove_dir_all(dir.path().join("var/lib/containerd")).unwrap();
    for container in &containers {
        assert!(
            matches!(
                annotation.identify(container).await,
                Identified::Listed { .. }
            ),
            "the chain ID of each target is kept"
        );
    }
}

#[tokio::test]
async fn an_image_without_a_manifest_for_the_node_has_no_chain_id() {
    let image = image();
    let (_fake, mut annotation, _dir) = node(
        &image,
        vec![snapshot(CONTAINER, &image.amd64.to_string(), false)],
    );
    annotation.host.arch = "riscv64".to_owned();
    assert_eq!(
        annotation.identify(&container(Some(NAME))).await,
        Identified::Unknown(NO_CHAIN)
    );
}

#[tokio::test]
async fn a_single_platform_image_is_read_from_its_manifest() {
    let image = image();
    let (_fake, mut annotation, _dir) = node(
        &image,
        vec![snapshot(CONTAINER, &image.amd64.to_string(), false)],
    );
    let manifest = amd64_manifest(&image);
    annotation.store = [(NAME.to_owned(), manifest.clone())].into_iter().collect();
    assert_eq!(
        annotation.identify(&container(Some(NAME))).await,
        Identified::Listed {
            digest: manifest,
            name: NAME
        }
    );
}

#[tokio::test]
async fn the_snapshotter_is_the_image_service_s_or_the_default() {
    let image = image();
    let (_fake, annotation, dir) = node(&image, Vec::new());
    annotation.configure();
    assert_eq!(
        **annotation.snapshotter.load(),
        DEFAULT_SNAPSHOTTER,
        "no config"
    );
    let config = dir.path().join("etc/containerd/config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    std::fs::write(
        &config,
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"native\"\n",
    )
    .unwrap();
    annotation.configure();
    assert_eq!(**annotation.snapshotter.load(), "native");
    std::fs::write(
        &config,
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"\"\n",
    )
    .unwrap();
    annotation.configure();
    assert_eq!(
        **annotation.snapshotter.load(),
        DEFAULT_SNAPSHOTTER,
        "empty"
    );
    std::fs::write(
        &config,
        "version = 3\n[plugins.\"io.containerd.cri.v1.images\"]\nsnapshotter = \"native\"\n",
    )
    .unwrap();
    annotation.configure();
    std::fs::write(&config, "version = \n").unwrap();
    annotation.configure();
    assert_eq!(
        **annotation.snapshotter.load(),
        "native",
        "unreadable: containerd runs on the config it read"
    );
    std::fs::remove_file(&config).unwrap();
    annotation.configure();
    assert_eq!(
        **annotation.snapshotter.load(),
        DEFAULT_SNAPSHOTTER,
        "removed"
    );
}

#[tokio::test]
async fn the_store_follows_containerd_s_images() {
    let image = image();
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("containerd.sock");
    let mut answers = Answers::containerd("2.3.7");
    answers.snapshots = vec![snapshot(CONTAINER, &image.amd64.to_string(), false)];
    answers.image_store = vec![(NAME.to_owned(), image.target.to_string())];
    let _fake = Fake::start(&socket, answers).unwrap();
    put(dir.path(), &image.blobs);
    let containerd = Containerd::new(Paths::under(dir.path()), &socket, None);
    let annotation = Annotation::new(containerd.clone(), amd64());
    let container = container(Some(NAME));
    let identified = tokio::select! {
        () = annotation.follow() => panic!("following ends only when the agent stops"),
        identified = async {
            loop {
                if let identified @ Identified::Listed { .. } = annotation.identify(&container).await {
                    break identified;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        } => identified,
    };
    assert_eq!(
        identified,
        Identified::Listed {
            digest: image.target.clone(),
            name: NAME
        }
    );
}
