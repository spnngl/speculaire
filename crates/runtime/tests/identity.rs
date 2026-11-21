//! Each identity path on the `CreateContainer` requests a runtime sent, and the image list it held then.
//!
//! `recorded/<runtime>-<version>/` holds what an NRI plugin received for a pod run by tag (`tag.pb`) and by another
//! name, and `crictl images -o json` on the node right after.

use futures_util::FutureExt as _;
use prost::Message as _;
use speculaire_nri::api::{Container, CreateContainerRequest, PodSandbox};
use speculaire_oci::reference::Digest;
use speculaire_runtime::cri::ListedImage;
use speculaire_runtime::identity::{Identified, Identity, ImageId, Nri};
use speculaire_runtime::images::{Image, List, Update};

/// busybox:1.37's index, which both runtimes pulled.
const INDEX: &str = "sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec";
/// Its linux/arm64 manifest.
const ARM64: &str = "sha256:d82c2ab94640ded77cf76514ce6a84870761105058a4a9e51b05a8a79be97a6c";
/// Its linux/arm64 config: the image ID on both runtimes.
const CONFIG: &str = "sha256:ad4f11f7c85f87c0a6d6c0fe492ad53f9cdcff6e8c88b881360c70eff701c67b";

fn recorded(path: &str) -> Vec<u8> {
    let path = format!("{}/tests/recorded/{path}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).expect("a recording")
}

fn container(path: &str) -> Container {
    let request = CreateContainerRequest::decode(recorded(path).as_slice()).expect("a request");
    request.container.expect("a container")
}

/// The image list in `crictl images -o json`.
fn list(path: &str) -> List {
    let json: serde_json::Value = serde_json::from_slice(&recorded(path)).expect("JSON");
    let strings = |image: &serde_json::Value, key: &str| -> Vec<String> {
        image[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|text| Some(text.as_str()?.to_owned()))
            .collect()
    };
    let images = json["images"].as_array().expect("images");
    let images = images.iter().filter_map(|image| {
        Image::from_listed(&ListedImage {
            id: image["id"].as_str()?.to_owned(),
            repo_tags: strings(image, "repoTags"),
            repo_digests: strings(image, "repoDigests"),
        })
    });
    let mut list = List::default();
    list.apply(Update::Listing(images.collect()));
    list
}

fn identify<'a>(identity: &'a impl Identity, container: &'a Container) -> Identified<'a> {
    identity
        .identify(&PodSandbox::default(), container)
        .now_or_never()
        .expect("the path reads the request alone")
}

fn digest(text: &str) -> Digest {
    Digest::parse(text).expect("a digest")
}

/// containerd names the digest of the image's index, by tag or by platform manifest digest alike: the target of the
/// image it resolved, which is a repository digest it lists for the image.
#[test]
fn nri_on_containerd_2_4_2_reads_the_index_the_image_was_listed_with() {
    let list = list("containerd-2.4.2/images.json");
    let image = list
        .images()
        .find(|image| image.id == digest(CONFIG))
        .expect("busybox");
    for path in ["containerd-2.4.2/tag.pb", "containerd-2.4.2/digest.pb"] {
        let container = container(path);
        let identified = identify(&Nri, &container);
        let want = Identified::Listed {
            digest: digest(INDEX),
            name: "docker.io/library/busybox:1.37",
        };
        assert_eq!(identified, want, "{path}");
        let repo_digests: Vec<_> = image.repo_digests.iter().map(|repo| &repo.digest).collect();
        assert!(repo_digests.contains(&&digest(INDEX)), "{repo_digests:?}");
        assert!(repo_digests.contains(&&digest(ARM64)), "{repo_digests:?}");
    }
}

/// CRI-O names the image ID, whichever name the pod used: the identity is every listed manifest of the image, and its
/// names are both repositories it was pulled from.
#[test]
fn image_id_on_cri_o_1_37_2_reads_every_manifest_and_name_of_the_image() {
    let image_id = ImageId::default();
    image_id.keep(&list("crio-1.37.2/images.json"));
    for path in ["crio-1.37.2/tag.pb", "crio-1.37.2/mirror.pb"] {
        let container = container(path);
        assert!(container.image.is_none(), "CRI-O fills no Container.image");
        let identified = identify(&image_id, &container);
        let Identified::Image(image) = &identified else {
            panic!("{path}: {identified:?}");
        };
        assert_eq!(image.id, digest(CONFIG), "{path}");
        let digests: Vec<_> = identified.digests().collect();
        assert_eq!(digests, [&digest(INDEX), &digest(ARM64)], "{path}");
        let names: Vec<_> = identified.names().collect();
        let want = ["docker.io/library/busybox", "mirror.gcr.io/library/busybox"];
        assert_eq!(names, want, "{path}");
    }
}

/// On CRI-O the Configure call announces NRI v0.12.2 but `Container.image` stays empty: `nri` reads no identity there,
/// so the path is chosen by the runtime's name.
#[test]
fn nri_on_cri_o_1_37_2_reads_no_identity() {
    let container = container("crio-1.37.2/tag.pb");
    assert!(matches!(identify(&Nri, &container), Identified::Unknown(_)));
}
