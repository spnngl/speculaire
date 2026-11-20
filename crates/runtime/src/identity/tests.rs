//! Each path on requests made up for the cases a runtime does not record; `tests/identity.rs` has recorded ones.

use futures_util::FutureExt as _;
use speculaire_nri::api;

use super::*;
use crate::cri::ListedImage;
use crate::detect::Runtime;
use crate::images::Update;

const ID: &str = "ad4f11f7c85f87c0a6d6c0fe492ad53f9cdcff6e8c88b881360c70eff701c67b";

fn digest(byte: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
}

fn listed(id: &str, repo_tags: &[&str], repo_digests: &[&str]) -> List {
    let listed = ListedImage {
        id: id.to_owned(),
        repo_tags: repo_tags.iter().map(|&tag| tag.to_owned()).collect(),
        repo_digests: repo_digests.iter().map(|&repo| repo.to_owned()).collect(),
    };
    let mut list = List::default();
    list.apply(Update::Listing(vec![Image::from_listed(&listed).unwrap()]));
    list
}

fn identify<'a>(identity: &'a impl Identity, container: &'a Container) -> Identified<'a> {
    identity
        .identify(container)
        .now_or_never()
        .expect("the path reads the request alone")
}

fn annotated(image_ref: &str) -> Container {
    Container {
        annotations: [(IMAGE_REF.to_owned(), image_ref.to_owned())].into(),
        ..Container::default()
    }
}

#[test]
fn nri_reads_the_image_digest_and_name() {
    let container = Container {
        image: Some(api::Image {
            name: "docker.io/library/busybox:1.37".to_owned(),
            digest: digest(1).to_string(),
            config_digest: digest(2).to_string(),
        }),
        ..Container::default()
    };
    let identified = identify(&Nri, &container);
    let want = Identified::Listed {
        digest: digest(1),
        name: "docker.io/library/busybox:1.37",
    };
    assert_eq!(identified, want);
    assert_eq!(identified.digests().collect::<Vec<_>>(), [&digest(1)]);
    assert_eq!(
        identified.names().collect::<Vec<_>>(),
        ["docker.io/library/busybox:1.37"]
    );
}

#[test]
fn nri_without_an_image_name_or_digest_reads_no_identity() {
    let image = |name: &str, digest: &str| api::Image {
        name: name.to_owned(),
        digest: digest.to_owned(),
        config_digest: String::new(),
    };
    for image in [
        None,
        Some(image("", &digest(1).to_string())),
        Some(image("busybox:1.37", "")),
        Some(image("busybox:1.37", "sha256:00")),
    ] {
        let container = Container {
            image: image.clone(),
            ..Container::default()
        };
        let identified = identify(&Nri, &container);
        assert_eq!(identified, Identified::Unknown(MISSING), "{image:?}");
        assert_eq!(identified.digests().count(), 0);
        assert_eq!(identified.names().count(), 0);
    }
}

#[test]
fn image_id_reads_the_listed_image_with_every_manifest_and_repository_once() {
    let image_id = ImageId::default();
    let a = format!("{}", digest(0xa));
    let b = format!("{}", digest(0xb));
    image_id.keep(&listed(
        ID,
        &["reg.test/one:1", "reg.test/two:2", "reg.test/three:3"],
        &[
            &format!("reg.test/one@{a}"),
            &format!("reg.test/one@{b}"),
            &format!("reg.test/two@{a}"),
            &format!("reg.test/two@{b}"),
        ],
    ));
    for image_ref in [ID.to_owned(), format!("sha256:{ID}")] {
        let container = annotated(&image_ref);
        let identified = identify(&image_id, &container);
        let Identified::Image(image) = &identified else {
            panic!("{image_ref}: {identified:?}");
        };
        assert_eq!(image.id.encoded(), ID);
        let digests: Vec<_> = identified.digests().collect();
        assert_eq!(digests, [&digest(0xa), &digest(0xb)]);
        let names: Vec<_> = identified.names().collect();
        assert_eq!(names, ["reg.test/one", "reg.test/two", "reg.test/three"]);
    }
}

#[test]
fn image_id_without_a_listed_image_reads_no_identity() {
    let image_id = ImageId::default();
    let unlisted = annotated(ID);
    assert_eq!(
        identify(&image_id, &unlisted),
        Identified::Unknown(NOT_CONFIG)
    );
    image_id.keep(&listed(ID, &["reg.test/one:1"], &[]));
    let Identified::Image(image) = identify(&image_id, &unlisted) else {
        panic!("the image is listed now");
    };
    assert_eq!(image.repo_digests, []);
    let other = "0".repeat(64);
    image_id.keep(&listed(&other, &[], &[]));
    assert_eq!(
        identify(&image_id, &unlisted),
        Identified::Unknown(NOT_CONFIG),
        "the list is replaced"
    );
    for bad in ["", "ad4f", &format!("{ID}0"), "sha256:", "é"] {
        assert_eq!(
            identify(&image_id, &annotated(bad)),
            Identified::Unknown(NOT_CONFIG),
            "{bad:?}"
        );
    }
    assert_eq!(
        identify(&image_id, &Container::default()),
        Identified::Unknown(MISSING)
    );
}

#[test]
fn each_runtime_has_its_path_and_cri_o_alone_keeps_the_list() {
    let list = listed(ID, &[], &[&format!("reg.test/one@{}", digest(0xa))]);
    let nri = NodeIdentity::of(Runtime::Containerd);
    nri.keep(&list);
    assert_eq!(nri.path(), "nri");
    assert_eq!(identify(&nri, &annotated(ID)), Identified::Unknown(MISSING));
    let image_id = NodeIdentity::of(Runtime::CriO);
    image_id.keep(&list);
    assert_eq!(image_id.path(), "image_id");
    assert!(matches!(
        identify(&image_id, &annotated(ID)),
        Identified::Image(_)
    ));
}
