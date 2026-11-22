//! Each path on requests made up for the cases a runtime does not record; `tests/identity.rs` has recorded ones.

use futures_util::FutureExt as _;
use speculaire_nri::api;
use speculaire_nri::version::InferError;
use speculaire_oci::platform::Host;

use super::*;
use crate::containerd::Containerd;
use crate::cri::ListedImage;
use crate::images::Update;
use crate::paths::Paths;

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
        .identify(&api::PodSandbox::default(), container)
        .now_or_never()
        .expect("the path reads the request alone")
}

fn annotated(image_ref: &str) -> Container {
    Container {
        annotations: [(IMAGE_REF.to_owned(), image_ref.to_owned())].into(),
        ..Container::default()
    }
}

/// A container of the image of `ID`, listed with digest 1, which containerd names `name` and the pod `asked` for.
fn nri_container(name: &str, asked: Option<&str>) -> Container {
    Container {
        annotations: asked
            .map(|asked| (annotation::IMAGE_NAME.to_owned(), asked.to_owned()))
            .into_iter()
            .collect(),
        image: Some(api::Image {
            name: name.to_owned(),
            digest: digest(1).to_string(),
            config_digest: format!("sha256:{ID}"),
        }),
        ..Container::default()
    }
}

fn unconfirmed(names: &[&str]) -> Identified<'static> {
    Identified::Unconfirmed {
        digest: digest(1),
        names: names.iter().map(|&name| name.to_owned()).collect(),
    }
}

#[test]
fn nri_reads_the_image_digest_and_the_name_the_pod_asked_for_once_the_list_names_the_image_by_it() {
    let nri = Nri::default();
    let two = nri_container("reg.test/one:1", Some("reg.test/two:2"));
    let identified = identify(&nri, &two);
    assert_eq!(
        identified,
        unconfirmed(&["reg.test/two", "reg.test/one"]),
        "unlisted: every name"
    );
    assert_eq!(identified.identity(), Some(&digest(1)));
    assert_eq!(identified.digests().collect::<Vec<_>>(), [&digest(1)]);
    assert_eq!(
        identified.names().collect::<Vec<_>>(),
        ["reg.test/two", "reg.test/one"]
    );

    let by_digest = format!("reg.test/two@{}", digest(1));
    nri.keep(&listed(
        ID,
        &[
            "reg.test/one:1",
            "reg.test/two:2",
            "docker.io/library/busybox:1.37",
        ],
        &[&by_digest],
    ));
    let identified = identify(&nri, &two);
    let want = Identified::Listed {
        digest: digest(1),
        name: "reg.test/two:2",
    };
    assert_eq!(identified, want);
    assert_eq!(identified.names().collect::<Vec<_>>(), ["reg.test/two:2"]);
    for asked in ["busybox:1.37", by_digest.as_str()] {
        let container = nri_container("reg.test/one:1", Some(asked));
        let want = Identified::Listed {
            digest: digest(1),
            name: asked,
        };
        assert_eq!(identify(&nri, &container), want, "{asked}");
    }

    let every = ["reg.test/one", "reg.test/two", "docker.io/library/busybox"];
    let three = [&["reg.test/three"][..], &every].concat();
    for (asked, names) in [
        (Some("reg.test/three:3"), &three[..]),
        (Some("not a name"), &every[..]),
        (None, &every[..]),
    ] {
        let container = nri_container("reg.test/one:1", asked);
        assert_eq!(identify(&nri, &container), unconfirmed(names), "{asked:?}");
    }
}

/// containerd's digest is its first name's manifest: the pod's repository has its own, which stands for the image.
#[test]
fn nri_takes_the_manifest_listed_for_the_repository_the_pod_asked_for() {
    let nri = Nri::default();
    let (one, two) = (
        format!("reg.test/one@{}", digest(1)),
        format!("reg.test/two@{}", digest(3)),
    );
    nri.keep(&listed(
        ID,
        &["reg.test/one:1", "reg.test/two:2"],
        &[&one, &two],
    ));
    let container = nri_container("reg.test/one:1", Some("reg.test/two:2"));
    let want = Identified::Listed {
        digest: digest(3),
        name: "reg.test/two:2",
    };
    assert_eq!(identify(&nri, &container), want);
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
        let nri = Nri::default();
        let identified = identify(&nri, &container);
        assert_eq!(identified, Identified::Unknown(MISSING), "{image:?}");
        assert_eq!(identified.identity(), None);
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
        assert_eq!(identified.identity(), Some(&image.id));
        let digests: Vec<_> = identified.digests().collect();
        assert_eq!(digests, [&digest(0xa), &digest(0xb)]);
        let names: Vec<_> = identified.names().collect();
        assert_eq!(names, ["reg.test/one", "reg.test/two", "reg.test/three"]);
    }
}

#[test]
fn image_id_without_a_listed_image_is_unlisted_until_a_list_names_it() {
    let image_id = ImageId::default();
    let unlisted = annotated(ID);
    assert_eq!(identify(&image_id, &unlisted), Identified::Unlisted);
    assert_eq!(Identified::Unlisted.identity(), None);
    assert_eq!(Identified::Mismatched.identity(), None);
    image_id.keep(&listed(ID, &["reg.test/one:1"], &[]));
    let Identified::Image(image) = identify(&image_id, &unlisted) else {
        panic!("the image is listed now");
    };
    assert_eq!(image.repo_digests, []);
    let other = "0".repeat(64);
    image_id.keep(&listed(&other, &[], &[]));
    assert_eq!(
        identify(&image_id, &unlisted),
        Identified::Unlisted,
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

fn containerd() -> (NodeIdentity, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let containerd = Containerd::new(
        Paths::under(dir.path()),
        dir.path().join("containerd.sock"),
        None,
    );
    let identity = NodeIdentity::containerd(Annotation::new(containerd, Host::current()));
    (identity, dir)
}

#[test]
fn each_runtime_has_its_path() {
    let list = listed(ID, &[], &[&format!("reg.test/one@{}", digest(0xa))]);
    let (nri, _dir) = containerd();
    nri.keep(&list);
    assert_eq!(nri.path(), "nri");
    assert_eq!(identify(&nri, &annotated(ID)), Identified::Unknown(MISSING));
    let image_id = NodeIdentity::crio();
    image_id.keep(&list);
    assert_eq!(image_id.path(), "image_id");
    assert_eq!(
        image_id.configure(&NriVersion::Announced("v0.12.0".to_owned())),
        "image_id",
        "CRI-O's path is by name"
    );
    assert!(matches!(
        identify(&image_id, &annotated(ID)),
        Identified::Image(_)
    ));
}

#[test]
fn the_image_name_is_the_names_policies_match_and_else_containerd_s_annotation() {
    let mut container = annotated(ID);
    container
        .annotations
        .insert(annotation::IMAGE_NAME.to_owned(), "busybox:1.37".to_owned());
    let (containerd, _dir) = containerd();
    assert_eq!(containerd.image_name(&container, None), "busybox:1.37");
    assert_eq!(containerd.image_name(&Container::default(), None), "");
    let unknown = Identified::Unknown(MISSING);
    assert_eq!(
        containerd.image_name(&container, Some(&unknown)),
        "busybox:1.37"
    );
    let every = unconfirmed(&["docker.io/library/busybox", "reg.test/one"]);
    assert_eq!(
        containerd.image_name(&container, Some(&every)),
        "docker.io/library/busybox, reg.test/one"
    );

    let crio = NodeIdentity::crio();
    crio.keep(&listed(ID, &["reg.test/one:1", "reg.test/two:2"], &[]));
    let identified = identify(&crio, &container);
    assert_eq!(
        crio.image_name(&container, Some(&identified)),
        "reg.test/one, reg.test/two"
    );
    assert_eq!(crio.image_name(&container, None), "");
}

#[test]
fn containerd_reads_the_annotation_below_nri_v0_12_2_or_an_unknown_version() {
    let (identity, _dir) = containerd();
    let unknown = NriVersion::Unknown {
        announced: String::new(),
        error: InferError::NoMatch("v1.7.0".to_owned()),
    };
    for (version, path) in [
        (NriVersion::Announced("v0.12.0".to_owned()), "annotation"),
        (NriVersion::Announced("v0.12.2".to_owned()), "nri"),
        (NriVersion::Inferred("v0.11.0"), "annotation"),
        (NriVersion::Announced("v0.12.3".to_owned()), "nri"),
        (unknown, "annotation"),
        (NriVersion::Inferred("v0.12.2"), "nri"),
        (NriVersion::Announced("v0.12.1".to_owned()), "annotation"),
        (NriVersion::Announced("v1.0.0".to_owned()), "nri"),
        (NriVersion::Announced("devel".to_owned()), "annotation"),
    ] {
        assert_eq!(identity.configure(&version), path, "{version:?}");
        assert_eq!(identity.path(), path, "{version:?}");
    }
    let container = Container {
        image: Some(api::Image {
            name: "docker.io/library/busybox:1.37".to_owned(),
            digest: digest(1).to_string(),
            config_digest: digest(2).to_string(),
        }),
        ..Container::default()
    };
    assert_eq!(
        identify(&identity, &container),
        Identified::Unknown(MISSING),
        "the annotation path reads no `Container.image`"
    );
    identity.configure(&NriVersion::Announced("v0.12.3".to_owned()));
    assert_eq!(
        identify(&identity, &container),
        unconfirmed(&["docker.io/library/busybox"]),
        "the nri path reads `Container.image` again"
    );
}
