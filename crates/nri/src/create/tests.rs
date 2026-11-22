use std::collections::HashMap;

use prost::Message as _;

use super::*;
use crate::api::{self, CreateContainerRequest, PodSandbox};
use crate::testing::agrees;

/// Seeded requests, each compared with prost's decoding of the same bytes.
const CASES: u64 = 512;

/// Strings drawn from these: empty, ASCII, multibyte, and the annotations the gate looks up.
const WORDS: [&str; 8] = [
    "",
    "a",
    "team",
    "io.kubernetes.cri.image-name",
    "io.kubernetes.cri-o.ImageRef",
    "registry.test/team/app:1.0",
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "émoji 🦀 ünïcode",
];

fn word(rng: &mut fastrand::Rng) -> String {
    let count = rng.usize(0..3);
    (0..count)
        .map(|_| WORDS[rng.usize(..WORDS.len())])
        .collect()
}

fn map(rng: &mut fastrand::Rng) -> HashMap<String, String> {
    (0..rng.usize(0..6))
        .map(|_| (word(rng), word(rng)))
        .collect()
}

fn pod(rng: &mut fastrand::Rng) -> PodSandbox {
    PodSandbox {
        id: word(rng),
        name: word(rng),
        uid: word(rng),
        namespace: word(rng),
        labels: map(rng),
        annotations: map(rng),
        runtime_handler: word(rng),
    }
}

fn container(rng: &mut fastrand::Rng) -> api::Container {
    api::Container {
        id: word(rng),
        pod_sandbox_id: word(rng),
        name: word(rng),
        state: rng.i32(0..5),
        labels: map(rng),
        annotations: map(rng),
        image: rng.bool().then(|| api::Image {
            name: word(rng),
            digest: word(rng),
            config_digest: word(rng),
        }),
    }
}

/// Fields of each wire type that neither reader knows, numbered from `first`, as the runtime's whole messages carry.
fn unknown(rng: &mut fastrand::Rng, first: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..rng.usize(0..4) {
        let field = rng.u32(first..first + 8);
        match rng.u8(0..4) {
            0 => prost::encoding::uint64::encode(field, &rng.u64(..), &mut bytes),
            1 => prost::encoding::fixed64::encode(field, &rng.u64(..), &mut bytes),
            2 => prost::encoding::string::encode(field, &word(rng), &mut bytes),
            _ => prost::encoding::fixed32::encode(field, &rng.u32(..), &mut bytes),
        }
    }
    bytes
}

/// A `CreateContainerRequest` with unknown fields in each message, its pod and container each written in one part or
/// two, which protobuf merges.
fn request(rng: &mut fastrand::Rng) -> Vec<u8> {
    let mut bytes = Vec::new();
    for _ in 0..rng.usize(0..3) {
        if rng.bool() {
            let mut pod = pod(rng).encode_to_vec();
            pod.extend(unknown(rng, 8));
            prost::encoding::bytes::encode(POD, &pod, &mut bytes);
        }
        if rng.bool() {
            let mut container = container(rng).encode_to_vec();
            container.extend(unknown(rng, 7));
            prost::encoding::bytes::encode(CONTAINER, &container, &mut bytes);
        }
        bytes.extend(unknown(rng, 3));
    }
    bytes
}

#[test]
fn reads_what_prost_decodes() {
    let mut rng = fastrand::Rng::with_seed(0x5eed);
    for case in 0..CASES {
        let bytes = request(&mut rng);
        let decoded = CreateContainerRequest::decode(bytes.as_slice()).expect("prost decodes");
        let read = Request::read(&bytes).expect("the request reads");
        assert!(
            agrees(&read, &decoded),
            "case {case}: {read:?} != {decoded:?}"
        );
    }
}

#[test]
fn a_later_annotation_replaces_an_earlier_one_across_parts() {
    let part = |value: &str| {
        let container = api::Container {
            annotations: [("key".to_owned(), value.to_owned())].into(),
            ..api::Container::default()
        };
        CreateContainerRequest {
            pod: None,
            container: Some(container),
        }
        .encode_to_vec()
    };
    let bytes = [part("first"), part("second")].concat();
    let read = Request::read(&bytes).expect("the request reads");
    let annotations = read.container.expect("a container").annotations;
    assert_eq!(annotations.get("key"), Some("second"));
    assert_eq!(annotations.get("other"), None);
    assert_eq!(
        format!("{annotations:?}"),
        r#"{"key": "first", "key": "second"}"#
    );
}

#[test]
fn a_field_read_refuses_what_prost_refuses() {
    // The pod's namespace, field 4, as a varint; its name, field 2, not UTF-8.
    let namespace = [0x0a, 2, 0x20, 1];
    let name = [0x0a, 3, 0x12, 1, 0xff];
    // A container image, field 22, whose key is two bytes, cut short.
    let image = [0x12, 3, 0xb2, 0x01, 5];
    // An annotation, field 6, of the pod and of the container, whose key is not UTF-8.
    let pod_annotation = [0x0a, 5, 0x32, 3, 0x0a, 1, 0xff];
    let container_annotation = [0x12, 5, 0x32, 3, 0x0a, 1, 0xff];
    for bytes in [
        &namespace[..],
        &name,
        &image,
        &pod_annotation,
        &container_annotation,
    ] {
        assert!(Request::read(bytes).is_err(), "{bytes:?}");
        assert!(CreateContainerRequest::decode(bytes).is_err(), "{bytes:?}");
    }
    assert_eq!(
        Request::read(&namespace).err(),
        Some(Error::WireType {
            field: 4,
            wire_type: 0
        })
    );
    assert_eq!(Request::read(&name).err(), Some(Error::Utf8 { field: 2 }));
}

#[test]
fn an_empty_request_has_no_pod_and_no_container() {
    let read = Request::read(&[]).expect("an empty message reads");
    assert!(read.pod.is_none() && read.container.is_none());
    assert_eq!(Annotations::default().get(""), None);
}

#[test]
fn a_group_prost_skips_is_refused() {
    // The pod's field 8, unknown to both, as a group holding a varint; then its namespace.
    let bytes = [0x0a, 6, 0x43, 0x08, 1, 0x44, 0x22, 0];
    assert!(CreateContainerRequest::decode(&bytes[..]).is_ok());
    assert_eq!(
        Request::read(&bytes).err(),
        Some(Error::Unread {
            field: 8,
            wire_type: 3
        })
    );
}
