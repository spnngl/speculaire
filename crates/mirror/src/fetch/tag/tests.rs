//! Tags resolved by real peer APIs over mutual TLS.

use std::collections::HashMap;
use std::time::Duration;

use http::StatusCode;
use speculaire_runtime::images::{Image, RepoDigest};

use super::*;
use crate::fetch::Settings;
use crate::fetch::tests::{Held, Nodes, SETTINGS, assert_counted, pattern, recorder, sha};
use crate::listed::Listed;
use crate::pulls::{Answer, Local, Pull, Pulls as _};
use crate::request::{Kind, Reference};

const TAG: &str = "docker.io/library/busybox:1.37";

fn tagged() -> Tagged {
    Tagged::parse(TAG).unwrap()
}

fn index(seed: u8) -> Bytes {
    Bytes::from(format!(
        r#"{{"schemaVersion":2,"manifests":[],"annotations":{{"seed":"{seed}"}}}}"#
    ))
}

/// The runtime list of a node that pulled [`TAG`] by `digest`.
fn listing(digest: &Digest) -> Listed {
    Listed::of(vec![Image {
        id: sha(b"config"),
        repo_digests: vec![RepoDigest {
            repository: "docker.io/library/busybox".to_owned(),
            digest: digest.clone(),
        }],
        tags: vec![tagged()],
    }])
}

/// The peer API of `node`, which pulled [`TAG`] by `manifest`'s digest and holds `manifest` when `held`.
async fn holder(nodes: &mut Nodes, node: &str, manifest: &Bytes, held: bool) -> Holder {
    let digest = sha(manifest);
    let blobs: &[(&Digest, &Bytes)] = if held { &[(&digest, manifest)] } else { &[] };
    nodes.listing(node, blobs, listing(&digest), 4).await.0
}

#[tokio::test]
async fn a_tag_resolves_from_a_holder_that_answers_after_one_that_does_not() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let manifest = index(1);
    let lacking = holder(&mut nodes, "node-a", &manifest, false).await;
    let holding = holder(&mut nodes, "node-b", &manifest, true).await;
    let fetcher = nodes.fetcher(vec![lacking, holding], SETTINGS);
    let resolved = fetcher.tag(&tagged()).await.expect("node-b resolves it");
    assert_eq!(resolved.digest, sha(&manifest));
    assert_eq!(resolved.bytes, manifest);
    assert_eq!(
        resolved.media_type,
        "application/vnd.oci.image.index.v1+json"
    );
    assert_counted(
        &handle,
        &[r#"speculaire_tag_lookups_total{result="peer"} 1"#],
    );

    // containerd names the registry apart, and asks for the head.
    let local = Local::new(Held(HashMap::new()), fetcher);
    let reference = Reference::Tag("1.37");
    let pull = Pull {
        kind: Kind::Manifest,
        name: "library/busybox",
        namespace: Some("docker.io"),
        reference: Some(&reference),
        head: true,
        range: None,
        accept: None,
    };
    let Answer::Served(source, response) = local.pull(pull).await else {
        panic!("a tag a peer holds is served");
    };
    assert_eq!(source, crate::metrics::Source::Peer);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["docker-content-digest"],
        sha(&manifest).to_string().as_str()
    );
    assert!(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
}

#[tokio::test]
async fn two_holders_that_disagree_are_counted_and_the_first_answer_is_served() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let (one, two) = (index(1), index(2));
    let a = holder(&mut nodes, "node-a", &one, true).await;
    let b = holder(&mut nodes, "node-b", &two, true).await;
    let fetcher = nodes.fetcher(vec![a, b], SETTINGS);
    let resolved = fetcher.tag(&tagged()).await.expect("both resolve it");
    assert!([sha(&one), sha(&two)].contains(&resolved.digest));
    let conflict = "speculaire_tag_conflicts_total 1";
    tokio::time::timeout(Duration::from_secs(10), async {
        while !handle.render().lines().any(|line| line == conflict) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the second answer is compared");
}

#[tokio::test]
async fn a_tag_no_holder_answers_with_a_manifest_is_a_miss_and_resolve_tags_off_asks_none() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    // A holder whose content under the digest is no manifest.
    let blob = pattern(100, 0);
    let digest = sha(&blob);
    let not_manifest = nodes
        .listing("node-a", &[(&digest, &blob)], listing(&digest), 4)
        .await
        .0;
    let fetcher = nodes.fetcher(vec![not_manifest], SETTINGS);
    assert!(fetcher.tag(&tagged()).await.is_none());
    assert!(
        nodes
            .fetcher(Vec::new(), SETTINGS)
            .tag(&tagged())
            .await
            .is_none()
    );
    assert_counted(
        &handle,
        &[r#"speculaire_tag_lookups_total{result="miss"} 2"#],
    );

    let holding = holder(&mut nodes, "node-b", &index(1), true).await;
    let off = Settings {
        resolve_tags: false,
        ..SETTINGS
    };
    assert!(
        nodes
            .fetcher(vec![holding], off)
            .tag(&tagged())
            .await
            .is_none()
    );
    assert_counted(
        &handle,
        &[
            r#"speculaire_tag_lookups_total{result="miss"} 2"#,
            r#"speculaire_tag_lookups_total{result="peer"} 0"#,
        ],
    );
}
