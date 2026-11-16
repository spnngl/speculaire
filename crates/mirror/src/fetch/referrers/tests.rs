//! Referrers listed by real peer APIs over mutual TLS.

use std::collections::{HashMap, HashSet};

use bytes::Bytes;
use speculaire_oci::referrers::{BUNDLE, EMPTY, MANIFEST};
use speculaire_runtime::content::{Blob, Content, Error};

use super::*;
use crate::fetch::tests::{Fault, Held, Nodes, SETTINGS, behind, held, sha};
use crate::listed::Listed;

/// Artifact manifests, every one about `target`.
struct About {
    manifests: Held,
    target: Digest,
}

impl Content for About {
    fn open(&self, digest: &Digest) -> impl Future<Output = Result<Option<Blob>, Error>> + Send {
        self.manifests.open(digest)
    }
}

impl crate::referrers::Referrers for About {
    fn referrers(&self, target: &Digest) -> Vec<Digest> {
        if *target == self.target {
            self.manifests.0.keys().cloned().collect()
        } else {
            Vec::new()
        }
    }
}

fn target() -> Digest {
    sha(b"target")
}

/// A bundle about [`target`], told apart by `seed`.
fn bundle(seed: u8) -> Bytes {
    annotated(seed, 0)
}

/// A bundle about [`target`], told apart by `seed`, with an annotation of `size` bytes.
fn annotated(seed: u8, size: usize) -> Bytes {
    Bytes::from(format!(
        r#"{{"schemaVersion":2,"mediaType":"{MANIFEST}","artifactType":"{BUNDLE}",
            "subject":{{"mediaType":"{MANIFEST}","digest":"{}","size":1}},
            "config":{{"mediaType":"{EMPTY}","digest":"{}","size":2}},
            "layers":[{{"mediaType":"{BUNDLE}","digest":"{}","size":10}}],
            "annotations":{{"padding":"{}"}}}}"#,
        target(),
        sha(b"{}"),
        sha(&[seed]),
        "x".repeat(size),
    ))
}

/// The peer API of `node`, holding the bundles `seeds` about [`target`].
async fn holder(nodes: &mut Nodes, node: &str, seeds: &[u8]) -> Holder {
    serving(
        nodes,
        node,
        seeds.iter().map(|&seed| bundle(seed)).collect(),
    )
    .await
}

/// The peer API of `node`, holding the bundles `manifests` about [`target`].
async fn serving(nodes: &mut Nodes, node: &str, manifests: Vec<Bytes>) -> Holder {
    let manifests: Vec<(Digest, Bytes)> = manifests
        .into_iter()
        .map(|manifest| (sha(&manifest), manifest))
        .collect();
    let refs: Vec<(&Digest, &Bytes)> = manifests.iter().map(|(d, b)| (d, b)).collect();
    let about = About {
        manifests: held(&refs),
        target: target(),
    };
    nodes
        .serving(node, Held(HashMap::new()), Listed::of(Vec::new()), about, 4)
        .await
        .0
}

fn digests(listed: &[Descriptor]) -> HashSet<Digest> {
    listed.iter().map(|d| d.digest.clone()).collect()
}

fn of(seeds: &[u8]) -> HashSet<Digest> {
    seeds.iter().map(|&seed| sha(&bundle(seed))).collect()
}

#[tokio::test]
async fn the_lists_of_the_holders_are_unioned_each_referrer_once() {
    let mut nodes = Nodes::new();
    let a = holder(&mut nodes, "node-a", &[1, 2]).await;
    let b = holder(&mut nodes, "node-b", &[2, 3]).await;
    let listed = nodes
        .fetcher(vec![a, b], SETTINGS)
        .referrers(&target())
        .await;
    assert_eq!(listed.len(), 3);
    assert_eq!(digests(&listed), of(&[1, 2, 3]));
    assert!(
        listed
            .iter()
            .all(|d| d.artifact_type.as_deref() == Some(BUNDLE))
    );
}

#[tokio::test]
async fn only_the_first_holders_are_asked_and_a_denied_one_is_not() {
    let mut nodes = Nodes::new();
    let mut holders = Vec::new();
    for seed in 1..=6 {
        holders.push(holder(&mut nodes, &format!("node-{seed}"), &[seed]).await);
    }
    let fetcher = nodes.fetcher(holders.clone(), SETTINGS);
    assert_eq!(
        digests(&fetcher.referrers(&target()).await),
        of(&[1, 2, 3, 4])
    );
    fetcher.0.deny(&holders[..1], &target());
    assert_eq!(
        digests(&fetcher.referrers(&target()).await),
        of(&[2, 3, 4, 5])
    );
}

#[tokio::test]
async fn an_unlinked_fetcher_or_a_holder_without_an_index_lists_nothing() {
    let mut nodes = Nodes::new();
    let unlinked = Fetcher::new(std::path::PathBuf::new(), SETTINGS);
    assert_eq!(unlinked.referrers(&target()).await, []);
    // A holder that is gone: its port is closed.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gone = Holder {
        node: "node-gone".to_owned(),
        address: closed.local_addr().unwrap(),
    };
    drop(closed);
    let none = holder(&mut nodes, "node-none", &[]).await;
    let fetcher = nodes.fetcher(vec![gone, none], SETTINGS);
    assert_eq!(fetcher.referrers(&target()).await, []);
}

#[tokio::test]
async fn an_index_larger_than_a_manifest_or_cut_short_lists_nothing() {
    let mut nodes = Nodes::new();
    // Three annotations of 1.5 MiB make an index above the 4 MiB of a manifest.
    let large: Vec<Bytes> = (1..=3).map(|seed| annotated(seed, 3 << 19)).collect();
    let large = serving(&mut nodes, "node-large", large).await;
    // An index of 128 KiB, of which the answer carries 64 KiB.
    let whole = serving(&mut nodes, "node-cut", vec![annotated(4, 128 << 10)]).await;
    let cut = behind(&whole, Fault::Cut(64 << 10)).await;
    let fetcher = nodes.fetcher(vec![large, cut], SETTINGS);
    assert_eq!(fetcher.referrers(&target()).await, []);
    // The whole index of the second lists its bundle.
    let fetcher = nodes.fetcher(vec![whole], SETTINGS);
    assert_eq!(fetcher.referrers(&target()).await.len(), 1);
}
