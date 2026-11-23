//! Discovery from real peer APIs over mutual TLS, each serving a real artifact store.

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::future::BoxFuture;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use serde_json::{Value, json};
use speculaire_mirror::fetch::{Fetcher, Holder, Lookup};
use speculaire_mirror::listed::Listed;
use speculaire_mirror::peer::{Uploads, serve};
use speculaire_oci::referrers::{BUNDLE, COSIGN_ATTESTATION, EMPTY, INDEX, MANIFEST};
use speculaire_pki::node::Credentials;
use speculaire_pki::testing::Cluster;
use speculaire_runtime::content::{self, Blob};
use speculaire_runtime::images::{Images, Update};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::super::tests::{NAME, SETTINGS, Test};
use super::*;
use crate::discover::{Error, Limits, Reason};
use crate::store::Store;

/// The node that discovers.
const NODE: &str = "node-b";

/// Blobs held in memory: a node's runtime content.
#[derive(Default)]
struct Held(HashMap<Digest, Bytes>);

impl Held {
    fn put(&mut self, bytes: impl Into<Bytes>) -> Digest {
        let bytes = bytes.into();
        let digest = digest_of(&bytes);
        self.0.insert(digest.clone(), bytes);
        digest
    }
}

impl Content for Held {
    fn open(
        &self,
        digest: &Digest,
    ) -> impl Future<Output = Result<Option<Blob>, content::Error>> + Send {
        std::future::ready(Ok(self.0.get(digest).cloned().map(Blob::from_bytes)))
    }
}

/// An image list that never lists anything.
struct NoImages;

impl Images for NoImages {
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
        Box::pin(async move { updates.closed().await })
    }
}

/// Holders per digest: a scripted digest answers each list in turn, then its last again; any other answers `all`.
struct Script {
    all: Vec<Holder>,
    turns: Mutex<HashMap<Digest, VecDeque<Vec<Holder>>>>,
}

impl Lookup for Script {
    fn holders<'a>(
        &'a self,
        digest: &'a Digest,
    ) -> std::pin::Pin<Box<dyn Future<Output = Vec<Holder>> + Send + 'a>> {
        let mut turns = self.turns.lock().unwrap();
        let holders = match turns.get_mut(digest) {
            Some(queue) if queue.len() > 1 => queue.pop_front().unwrap(),
            Some(queue) => queue[0].clone(),
            None => self.all.clone(),
        };
        Box::pin(std::future::ready(holders))
    }
}

fn digest_of(bytes: &[u8]) -> Digest {
    speculaire_oci::hash::of("sha256", bytes).unwrap()
}

fn descriptor(media_type: &str, digest: &Digest, size: usize) -> Value {
    json!({"mediaType": media_type, "digest": digest.to_string(), "size": size})
}

/// A cluster whose nodes serve peer APIs until the test ends.
struct Nodes {
    cluster: Cluster,
    dir: TempDir,
}

impl Nodes {
    fn new() -> Self {
        Self {
            cluster: Cluster::new("kubernetes"),
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn credentials(&self, node: &str) -> Arc<Credentials> {
        let credentials = Arc::new(Credentials::default());
        let certificate = self.dir.path().join(format!("{node}.pem"));
        let ca = self.dir.path().join("ca.crt");
        std::fs::write(&certificate, self.cluster.kubelet(node)).unwrap();
        std::fs::write(&ca, self.cluster.ca()).unwrap();
        credentials.load_identity(&certificate).unwrap();
        credentials.load_authority(&ca).unwrap();
        credentials
    }

    /// The artifact store of `node`.
    fn store(&self, node: &str) -> Arc<Store> {
        Arc::new(Store::open(self.dir.path().join(node)).unwrap())
    }

    /// The peer API of `node`, serving `content` and the artifacts of `store`.
    async fn peer(&self, node: &str, content: Held, store: Arc<Store>) -> Holder {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            self.credentials(node).server(),
            Arc::new(content),
            Listed::follow(Arc::new(NoImages)),
            store,
            Arc::new(Uploads::new(NonZeroUsize::new(4).unwrap())),
            std::future::pending(),
        ));
        Holder {
            node: node.to_owned(),
            address,
        }
    }

    /// Discovery on [`NODE`], holding `local`, asking peers as `lookup` says and the test's registry upstream.
    async fn test(&self, local: Held, lookup: Script) -> Test {
        self.limited(Limits::new(1024), local, lookup).await
    }

    /// [`Self::test`] under `limits`.
    async fn limited(&self, limits: Limits, local: Held, lookup: Script) -> Test {
        let dir = tempfile::tempdir().unwrap();
        let peers = Fetcher::new(
            dir.path().join("staging"),
            speculaire_mirror::space::Space::new(u64::MAX),
            SETTINGS,
        );
        peers.link(Arc::new(lookup), self.credentials(NODE));
        Test::near(
            limits,
            |registry| vec![registry.endpoint()],
            Arc::new(local),
            peers,
            dir,
        )
        .await
    }
}

fn everyone(holders: &[&Holder]) -> Script {
    Script {
        all: holders.iter().map(|&holder| holder.clone()).collect(),
        turns: Mutex::default(),
    }
}

/// Keeps `bytes` in `store`: their digest.
async fn put(store: &Store, bytes: &[u8]) -> Digest {
    let digest = digest_of(bytes);
    store.keep(&digest, bytes).await.unwrap();
    digest
}

/// An image manifest, told apart by `seed`.
fn image(seed: &str) -> Bytes {
    json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": descriptor("application/vnd.oci.image.config.v1+json", &digest_of(seed.as_bytes()), 6),
        "layers": [],
    })
    .to_string()
    .into()
}

/// A manifest of `artifact_type` about `subject`, kept in `store` with its blobs, as an artifact of `target`.
async fn referrer(
    store: &Store,
    artifact_type: &str,
    subject: &Digest,
    content: &[u8],
    target: &Digest,
) -> Artifact {
    let empty = put(store, b"{}").await;
    let layer = put(store, content).await;
    let bytes = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "artifactType": artifact_type,
        "config": descriptor(EMPTY, &empty, 2),
        "layers": [descriptor(BUNDLE, &layer, content.len())],
        "subject": descriptor(MANIFEST, subject, 100),
    })
    .to_string();
    Artifact {
        target: target.clone(),
        manifest: put(store, bytes.as_bytes()).await,
        kind: Kind::Bundle,
        blobs: vec![empty, layer],
    }
}

/// A Sigstore bundle about `target`, kept in `store` with its blobs.
async fn bundle(store: &Store, target: &Digest, content: &[u8]) -> Artifact {
    referrer(store, BUNDLE, target, content, target).await
}

/// A legacy `.sig` manifest of `target`, kept in `store` with its blobs.
async fn signature(store: &Store, target: &Digest) -> Artifact {
    let config = put(store, b"sigconfig").await;
    let payload = put(store, b"payload").await;
    let bytes = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": descriptor("application/vnd.oci.image.config.v1+json", &config, 9),
        "layers": [descriptor(SIMPLE_SIGNING, &payload, 7)],
    })
    .to_string();
    Artifact {
        target: target.clone(),
        manifest: put(store, bytes.as_bytes()).await,
        kind: Kind::Signature,
        blobs: vec![config, payload],
    }
}

fn recorder() -> (PrometheusHandle, ::metrics::LocalRecorderGuard<'static>) {
    let recorder = Box::leak(Box::new(PrometheusBuilder::new().build_recorder()));
    let handle = recorder.handle();
    (handle, ::metrics::set_default_local_recorder(recorder))
}

/// The count of `speculaire_artifact_fetches_total` from peers with `result`.
fn from_peers(handle: &PrometheusHandle, result: &str) -> Option<String> {
    let rendered = handle.render();
    rendered
        .lines()
        .find(|line| {
            line.starts_with("speculaire_artifact_fetches_total{")
                && line.contains(r#"source="peer""#)
                && line.contains(r#"upstream="""#)
                && line.contains(&format!(r#"result="{result}""#))
        })
        .and_then(|line| line.rsplit(' ').next())
        .map(str::to_owned)
}

fn sorted(mut artifacts: Vec<Artifact>) -> Vec<(Digest, Kind, Digest, Vec<Digest>)> {
    let mut rows: Vec<_> = artifacts
        .drain(..)
        .map(|a| (a.target, a.kind, a.manifest, a.blobs))
        .collect();
    rows.sort_by_key(|row| row.2.to_string());
    rows
}

#[tokio::test]
async fn peers_give_every_artifact_and_a_rate_limited_upstream_is_not_asked() {
    let (handle, _guard) = recorder();
    let nodes = Nodes::new();
    let mut local = Held::default();
    let root = local.put(image("app"));
    let a = nodes.store("node-a");
    let held = vec![
        bundle(&a, &root, b"bundle").await,
        signature(&a, &root).await,
    ];
    a.record(&root, &held).await.unwrap();
    let holder = nodes.peer("node-a", Held::default(), a).await;
    let test = nodes.test(local, everyone(&[&holder])).await;
    // Upstream limits this node (D38), which pauses its host: peers are still asked, and upstream is not.
    let limited = digest_of(b"limited");
    test.registry
        .put(&format!("/app/manifests/{limited}"), 429, "");
    let paused = test.discover(&limited).await;
    assert!(
        matches!(
            &paused,
            Err(Error::Unverifiable {
                reason: Reason::RateLimited { .. },
                ..
            })
        ),
        "{paused:?}"
    );

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(sorted(artifacts.clone()), sorted(held));
    assert_eq!(
        test.registry.requests(),
        [format!("HEAD /app/manifests/{limited}")]
    );
    let store = test.discovery.store();
    for artifact in &artifacts {
        assert!(store.contains(&artifact.manifest));
        assert!(artifact.blobs.iter().all(|blob| store.contains(blob)));
    }
    assert_eq!(store.recorded(&root).await.unwrap(), Some(artifacts));
    // Two manifests and four blobs, each from a peer once; an image manifest is not kept as an index.
    assert_eq!(from_peers(&handle, "ok").as_deref(), Some("6"));
    assert!(!store.contains(&root));
}

#[tokio::test]
async fn the_store_comes_before_peers_and_peers_before_upstream() {
    let (handle, _guard) = recorder();
    let nodes = Nodes::new();
    let mut local = Held::default();
    let root = local.put(image("app"));
    let a = nodes.store("node-a");
    let held = bundle(&a, &root, b"bundle").await;
    a.record(&root, std::slice::from_ref(&held)).await.unwrap();
    let holder = nodes.peer("node-a", Held::default(), a).await;
    let test = nodes.test(local, everyone(&[&holder])).await;
    let store = test.discovery.store();
    put(store, b"{}").await;
    put(store, b"bundle").await;

    assert_eq!(test.discover(&root).await.unwrap(), vec![held]);
    // The blobs were held: only the manifest came from the peer.
    assert_eq!(from_peers(&handle, "ok").as_deref(), Some("1"));
    assert_eq!(test.registry.requests(), Vec::<String>::new());

    // A root peers list nothing about goes upstream, as before peers.
    let unknown = test.root();
    assert_eq!(test.discover(&unknown).await.unwrap(), Vec::new());
    assert!(
        test.registry
            .requests()
            .contains(&format!("HEAD /app/manifests/{unknown}")),
        "{:?}",
        test.registry.requests()
    );
    // Neither the node nor its peer holds the root itself.
    assert_eq!(from_peers(&handle, "not_found").as_deref(), Some("1"));
}

#[tokio::test]
async fn a_referrer_about_another_digest_or_of_another_type_is_dropped() {
    let nodes = Nodes::new();
    let mut local = Held::default();
    let root = local.put(image("app"));
    let other = digest_of(b"other");
    let a = nodes.store("node-a");
    let good = bundle(&a, &root, b"good").await;
    let elsewhere = referrer(&a, BUNDLE, &other, b"elsewhere", &root).await;
    let att = referrer(&a, COSIGN_ATTESTATION, &root, b"att", &root).await;
    // A signature with a subject is about that subject alone, here another digest.
    let signed = referrer(&a, SIMPLE_SIGNING, &other, b"signed", &root).await;
    a.record(
        &root,
        &[good.clone(), elsewhere.clone(), att.clone(), signed.clone()],
    )
    .await
    .unwrap();
    let holder = nodes.peer("node-a", Held::default(), a).await;
    let test = nodes.test(local, everyone(&[&holder])).await;

    assert_eq!(test.discover(&root).await.unwrap(), vec![good]);
    let store = test.discovery.store();
    assert!(!store.contains(&elsewhere.manifest));
    assert!(!store.contains(&signed.blobs[1]));
    // A type that is no bundle's is not even fetched.
    assert!(!store.contains(&att.manifest));
    assert!(!store.contains(&att.blobs[1]));
}

#[tokio::test]
async fn a_peer_that_sends_wrong_bytes_is_denied_and_the_next_holder_gives_the_artifact() {
    let (handle, _guard) = recorder();
    let nodes = Nodes::new();
    let mut local = Held::default();
    let root = local.put(image("app"));
    let a = nodes.store("node-a");
    let held = bundle(&a, &root, b"bundle").await;
    a.record(&root, std::slice::from_ref(&held)).await.unwrap();
    let honest = nodes.peer("node-a", Held::default(), a).await;
    let mut wrong = Held::default();
    wrong
        .0
        .insert(held.manifest.clone(), image("not the manifest"));
    let liar = nodes.peer("node-c", wrong, nodes.store("node-c")).await;
    // The liar alone holds the manifest at first; once it is denied, the honest node does.
    let lookup = everyone(&[&honest]);
    lookup.turns.lock().unwrap().insert(
        held.manifest.clone(),
        VecDeque::from([vec![liar.clone()], vec![liar, honest]]),
    );
    let test = nodes.test(local, lookup).await;

    assert_eq!(test.discover(&root).await.unwrap(), vec![held]);
    let rendered = handle.render();
    assert!(
        rendered.contains(r#"speculaire_peer_fetches_total{result="digest_mismatch"} 1"#),
        "{rendered}"
    );
    assert_eq!(test.registry.requests(), Vec::<String>::new());
}

#[tokio::test]
async fn an_index_and_its_attestations_come_from_peers_and_the_index_is_kept() {
    let nodes = Nodes::new();
    let a = nodes.store("node-a");
    let mut content = Held::default();
    let platform = content.put(image("amd64"));
    let config = put(&a, b"{}").await;
    let statement = put(&a, b"statement").await;
    let attestation = put(
        &a,
        json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": descriptor("application/vnd.oci.image.config.v1+json", &config, 2),
            "layers": [descriptor("application/vnd.in-toto+json", &statement, 9)],
        })
        .to_string()
        .as_bytes(),
    )
    .await;
    let root = content.put(
        json!({
            "schemaVersion": 2,
            "mediaType": INDEX,
            "manifests": [
                {"mediaType": MANIFEST, "digest": platform.to_string(), "size": 100,
                 "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": MANIFEST, "digest": attestation.to_string(), "size": 100,
                 "platform": {"os": "unknown", "architecture": "unknown"},
                 "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                                 "vnd.docker.reference.digest": platform.to_string()}},
            ],
        })
        .to_string(),
    );
    let attested = Artifact {
        target: platform.clone(),
        manifest: attestation.clone(),
        kind: Kind::Attestation,
        blobs: vec![config, statement],
    };
    let signed = bundle(&a, &attestation, b"about the attestation").await;
    a.record(&root, &[attested.clone(), signed.clone()])
        .await
        .unwrap();
    let holder = nodes.peer("node-a", content, a).await;
    let test = nodes.test(Held::default(), everyone(&[&holder])).await;

    let artifacts = test
        .discovery
        .discover(&root, &[NAME.to_owned()])
        .await
        .unwrap();

    assert_eq!(artifacts, vec![attested, signed]);
    assert_eq!(test.registry.requests(), Vec::<String>::new());
    // The index is kept, so that this node serves it to the next.
    assert!(test.discovery.store().contains(&root));
}

#[tokio::test]
async fn the_lists_of_two_peers_are_unioned() {
    let nodes = Nodes::new();
    let mut local = Held::default();
    let root = local.put(image("app"));
    let a = nodes.store("node-a");
    let signed = bundle(&a, &root, b"bundle").await;
    a.record(&root, std::slice::from_ref(&signed))
        .await
        .unwrap();
    let c = nodes.store("node-c");
    let legacy = signature(&c, &root).await;
    c.record(&root, std::slice::from_ref(&legacy))
        .await
        .unwrap();
    let first = nodes.peer("node-a", Held::default(), a).await;
    let second = nodes.peer("node-c", Held::default(), c).await;
    let test = nodes.test(local, everyone(&[&first, &second])).await;

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(sorted(artifacts), sorted(vec![signed, legacy]));
    assert_eq!(test.registry.requests(), Vec::<String>::new());
}

#[tokio::test]
async fn a_held_index_peers_list_nothing_about_is_asked_upstream_by_head_alone() {
    let nodes = Nodes::new();
    let index = json!({"schemaVersion": 2, "mediaType": INDEX, "manifests": []}).to_string();
    let mut local = Held::default();
    let root = local.put(index.clone());
    let test = nodes.test(local, everyone(&[])).await;
    test.registry.manifest(index.as_bytes());

    assert_eq!(test.discover(&root).await.unwrap(), Vec::new());

    let requests = test.registry.requests();
    assert!(
        requests.contains(&format!("HEAD /app/manifests/{root}")),
        "{requests:?}"
    );
    assert!(
        !requests.contains(&format!("GET /app/manifests/{root}")),
        "{requests:?}"
    );
    assert!(test.discovery.store().contains(&root));
}

#[tokio::test]
async fn an_artifact_whose_manifest_or_blob_no_peer_gives_is_dropped() {
    let (handle, _guard) = recorder();
    let nodes = Nodes::new();
    let mut local = Held::default();
    let root = local.put(image("app"));
    let a = nodes.store("node-a");
    let no_manifest = bundle(&a, &root, b"no manifest").await;
    let no_blob = bundle(&a, &root, b"no blob").await;
    a.record(&root, &[no_manifest.clone(), no_blob.clone()])
        .await
        .unwrap();
    let holder = nodes.peer("node-a", Held::default(), a).await;
    // The node lists both, but no holder is found for the one's manifest or the other's layer.
    let lookup = everyone(&[&holder]);
    for missing in [&no_manifest.manifest, &no_blob.blobs[1]] {
        lookup
            .turns
            .lock()
            .unwrap()
            .insert(missing.clone(), VecDeque::from([Vec::new()]));
    }
    let test = nodes.test(local, lookup).await;
    test.registry.manifest(&image("app"));

    assert_eq!(test.discover(&root).await.unwrap(), Vec::new());
    assert_eq!(from_peers(&handle, "not_found").as_deref(), Some("2"));
    // Peers gave nothing: upstream was asked.
    assert!(
        test.registry
            .requests()
            .contains(&format!("HEAD /app/manifests/{root}"))
    );
}

#[tokio::test]
async fn peers_list_at_most_the_referrers_cap_per_target() {
    let nodes = Nodes::new();
    let mut local = Held::default();
    let root = local.put(image("app"));
    let a = nodes.store("node-a");
    let held = vec![
        bundle(&a, &root, b"first").await,
        bundle(&a, &root, b"second").await,
    ];
    a.record(&root, &held).await.unwrap();
    let holder = nodes.peer("node-a", Held::default(), a).await;
    let limits = Limits {
        referrers: 1,
        ..Limits::new(1024)
    };
    let test = nodes.limited(limits, local, everyone(&[&holder])).await;

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(artifacts.len(), 1);
    assert!(held.contains(&artifacts[0]));
}

#[tokio::test]
async fn an_attestation_no_peer_gives_or_that_is_no_image_manifest_is_dropped() {
    let nodes = Nodes::new();
    let a = nodes.store("node-a");
    let mut content = Held::default();
    let platform = content.put(image("amd64"));
    let missing = digest_of(b"missing");
    let nested = put(
        &a,
        json!({"schemaVersion": 2, "mediaType": INDEX, "manifests": []})
            .to_string()
            .as_bytes(),
    )
    .await;
    let attestation = |digest: &Digest| {
        json!({"mediaType": MANIFEST, "digest": digest.to_string(), "size": 100,
               "platform": {"os": "unknown", "architecture": "unknown"},
               "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                               "vnd.docker.reference.digest": platform.to_string()}})
    };
    let root = content.put(
        json!({
            "schemaVersion": 2,
            "mediaType": INDEX,
            "manifests": [
                {"mediaType": MANIFEST, "digest": platform.to_string(), "size": 100,
                 "platform": {"os": "linux", "architecture": "amd64"}},
                attestation(&missing),
                attestation(&nested),
            ],
        })
        .to_string(),
    );
    let signed = bundle(&a, &root, b"bundle").await;
    a.record(&root, std::slice::from_ref(&signed))
        .await
        .unwrap();
    let holder = nodes.peer("node-a", content, a).await;
    let test = nodes.test(Held::default(), everyone(&[&holder])).await;

    let artifacts = test
        .discovery
        .discover(&root, &[NAME.to_owned()])
        .await
        .unwrap();

    assert_eq!(artifacts, vec![signed]);
    assert!(!test.discovery.store().contains(&nested));
}

#[tokio::test]
async fn a_referrer_listed_above_the_manifest_cap_is_not_fetched() {
    let (handle, _guard) = recorder();
    let nodes = Nodes::new();
    let mut local = Held::default();
    let root = local.put(image("app"));
    let a = nodes.store("node-a");
    let small = bundle(&a, &root, b"small").await;
    let layer = put(&a, b"large").await;
    let empty = put(&a, b"{}").await;
    let large = Artifact {
        target: root.clone(),
        manifest: put(
            &a,
            json!({
                "schemaVersion": 2,
                "mediaType": MANIFEST,
                "artifactType": BUNDLE,
                "config": descriptor(EMPTY, &empty, 2),
                "layers": [descriptor(BUNDLE, &layer, 5)],
                "subject": descriptor(MANIFEST, &root, 100),
                "annotations": {"padding": "x".repeat(2048)},
            })
            .to_string()
            .as_bytes(),
        )
        .await,
        kind: Kind::Bundle,
        blobs: vec![empty, layer],
    };
    a.record(&root, &[small.clone(), large]).await.unwrap();
    let holder = nodes.peer("node-a", Held::default(), a).await;
    let limits = Limits {
        manifest: 1024,
        ..Limits::new(1024)
    };
    let test = nodes.limited(limits, local, everyone(&[&holder])).await;

    assert_eq!(test.discover(&root).await.unwrap(), vec![small]);
    // The large one was not even asked for.
    assert_eq!(from_peers(&handle, "not_found"), None);
}
