//! The peer API over real mutual TLS with node identities, against content in memory and the blob cache.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use http_body_util::Empty;
use hyper::client::conn::http1::SendRequest;
use hyper::header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE};
use hyper::{HeaderMap, Method};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::{BUNDLE, EMPTY, INDEX, MANIFEST, SIMPLE_SIGNING};
use speculaire_pki::node::Credentials;
use speculaire_pki::testing::Cluster;
use speculaire_runtime::content::{Blob, Error};
use speculaire_runtime::inventory::{Change, Inventory as _, Update};
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsConnector;

use super::*;
use crate::cache::Cache;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// The node whose peer API answers.
const SERVER: &str = "node-a";
/// More than loopback's socket buffers hold: a body this long stays in flight until the client reads it.
const LARGE: usize = 64 << 20;

/// Blobs held in memory.
struct Held(HashMap<Digest, Bytes>);

impl Content for Held {
    fn open(&self, digest: &Digest) -> impl Future<Output = Result<Option<Blob>, Error>> + Send {
        std::future::ready(Ok(self.0.get(digest).cloned().map(Blob::from_bytes)))
    }
}

/// Artifacts held in memory: their manifests and blobs, and the manifests about each target.
#[derive(Default)]
struct Artifacts {
    held: HashMap<Digest, Bytes>,
    about: HashMap<Digest, Vec<Digest>>,
    /// A blob that is there but cannot be read.
    unreadable: Option<Digest>,
}

impl Content for Artifacts {
    fn open(&self, digest: &Digest) -> impl Future<Output = Result<Option<Blob>, Error>> + Send {
        std::future::ready(if self.unreadable.as_ref() == Some(digest) {
            Err(Error::Io(std::io::Error::other("unreadable")))
        } else {
            Ok(self.held.get(digest).cloned().map(Blob::from_bytes))
        })
    }
}

impl Referrers for Artifacts {
    fn referrers(&self, target: &Digest) -> Vec<Digest> {
        self.about.get(target).cloned().unwrap_or_default()
    }
}

fn digest_of(seed: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn pattern(len: usize) -> Bytes {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect::<Vec<_>>()
        .into()
}

fn blob_path(digest: &Digest) -> String {
    format!("/v2/library/busybox/blobs/{digest}")
}

/// The identity of `node`, from `cluster`'s CA, with that CA.
fn credentials(cluster: &Cluster, dir: &TempDir, node: &str) -> Arc<Credentials> {
    let credentials = Arc::new(Credentials::default());
    let certificate = dir.path().join(format!("{node}.pem"));
    let ca = dir.path().join("ca.crt");
    std::fs::write(&certificate, cluster.kubelet(node)).unwrap();
    std::fs::write(&ca, cluster.ca()).unwrap();
    credentials.load_identity(&certificate).unwrap();
    credentials.load_authority(&ca).unwrap();
    credentials
}

/// A peer API of [`SERVER`], serving until the test ends or calls [`Test::stop`].
struct Test {
    cluster: Cluster,
    dir: TempDir,
    address: SocketAddr,
    uploads: Arc<Uploads>,
    stop: oneshot::Sender<()>,
    served: tokio::task::JoinHandle<()>,
}

impl Test {
    async fn start<C: Content>(content: Arc<C>, max_uploads: usize) -> Self {
        Self::listing(content, Listed::of(Vec::new()), max_uploads).await
    }

    async fn listing<C: Content>(content: Arc<C>, listed: Listed, max_uploads: usize) -> Self {
        Self::serving(content, listed, Arc::new(Artifacts::default()), max_uploads).await
    }

    async fn serving<C: Content>(
        content: Arc<C>,
        listed: Listed,
        artifacts: Arc<Artifacts>,
        max_uploads: usize,
    ) -> Self {
        let cluster = Cluster::new("kubernetes");
        let dir = tempfile::tempdir().unwrap();
        let tls = credentials(&cluster, &dir, SERVER).server();
        let listener = TcpListener::bind((IP, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let uploads = Arc::new(Uploads::new(NonZeroUsize::new(max_uploads).unwrap()));
        let (stop, stopped) = oneshot::channel::<()>();
        let served = tokio::spawn(serve(
            listener,
            tls,
            content,
            listed,
            artifacts,
            Arc::clone(&uploads),
            async {
                // An error means the sender went with the test: stop too.
                let _ = stopped.await;
            },
        ));
        Self {
            cluster,
            dir,
            address,
            uploads,
            stop,
            served,
        }
    }

    /// Stops the peer API; the handle completes when `serve` returns.
    fn stop(self) -> tokio::task::JoinHandle<()> {
        let _ = self.stop.send(());
        self.served
    }

    /// A connection from `node`'s agent, which checks that [`SERVER`] answers.
    async fn client(&self, node: &str) -> SendRequest<Empty<Bytes>> {
        let config = credentials(&self.cluster, &self.dir, node).client(SERVER);
        connect(self.address, config).await.unwrap()
    }
}

async fn connect(
    address: SocketAddr,
    mut config: ClientConfig,
) -> io::Result<SendRequest<Empty<Bytes>>> {
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = TcpStream::connect(address).await?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::IpAddress(IP.into()), tcp)
        .await?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(connection);
    Ok(sender)
}

/// The response to `method` of `path`, its body unread.
async fn send(
    sender: &mut SendRequest<Empty<Bytes>>,
    method: Method,
    path: &str,
    range: Option<&str>,
) -> hyper::Result<Response<Incoming>> {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", SERVER);
    if let Some(range) = range {
        request = request.header("range", range);
    }
    sender
        .send_request(request.body(Empty::new()).unwrap())
        .await
}

struct Answer {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

async fn ask(
    sender: &mut SendRequest<Empty<Bytes>>,
    method: Method,
    path: &str,
    range: Option<&str>,
) -> Answer {
    let response = send(sender, method, path, range).await.unwrap();
    let (parts, body) = response.into_parts();
    Answer {
        status: parts.status,
        headers: parts.headers,
        body: body.collect().await.unwrap().to_bytes(),
    }
}

async fn get(sender: &mut SendRequest<Empty<Bytes>>, path: &str) -> Answer {
    ask(sender, Method::GET, path, None).await
}

fn header(answer: &Answer, name: impl hyper::header::AsHeaderName) -> &str {
    answer
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

#[tokio::test]
async fn another_node_reads_a_blob_whole_and_in_part_and_a_manifest_by_digest() {
    use metrics_exporter_prometheus::PrometheusBuilder;
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    // This test thread only: the other tests of the process count into the global recorder, if there is one.
    let _local = ::metrics::set_default_local_recorder(&recorder);
    crate::metrics::describe_peer();
    let (blob, manifest) = (digest_of(1), digest_of(2));
    let index = Bytes::from_static(br#"{"schemaVersion":2,"manifests":[]}"#);
    let test = Test::start(
        Arc::new(Held(HashMap::from([
            (blob.clone(), pattern(1000)),
            (manifest.clone(), index.clone()),
        ]))),
        4,
    )
    .await;
    let mut sender = test.client("node-b").await;

    let whole = get(&mut sender, &blob_path(&blob)).await;
    assert_eq!(whole.status, StatusCode::OK);
    assert_eq!(whole.body, pattern(1000));
    assert_eq!(header(&whole, "docker-content-digest"), blob.to_string());

    let part = ask(
        &mut sender,
        Method::GET,
        &blob_path(&blob),
        Some("bytes=10-19"),
    )
    .await;
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.body, pattern(1000).slice(10..20));
    assert_eq!(header(&part, CONTENT_RANGE), "bytes 10-19/1000");

    let head = ask(&mut sender, Method::HEAD, &blob_path(&blob), None).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(header(&head, CONTENT_LENGTH), "1000");

    let served = get(
        &mut sender,
        &format!("/v2/library/busybox/manifests/{manifest}"),
    )
    .await;
    assert_eq!(served.status, StatusCode::OK);
    assert_eq!(served.body, index);
    assert_eq!(
        header(&served, CONTENT_TYPE),
        "application/vnd.oci.image.index.v1+json"
    );

    let rendered = handle.render();
    for line in [
        r#"speculaire_peer_uploads_total{result="served"} 4"#,
        r#"speculaire_peer_uploads_total{result="busy"} 0"#,
        "speculaire_peer_upload_bytes_total 1010",
        // The whole blob and its part; neither the head nor the manifest.
        "speculaire_peer_upload_seconds_count 2",
        "speculaire_peer_uploads_in_flight 0",
    ] {
        assert!(
            rendered.lines().any(|l| l == line),
            "no `{line}` in\n{rendered}"
        );
    }
}

#[tokio::test]
async fn everything_but_a_manifest_or_a_blob_by_digest_a_listed_tag_or_referrers_answers_404() {
    let held = digest_of(1);
    let test = Test::start(
        Arc::new(Held(HashMap::from([(held.clone(), pattern(10))]))),
        4,
    )
    .await;
    let mut sender = test.client("node-b").await;
    for path in [
        "/v2/".to_owned(),
        "/v2/library/busybox/manifests/latest".to_owned(),
        blob_path(&digest_of(2)),
        format!("/v3/library/busybox/blobs/{held}"),
    ] {
        assert_eq!(
            get(&mut sender, &path).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    let post = ask(&mut sender, Method::POST, &blob_path(&held), None).await;
    assert_eq!(post.status, StatusCode::NOT_FOUND);
    let referrers = format!("/v2/library/busybox/referrers/{held}");
    let referrers_head = ask(&mut sender, Method::HEAD, &referrers, None).await;
    assert_eq!(referrers_head.status, StatusCode::NOT_FOUND);
}

/// distribution-spec v1.1.1-57-g9727462 `spec.md:626-627`: a referrers API never answers 404, and a `<digest>` of
/// invalid syntax is a 400.
#[tokio::test]
async fn referrers_of_anything_but_a_digest_answer_400() {
    let test = Test::start(Arc::new(Held(HashMap::new())), 4).await;
    let mut sender = test.client("node-b").await;
    for reference in ["latest", "sha256:zz", "sha256", "md5:aa"] {
        let path = format!("/v2/library/busybox/referrers/{reference}");
        assert_eq!(
            get(&mut sender, &path).await.status,
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
}

/// An artifact manifest about `target`, of `artifact_type` when there is one, with `annotations`.
fn artifact(target: Option<&Digest>, artifact_type: Option<&str>, annotations: &str) -> Bytes {
    let subject = target.map_or(String::new(), |target| {
        format!(r#""subject":{{"mediaType":"{MANIFEST}","digest":"{target}","size":1}},"#)
    });
    let artifact_type =
        artifact_type.map_or(String::new(), |t| format!(r#""artifactType":"{t}","#));
    Bytes::from(format!(
        r#"{{"schemaVersion":2,"mediaType":"{}",{artifact_type}{subject}
            "config":{{"mediaType":"{EMPTY}","digest":"{}","size":2}},
            "layers":[{{"mediaType":"{SIMPLE_SIGNING}","digest":"{}","size":10}}],
            "annotations":{annotations}}}"#,
        MANIFEST,
        digest_of(20),
        digest_of(21),
    ))
}

#[tokio::test]
async fn the_referrers_of_a_manifest_list_the_artifacts_held_about_it_and_a_filter_keeps_one_type()
{
    let (target, bundle, sig, junk, gone, unreadable) = (
        digest_of(1),
        digest_of(2),
        digest_of(3),
        digest_of(4),
        digest_of(5),
        digest_of(6),
    );
    let held = HashMap::from([
        (
            bundle.clone(),
            artifact(
                Some(&target),
                Some(BUNDLE),
                r#"{"dev.sigstore.bundle.predicateType":"p","n":1}"#,
            ),
        ),
        (sig.clone(), artifact(None, None, r#"{"a":"b"}"#)),
        (junk.clone(), Bytes::from_static(b"not a manifest")),
        (digest_of(21), pattern(10)),
    ]);
    let artifacts = Artifacts {
        held: held.clone(),
        about: HashMap::from([(
            target.clone(),
            vec![bundle.clone(), sig.clone(), junk, gone, unreadable.clone()],
        )]),
        unreadable: Some(unreadable),
    };
    let test = Test::serving(
        Arc::new(Held(HashMap::new())),
        Listed::of(Vec::new()),
        Arc::new(artifacts),
        4,
    )
    .await;
    let mut sender = test.client("node-b").await;
    let list =
        |answer: &Answer| -> serde_json::Value { serde_json::from_slice(&answer.body).unwrap() };

    // Any repository: the store is not by repository.
    let all = get(&mut sender, &format!("/v2/any/where/referrers/{target}")).await;
    assert_eq!(all.status, StatusCode::OK);
    assert_eq!(header(&all, CONTENT_TYPE), INDEX);
    assert_eq!(header(&all, CONTENT_LENGTH), all.body.len().to_string());
    assert!(!all.headers.contains_key("oci-filters-applied"));
    assert_eq!(
        list(&all),
        serde_json::json!({
            "schemaVersion": 2,
            "mediaType": INDEX,
            "manifests": [
                {
                    "mediaType": MANIFEST,
                    "digest": bundle.to_string(),
                    "size": held[&bundle].len(),
                    "artifactType": BUNDLE,
                    "annotations": {"dev.sigstore.bundle.predicateType": "p"},
                },
                {
                    "mediaType": MANIFEST,
                    "digest": sig.to_string(),
                    "size": held[&sig].len(),
                    "artifactType": SIMPLE_SIGNING,
                    "annotations": {"a": "b"},
                },
            ],
        })
    );

    let path = format!(
        "/v2/e2e/signed/referrers/{target}?artifactType=application%2Fvnd.dev.sigstore.bundle.v0.3%2Bjson"
    );
    let bundles = get(&mut sender, &path).await;
    assert_eq!(header(&bundles, "oci-filters-applied"), "artifactType");
    let digests = list(&bundles)["manifests"]
        .as_array()
        .unwrap()
        .iter()
        .map(|listed| listed["digest"].clone())
        .collect::<Vec<_>>();
    assert_eq!(digests, [serde_json::json!(bundle.to_string())]);

    let none = get(
        &mut sender,
        &format!("/v2/e2e/signed/referrers/{target}?artifactType=application/none"),
    )
    .await;
    assert_eq!(none.status, StatusCode::OK);
    assert_eq!(header(&none, "oci-filters-applied"), "artifactType");
    assert_eq!(list(&none)["manifests"], serde_json::json!([]));

    let unknown = get(
        &mut sender,
        &format!("/v2/e2e/signed/referrers/{}", digest_of(7)),
    )
    .await;
    assert_eq!(unknown.status, StatusCode::OK);
    assert!(!unknown.headers.contains_key("oci-filters-applied"));
    assert_eq!(list(&unknown)["manifests"], serde_json::json!([]));
}

#[tokio::test]
async fn a_manifest_or_blob_the_runtime_lacks_is_served_from_the_artifact_store() {
    let (target, bundle, layer) = (digest_of(1), digest_of(2), digest_of(21));
    let manifest = artifact(Some(&target), Some(BUNDLE), "{}");
    let artifacts = Artifacts {
        held: HashMap::from([
            (bundle.clone(), manifest.clone()),
            (layer.clone(), pattern(10)),
        ]),
        about: HashMap::new(),
        unreadable: None,
    };
    // The runtime's content comes first.
    let content = Held(HashMap::from([(layer.clone(), pattern(20))]));
    let test = Test::serving(
        Arc::new(content),
        Listed::of(Vec::new()),
        Arc::new(artifacts),
        4,
    )
    .await;
    let mut sender = test.client("node-b").await;
    let served = get(&mut sender, &format!("/v2/e2e/signed/manifests/{bundle}")).await;
    assert_eq!(served.status, StatusCode::OK);
    assert_eq!(served.body, manifest);
    assert_eq!(header(&served, CONTENT_TYPE), MANIFEST);
    assert_eq!(get(&mut sender, &blob_path(&layer)).await.body, pattern(20));
    let missing = get(&mut sender, &blob_path(&digest_of(22))).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
}

fn listed(tags: &[&str], repo_digests: &[(&str, &Digest)]) -> Listed {
    Listed::of(vec![speculaire_runtime::images::Image {
        id: digest_of(9),
        repo_digests: repo_digests
            .iter()
            .map(
                |&(repository, digest)| speculaire_runtime::images::RepoDigest {
                    repository: repository.to_owned(),
                    digest: digest.clone(),
                },
            )
            .collect(),
        tags: tags.iter().filter_map(|tag| Tagged::parse(tag)).collect(),
    }])
}

#[tokio::test]
async fn a_listed_tag_answers_the_index_it_was_pulled_by_before_a_manifest() {
    let manifest = Bytes::from_static(br#"{"schemaVersion":2,"config":{},"layers":[]}"#);
    let index = Bytes::from_static(br#"{"schemaVersion":2,"manifests":[]}"#);
    let (manifest_digest, index_digest) = (digest_of(1), digest_of(2));
    let other = digest_of(3);
    let test = Test::listing(
        Arc::new(Held(HashMap::from([
            (manifest_digest.clone(), manifest.clone()),
            (index_digest.clone(), index.clone()),
            (other.clone(), index.clone()),
        ]))),
        listed(
            &["busybox:1.37"],
            &[
                // Another repository's digest is not this tag's.
                ("docker.io/library/other", &other),
                ("docker.io/library/busybox", &digest_of(4)),
                ("docker.io/library/busybox", &manifest_digest),
                ("docker.io/library/busybox", &index_digest),
            ],
        ),
        4,
    )
    .await;
    let mut sender = test.client("node-b").await;
    let path = "/v2/docker.io/library/busybox/manifests/1.37";
    let got = get(&mut sender, path).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.body, index);
    assert_eq!(
        header(&got, "docker-content-digest"),
        index_digest.to_string()
    );
    assert_eq!(
        header(&got, CONTENT_TYPE),
        "application/vnd.oci.image.index.v1+json"
    );
    let head = ask(&mut sender, Method::HEAD, path, None).await;
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(header(&head, CONTENT_LENGTH), index.len().to_string());
    assert!(head.body.is_empty());
    for missing in [
        "/v2/docker.io/library/busybox/manifests/1.36",
        "/v2/docker.io/library/other/manifests/1.37",
        "/v2/docker.io/library/busybox/blobs/1.37",
    ] {
        assert_eq!(
            get(&mut sender, missing).await.status,
            StatusCode::NOT_FOUND,
            "{missing}"
        );
    }

    // Without the index, the manifest; without either, a 404.
    let only_manifest = Test::listing(
        Arc::new(Held(HashMap::from([(
            manifest_digest.clone(),
            manifest.clone(),
        )]))),
        listed(
            &["busybox:1.37"],
            &[
                ("docker.io/library/busybox", &manifest_digest),
                ("docker.io/library/busybox", &index_digest),
            ],
        ),
        4,
    )
    .await;
    let got = get(&mut only_manifest.client("node-b").await, path).await;
    assert_eq!(got.body, manifest);
    let nothing = Test::listing(
        Arc::new(Held(HashMap::new())),
        listed(
            &["busybox:1.37"],
            &[("docker.io/library/busybox", &index_digest)],
        ),
        4,
    )
    .await;
    let got = get(&mut nothing.client("node-b").await, path).await;
    assert_eq!(got.status, StatusCode::NOT_FOUND);
}

/// Whether the peer API refuses a client with `config`: in TLS 1.3, the handshake completes on the client's side, and
/// the refusal comes as an alert on the first read (D16).
async fn refused(test: &Test, config: ClientConfig) -> bool {
    let Ok(mut sender) = connect(test.address, config).await else {
        return true;
    };
    send(&mut sender, Method::GET, &blob_path(&digest_of(1)), None)
        .await
        .is_err()
}

#[tokio::test]
async fn a_client_without_a_kubelet_certificate_from_the_cluster_ca_is_refused() {
    let test = Test::start(Arc::new(Held(HashMap::new())), 4).await;
    // No certificate at all: the CA alone.
    let anonymous = Arc::new(Credentials::default());
    let ca = test.dir.path().join("ca.crt");
    anonymous.load_authority(&ca).unwrap();
    assert!(refused(&test, anonymous.client(SERVER)).await);
    // A kubelet certificate of another cluster's CA.
    let other = Cluster::new("other");
    let dir = tempfile::tempdir().unwrap();
    let stranger = credentials(&other, &dir, "node-b");
    stranger.load_authority(&ca).unwrap();
    assert!(refused(&test, stranger.client(SERVER)).await);
    // The cluster's own node is not refused.
    let node = credentials(&test.cluster, &test.dir, "node-b");
    assert!(!refused(&test, node.client(SERVER)).await);
}

#[tokio::test]
async fn a_blob_removed_after_it_was_announced_answers_404() {
    let dir = tempfile::tempdir().unwrap();
    let cache = Arc::new(Cache::open(dir.path(), crate::space::Space::new(u64::MAX)).unwrap());
    let held = digest_of(1);
    let mut writer = cache.writer().await.unwrap();
    writer.write(&pattern(100)).await.unwrap();
    writer.commit(&cache, &held).await.unwrap();
    // What the agent announces: the cache's listing, then its changes (D99).
    let (updates, mut announced) = mpsc::channel(8);
    tokio::spawn(Arc::clone(&cache).follow(updates));
    assert_eq!(
        announced.recv().await,
        Some(Update::Listing([held.clone()].into()))
    );
    let test = Test::start(Arc::clone(&cache), 4).await;
    let mut sender = test.client("node-b").await;
    assert_eq!(
        get(&mut sender, &blob_path(&held)).await.status,
        StatusCode::OK
    );
    // Deleted behind the cache's back, as a cleanup of the node would.
    std::fs::remove_file(
        dir.path()
            .join("blobs")
            .join(held.algorithm())
            .join(held.encoded()),
    )
    .unwrap();
    assert_eq!(
        get(&mut sender, &blob_path(&held)).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        announced.recv().await,
        Some(Update::Change(Change::Removed(held)))
    );
}

/// A `GET` of a [`LARGE`] blob whose headers came and whose body is still in flight.
async fn in_flight(test: &Test, held: &Digest) -> Response<Incoming> {
    let mut sender = test.client("node-b").await;
    let response = send(&mut sender, Method::GET, &blob_path(held), None)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response
}

#[tokio::test]
async fn at_max_uploads_a_further_body_answers_503_at_once() {
    use metrics_exporter_prometheus::PrometheusBuilder;
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _local = ::metrics::set_default_local_recorder(&recorder);
    let held = digest_of(1);
    let test = Test::start(
        Arc::new(Held(HashMap::from([(held.clone(), pattern(LARGE))]))),
        1,
    )
    .await;
    let first = in_flight(&test, &held).await;
    let mut sender = test.client("node-c").await;
    let second = tokio::time::timeout(Duration::from_secs(1), get(&mut sender, &blob_path(&held)))
        .await
        .expect("a 503 at once");
    assert_eq!(second.status, StatusCode::SERVICE_UNAVAILABLE);
    let rendered = handle.render();
    for line in [
        r#"speculaire_peer_uploads_total{result="busy"} 1"#,
        "speculaire_peer_uploads_in_flight 1",
    ] {
        assert!(
            rendered.lines().any(|l| l == line),
            "no `{line}` in\n{rendered}"
        );
    }
    // A `HEAD` sends no body: it is not capped.
    let sized = ask(&mut sender, Method::HEAD, &blob_path(&held), None).await;
    assert_eq!(sized.status, StatusCode::OK);
    // A raised cap takes the next request.
    test.uploads.set_limit(NonZeroUsize::new(2).unwrap());
    let raised = in_flight(&test, &held).await;
    drop((first, raised));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !handle
            .render()
            .lines()
            .any(|l| l == "speculaire_peer_uploads_in_flight 0")
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a dropped body ends its upload");
    test.uploads.set_limit(NonZeroUsize::new(1).unwrap());
    assert_eq!(in_flight(&test, &held).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn once_stopped_new_requests_answer_503_and_the_api_ends_after_the_body_in_flight() {
    let held = digest_of(1);
    let test = Test::start(
        Arc::new(Held(HashMap::from([(held.clone(), pattern(LARGE))]))),
        4,
    )
    .await;
    let first = in_flight(&test, &held).await;
    test.uploads.stop();
    let mut sender = test.client("node-c").await;
    for method in [Method::GET, Method::HEAD] {
        let answer = ask(&mut sender, method.clone(), &blob_path(&held), None).await;
        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE, "{method}");
    }
    let (address, late) = (
        test.address,
        credentials(&test.cluster, &test.dir, "node-d").client(SERVER),
    );
    let mut served = test.stop();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut served)
            .await
            .is_err(),
        "a body is in flight"
    );
    // The idle connection closed at once, and a new one is answered 503 (D177); the busy one sends its whole body.
    assert!(sender.ready().await.is_err(), "an idle connection stays");
    let mut late = connect(address, late).await.unwrap();
    let answer = ask(&mut late, Method::GET, &blob_path(&held), None).await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    let body = first.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, pattern(LARGE));
    tokio::time::timeout(Duration::from_secs(5), served)
        .await
        .expect("the API ends once its body is sent")
        .unwrap();
}
