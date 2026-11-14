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
        let cluster = Cluster::new("kubernetes");
        let dir = tempfile::tempdir().unwrap();
        let tls = credentials(&cluster, &dir, SERVER).server();
        let listener = TcpListener::bind((IP, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let uploads = Arc::new(Uploads::new(NonZeroUsize::new(max_uploads).unwrap()));
        let (stop, stopped) = oneshot::channel::<()>();
        let served = tokio::spawn(serve(listener, tls, content, Arc::clone(&uploads), async {
            // An error means the sender went with the test: stop too.
            let _ = stopped.await;
        }));
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
    metrics::describe_peer();
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
        "speculaire_peer_uploads_in_flight 0",
    ] {
        assert!(
            rendered.lines().any(|l| l == line),
            "no `{line}` in\n{rendered}"
        );
    }
}

#[tokio::test]
async fn everything_but_a_manifest_or_a_blob_by_digest_answers_404() {
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
        format!("/v2/library/busybox/referrers/{held}"),
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
    let cache = Arc::new(Cache::open(dir.path(), u64::MAX).unwrap());
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
    let mut served = test.stop();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut served)
            .await
            .is_err(),
        "a body is in flight"
    );
    // The idle connection closed at once; the busy one sends its whole body.
    assert!(sender.ready().await.is_err(), "an idle connection stays");
    let body = first.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, pattern(LARGE));
    tokio::time::timeout(Duration::from_secs(5), served)
        .await
        .expect("the API ends once its body is sent")
        .unwrap();
}
