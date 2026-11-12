//! The mirror over real TLS, against content held in memory.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::client::conn::http1::SendRequest;
use hyper::{HeaderMap, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use secrecy::ExposeSecret as _;
use speculaire_pki::mirror::{Mirror, Part};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;

use super::*;

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

struct Fake(HashMap<Digest, Bytes>);

impl Content for Fake {
    fn open(&self, digest: &Digest) -> impl Future<Output = Result<Option<Blob>, Error>> + Send {
        std::future::ready(Ok(self.0.get(digest).cloned().map(Blob::from_bytes)))
    }
}

struct Failing;

impl Content for Failing {
    fn open(&self, _: &Digest) -> impl Future<Output = Result<Option<Blob>, Error>> + Send {
        std::future::ready(Err(Error::Io(io::Error::other("disk on fire"))))
    }
}

fn digest_of(seed: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{seed:02x}").repeat(32))).unwrap()
}

fn pattern(len: usize) -> Bytes {
    Bytes::from(
        (0..len)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>(),
    )
}

struct Server {
    address: SocketAddr,
    directory: tempfile::TempDir,
    mirror: Mirror,
    _stop: oneshot::Sender<()>,
}

fn write_files(dir: &Path, mirror: &Mirror) {
    for part in Part::ALL {
        std::fs::write(
            dir.join(part.file_name()),
            mirror.contents(part).expose_secret(),
        )
        .unwrap();
    }
}

async fn start<C: Content>(content: C) -> Server {
    let directory = tempfile::tempdir().unwrap();
    let mirror = Mirror::generate(IP, SystemTime::now()).unwrap();
    write_files(directory.path(), &mirror);
    let tls = Arc::new(Tls::load(directory.path()).unwrap());
    let listener = TcpListener::bind((IP, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(serve(listener, tls, Arc::new(content), async {
        // An error means the sender went with the test: stop too.
        let _ = stopped.await;
    }));
    Server {
        address,
        directory,
        mirror,
        _stop: stop,
    }
}

/// A client that trusts the CA of `trusting`, and presents the client certificate of `presenting` when there is one.
fn client_config(trusting: &Mirror, presenting: Option<&Mirror>) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = RootCertStore::empty();
    for der in CertificateDer::pem_slice_iter(trusting.ca().as_bytes()) {
        roots.add(der.unwrap()).unwrap();
    }
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let config = match presenting {
        Some(mirror) => {
            let pem = mirror.contents(Part::Client);
            let chain = CertificateDer::pem_slice_iter(pem.expose_secret().as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            let key = PrivateKeyDer::from_pem_slice(pem.expose_secret().as_bytes()).unwrap();
            builder.with_client_auth_cert(chain, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    Arc::new(config)
}

async fn connect(
    address: SocketAddr,
    config: Arc<ClientConfig>,
) -> io::Result<SendRequest<Empty<Bytes>>> {
    let tcp = TcpStream::connect(address).await?;
    let tls = TlsConnector::from(config)
        .connect(ServerName::IpAddress(IP.into()), tcp)
        .await?;
    let (sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(io::Error::other)?;
    tokio::spawn(connection);
    Ok(sender)
}

async fn client(server: &Server) -> SendRequest<Empty<Bytes>> {
    connect(
        server.address,
        client_config(&server.mirror, Some(&server.mirror)),
    )
    .await
    .unwrap()
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
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mirror");
    if let Some(range) = range {
        request = request.header("range", range);
    }
    let response = sender
        .send_request(request.body(Empty::new()).unwrap())
        .await
        .unwrap();
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

fn header<'a>(answer: &'a Answer, name: &str) -> &'a str {
    answer
        .headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

fn blob_path(digest: &Digest) -> String {
    format!("/v2/library/busybox/blobs/{digest}?ns=docker.io")
}

fn manifest_path(digest: &Digest) -> String {
    format!("/v2/library/busybox/manifests/{digest}?ns=docker.io")
}

#[tokio::test]
async fn the_ping_answers_200_to_a_client_with_the_certificate() {
    let server = start(Fake(HashMap::new())).await;
    let mut sender = client(&server).await;
    let answer = get(&mut sender, "/v2/").await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(
        header(&answer, "docker-distribution-api-version"),
        "registry/2.0"
    );
    assert_eq!(answer.body, "{}");
    assert_eq!(
        ask(&mut sender, Method::HEAD, "/v2/", None).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_blob_is_served_whole_by_get_and_described_by_head_at_any_size() {
    // Around the read size, and large enough for the socket to fill: the response must arrive whole each time
    // (tokio-rustls can return from a write with the tail buffered; D67, Measured).
    let sizes = [
        0,
        1,
        100,
        256 * 1024 - 1,
        256 * 1024,
        256 * 1024 + 1,
        5 * 1024 * 1024,
    ];
    let held: HashMap<Digest, Bytes> = sizes
        .iter()
        .enumerate()
        .map(|(i, size)| (digest_of(u8::try_from(i).unwrap()), pattern(*size)))
        .collect();
    let server = start(Fake(held.clone())).await;
    let mut sender = client(&server).await;
    for (digest, bytes) in &held {
        let answer = get(&mut sender, &blob_path(digest)).await;
        assert_eq!(answer.status, StatusCode::OK, "{} bytes", bytes.len());
        assert_eq!(answer.body, *bytes, "{} bytes", bytes.len());
        assert_eq!(header(&answer, "content-length"), bytes.len().to_string());
        assert_eq!(header(&answer, "content-type"), "application/octet-stream");
        assert_eq!(header(&answer, "docker-content-digest"), digest.to_string());
        assert_eq!(header(&answer, "accept-ranges"), "bytes");
        let headed = ask(&mut sender, Method::HEAD, &blob_path(digest), None).await;
        assert_eq!(headed.status, StatusCode::OK);
        assert_eq!(header(&headed, "content-length"), bytes.len().to_string());
        assert_eq!(headed.body, "");
    }
}

#[tokio::test]
async fn ranges_give_partial_content_and_ranges_past_the_end_give_416() {
    let digest = digest_of(1);
    let bytes = pattern(2048);
    let server = start(Fake(HashMap::from([(digest.clone(), bytes.clone())]))).await;
    let mut sender = client(&server).await;
    let path = blob_path(&digest);
    for (range, first, last) in [
        ("bytes=500-1499", 500, 1499),
        ("bytes=500-", 500, 2047),
        ("bytes=-500", 1548, 2047),
        ("bytes=2000-5000", 2000, 2047),
        ("bytes=0-0", 0, 0),
    ] {
        let answer = ask(&mut sender, Method::GET, &path, Some(range)).await;
        assert_eq!(answer.status, StatusCode::PARTIAL_CONTENT, "{range}");
        assert_eq!(
            header(&answer, "content-range"),
            format!("bytes {first}-{last}/2048"),
            "{range}"
        );
        assert_eq!(answer.body, bytes.slice(first..=last), "{range}");
        assert_eq!(
            header(&answer, "content-length"),
            (last - first + 1).to_string()
        );
    }
    for range in ["bytes=500-0", "bytes=5000-10000", "bytes=2048-"] {
        let answer = ask(&mut sender, Method::GET, &path, Some(range)).await;
        assert_eq!(answer.status, StatusCode::RANGE_NOT_SATISFIABLE, "{range}");
        assert_eq!(header(&answer, "content-range"), "bytes */2048", "{range}");
        assert_eq!(answer.body, "");
    }
    // Ignored: the whole blob. A HEAD takes no range.
    for range in ["bytes=0-1,5-6", "items=1-2", "garbage"] {
        let answer = ask(&mut sender, Method::GET, &path, Some(range)).await;
        assert_eq!(
            (answer.status, answer.body.len()),
            (StatusCode::OK, 2048),
            "{range}"
        );
    }
    let head = ask(&mut sender, Method::HEAD, &path, Some("bytes=0-9")).await;
    assert_eq!(
        (head.status, header(&head, "content-length")),
        (StatusCode::OK, "2048")
    );
}

#[tokio::test]
async fn a_manifest_is_served_with_the_media_type_it_names_or_its_shape_implies() {
    let index = Bytes::from_static(br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}"#);
    let docker = Bytes::from_static(br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","layers":[]}"#);
    let unnamed_index = Bytes::from_static(br#"{"schemaVersion":2,"manifests":[]}"#);
    let unnamed_image = Bytes::from_static(br#"{"schemaVersion":2,"config":{},"layers":[]}"#);
    let layer = pattern(1000);
    let big = Bytes::from(vec![b' '; usize::try_from(MAX_MANIFEST).unwrap() + 1]);
    let all = [
        (index, "application/vnd.oci.image.index.v1+json"),
        (
            docker,
            "application/vnd.docker.distribution.manifest.v2+json",
        ),
        (unnamed_index, "application/vnd.oci.image.index.v1+json"),
        (unnamed_image, "application/vnd.oci.image.manifest.v1+json"),
    ];
    let mut held = HashMap::new();
    for (i, (bytes, _)) in all.iter().enumerate() {
        held.insert(digest_of(u8::try_from(i).unwrap()), bytes.clone());
    }
    held.insert(digest_of(10), layer);
    held.insert(digest_of(11), big);
    let server = start(Fake(held)).await;
    let mut sender = client(&server).await;
    for (i, (bytes, media_type)) in all.iter().enumerate() {
        let digest = digest_of(u8::try_from(i).unwrap());
        let answer = get(&mut sender, &manifest_path(&digest)).await;
        assert_eq!(answer.status, StatusCode::OK);
        assert_eq!(header(&answer, "content-type"), *media_type);
        assert_eq!(header(&answer, "docker-content-digest"), digest.to_string());
        assert_eq!(answer.body, *bytes);
        let headed = ask(&mut sender, Method::HEAD, &manifest_path(&digest), None).await;
        assert_eq!(header(&headed, "content-length"), bytes.len().to_string());
        assert_eq!(headed.body, "");
    }
    // Not a manifest, and too large to be one: a miss.
    for seed in [10, 11] {
        let answer = get(&mut sender, &manifest_path(&digest_of(seed))).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{seed}");
    }
}

#[tokio::test]
async fn everything_the_mirror_does_not_serve_is_a_fast_404_and_never_a_401_408_or_429() {
    let held = digest_of(1);
    let server = start(Fake(HashMap::from([(held.clone(), pattern(10))]))).await;
    let mut sender = client(&server).await;
    let unheld = digest_of(2);
    for (method, path) in [
        (Method::GET, blob_path(&unheld)),
        (Method::GET, manifest_path(&unheld)),
        (Method::HEAD, blob_path(&unheld)),
        (
            Method::GET,
            "/v2/library/busybox/manifests/latest".to_owned(),
        ),
        (
            Method::GET,
            "/v2/library/busybox/blobs/sha256:short".to_owned(),
        ),
        (Method::GET, format!("/v2/library/busybox/referrers/{held}")),
        (Method::GET, "/v2/library/busybox/tags/list".to_owned()),
        (
            Method::POST,
            "/v2/library/busybox/blobs/uploads/".to_owned(),
        ),
        (Method::PUT, manifest_path(&held)),
        (Method::DELETE, blob_path(&held)),
        (Method::GET, "/".to_owned()),
        (Method::GET, "/metrics".to_owned()),
    ] {
        let answer = ask(&mut sender, method.clone(), &path, None).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(answer.body, "", "{method} {path}");
    }
    // The same connection still serves what is held.
    assert_eq!(
        get(&mut sender, &blob_path(&held)).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn content_that_cannot_be_read_is_a_404_too() {
    let server = start(Failing).await;
    let mut sender = client(&server).await;
    let answer = get(&mut sender, &blob_path(&digest_of(1))).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(get(&mut sender, "/v2/").await.status, StatusCode::OK);
}

/// Whether a client is refused: its handshake fails, or its first request does (TLS 1.3 reports a refused client
/// certificate after the handshake).
async fn refused(server: &Server, config: Arc<ClientConfig>) -> bool {
    match connect(server.address, config).await {
        Err(_) => true,
        Ok(mut sender) => sender
            .send_request(
                Request::get("/v2/")
                    .header("host", "mirror")
                    .body(Empty::new())
                    .unwrap(),
            )
            .await
            .is_err(),
    }
}

#[tokio::test]
async fn a_client_without_the_local_certificate_is_refused() {
    let server = start(Fake(HashMap::new())).await;
    assert!(refused(&server, client_config(&server.mirror, None)).await);
    // A certificate that another CA signed.
    let other = Mirror::generate(IP, SystemTime::now()).unwrap();
    assert!(refused(&server, client_config(&server.mirror, Some(&other))).await);
    // The server is still serving.
    let mut sender = client(&server).await;
    assert_eq!(get(&mut sender, "/v2/").await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_client_that_trusts_another_ca_does_not_trust_the_server() {
    let server = start(Fake(HashMap::new())).await;
    let other = Mirror::generate(IP, SystemTime::now()).unwrap();
    assert!(
        connect(server.address, client_config(&other, Some(&other)))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn connections_are_kept_alive_and_served_concurrently() {
    let digest = digest_of(1);
    let bytes = pattern(300_000);
    let server = start(Fake(HashMap::from([(digest.clone(), bytes.clone())]))).await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let mut sender = client(&server).await;
        let (path, bytes) = (blob_path(&digest), bytes.clone());
        tasks.push(tokio::spawn(async move {
            for _ in 0..3 {
                let answer = get(&mut sender, &path).await;
                assert_eq!(answer.body, bytes);
            }
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn replaced_certificates_serve_the_next_connection() {
    let server = start(Fake(HashMap::new())).await;
    let mut old = client(&server).await;
    assert_eq!(get(&mut old, "/v2/").await.status, StatusCode::OK);
    let replacement = Mirror::generate(IP, SystemTime::now()).unwrap();
    write_files(server.directory.path(), &replacement);
    // The files are looked at once a second, when a connection comes.
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    // A connection with the new files in hand takes the new certificates, and the old client is refused.
    let mut fresh = connect(
        server.address,
        client_config(&replacement, Some(&replacement)),
    )
    .await
    .unwrap();
    assert_eq!(get(&mut fresh, "/v2/").await.status, StatusCode::OK);
    assert!(refused(&server, client_config(&server.mirror, Some(&server.mirror))).await);
    // The connection that was open keeps working.
    assert_eq!(get(&mut old, "/v2/").await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_metrics_count_requests_bytes_and_first_byte_times() {
    use metrics_exporter_prometheus::PrometheusBuilder;
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    ::metrics::set_global_recorder(recorder).unwrap();
    metrics::describe();
    let held = digest_of(1);
    let server = start(Fake(HashMap::from([(held.clone(), pattern(1000))]))).await;
    let mut sender = client(&server).await;
    assert_eq!(
        get(&mut sender, &blob_path(&held)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        get(&mut sender, &blob_path(&digest_of(2))).await.status,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        get(&mut sender, "/v2/x/manifests/latest").await.status,
        StatusCode::NOT_FOUND
    );
    let text = handle.render();
    for line in [
        r#"speculaire_mirror_requests_total{kind="blob",result="served"} 1"#,
        r#"speculaire_mirror_requests_total{kind="blob",result="fall_through"} 1"#,
        r#"speculaire_mirror_requests_total{kind="manifest",result="fall_through"} 1"#,
        r#"speculaire_mirror_requests_total{kind="referrers",result="served"} 0"#,
        r#"speculaire_mirror_bytes_total{source="local"} 1000"#,
    ] {
        assert!(text.lines().any(|l| l == line), "no `{line}` in\n{text}");
    }
}
