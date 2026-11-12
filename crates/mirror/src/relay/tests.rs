//! The relay against a fake registry on a local port, behind a registry config written to a temporary root.

use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use secrecy::SecretString;
use speculaire_runtime::registries::{Credentials, Endpoint, Error as ConfigError};
use tokio::net::TcpListener;

use super::*;

/// What the fake registry answers for a path.
#[derive(Clone)]
struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: Bytes,
    /// The body is sent in pieces of this many bytes, so that the relay holds one back; 0 for one piece.
    pieces: usize,
    /// The body is shorter than the length the headers promise.
    cut: bool,
    /// The `Authorization` the request must carry; without it the answer is a 401 with a Basic challenge.
    requires: Option<&'static str>,
}

impl Reply {
    fn ok(body: impl Into<Bytes>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
            pieces: 0,
            cut: false,
            requires: None,
        }
    }
}

type Replies = Arc<Mutex<HashMap<String, Reply>>>;

/// What the fake registry saw: the path, the `Authorization` and the `Range` of each request.
type Journal = Arc<Mutex<Vec<(String, Option<String>, Option<String>)>>>;

struct Registry {
    address: SocketAddr,
    replies: Replies,
    log: Journal,
}

impl Registry {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let replies: Replies = Arc::default();
        let log = Arc::new(Mutex::new(Vec::new()));
        let (served, journal) = (Arc::clone(&replies), Arc::clone(&log));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (replies, log) = (Arc::clone(&served), Arc::clone(&journal));
                tokio::spawn(async move {
                    let service =
                        service_fn(move |request: http::Request<hyper::body::Incoming>| {
                            let (replies, log) = (Arc::clone(&replies), Arc::clone(&log));
                            async move { Ok::<_, Infallible>(answer(&replies, &log, &request)) }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            address,
            replies,
            log,
        }
    }

    fn put(&self, path: &str, reply: Reply) {
        self.replies.lock().unwrap().insert(path.to_owned(), reply);
    }

    /// Every request so far: `METHOD path`.
    fn requests(&self) -> Vec<String> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .map(|(r, ..)| r.clone())
            .collect()
    }

    fn headers_of(&self, needle: &str) -> Vec<(Option<String>, Option<String>)> {
        self.log
            .lock()
            .unwrap()
            .iter()
            .filter(|(r, ..)| r.contains(needle))
            .map(|(_, range, auth)| (range.clone(), auth.clone()))
            .collect()
    }
}

fn answer(
    replies: &Replies,
    log: &Journal,
    request: &http::Request<hyper::body::Incoming>,
) -> http::Response<Body> {
    let path = request.uri().path().to_owned();
    let header = |name: &str| {
        request
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    log.lock().unwrap().push((
        format!("{} {path}", request.method()),
        header("range"),
        header("authorization"),
    ));
    let Some(reply) = replies.lock().unwrap().get(&path).cloned() else {
        return plain(404, Bytes::new());
    };
    if let Some(required) = reply.requires
        && header("authorization").as_deref() != Some(required)
    {
        let mut unauthorized = plain(401, Bytes::new());
        unauthorized.headers_mut().insert(
            "www-authenticate",
            http::HeaderValue::from_static(r#"Basic realm="registry""#),
        );
        return unauthorized;
    }
    let mut body = reply.body.clone();
    let mut status = reply.status;
    let mut headers = reply.headers.clone();
    // A range on a 200 gets what it asks, as a registry that supports ranges answers.
    if status == 200
        && let Some(spec) =
            header("range").and_then(|r| r.strip_prefix("bytes=").map(str::to_owned))
        && let Some((first, last)) = spec.split_once('-')
        && let (Ok(first), Ok(last)) = (first.parse::<usize>(), last.parse::<usize>())
    {
        let total = body.len();
        let last = last.min(total - 1);
        body = body.slice(first..=last);
        status = 206;
        headers.push((
            "content-range".to_owned(),
            format!("bytes {first}-{last}/{total}"),
        ));
    }
    let length = body.len();
    let shown = if *request.method() == Method::HEAD {
        0
    } else {
        length
    };
    let mut builder = http::Response::builder().status(status);
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    builder = builder.header(CONTENT_LENGTH, length);
    let body = if *request.method() == Method::HEAD {
        crate::serve::empty()
    } else if reply.cut {
        // Promise `length`, send half of it, pause so that the half goes out, and break the connection.
        let size = reply.pieces.max(1);
        let frames: Vec<Result<Frame<Bytes>, io::Error>> = body
            .slice(..shown / 2)
            .chunks(size)
            .map(|chunk| Ok(Frame::data(Bytes::copy_from_slice(chunk))))
            .collect();
        let broken = futures_util::stream::once(async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            Err(io::Error::other("the registry went away"))
        });
        StreamBody::new(futures_util::StreamExt::chain(
            futures_util::stream::iter(frames),
            broken,
        ))
        .boxed_unsync()
    } else {
        pieces(&body, reply.pieces)
    };
    builder.body(body).unwrap()
}

fn plain(status: u16, body: Bytes) -> http::Response<Body> {
    http::Response::builder()
        .status(status)
        .header(CONTENT_LENGTH, body.len())
        .body(http_body_util::BodyExt::boxed_unsync(
            http_body_util::BodyExt::map_err(Full::new(body), |never: Infallible| match never {}),
        ))
        .unwrap()
}

/// A body of pieces of `size` bytes.
fn pieces(body: &Bytes, size: usize) -> Body {
    if size == 0 {
        return StreamBody::new(futures_util::stream::iter([Ok::<_, io::Error>(
            Frame::data(body.clone()),
        )]))
        .boxed_unsync();
    }
    let frames: Vec<Result<Frame<Bytes>, io::Error>> = body
        .chunks(size)
        .map(|chunk| Ok(Frame::data(Bytes::copy_from_slice(chunk))))
        .collect();
    StreamBody::new(futures_util::stream::iter(frames)).boxed_unsync()
}

/// Registry config that is what a test says: the sources of every name under `reg.test`, and an error for the rest.
struct Fixed(Mutex<Vec<Source>>);

impl Registries for Fixed {
    fn sources(
        &self,
        name: &str,
        _reference: registries::Reference<'_>,
    ) -> Result<Vec<Source>, ConfigError> {
        if !name.starts_with("reg.test/") {
            return Err(ConfigError::Name(name.to_owned()));
        }
        Ok(self.0.lock().unwrap().clone())
    }
}

fn source(address: SocketAddr, credentials: Credentials) -> Source {
    Source {
        candidates: vec![Endpoint::new(false, address.to_string())],
        repository: "app/web".to_owned(),
        credentials,
    }
}

struct Node {
    dir: tempfile::TempDir,
    registry: Registry,
    config: Arc<Fixed>,
}

impl Node {
    /// A node whose registry config sends `reg.test` to the fake registry, anonymously.
    async fn new() -> Self {
        let registry = Registry::start().await;
        let config = Arc::new(Fixed(Mutex::new(vec![source(
            registry.address,
            Credentials::Anonymous,
        )])));
        Self {
            dir: tempfile::tempdir().unwrap(),
            registry,
            config,
        }
    }

    /// The registry config says these sources from now on.
    fn sources(&self, sources: Vec<Source>) {
        *self.config.0.lock().unwrap() = sources;
    }

    fn relay(&self, max_size: u64) -> Relay<NoImages> {
        self.relay_with(max_size, NoImages)
    }

    fn relay_with<I: Images>(&self, max_size: u64, images: I) -> Relay<I> {
        let cache = Cache::open(self.dir.path().join("blobs"), max_size).unwrap();
        Relay::new(
            cache,
            Arc::clone(&self.config) as Arc<dyn Registries>,
            images,
        )
    }
}

/// The digest of `bytes`.
fn sha(bytes: &[u8]) -> Digest {
    hash_of("sha256", bytes).unwrap()
}

/// An image of two layers on the fake registry under `reg.test/app/web`: the config, the layers, the manifest.
struct Image {
    manifest: Bytes,
    manifest_digest: Digest,
    config: Bytes,
    layers: Vec<Bytes>,
}

impl Image {
    fn new(registry: &Registry, layer_sizes: &[usize]) -> Self {
        let config = Bytes::from_static(
            br#"{"architecture":"arm64","os":"linux","rootfs":{"type":"layers"}}"#,
        );
        let layers: Vec<Bytes> = layer_sizes
            .iter()
            .enumerate()
            .map(|(i, size)| {
                Bytes::from(
                    (0..*size)
                        .map(|n| u8::try_from((n + i * 7) % 251).unwrap())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        let descriptors = |blobs: &[&Bytes]| {
            blobs
                .iter()
                .map(|b| format!(r#"{{"digest":"{}","size":{}}}"#, sha(b), b.len()))
                .collect::<Vec<_>>()
                .join(",")
        };
        let manifest = Bytes::from(format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"digest":"{}","size":{}}},"layers":[{}]}}"#,
            sha(&config),
            config.len(),
            descriptors(&layers.iter().collect::<Vec<_>>())
        ));
        let manifest_digest = sha(&manifest);
        let mut reply = Reply::ok(manifest.clone());
        reply.headers.push((
            "content-type".to_owned(),
            "application/vnd.oci.image.manifest.v1+json".to_owned(),
        ));
        registry.put("/v2/app/web/manifests/1.0", reply.clone());
        registry.put(&format!("/v2/app/web/manifests/{manifest_digest}"), reply);
        registry.put(
            &format!("/v2/app/web/blobs/{}", sha(&config)),
            Reply::ok(config.clone()),
        );
        for layer in &layers {
            let mut reply = Reply::ok(layer.clone());
            reply.pieces = 64 * 1024;
            registry.put(&format!("/v2/app/web/blobs/{}", sha(layer)), reply);
        }
        Self {
            manifest,
            manifest_digest,
            config,
            layers,
        }
    }
}

fn pull<'a>(kind: Kind, reference: &'a Reference, head: bool, range: Option<&'a str>) -> Pull<'a> {
    Pull {
        kind,
        name: "reg.test/app/web",
        reference: Some(reference),
        head,
        range,
        accept: Some("application/vnd.oci.image.manifest.v1+json"),
    }
}

fn tag(text: &str) -> Reference {
    Reference::Tag(text.to_owned())
}

fn by(digest: &Digest) -> Reference {
    Reference::Digest(digest.clone())
}

/// What a client of the mirror got: the status, the headers, and the body as far as it came, with the error that cut it.
struct Got {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
    error: Option<String>,
}

async fn read(answer: Answer) -> Option<Got> {
    let Answer::Served(response) = answer else {
        return None;
    };
    let (parts, mut body) = response.into_parts();
    let mut got = Got {
        status: parts.status,
        headers: parts.headers,
        body: Vec::new(),
        error: None,
    };
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    got.body.extend_from_slice(&data);
                }
            }
            Err(err) => {
                got.error = Some(err.to_string());
                break;
            }
        }
    }
    Some(got)
}

fn is_missing(answer: &Answer) -> bool {
    matches!(answer, Answer::Missing)
}

#[tokio::test]
async fn a_manifest_by_tag_is_resolved_upstream_served_with_its_digest_and_kept() {
    let node = Node::new().await;
    let image = Image::new(&node.registry, &[1000, 2000]);
    let relay = node.relay(1 << 30);
    let got = read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.body, image.manifest);
    assert_eq!(
        got.headers["docker-content-digest"],
        image.manifest_digest.to_string()
    );
    assert_eq!(
        got.headers["content-type"],
        "application/vnd.oci.image.manifest.v1+json"
    );
    assert_eq!(
        got.headers["content-length"],
        image.manifest.len().to_string()
    );
    assert!(got.error.is_none());
    assert!(relay.cache().contains(&image.manifest_digest));
    // Upstream was asked with the Accept CRI-O sent.
    assert_eq!(node.registry.requests(), ["GET /v2/app/web/manifests/1.0"]);
    // By digest, the relay serves its own copy: nothing more goes upstream.
    let again = read(
        relay
            .pull(pull(
                Kind::Manifest,
                &by(&image.manifest_digest),
                false,
                None,
            ))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(again.body, image.manifest);
    assert_eq!(node.registry.requests().len(), 1);
    // The head of the manifest by digest, from the copy too.
    let head = read(
        relay
            .pull(pull(
                Kind::Manifest,
                &by(&image.manifest_digest),
                true,
                None,
            ))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(head.body, b"");
    assert_eq!(
        head.headers["content-length"],
        image.manifest.len().to_string()
    );
    assert_eq!(node.registry.requests().len(), 1);
}

#[tokio::test]
async fn the_head_of_a_tag_is_asked_as_a_head_and_keeps_nothing() {
    let node = Node::new().await;
    let image = Image::new(&node.registry, &[10]);
    let mut reply = Reply::ok(image.manifest.clone());
    reply.headers.push((
        "docker-content-digest".to_owned(),
        image.manifest_digest.to_string(),
    ));
    reply.headers.push((
        "content-type".to_owned(),
        "application/vnd.oci.image.manifest.v1+json".to_owned(),
    ));
    node.registry.put("/v2/app/web/manifests/1.0", reply);
    let relay = node.relay(1 << 30);
    let got = read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), true, None))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.body, b"");
    assert_eq!(
        got.headers["docker-content-digest"],
        image.manifest_digest.to_string()
    );
    assert_eq!(
        got.headers["content-length"],
        image.manifest.len().to_string()
    );
    assert_eq!(node.registry.requests(), ["HEAD /v2/app/web/manifests/1.0"]);
    assert!(!relay.cache().contains(&image.manifest_digest));
}

#[tokio::test]
async fn a_blob_is_served_only_below_a_manifest_the_relay_served_and_is_fetched_once() {
    let node = Node::new().await;
    let image = Image::new(&node.registry, &[300_000, 2000]);
    let relay = node.relay(1 << 30);
    let layer = sha(&image.layers[0]);
    // Before any manifest: no.
    assert!(is_missing(
        &relay.pull(pull(Kind::Blob, &by(&layer), false, None)).await
    ));
    assert_eq!(node.registry.requests().len(), 0);
    read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await,
    )
    .await
    .unwrap();
    // A blob that no manifest points to is not served, though it exists upstream.
    node.registry
        .put("/v2/app/web/blobs/sha256:other", Reply::ok("x"));
    let stranger = sha(b"stranger");
    node.registry.put(
        &format!("/v2/app/web/blobs/{stranger}"),
        Reply::ok("stranger"),
    );
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Blob, &by(&stranger), false, None))
            .await
    ));
    // Every blob of the image, the config first, whole and in order.
    for (blob, bytes) in [
        (sha(&image.config), &image.config),
        (layer.clone(), &image.layers[0]),
        (sha(&image.layers[1]), &image.layers[1]),
    ] {
        let got = read(relay.pull(pull(Kind::Blob, &by(&blob), false, None)).await)
            .await
            .unwrap();
        assert_eq!(got.status, StatusCode::OK);
        assert!(got.error.is_none(), "{:?}", got.error);
        assert_eq!(got.body.len(), bytes.len());
        assert!(got.body == bytes.as_ref(), "the bytes differ");
        assert_eq!(got.headers["docker-content-digest"], blob.to_string());
        assert_eq!(got.headers["content-length"], bytes.len().to_string());
        assert_eq!(got.headers["content-type"], "application/octet-stream");
        assert!(relay.cache().contains(&blob), "{blob}");
    }
    // Served again, from the cache: upstream sees no second request, and a range is cut from the file.
    let before = node.registry.requests().len();
    let again = read(relay.pull(pull(Kind::Blob, &by(&layer), false, None)).await)
        .await
        .unwrap();
    assert_eq!(again.body, image.layers[0].as_ref());
    let part = read(
        relay
            .pull(pull(Kind::Blob, &by(&layer), false, Some("bytes=100-199")))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(part.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.body, image.layers[0].slice(100..200));
    assert_eq!(node.registry.requests().len(), before);
    assert_eq!(
        std::fs::read_dir(node.dir.path().join("blobs/tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn a_blob_whose_bytes_are_not_its_digest_is_never_sent_whole_and_never_kept() {
    let node = Node::new().await;
    let image = Image::new(&node.registry, &[300_000]);
    let relay = node.relay(1 << 30);
    read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await,
    )
    .await
    .unwrap();
    let layer = sha(&image.layers[0]);
    // A proxy flips a byte in the middle.
    let mut flipped = image.layers[0].to_vec();
    flipped[150_000] ^= 0xff;
    let mut reply = Reply::ok(Bytes::from(flipped));
    reply.pieces = 64 * 1024;
    node.registry
        .put(&format!("/v2/app/web/blobs/{layer}"), reply);
    let got = read(relay.pull(pull(Kind::Blob, &by(&layer), false, None)).await)
        .await
        .unwrap();
    // The status and headers went out, the body stopped short with an error.
    assert_eq!(got.status, StatusCode::OK);
    assert!(got.error.is_some(), "the body ended as if it were whole");
    assert!(
        got.body.len() < image.layers[0].len(),
        "the client received the whole wrong blob: {} of {}",
        got.body.len(),
        image.layers[0].len()
    );
    assert!(!relay.cache().contains(&layer));
    assert_eq!(relay.cache().size(), image.manifest.len() as u64);
    assert_eq!(
        std::fs::read_dir(node.dir.path().join("blobs/tmp"))
            .unwrap()
            .count(),
        0
    );
    // A retry with the right bytes works.
    let mut reply = Reply::ok(image.layers[0].clone());
    reply.pieces = 64 * 1024;
    node.registry
        .put(&format!("/v2/app/web/blobs/{layer}"), reply);
    let got = read(relay.pull(pull(Kind::Blob, &by(&layer), false, None)).await)
        .await
        .unwrap();
    assert!(got.error.is_none() && got.body == image.layers[0].as_ref());
    assert!(relay.cache().contains(&layer));
}

#[tokio::test]
async fn a_blob_cut_short_by_upstream_is_not_kept() {
    let node = Node::new().await;
    let image = Image::new(&node.registry, &[100_000]);
    let relay = node.relay(1 << 30);
    read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await,
    )
    .await
    .unwrap();
    let layer = sha(&image.layers[0]);
    let mut reply = Reply::ok(image.layers[0].clone());
    reply.cut = true;
    reply.pieces = 16 * 1024;
    node.registry
        .put(&format!("/v2/app/web/blobs/{layer}"), reply);
    let got = read(relay.pull(pull(Kind::Blob, &by(&layer), false, None)).await)
        .await
        .unwrap();
    assert!(got.error.is_some());
    assert!(got.body.len() < image.layers[0].len());
    assert!(!relay.cache().contains(&layer));
    assert_eq!(
        std::fs::read_dir(node.dir.path().join("blobs/tmp"))
            .unwrap()
            .count(),
        0
    );
}

#[tokio::test]
async fn a_range_of_a_blob_the_cache_lacks_is_relayed_as_upstream_answers_and_not_kept() {
    let node = Node::new().await;
    let image = Image::new(&node.registry, &[5000]);
    let relay = node.relay(1 << 30);
    read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await,
    )
    .await
    .unwrap();
    let layer = sha(&image.layers[0]);
    let got = read(
        relay
            .pull(pull(Kind::Blob, &by(&layer), false, Some("bytes=10-19")))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(got.status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(got.body, image.layers[0].slice(10..20));
    assert_eq!(got.headers["content-range"], "bytes 10-19/5000");
    assert_eq!(got.headers["content-length"], "10");
    assert_eq!(
        node.registry.headers_of(&format!("blobs/{layer}"))[0]
            .0
            .as_deref(),
        Some("bytes=10-19")
    );
    assert!(!relay.cache().contains(&layer));
    // The head of an uncached blob is upstream's head.
    let head = read(relay.pull(pull(Kind::Blob, &by(&layer), true, None)).await)
        .await
        .unwrap();
    assert_eq!(head.status, StatusCode::OK);
    assert_eq!(head.body, b"");
    assert_eq!(head.headers["content-length"], "5000");
}

#[tokio::test]
async fn a_registry_that_has_no_manifest_or_wants_a_login_the_node_lacks_is_a_fall_through() {
    let node = Node::new().await;
    let relay = node.relay(1 << 30);
    // 404.
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Manifest, &tag("nope"), false, None))
            .await
    ));
    // 401, and the node has no credentials: the image needs a pull secret, which only the pod has.
    let mut reply = Reply::ok("");
    reply.status = 401;
    reply.headers.push((
        "www-authenticate".to_owned(),
        r#"Basic realm="registry""#.to_owned(),
    ));
    node.registry.put("/v2/app/web/manifests/1.0", reply);
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await
    ));
    // Other statuses, and a kind the relay does not serve.
    let mut reply = Reply::ok("");
    reply.status = 429;
    node.registry.put("/v2/app/web/manifests/busy", reply);
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Manifest, &tag("busy"), false, None))
            .await
    ));
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Referrers, &tag("x"), false, None))
            .await
    ));
    assert!(is_missing(
        &relay.pull(pull(Kind::Blob, &tag("x"), false, None)).await
    ));
    let x = tag("x");
    let nothing = Pull {
        reference: None,
        ..pull(Kind::Manifest, &x, false, None)
    };
    assert!(is_missing(&relay.pull(nothing).await));
}

#[tokio::test]
async fn the_nodes_login_answers_a_basic_challenge() {
    let node = Node::new().await;
    node.sources(vec![source(
        node.registry.address,
        Credentials::Login {
            username: "alice".to_owned(),
            password: SecretString::from("s3cret".to_owned()),
            identity_token: None,
        },
    )]);
    let image = Image::new(&node.registry, &[100]);
    let mut reply = Reply::ok(image.manifest.clone());
    reply.requires = Some("Basic YWxpY2U6czNjcmV0");
    node.registry.put("/v2/app/web/manifests/1.0", reply);
    let relay = node.relay(1 << 30);
    let got = read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(got.body, image.manifest);
    // The first request carried no login, the second the node's.
    let sent = node.registry.headers_of("manifests/1.0");
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].1, None);
    assert_eq!(sent[1].1.as_deref(), Some("Basic YWxpY2U6czNjcmV0"));
}

#[tokio::test]
async fn a_manifest_by_digest_that_is_not_that_digest_or_is_of_a_kind_the_relay_does_not_read_is_a_fall_through()
 {
    let node = Node::new().await;
    let relay = node.relay(1 << 30);
    let wrong = sha(b"what the client asked for");
    node.registry.put(
        &format!("/v2/app/web/manifests/{wrong}"),
        Reply::ok(r#"{"schemaVersion":2,"config":{"digest":"sha256:00"},"layers":[]}"#),
    );
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Manifest, &by(&wrong), false, None))
            .await
    ));
    assert!(!relay.cache().contains(&wrong));
    // A schema 1 manifest, by tag: no children to know.
    node.registry.put(
        "/v2/app/web/manifests/old",
        Reply::ok(r#"{"schemaVersion":1,"fsLayers":[{"blobSum":"sha256:00"}]}"#),
    );
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Manifest, &tag("old"), false, None))
            .await
    ));
    // Not JSON at all.
    node.registry
        .put("/v2/app/web/manifests/junk", Reply::ok("<html>"));
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Manifest, &tag("junk"), false, None))
            .await
    ));
    assert_eq!(relay.cache().size(), 0);
}

#[tokio::test]
async fn an_admin_mirror_is_tried_before_the_registry_and_a_dead_one_is_skipped() {
    let node = Node::new().await;
    let image = Image::new(&node.registry, &[100]);
    let mirror = Registry::start().await;
    // The mirror answers 404 to everything but a blob; a dead one is a port nobody listens on.
    let dead = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    node.sources(vec![
        source(dead, Credentials::Anonymous),
        source(mirror.address, Credentials::Anonymous),
        source(node.registry.address, Credentials::Anonymous),
    ]);
    let relay = node.relay(1 << 30);
    let got = read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(got.body, image.manifest);
    // The live mirror was asked, said no, and the registry answered.
    assert_eq!(mirror.requests(), ["GET /v2/app/web/manifests/1.0"]);
    assert_eq!(node.registry.requests(), ["GET /v2/app/web/manifests/1.0"]);
}

#[tokio::test]
async fn a_name_with_no_registry_is_an_error_and_a_blocked_registry_a_fall_through() {
    let node = Node::new().await;
    let relay = node.relay(1 << 30);
    let reference = tag("1");
    let bare = Pull {
        name: "busybox",
        ..pull(Kind::Manifest, &reference, false, None)
    };
    assert!(matches!(
        relay.pull(bare).await,
        Answer::Failed(Error::Relay(_))
    ));
    node.sources(Vec::new());
    let relay = node.relay(1 << 30);
    assert!(is_missing(
        &relay
            .pull(pull(Kind::Manifest, &reference, false, None))
            .await
    ));
}

/// A list of images that the runtime has.
struct Listed(Vec<Digest>);

impl Images for Listed {
    fn listed(&self) -> impl std::future::Future<Output = Vec<Digest>> + Send {
        std::future::ready(self.0.clone())
    }
}

#[tokio::test]
async fn above_the_bound_the_blobs_of_unlisted_images_go_before_those_of_listed_ones() {
    let node = Node::new().await;
    let kept = Image::new(&node.registry, &[3000]);
    let relay = node.relay_with(1 << 30, Listed(vec![kept.manifest_digest.clone()]));
    for image in [&kept] {
        read(
            relay
                .pull(pull(
                    Kind::Manifest,
                    &by(&image.manifest_digest),
                    false,
                    None,
                ))
                .await,
        )
        .await
        .unwrap();
        for blob in std::iter::once(&image.config).chain(&image.layers) {
            read(
                relay
                    .pull(pull(Kind::Blob, &by(&sha(blob)), false, None))
                    .await,
            )
            .await
            .unwrap();
        }
    }
    // A second image, newer, which the runtime does not list.
    let other_config = Bytes::from_static(b"{\"other\":true}");
    let other_layer = Bytes::from(vec![9_u8; 4000]);
    let other_manifest = Bytes::from(format!(
        r#"{{"schemaVersion":2,"config":{{"digest":"{}"}},"layers":[{{"digest":"{}"}}]}}"#,
        sha(&other_config),
        sha(&other_layer)
    ));
    node.registry.put(
        &format!("/v2/app/web/manifests/{}", sha(&other_manifest)),
        Reply::ok(other_manifest.clone()),
    );
    node.registry.put(
        &format!("/v2/app/web/blobs/{}", sha(&other_config)),
        Reply::ok(other_config.clone()),
    );
    node.registry.put(
        &format!("/v2/app/web/blobs/{}", sha(&other_layer)),
        Reply::ok(other_layer.clone()),
    );
    read(
        relay
            .pull(pull(
                Kind::Manifest,
                &by(&sha(&other_manifest)),
                false,
                None,
            ))
            .await,
    )
    .await
    .unwrap();
    for blob in [&other_config, &other_layer] {
        read(
            relay
                .pull(pull(Kind::Blob, &by(&sha(blob)), false, None))
                .await,
        )
        .await
        .unwrap();
    }
    let total = relay.cache().size();
    // A bound under the total by a little: the other image's biggest blob is the least recently served among the
    // unlisted ones that no listed image protects only if it is the oldest, so make the listed image the more recent.
    relay.cache().set_max_size(total - 1);
    read(
        relay
            .pull(pull(Kind::Blob, &by(&sha(&kept.layers[0])), false, None))
            .await,
    )
    .await
    .unwrap();
    relay.evict().await;
    // The unlisted image's oldest blob went; every blob of the listed image is still there.
    assert!(!relay.cache().contains(&sha(&other_manifest)));
    for digest in std::iter::once(sha(&kept.config))
        .chain(kept.layers.iter().map(|l| sha(l)))
        .chain([kept.manifest_digest.clone()])
    {
        assert!(relay.cache().contains(&digest), "{digest}");
    }
    assert!(!relay.cache().over());
    // A bound that leaves only room for the listed image's smallest blob evicts what it protects as a last resort.
    relay.cache().set_max_size(10);
    relay.evict().await;
    assert!(relay.cache().size() <= 10);
}

#[tokio::test]
async fn a_cache_over_its_bound_is_evicted_by_the_task_that_waits_for_it() {
    let node = Node::new().await;
    let image = Image::new(&node.registry, &[3000, 3000]);
    let relay = Arc::new(node.relay(1 << 30));
    read(
        relay
            .pull(pull(Kind::Manifest, &tag("1.0"), false, None))
            .await,
    )
    .await
    .unwrap();
    let task = tokio::spawn({
        let relay = Arc::clone(&relay);
        async move { relay.evict_when_over().await }
    });
    relay.cache().set_max_size(4000);
    for blob in std::iter::once(&image.config).chain(&image.layers) {
        read(
            relay
                .pull(pull(Kind::Blob, &by(&sha(blob)), false, None))
                .await,
        )
        .await
        .unwrap();
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while relay.cache().over() {
        assert!(
            std::time::Instant::now() < deadline,
            "the cache stayed over its bound"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(relay.cache().size() <= 4000);
    task.abort();
}

#[test]
fn every_algorithm_a_digest_may_name_hashes_to_its_known_value() {
    for (name, hex) in [
        (
            "sha256",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "sha384",
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
        ),
        (
            "sha512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ] {
        let digest = hash_of(name, b"abc").expect("a known algorithm");
        assert_eq!(digest.to_string(), format!("{name}:{hex}"));
    }
    assert!(hash_of("md5", b"abc").is_none());
}
