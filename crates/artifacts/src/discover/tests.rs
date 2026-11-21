//! Discovery against fake registries on local ports.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Mutex;

use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::{Value, json};
use speculaire_mirror::fetch::Settings;
use speculaire_oci::referrers::{
    BUNDLE, COSIGN_ATTESTATION, EMPTY, INDEX, MANIFEST, SIMPLE_SIGNING,
};
use speculaire_runtime::content::{self, Blob, Content};
use speculaire_runtime::registries::{
    Credentials, Endpoint, Error as ConfigError, Reloaded, Source,
};
use tokio::net::TcpListener;

use super::*;

mod recorded;

pub(super) const NAME: &str = "reg.test/app";
const MIRROR: &str = "127.0.0.1:7480";

/// A status, headers and a body.
type Reply = (u16, Vec<(&'static str, String)>, Bytes);

/// A fake registry: each path with its query answers its status and body, and every request is logged.
pub(super) struct Registry {
    address: SocketAddr,
    replies: Arc<Mutex<HashMap<String, Reply>>>,
    log: Arc<Mutex<Vec<String>>>,
}

impl Registry {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let replies: Arc<Mutex<HashMap<_, _>>> = Arc::default();
        let log: Arc<Mutex<Vec<String>>> = Arc::default();
        let (served, journal) = (Arc::clone(&replies), Arc::clone(&log));
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (replies, log) = (Arc::clone(&served), Arc::clone(&journal));
                let service = service_fn(move |request: http::Request<Incoming>| {
                    let target = request
                        .uri()
                        .path_and_query()
                        .map_or(String::new(), ToString::to_string)
                        .trim_start_matches("/v2")
                        .to_owned();
                    log.lock()
                        .unwrap()
                        .push(format!("{} {target}", request.method()));
                    let (status, headers, body) = replies
                        .lock()
                        .unwrap()
                        .get(&target)
                        .cloned()
                        .unwrap_or((404, Vec::new(), Bytes::new()));
                    let mut response = http::Response::builder().status(status);
                    for (name, value) in headers {
                        response = response.header(name, value);
                    }
                    let response = response.body(Full::new(body)).unwrap();
                    async move { Ok::<_, Infallible>(response) }
                });
                tokio::spawn(
                    hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service),
                );
            }
        });
        Self {
            address,
            replies,
            log,
        }
    }

    pub(super) fn put(&self, path: &str, status: u16, body: impl Into<Bytes>) {
        self.put_with(path, status, Vec::new(), body);
    }

    fn put_with(
        &self,
        path: &str,
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: impl Into<Bytes>,
    ) {
        self.replies
            .lock()
            .unwrap()
            .insert(path.to_owned(), (status, headers, body.into()));
    }

    /// Serves `bytes` as the manifest `digest`, with its media type, and returns the digest.
    pub(super) fn manifest(&self, bytes: &[u8]) -> Digest {
        let digest = digest_of(bytes);
        let manifest: Value = serde_json::from_slice(bytes).unwrap();
        let media_type = manifest["mediaType"].as_str().unwrap().to_owned();
        self.put_with(
            &format!("/app/manifests/{digest}"),
            200,
            vec![("content-type", media_type)],
            bytes.to_vec(),
        );
        digest
    }

    /// Serves `bytes` as a blob and returns its digest.
    fn blob(&self, bytes: &'static [u8]) -> Digest {
        let digest = digest_of(bytes);
        self.put(&format!("/app/blobs/{digest}"), 200, bytes);
        digest
    }

    pub(super) fn requests(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    pub(super) fn endpoint(&self) -> Endpoint {
        Endpoint::new(false, self.address.to_string())
    }
}

/// Registry config with one source for every name: `candidates`, anonymous. `configured.test` has an entry.
struct Fixed(Vec<Endpoint>);

impl Registries for Fixed {
    fn sources(&self, name: &str, _: Reference<'_>) -> Result<Vec<Source>, ConfigError> {
        let (_, repository) = name.split_once('/').unwrap();
        Ok(vec![Source {
            candidates: self.0.clone(),
            repository: repository.to_owned(),
            credentials: Credentials::Anonymous,
        }])
    }

    fn configured(&self, host: &str) -> bool {
        host == "configured.test"
    }

    fn poll(&self) -> Option<Result<Reloaded, ConfigError>> {
        None
    }

    fn reload(&self) -> Result<Reloaded, ConfigError> {
        Ok(Reloaded::default())
    }
}

/// The fetcher's settings in tests.
pub(super) const SETTINGS: Settings = Settings {
    stall_timeout: std::time::Duration::from_secs(5),
    deny_ttl: std::time::Duration::from_secs(600),
    resolve_tags: false,
};

/// A node that holds nothing.
pub(super) struct Nothing;

impl Content for Nothing {
    fn open(
        &self,
        _: &Digest,
    ) -> impl Future<Output = Result<Option<Blob>, content::Error>> + Send {
        std::future::ready(Ok(None))
    }
}

fn digest_of(bytes: &[u8]) -> Digest {
    speculaire_oci::hash::of("sha256", bytes).unwrap()
}

fn descriptor(media_type: &str, digest: &Digest, size: usize) -> Value {
    json!({"mediaType": media_type, "digest": digest.to_string(), "size": size})
}

fn platform() -> Host {
    Host {
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        variant: String::new(),
    }
}

/// A test: one registry, a store, and discovery through `Fixed` with the limits of D121.
pub(super) struct Test {
    pub(super) registry: Registry,
    pub(super) discovery: Discovery,
    _dir: tempfile::TempDir,
}

impl Test {
    async fn start() -> Self {
        Self::with(Limits::new(1024), |registry| vec![registry.endpoint()]).await
    }

    async fn with(limits: Limits, candidates: impl FnOnce(&Registry) -> Vec<Endpoint>) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let unlinked = Fetcher::new(dir.path().join("staging"), SETTINGS);
        Self::near(limits, candidates, Arc::new(Nothing), unlinked, dir).await
    }

    /// A test whose node holds what `local` does and asks `peers`, its store below `dir`.
    pub(super) async fn near(
        limits: Limits,
        candidates: impl FnOnce(&Registry) -> Vec<Endpoint>,
        local: Arc<dyn Local>,
        peers: Fetcher,
        dir: tempfile::TempDir,
    ) -> Self {
        let registry = Registry::start().await;
        let store = Arc::new(Store::open(dir.path().join("store")).unwrap());
        let discovery = Discovery::new(
            store,
            local,
            peers,
            Arc::new(Fixed(candidates(&registry))),
            MIRROR.to_owned(),
            platform(),
            limits,
        );
        Self {
            registry,
            discovery,
            _dir: dir,
        }
    }

    /// An image manifest served as the root.
    pub(super) fn root(&self) -> Digest {
        let config = self.registry.blob(b"config");
        self.registry.manifest(
            json!({
                "schemaVersion": 2,
                "mediaType": MANIFEST,
                "config": descriptor("application/vnd.oci.image.config.v1+json", &config, 6),
                "layers": [],
            })
            .to_string()
            .as_bytes(),
        )
    }

    /// A Sigstore bundle referrer of `subject`, `artifact_type` as its artifact type, served with its blobs.
    fn bundle(
        &self,
        subject: &Digest,
        artifact_type: &str,
        content: &'static [u8],
    ) -> (Digest, Value) {
        self.bundle_listed(subject, artifact_type, content, content.len())
    }

    /// As [`Test::bundle`], its layer descriptor listing `size` as the bundle's size.
    fn bundle_listed(
        &self,
        subject: &Digest,
        artifact_type: &str,
        content: &'static [u8],
        size: usize,
    ) -> (Digest, Value) {
        let empty = self.registry.blob(b"{}");
        let layer = self.registry.blob(content);
        let bytes = json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "artifactType": artifact_type,
            "config": descriptor(EMPTY, &empty, 2),
            "layers": [descriptor(BUNDLE, &layer, size)],
            "subject": descriptor(MANIFEST, subject, 100),
        })
        .to_string();
        let digest = self.registry.manifest(bytes.as_bytes());
        let mut listed = descriptor(MANIFEST, &digest, bytes.len());
        listed["artifactType"] = json!(artifact_type);
        (digest, listed)
    }

    /// A legacy `.sig` manifest of `target`, served with its blobs.
    fn signature(&self, target: &Digest) -> Digest {
        let config = self.registry.blob(b"sigconfig");
        let payload = self.registry.blob(b"payload");
        let bytes = json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": descriptor("application/vnd.oci.image.config.v1+json", &config, 9),
            "layers": [descriptor(SIMPLE_SIGNING, &payload, 7)],
        })
        .to_string();
        self.registry.put(
            &format!("/app/manifests/{}", referrers::signature_tag(target)),
            200,
            bytes.clone(),
        );
        digest_of(bytes.as_bytes())
    }

    fn referrers(&self, path: &str, listed: &[Value], next: Option<&str>) {
        let index =
            json!({"schemaVersion": 2, "mediaType": INDEX, "manifests": listed}).to_string();
        let headers = next
            .map(|next| vec![("link", format!("<{next}>; rel=\"next\""))])
            .unwrap_or_default();
        self.registry.put_with(path, 200, headers, index);
    }

    pub(super) async fn discover(&self, root: &Digest) -> Result<Vec<Artifact>, Error> {
        self.discovery.discover(root, &[NAME.to_owned()]).await
    }
}

fn kinds(artifacts: &[Artifact]) -> Vec<(Kind, Digest)> {
    artifacts
        .iter()
        .map(|artifact| (artifact.kind, artifact.manifest.clone()))
        .collect()
}

#[tokio::test]
async fn the_api_then_the_fallback_tag_then_the_sig_tag_and_each_tag_is_asked_by_head_first() {
    let test = Test::start().await;
    let root = test.root();
    let (bundle, listed) = test.bundle(&root, BUNDLE, b"bundle");
    let fallback = format!("/app/manifests/{}", referrers::fallback_tag(&root));
    test.referrers(&fallback, &[listed], None);
    let signature = test.signature(&root);

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(
        kinds(&artifacts),
        [
            (Kind::Bundle, bundle.clone()),
            (Kind::Signature, signature.clone())
        ]
    );
    let sig = format!("/app/manifests/{}", referrers::signature_tag(&root));
    let wanted = [
        format!("HEAD /app/manifests/{root}"),
        format!("GET /app/referrers/{root}"),
        format!("HEAD {fallback}"),
        format!("GET {fallback}"),
        format!("GET /app/manifests/{bundle}"),
        format!("HEAD {sig}"),
        format!("GET {sig}"),
    ];
    let requests = test.registry.requests();
    let order: Vec<usize> = wanted
        .iter()
        .map(|wanted| {
            requests
                .iter()
                .position(|request| request == wanted)
                .unwrap_or_else(|| panic!("{wanted} in {requests:?}"))
        })
        .collect();
    assert!(order.is_sorted(), "{requests:?}");
    // An image manifest is no index: it is never fetched.
    assert!(!requests.contains(&format!("GET /app/manifests/{root}")));
    let store = test.discovery.store();
    for artifact in &artifacts {
        assert!(store.contains(&artifact.manifest));
        assert!(artifact.blobs.iter().all(|blob| store.contains(blob)));
    }
    assert_eq!(store.recorded(&root).await.unwrap(), Some(artifacts));
}

#[tokio::test]
async fn asked_again_upstream_adds_what_it_serves_now_to_the_record() {
    let test = Test::start().await;
    let root = test.root();
    let signature = test.signature(&root);
    let first = test.discover(&root).await.unwrap();
    let (bundle, listed) = test.bundle(&root, BUNDLE, b"bundle");
    test.referrers(&format!("/app/referrers/{root}"), &[listed], None);

    let again = test
        .discovery
        .again(&root, &[NAME.to_owned()])
        .await
        .unwrap();

    assert_eq!(kinds(&first), [(Kind::Signature, signature.clone())]);
    assert_eq!(
        kinds(&again),
        [(Kind::Bundle, bundle), (Kind::Signature, signature)]
    );
    let store = test.discovery.store();
    assert_eq!(store.recorded(&root).await.unwrap(), Some(again));
}

#[tokio::test]
async fn a_tag_that_is_not_there_is_never_fetched() {
    let test = Test::start().await;
    let root = test.root();
    assert_eq!(test.discover(&root).await.unwrap(), Vec::new());
    let requests = test.registry.requests();
    assert!(
        requests
            .iter()
            .all(|r| !r.starts_with("GET /app/manifests/sha256-")),
        "{requests:?}"
    );
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("HEAD /app/manifests/sha256-"))
            .count(),
        2
    );
}

#[tokio::test]
async fn the_api_pages_are_followed_and_no_fallback_tag_is_asked() {
    let test = Test::start().await;
    let root = test.root();
    let (first, one) = test.bundle(&root, BUNDLE, b"one");
    let (second, two) = test.bundle(&root, EMPTY, b"two");
    let page = format!("/app/referrers/{root}?n=1&last=x");
    test.referrers(
        &format!("/app/referrers/{root}"),
        &[one],
        Some(&format!("/v2{page}")),
    );
    test.referrers(&page, &[two], None);

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(
        kinds(&artifacts),
        [(Kind::Bundle, first), (Kind::Bundle, second)]
    );
    let fallback = referrers::fallback_tag(&root);
    let requests = test.registry.requests();
    assert!(
        requests.iter().all(|r| !r.ends_with(&fallback)),
        "{requests:?}"
    );
}

#[tokio::test]
async fn a_referrer_of_another_subject_and_a_cosign_attestation_are_dropped_the_latter_unfetched() {
    let test = Test::start().await;
    let root = test.root();
    let other = digest_of(b"other");
    let (elsewhere, wrong) = test.bundle(&other, BUNDLE, b"elsewhere");
    let (att, attestation) = test.bundle(&root, COSIGN_ATTESTATION, b"att");
    test.referrers(
        &format!("/app/referrers/{root}"),
        &[wrong, attestation],
        None,
    );

    assert_eq!(test.discover(&root).await.unwrap(), Vec::new());

    let requests = test.registry.requests();
    assert!(requests.contains(&format!("GET /app/manifests/{elsewhere}")));
    assert!(
        !requests.contains(&format!("GET /app/manifests/{att}")),
        "{requests:?}"
    );
}

#[tokio::test]
async fn referrers_beyond_the_cap_and_pages_beyond_the_cap_are_not_fetched() {
    let limits = Limits {
        referrers: 2,
        pages: 1,
        ..Limits::new(1024)
    };
    let test = Test::with(limits, |registry| vec![registry.endpoint()]).await;
    let root = test.root();
    let (a, one) = test.bundle(&root, BUNDLE, b"a");
    let (b, two) = test.bundle(&root, BUNDLE, b"b");
    let (c, three) = test.bundle(&root, BUNDLE, b"c");
    let (_, four) = test.bundle(&root, BUNDLE, b"d");
    let page = format!("/app/referrers/{root}?last=c");
    test.referrers(
        &format!("/app/referrers/{root}"),
        &[one, two, three],
        Some(&format!("/v2{page}")),
    );
    test.referrers(&page, &[four], None);

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(kinds(&artifacts), [(Kind::Bundle, a), (Kind::Bundle, b)]);
    let requests = test.registry.requests();
    assert!(!requests.contains(&format!("GET /app/manifests/{c}")));
    assert!(!requests.contains(&format!("GET {page}")), "{requests:?}");
}

#[tokio::test]
async fn a_referrer_at_the_manifest_cap_is_fetched_and_one_listed_above_it_is_not() {
    // The same root and bundle give the same bytes in any test: a first one measures the bundle.
    let probe = Test::start().await;
    let (_, listed) = probe.bundle(&probe.root(), BUNDLE, b"at the cap");
    let cap = listed["size"].as_u64().unwrap();
    let limits = Limits {
        manifest: cap,
        ..Limits::new(1024)
    };
    let test = Test::with(limits, |registry| vec![registry.endpoint()]).await;
    let root = test.root();
    let (at, at_cap) = test.bundle(&root, BUNDLE, b"at the cap");
    assert_eq!(at_cap["size"].as_u64(), Some(cap));
    let (above, mut above_cap) = test.bundle(&root, BUNDLE, b"above it");
    above_cap["size"] = json!(cap + 1);
    test.referrers(
        &format!("/app/referrers/{root}"),
        &[at_cap, above_cap],
        None,
    );

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(kinds(&artifacts), [(Kind::Bundle, at)]);
    let requests = test.registry.requests();
    assert!(
        !requests.contains(&format!("GET /app/manifests/{above}")),
        "{requests:?}"
    );
}

#[tokio::test]
async fn a_blob_listed_above_the_cap_is_left_out_unfetched_and_one_growing_above_it_drops_its_artifact()
 {
    let test = Test::with(Limits::new(4), |registry| vec![registry.endpoint()]).await;
    let root = test.root();
    let (above, listed_above) = test.bundle(&root, BUNDLE, b"a bundle of more than four bytes");
    let (at, at_cap) = test.bundle(&root, BUNDLE, b"four");
    let (_, growing) = test.bundle_listed(&root, BUNDLE, b"listed as four bytes", 4);
    test.referrers(
        &format!("/app/referrers/{root}"),
        &[listed_above, at_cap, growing],
        None,
    );

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(
        kinds(&artifacts),
        [(Kind::Bundle, above), (Kind::Bundle, at)]
    );
    let store = test.discovery.store();
    let left_out = &artifacts[0].blobs[1];
    assert!(!store.contains(left_out));
    assert!(store.contains(&artifacts[0].manifest));
    assert!(store.contains(&artifacts[1].blobs[1]));
    let requests = test.registry.requests();
    assert!(
        !requests.contains(&format!("GET /app/blobs/{left_out}")),
        "{requests:?}"
    );
}

#[tokio::test]
async fn an_index_yields_its_platform_manifest_and_its_attestation_manifests_as_targets() {
    let test = Test::start().await;
    let image = test.root();
    let statement = test.registry.blob(b"statement");
    let config = test.registry.blob(b"{}");
    let attestation = test.registry.manifest(
        json!({
            "schemaVersion": 2,
            "mediaType": MANIFEST,
            "config": descriptor("application/vnd.oci.image.config.v1+json", &config, 2),
            "layers": [descriptor("application/vnd.in-toto+json", &statement, 9)],
        })
        .to_string()
        .as_bytes(),
    );
    let index = test.registry.manifest(
        json!({
            "schemaVersion": 2,
            "mediaType": INDEX,
            "manifests": [
                {"mediaType": MANIFEST, "digest": image.to_string(), "size": 100,
                 "platform": {"os": "linux", "architecture": "amd64"}},
                {"mediaType": MANIFEST, "digest": attestation.to_string(), "size": 100,
                 "platform": {"os": "unknown", "architecture": "unknown"},
                 "annotations": {"vnd.docker.reference.type": "attestation-manifest",
                                 "vnd.docker.reference.digest": image.to_string()}},
            ],
        })
        .to_string()
        .as_bytes(),
    );
    let signature = test.signature(&image);

    let artifacts = test.discover(&index).await.unwrap();

    assert_eq!(
        kinds(&artifacts),
        [
            (Kind::Attestation, attestation.clone()),
            (Kind::Signature, signature)
        ]
    );
    assert_eq!(artifacts[0].target, image);
    assert_eq!(artifacts[0].blobs, [config, statement]);
    let requests = test.registry.requests();
    for target in [&index, &image, &attestation] {
        assert!(
            requests.contains(&format!("GET /app/referrers/{target}")),
            "{target}"
        );
    }
}

#[tokio::test]
async fn a_401_from_every_source_leaves_the_artifacts_unreachable() {
    let test = Test::start().await;
    let root = digest_of(b"root");
    test.registry
        .put(&format!("/app/manifests/{root}"), 401, "");
    test.registry
        .put(&format!("/other/manifests/{root}"), 401, "");
    let names = [NAME.to_owned(), "reg.test/other".to_owned()];
    let before = Instant::now();
    let refused = test.discovery.discover(&root, &names).await;
    let Err(Error::Unverifiable { reason, retry_at }) = &refused else {
        panic!("{refused:?}");
    };
    assert_eq!(*reason, Reason::Unreachable);
    assert!(*retry_at >= before + RETRY && *retry_at <= Instant::now() + RETRY);
    assert_eq!(
        refused.unwrap_err().to_string(),
        "unverifiable: artifacts unreachable"
    );
    assert_eq!(test.registry.requests().len(), 2);
    assert_eq!(test.discovery.store().recorded(&root).await.unwrap(), None);
}

#[tokio::test]
async fn the_nodes_own_mirror_is_never_asked() {
    let mirror = Registry::start().await;
    let own = Endpoint::new(false, MIRROR.to_owned());
    let test = Test::with(Limits::new(1024), |registry| vec![own, registry.endpoint()]).await;
    let root = test.root();
    test.discover(&root).await.unwrap();
    assert_eq!(mirror.requests(), Vec::<String>::new());
    assert_eq!(
        test.registry.requests()[0],
        format!("HEAD /app/manifests/{root}")
    );
}

#[tokio::test]
async fn a_manifest_that_does_not_match_its_digest_is_dropped_and_counted() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _local = ::metrics::set_default_local_recorder(&recorder);
    let test = Test::start().await;
    let root = test.root();
    let (bundle, listed) = test.bundle(&root, BUNDLE, b"bundle");
    test.registry.put(
        &format!("/app/manifests/{bundle}"),
        200,
        "{\"tampered\":true}",
    );
    test.referrers(&format!("/app/referrers/{root}"), &[listed], None);

    assert_eq!(test.discover(&root).await.unwrap(), Vec::new());

    let rendered = handle.render();
    let count = |result: &str| {
        rendered
            .lines()
            .find(|line| {
                line.starts_with("speculaire_artifact_fetches_total{")
                    && line.contains("upstream=\"other\"")
                    && line.contains(&format!("result=\"{result}\""))
            })
            .and_then(|line| line.rsplit(' ').next())
            .map(str::to_owned)
    };
    assert_eq!(count("digest_mismatch").as_deref(), Some("1"), "{rendered}");
    // The root and the referrers index; then the `.sig` tag: HEAD answers 404.
    assert_eq!(count("ok").as_deref(), Some("2"), "{rendered}");
    assert_eq!(count("not_found").as_deref(), Some("1"), "{rendered}");
}

/// The host `discovered` came to rate limited, and when it may be asked again.
fn limited(discovered: &Result<Vec<Artifact>, Error>) -> (&str, Instant) {
    match discovered {
        Err(Error::Unverifiable {
            reason: Reason::RateLimited { host },
            retry_at,
        }) => (host, *retry_at),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn a_429_is_counted_as_rate_limited() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _local = ::metrics::set_default_local_recorder(&recorder);
    let test = Test::start().await;
    let root = digest_of(b"limited");
    test.registry
        .put(&format!("/app/manifests/{root}"), 429, "");

    let discovered = test.discover(&root).await;

    let host = test.registry.endpoint().authority;
    assert_eq!(limited(&discovered).0, host);
    assert_eq!(
        discovered.unwrap_err().to_string(),
        format!("unverifiable: upstream rate limited: {host}")
    );
    let rendered = handle.render();
    assert!(
        rendered.contains(r#"upstream="other",result="rate_limited"} 1"#),
        "{rendered}"
    );
}

#[tokio::test]
async fn a_refusal_mid_discovery_pauses_its_host_for_every_root_and_records_nothing() {
    let test = Test::start().await;
    let root = test.root();
    test.registry.put_with(
        &format!("/app/referrers/{root}"),
        429,
        vec![("retry-after", "120".to_owned())],
        "",
    );
    let before = Instant::now();

    let discovered = test.discover(&root).await;

    let (host, retry_at) = limited(&discovered);
    assert_eq!(host, test.registry.endpoint().authority);
    let window = Duration::from_secs(120);
    assert!(retry_at >= before + window && retry_at <= Instant::now() + window);
    assert_eq!(test.discovery.store().recorded(&root).await.unwrap(), None);
    let asked = test.registry.requests();
    assert_eq!(
        asked,
        [
            format!("HEAD /app/manifests/{root}"),
            format!("GET /app/referrers/{root}"),
        ]
    );
    // Another root, and the same one again, ask nothing until the pause ends.
    let other = digest_of(b"other");
    assert_eq!(limited(&test.discover(&other).await), (host, retry_at));
    assert_eq!(limited(&test.discover(&root).await), (host, retry_at));
    assert_eq!(test.registry.requests(), asked);
}

#[tokio::test]
async fn a_503_limits_only_with_retry_after() {
    let test = Test::start().await;
    let root = test.root();
    let referrers = format!("/app/referrers/{root}");
    test.registry.put(&referrers, 503, "");

    // An outage of the referrers API: discovery goes on to the `.sig` tag, and ends.
    assert_eq!(test.discover(&root).await.unwrap(), Vec::new());

    test.registry.put_with(
        &referrers,
        503,
        vec![("retry-after", "Fri, 31 Dec 9999 23:59:59 GMT".to_owned())],
        "",
    );
    let before = Instant::now();
    let (_, retry_at) = limited(&test.discover(&root).await);
    // A day's date asked, an hour's pause given (D38).
    let longest = Duration::from_secs(3600);
    assert!(retry_at >= before + longest && retry_at <= Instant::now() + longest);
}

#[tokio::test]
async fn a_paused_host_does_not_stop_another_candidate() {
    let limiting = Registry::start().await;
    let test = Test::with(Limits::new(1024), |registry| {
        vec![limiting.endpoint(), registry.endpoint()]
    })
    .await;
    let root = test.root();
    let (bundle, listed) = test.bundle(&root, BUNDLE, b"bundle");
    test.referrers(&format!("/app/referrers/{root}"), &[listed], None);
    limiting.put(&format!("/app/manifests/{root}"), 429, "");

    let artifacts = test.discover(&root).await.unwrap();

    assert_eq!(kinds(&artifacts), [(Kind::Bundle, bundle)]);
    // Paused after its refusal, the first candidate is passed for every later request.
    assert_eq!(limiting.requests(), [format!("HEAD /app/manifests/{root}")]);
}

#[tokio::test]
async fn when_every_candidate_refuses_the_pause_that_ends_first_is_the_outcome() {
    for first_ends_first in [true, false] {
        let first = Registry::start().await;
        let second = Registry::start().await;
        let test = Test::with(Limits::new(1024), |_| {
            vec![first.endpoint(), second.endpoint()]
        })
        .await;
        let root = test.root();
        let (sooner, later) = if first_ends_first {
            (&first, &second)
        } else {
            (&second, &first)
        };
        let path = format!("/app/manifests/{root}");
        sooner.put_with(&path, 429, vec![("retry-after", "120".to_owned())], "");
        later.put_with(&path, 429, vec![("retry-after", "600".to_owned())], "");
        let before = Instant::now();

        let discovered = test.discover(&root).await;

        let (host, retry_at) = limited(&discovered);
        assert_eq!(host, sooner.endpoint().authority);
        let window = Duration::from_secs(120);
        assert!(retry_at >= before + window && retry_at <= Instant::now() + window);
    }
}

#[test]
fn a_link_is_followed_below_the_api_root_relative_or_absolute() {
    assert_eq!(
        below("/v2/a/referrers/x?n=1", "/v2").as_deref(),
        Some("/a/referrers/x?n=1")
    );
    assert_eq!(
        below("https://reg.test/v2/a/referrers/x?last=y", "/v2").as_deref(),
        Some("/a/referrers/x?last=y")
    );
    assert_eq!(below("/elsewhere/a", "/v2"), None);
    assert_eq!(below("/v2x/a", "/v2"), None);
    assert_eq!(below("https://reg.test", "/v2"), None);
}

#[tokio::test]
async fn a_registry_the_config_names_counts_under_its_host() {
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _local = ::metrics::set_default_local_recorder(&recorder);
    let test = Test::start().await;
    let root = test.root();
    let names = ["configured.test/app".to_owned()];
    test.discovery.discover(&root, &names).await.unwrap();
    let rendered = handle.render();
    assert!(
        rendered.contains("upstream=\"configured.test\""),
        "{rendered}"
    );
    assert!(!rendered.contains("upstream=\"other\""), "{rendered}");
}

/// A node holding these manifests.
struct Holding(HashMap<Digest, Bytes>);

impl Local for Holding {
    fn manifest<'a>(
        &'a self,
        digest: &'a Digest,
        _: u64,
    ) -> std::pin::Pin<Box<dyn Future<Output = Option<Bytes>> + Send + 'a>> {
        Box::pin(std::future::ready(self.0.get(digest).cloned()))
    }
}

/// An image manifest whose config is `config`, as bytes.
fn image_manifest(config: &Digest) -> Bytes {
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST,
        "config": descriptor("application/vnd.oci.image.config.v1+json", config, 6),
        "layers": [],
    });
    Bytes::from(manifest.to_string())
}

#[tokio::test]
async fn the_config_digest_is_read_from_the_platform_manifest_the_node_holds() {
    let (amd64_config, arm64_config) = (digest_of(b"amd64"), digest_of(b"arm64"));
    let (amd64, arm64) = (image_manifest(&amd64_config), image_manifest(&arm64_config));
    let entry = |bytes: &Bytes, arch: &str| {
        let mut entry = descriptor(MANIFEST, &digest_of(bytes), bytes.len());
        entry["platform"] = json!({"os": "linux", "architecture": arch});
        entry
    };
    let index = Bytes::from(
        json!({"schemaVersion": 2, "mediaType": INDEX, "manifests": [entry(&arm64, "arm64"), entry(&amd64, "amd64")]})
            .to_string(),
    );
    let lone_config = digest_of(b"lone");
    let lone = image_manifest(&lone_config);
    let unheld = Bytes::from(
        json!({"schemaVersion": 2, "mediaType": INDEX, "manifests": [entry(&arm64, "amd64")]})
            .to_string(),
    );
    let held = [&index, &amd64, &lone, &unheld].map(|bytes| (digest_of(bytes), bytes.clone()));
    let dir = tempfile::tempdir().unwrap();
    let peers = Fetcher::new(dir.path().join("staging"), SETTINGS);
    let local = Arc::new(Holding(held.into_iter().collect()));
    let test = Test::near(Limits::new(1024), |_| Vec::new(), local, peers, dir).await;

    let cases = [
        (&index, Some(amd64_config), "an index: its amd64 manifest's"),
        (&lone, Some(lone_config), "an image manifest: its own"),
        (&arm64, None, "a manifest the node lacks"),
        (
            &unheld,
            None,
            "an index whose platform manifest the node lacks",
        ),
    ];
    for (root, config, case) in cases {
        assert_eq!(
            test.discovery.config(&digest_of(root)).await,
            config,
            "{case}"
        );
    }
}
