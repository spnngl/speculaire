//! The fetcher against real peer APIs over mutual TLS, some behind a relay that breaks the network as `tc netem` would.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;

use http::HeaderValue;
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use speculaire_pki::testing::Cluster;
use speculaire_runtime::content::{Content, Error};
use tempfile::TempDir;
use tokio::io::AsyncReadExt as _;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use super::*;
use crate::peer::{Uploads, serve};

const IP: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// The node that fetches.
const CLIENT: &str = "node-z";
/// More than one chunk of the peer API, so that a fault can fall in the middle of a body.
const SIZE: usize = 1 << 20;

/// Blobs held in memory, under whatever digest the test says.
pub(crate) struct Held(HashMap<Digest, Bytes>);

impl Content for Held {
    fn open(&self, digest: &Digest) -> impl Future<Output = Result<Option<Blob>, Error>> + Send {
        std::future::ready(Ok(self.0.get(digest).cloned().map(Blob::from_bytes)))
    }
}

/// The same holders for every digest.
struct Fixed(Vec<Holder>);

impl Lookup for Fixed {
    fn holders<'a>(
        &'a self,
        _: &'a Digest,
    ) -> Pin<Box<dyn Future<Output = Vec<Holder>> + Send + 'a>> {
        Box::pin(std::future::ready(self.0.clone()))
    }
}

pub(crate) fn pattern(len: usize, seed: u8) -> Bytes {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap() ^ seed)
        .collect::<Vec<_>>()
        .into()
}

fn sha(bytes: &[u8]) -> Digest {
    crate::hash::of("sha256", bytes).unwrap()
}

/// A cluster whose nodes serve peer APIs until the test ends.
pub(crate) struct Nodes {
    cluster: Cluster,
    dir: TempDir,
    stops: Vec<oneshot::Sender<()>>,
}

impl Nodes {
    pub(crate) fn new() -> Self {
        Self {
            cluster: Cluster::new("kubernetes"),
            dir: tempfile::tempdir().unwrap(),
            stops: Vec::new(),
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

    /// The peer API of `node`, holding `blobs`, at most `max_uploads` at once.
    pub(crate) async fn peer(
        &mut self,
        node: &str,
        blobs: &[(&Digest, &Bytes)],
        max_uploads: usize,
    ) -> (Holder, Arc<Uploads>) {
        let held = blobs
            .iter()
            .map(|(digest, bytes)| ((*digest).clone(), (*bytes).clone()))
            .collect();
        let listener = TcpListener::bind((IP, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let uploads = Arc::new(Uploads::new(NonZeroUsize::new(max_uploads).unwrap()));
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(serve(
            listener,
            self.credentials(node).server(),
            Arc::new(Held(held)),
            Arc::clone(&uploads),
            async {
                // An error means the sender went with the test: stop too.
                let _ = stopped.await;
            },
        ));
        self.stops.push(stop);
        let holder = Holder {
            node: node.to_owned(),
            address,
        };
        (holder, uploads)
    }

    /// A fetcher of [`CLIENT`] that asks `holders` in that order.
    pub(crate) fn fetcher(&self, holders: Vec<Holder>, settings: Settings) -> Fetcher {
        let fetcher = Fetcher::new(self.dir.path().join("staging"), settings);
        fetcher.link(Arc::new(Fixed(holders)), self.credentials(CLIENT));
        fetcher
    }
}

pub(crate) const SETTINGS: Settings = Settings {
    stall_timeout: Duration::from_secs(5),
    deny_ttl: Duration::from_secs(600),
};

/// What a network does wrong to the answers it carries.
#[derive(Clone, Copy)]
enum Fault {
    /// Closes the connection after this many bytes.
    Cut(usize),
    /// Holds the connection open but carries nothing after this many bytes.
    Stall(usize),
    /// Carries nothing for this long.
    Late(Duration),
}

/// `holder` behind a TCP relay that carries the requests as they are and the answers with `fault`.
async fn behind(holder: &Holder, fault: Fault) -> Holder {
    let listener = TcpListener::bind((IP, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let to = holder.address;
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let server = TcpStream::connect(to).await.unwrap();
                let (mut client_read, mut client_write) = client.into_split();
                let (mut server_read, mut server_write) = server.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
                });
                if let Fault::Late(delay) = fault {
                    tokio::time::sleep(delay).await;
                }
                let mut carried = 0;
                let mut buffer = vec![0; 16 * 1024];
                loop {
                    let Ok(read @ 1..) = server_read.read(&mut buffer).await else {
                        return;
                    };
                    let room = match fault {
                        Fault::Cut(limit) | Fault::Stall(limit) => limit - carried,
                        Fault::Late(_) => read,
                    };
                    let chunk = buffer.get(..read.min(room)).unwrap();
                    if client_write.write_all(chunk).await.is_err() {
                        return;
                    }
                    carried += chunk.len();
                    if chunk.len() < read {
                        if let Fault::Stall(_) = fault {
                            // Keeps both halves open, carrying nothing.
                            std::future::pending::<()>().await;
                        }
                        return;
                    }
                }
            });
        }
    });
    Holder {
        node: holder.node.clone(),
        address,
    }
}

/// A recorder for this test thread alone, with the fetcher's series described.
fn recorder() -> (PrometheusHandle, ::metrics::LocalRecorderGuard<'static>) {
    let recorder = Box::leak(Box::new(PrometheusBuilder::new().build_recorder()));
    let handle = recorder.handle();
    let guard = ::metrics::set_default_local_recorder(recorder);
    metrics::describe_fetch();
    (handle, guard)
}

fn assert_counted(handle: &PrometheusHandle, lines: &[&str]) {
    let rendered = handle.render();
    for line in lines {
        assert!(
            rendered.lines().any(|l| l == *line),
            "no `{line}` in\n{rendered}"
        );
    }
}

async fn read(blob: Blob) -> Bytes {
    blob.read_all(u64::MAX).await.unwrap()
}

#[tokio::test]
async fn a_blob_and_a_manifest_come_whole_from_a_peer_that_holds_them() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let (blob, manifest) = (
        pattern(SIZE, 0),
        Bytes::from_static(br#"{"schemaVersion":2,"manifests":[]}"#),
    );
    let (blob_digest, manifest_digest) = (sha(&blob), sha(&manifest));
    let (a, _) = nodes
        .peer(
            "node-a",
            &[(&blob_digest, &blob), (&manifest_digest, &manifest)],
            4,
        )
        .await;
    let fetcher = nodes.fetcher(vec![a], SETTINGS);
    let got = fetcher.whole(Kind::Blob, &blob_digest).await.unwrap();
    assert_eq!(got.size(), blob.len() as u64);
    assert_eq!(read(got).await, blob);
    let got = fetcher
        .whole(Kind::Manifest, &manifest_digest)
        .await
        .unwrap();
    assert_eq!(read(got).await, manifest);
    assert!(fetcher.whole(Kind::Blob, &sha(b"none")).await.is_none());
    assert_counted(
        &handle,
        &[
            r#"speculaire_peer_fetches_total{result="ok"} 2"#,
            r#"speculaire_peer_fetches_total{result="error"} 1"#,
            "speculaire_peer_hedges_total 0",
        ],
    );
}

#[tokio::test]
async fn on_containerd_a_whole_get_of_a_digest_the_node_lacks_is_served_from_a_peer() {
    use crate::pulls::{Answer, Local, Pull, Pulls as _};
    use crate::request::Reference;
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let blob = pattern(1000, 0);
    let digest = sha(&blob);
    let (a, _) = nodes.peer("node-a", &[(&digest, &blob)], 4).await;
    let local = Local::new(Held(HashMap::new()), nodes.fetcher(vec![a], SETTINGS));
    let reference = Reference::Digest(digest.clone());
    let pull = |head, range| Pull {
        kind: Kind::Blob,
        name: "library/busybox",
        reference: Some(&reference),
        head,
        range,
        accept: None,
    };
    let Answer::Served(response) = local.pull(pull(false, None)).await else {
        panic!("a blob a peer holds is served");
    };
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        blob
    );
    assert_counted(
        &handle,
        &[r#"speculaire_mirror_bytes_total{source="peer"} 1000"#],
    );
    // Neither waits for a whole blob: both fall through.
    assert!(matches!(
        local.pull(pull(true, None)).await,
        Answer::Missing
    ));
    assert!(matches!(
        local.pull(pull(false, Some("bytes=0-9"))).await,
        Answer::Missing
    ));
}

#[tokio::test]
async fn nothing_is_fetched_before_the_fetcher_is_linked_or_from_no_holder() {
    let nodes = Nodes::new();
    let unlinked = Fetcher::new(nodes.dir.path().join("staging"), SETTINGS);
    assert!(unlinked.whole(Kind::Blob, &sha(b"x")).await.is_none());
    let alone = nodes.fetcher(Vec::new(), SETTINGS);
    assert!(alone.download(Kind::Blob, &sha(b"x")).await.is_none());
}

#[tokio::test]
async fn a_peer_whose_certificate_names_another_node_than_the_lookup_is_refused() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let blob = pattern(1000, 0);
    let digest = sha(&blob);
    let (a, _) = nodes.peer("node-a", &[(&digest, &blob)], 4).await;
    let (b, _) = nodes.peer("node-b", &[(&digest, &blob)], 4).await;
    // The lookup says node-x is at node-a's address.
    let impostor = Holder {
        node: "node-x".to_owned(),
        address: a.address,
    };
    let refused = nodes.fetcher(vec![impostor.clone()], SETTINGS);
    assert!(refused.whole(Kind::Blob, &digest).await.is_none());
    let fetcher = nodes.fetcher(vec![impostor, b], SETTINGS);
    assert_eq!(
        read(fetcher.whole(Kind::Blob, &digest).await.unwrap()).await,
        blob
    );
    assert_counted(
        &handle,
        &[
            r#"speculaire_peer_fetches_total{result="error"} 2"#,
            r#"speculaire_peer_fetches_total{result="ok"} 1"#,
        ],
    );
}

#[tokio::test]
async fn a_busy_peer_gives_its_turn_to_the_next_at_once() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let blob = pattern(64 << 20, 0);
    let digest = sha(&blob);
    let manifest = Bytes::from_static(br#"{"schemaVersion":2,"manifests":[]}"#);
    let manifest_digest = sha(&manifest);
    let (a, _) = nodes
        .peer(
            "node-a",
            &[(&digest, &blob), (&manifest_digest, &manifest)],
            1,
        )
        .await;
    let (b, _) = nodes.peer("node-b", &[(&digest, &blob)], 4).await;
    // A body larger than loopback's buffers holds node-a's one upload while it is not read.
    let busy = nodes.fetcher(vec![a.clone()], SETTINGS);
    let held = busy.download(Kind::Blob, &digest).await.unwrap();
    let fetcher = nodes.fetcher(vec![a, b], SETTINGS);
    let download = fetcher.download(Kind::Blob, &digest).await.unwrap();
    assert_eq!(download.current.as_ref().unwrap().holder.node, "node-b");
    // A manifest takes no upload (D100): it is asked for as one.
    let got = busy.whole(Kind::Manifest, &manifest_digest).await.unwrap();
    assert_eq!(read(got).await, manifest);
    drop((held, download));
    // node-b was asked when node-a answered 503, not at the first hedge.
    assert_counted(
        &handle,
        &[
            r#"speculaire_peer_fetches_total{result="busy"} 1"#,
            "speculaire_peer_hedges_total 0",
        ],
    );
}

#[tokio::test(start_paused = true)]
async fn a_denied_peer_is_allowed_again_once_deny_ttl_has_passed() {
    let deny_ttl = Duration::from_secs(600);
    let fetcher = Fetcher::new(
        PathBuf::new(),
        Settings {
            deny_ttl,
            ..SETTINGS
        },
    );
    let holder = Holder {
        node: "node-a".to_owned(),
        address: SocketAddr::new(IP, 1),
    };
    fetcher.0.deny(&[holder], &sha(b"wrong"));
    tokio::time::advance(Duration::from_secs(599)).await;
    assert!(!fetcher.0.allowed("node-a"));
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(fetcher.0.allowed("node-a"));
}

#[test]
fn a_denial_prints_its_end() {
    let end: SystemTime =
        humantime::parse_rfc3339(&end_of_denial(Duration::from_secs(600)).to_string()).unwrap();
    let left = end.duration_since(SystemTime::now()).unwrap();
    assert!(
        left > Duration::from_secs(590) && left <= Duration::from_secs(600),
        "{left:?}"
    );
}

#[tokio::test]
async fn a_body_cut_short_resumes_from_the_next_peer_where_it_stopped() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let blob = pattern(SIZE, 0);
    let digest = sha(&blob);
    let (a, _) = nodes.peer("node-a", &[(&digest, &blob)], 4).await;
    let (b, _) = nodes.peer("node-b", &[(&digest, &blob)], 4).await;
    let cut = behind(&a, Fault::Cut(SIZE / 4)).await;
    let fetcher = nodes.fetcher(vec![cut, b], SETTINGS);
    assert_eq!(
        read(fetcher.whole(Kind::Blob, &digest).await.unwrap()).await,
        blob
    );
    assert_counted(
        &handle,
        &[
            r#"speculaire_peer_fetches_total{result="error"} 1"#,
            r#"speculaire_peer_fetches_total{result="ok"} 1"#,
        ],
    );
}

#[tokio::test]
async fn a_body_that_stalls_resumes_from_the_next_peer_after_the_stall_timeout() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let blob = pattern(SIZE, 0);
    let digest = sha(&blob);
    let (a, _) = nodes.peer("node-a", &[(&digest, &blob)], 4).await;
    let (b, _) = nodes.peer("node-b", &[(&digest, &blob)], 4).await;
    let stalled = behind(&a, Fault::Stall(SIZE / 4)).await;
    let stall_timeout = Duration::from_millis(300);
    let fetcher = nodes.fetcher(
        vec![stalled, b],
        Settings {
            stall_timeout,
            ..SETTINGS
        },
    );
    let start = Instant::now();
    assert_eq!(
        read(fetcher.whole(Kind::Blob, &digest).await.unwrap()).await,
        blob
    );
    assert!(start.elapsed() >= stall_timeout);
    assert_counted(
        &handle,
        &[
            r#"speculaire_peer_fetches_total{result="timeout"} 1"#,
            r#"speculaire_peer_fetches_total{result="ok"} 1"#,
        ],
    );
}

#[tokio::test]
async fn a_peer_slow_to_answer_is_hedged_and_the_first_good_answer_wins() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let blob = pattern(1000, 0);
    let digest = sha(&blob);
    let (a, _) = nodes.peer("node-a", &[(&digest, &blob)], 4).await;
    let (b, _) = nodes.peer("node-b", &[(&digest, &blob)], 4).await;
    let late = behind(&a, Fault::Late(Duration::from_secs(2))).await;
    let fetcher = nodes.fetcher(vec![late, b], SETTINGS);
    let download = fetcher.download(Kind::Blob, &digest).await.unwrap();
    assert_eq!(download.current.as_ref().unwrap().holder.node, "node-b");
    // The loser waits to resume the body, should the winner fail.
    assert_eq!(download.waiting.len(), 1);
    assert_counted(&handle, &["speculaire_peer_hedges_total 1"]);
}

#[tokio::test]
async fn a_peer_that_sends_another_blob_is_denied_and_the_next_round_skips_it() {
    let (handle, _guard) = recorder();
    let mut nodes = Nodes::new();
    let blob = pattern(SIZE, 0);
    let digest = sha(&blob);
    let (a, _) = nodes
        .peer("node-a", &[(&digest, &pattern(SIZE, 1))], 4)
        .await;
    let (b, _) = nodes.peer("node-b", &[(&digest, &blob)], 4).await;
    let deny_ttl = Duration::from_millis(500);
    let fetcher = nodes.fetcher(
        vec![a, b],
        Settings {
            deny_ttl,
            ..SETTINGS
        },
    );
    assert_eq!(
        read(fetcher.whole(Kind::Blob, &digest).await.unwrap()).await,
        blob
    );
    assert!(!fetcher.0.allowed("node-a"));
    assert!(fetcher.0.allowed("node-b"));
    assert_counted(
        &handle,
        &[
            r#"speculaire_peer_fetches_total{result="digest_mismatch"} 1"#,
            r#"speculaire_peer_fetches_total{result="ok"} 1"#,
        ],
    );
    tokio::time::sleep(deny_ttl).await;
    assert!(fetcher.0.allowed("node-a"));
}

#[tokio::test]
async fn every_peer_that_sent_part_of_a_wrong_blob_is_denied() {
    let mut nodes = Nodes::new();
    let blob = pattern(SIZE, 0);
    let digest = sha(&blob);
    let (a, _) = nodes.peer("node-a", &[(&digest, &blob)], 4).await;
    let (b, _) = nodes
        .peer("node-b", &[(&digest, &pattern(SIZE, 1))], 4)
        .await;
    let cut = behind(&a, Fault::Cut(SIZE / 4)).await;
    let fetcher = nodes.fetcher(vec![cut, b], SETTINGS);
    // Every holder is denied after the first round: none is left for the next.
    assert!(fetcher.whole(Kind::Blob, &digest).await.is_none());
    assert!(!fetcher.0.allowed("node-a"));
    assert!(!fetcher.0.allowed("node-b"));
}

#[tokio::test]
async fn a_live_stall_timeout_applies_to_the_next_fetch() {
    let mut nodes = Nodes::new();
    let blob = pattern(SIZE, 0);
    let digest = sha(&blob);
    let (a, _) = nodes.peer("node-a", &[(&digest, &blob)], 4).await;
    let stalled = behind(&a, Fault::Stall(SIZE / 4)).await;
    let fetcher = nodes.fetcher(vec![stalled], SETTINGS);
    fetcher.set(Settings {
        stall_timeout: Duration::from_millis(100),
        ..SETTINGS
    });
    let got = tokio::time::timeout(Duration::from_secs(2), fetcher.whole(Kind::Blob, &digest))
        .await
        .expect("the reloaded stall timeout");
    assert!(got.is_none());
}

#[test]
fn hedges_wait_for_the_80th_85th_and_90th_percentiles_of_answer_times_at_least_50_ms() {
    let fetcher = Fetcher::new(PathBuf::new(), SETTINGS);
    assert_eq!(fetcher.0.hedge_delays(), [HEDGE_FLOOR; 3]);
    for millis in (1..=100).rev() {
        fetcher.0.answered(Duration::from_millis(millis));
    }
    assert_eq!(
        fetcher.0.hedge_delays(),
        [80, 85, 90].map(Duration::from_millis)
    );
    for _ in 0..SAMPLES {
        fetcher.0.answered(Duration::from_millis(1));
    }
    assert_eq!(fetcher.0.hedge_delays(), [HEDGE_FLOOR; 3]);
}

fn head(status: StatusCode, headers: &[(&str, &str)]) -> (StatusCode, HeaderMap) {
    let headers = headers
        .iter()
        .map(|(name, value)| {
            (
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            )
        })
        .collect();
    (status, headers)
}

#[test]
fn a_head_gives_the_size_only_for_the_content_asked_for() {
    let ok = StatusCode::OK;
    let partial = StatusCode::PARTIAL_CONTENT;
    for (status, headers, offset, expected) in [
        (ok, vec![("content-length", "10")], 0, Ok(10)),
        (ok, vec![("content-length", "10")], 5, Err(Fetched::Error)),
        (ok, vec![], 0, Err(Fetched::Error)),
        (ok, vec![("content-length", "+10")], 0, Err(Fetched::Error)),
        (ok, vec![("content-length", "-1")], 0, Err(Fetched::Error)),
        (
            partial,
            vec![("content-length", "5"), ("content-range", "bytes 5-9/10")],
            5,
            Ok(10),
        ),
        (
            partial,
            vec![("content-length", "5"), ("content-range", "bytes 5-9/10")],
            0,
            Err(Fetched::Error),
        ),
        (
            partial,
            vec![("content-length", "10"), ("content-range", "bytes 0-9/10")],
            0,
            Err(Fetched::Error),
        ),
        (
            partial,
            vec![("content-length", "4"), ("content-range", "bytes 5-8/10")],
            5,
            Err(Fetched::Error),
        ),
        (
            partial,
            vec![("content-length", "5"), ("content-range", "bytes 4-8/10")],
            5,
            Err(Fetched::Error),
        ),
        (
            partial,
            vec![("content-length", "6"), ("content-range", "bytes 5-9/10")],
            5,
            Err(Fetched::Error),
        ),
        (
            partial,
            vec![("content-length", "5"), ("content-range", "bytes 5-9/*")],
            5,
            Err(Fetched::Error),
        ),
        (
            partial,
            vec![("content-length", "5"), ("content-range", "5-9/10")],
            5,
            Err(Fetched::Error),
        ),
        (
            partial,
            vec![("content-length", "5")],
            5,
            Err(Fetched::Error),
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            vec![],
            0,
            Err(Fetched::Busy),
        ),
        (StatusCode::NOT_FOUND, vec![], 0, Err(Fetched::Error)),
    ] {
        let (status, headers) = head(status, &headers);
        assert_eq!(
            read_head(status, &headers, offset),
            expected,
            "{status} {headers:?} from {offset}"
        );
    }
}
