//! The reflector over real TLS on loopback, with certificates of a test cluster CA (D2, D16, D97).
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of a test fail it by panicking"
)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{StreamExt as _, stream};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle, PrometheusRecorder};
use speculaire_pki::node::Credentials;
use speculaire_pki::testing::Cluster;
use speculaire_reflect::proto::reflector_client::ReflectorClient;
use speculaire_reflect::proto::{self, agent_message, reflector_message};
use speculaire_reflect::{Limits, Member, Reflector, Settings, connect};
use tempfile::TempDir;
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::transport::Channel;
use tonic::{Code, Streaming};

const REFLECTOR: &str = "control-plane";

/// A cluster, its reflector, and the credentials of any node in it.
struct Test {
    cluster: Cluster,
    dir: TempDir,
    reflector: Reflector,
    metrics: PrometheusHandle,
    _recorder: ::metrics::LocalRecorderGuard<'static>,
}

impl Test {
    async fn start(settings: Settings) -> Self {
        let recorder: &'static PrometheusRecorder =
            Box::leak(Box::new(PrometheusBuilder::new().build_recorder()));
        let metrics = recorder.handle();
        // Tests run on one thread each, server included: the others count into their own recorders.
        let guard = ::metrics::set_default_local_recorder(recorder);
        speculaire_reflect::metrics::describe();
        let cluster = Cluster::new("kubernetes");
        let dir = tempfile::tempdir().unwrap();
        let credentials = credentials(&cluster, &dir, REFLECTOR);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let reflector = Reflector::spawn(listener, &credentials, settings).unwrap();
        Self {
            cluster,
            dir,
            reflector,
            metrics,
            _recorder: guard,
        }
    }

    /// A channel to the reflector as `node`.
    async fn channel(&self, node: &str) -> Channel {
        let credentials = credentials(&self.cluster, &self.dir, node);
        connect(self.reflector.address(), credentials.client(REFLECTOR))
            .await
            .unwrap()
    }

    /// A client of the reflector as `node`.
    async fn client(&self, node: &str) -> ReflectorClient<Channel> {
        ReflectorClient::new(self.channel(node).await)
    }

    /// An `Announce` stream as `node`, after its `Hello` of `version` for `hello`.
    async fn agent(&self, node: &str, hello: &str, version: u32) -> Agent {
        let mut client = self.client(node).await;
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let outbound = stream::poll_fn(move |cx| receiver.poll_recv(cx));
        let replies = client.announce(outbound).await.unwrap().into_inner();
        let agent = Agent {
            client,
            sender,
            replies,
        };
        agent.send(agent_message::Message::Hello(proto::Hello {
            protocol_version: version,
            node: hello.to_owned(),
            peer_address: address_of(node).to_string(),
        }));
        agent
    }

    /// The value of a series, as the reflector exports it.
    fn metric(&self, series: &str) -> String {
        let text = self.metrics.render();
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{series} ")))
            .unwrap_or_else(|| panic!("no {series} in\n{text}"))
            .to_owned()
    }

    fn rejected(&self, reason: &str) -> String {
        self.metric(&format!(
            "speculaire_reflector_announce_rejected_total{{reason=\"{reason}\"}}"
        ))
    }
}

/// The credentials of `node` in `cluster`, from files as kubelet writes them.
fn credentials(cluster: &Cluster, dir: &TempDir, node: &str) -> Arc<Credentials> {
    let credentials = Arc::new(Credentials::default());
    let certificate = dir.path().join(format!("{node}.pem"));
    let ca = dir.path().join("ca.crt");
    write(&certificate, &cluster.kubelet(node));
    write(&ca, cluster.ca());
    credentials.load_identity(&certificate).unwrap();
    credentials.load_authority(&ca).unwrap();
    credentials
}

fn write(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
}

/// Where `node`'s peer API is, in these tests.
fn address_of(node: &str) -> SocketAddr {
    let last = node.bytes().fold(0_u8, u8::wrapping_add);
    SocketAddr::from(([10, 0, 0, last], 7484))
}

fn digest(n: u32) -> String {
    format!("sha256:{n:064x}")
}

fn digests(range: std::ops::Range<u32>) -> Vec<String> {
    range.map(digest).collect()
}

/// One agent's `Announce` stream.
struct Agent {
    client: ReflectorClient<Channel>,
    sender: mpsc::UnboundedSender<proto::AgentMessage>,
    replies: Streaming<proto::ReflectorMessage>,
}

impl Agent {
    fn send(&self, message: agent_message::Message) {
        self.sender
            .send(proto::AgentMessage {
                message: Some(message),
            })
            .unwrap();
    }

    fn snapshot(&self, digests: Vec<String>, seq: u64) {
        self.send(agent_message::Message::Snapshot(proto::Snapshot {
            digests,
            last: true,
            seq,
        }));
    }

    fn delta(&self, seq: u64, added: Vec<String>, removed: Vec<String>) {
        self.send(agent_message::Message::Delta(proto::Delta {
            seq,
            added,
            removed,
        }));
    }

    /// The nodes a lookup of `digest` returns, by this agent's node.
    async fn lookup(&mut self, digest: &str) -> Vec<String> {
        let request = proto::LookupRequest {
            digest: digest.to_owned(),
        };
        let mut peers: Vec<String> = self
            .client
            .lookup(request)
            .await
            .unwrap()
            .into_inner()
            .peers
            .into_iter()
            .map(|peer| {
                assert_eq!(peer.address, address_of(&peer.node).to_string());
                peer.node
            })
            .collect();
        peers.sort();
        peers
    }

    /// Looks `digest` up until the lookup returns `expected`.
    async fn wait_lookup(&mut self, digest: &str, expected: &[&str]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let peers = self.lookup(digest).await;
            if peers == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{digest}: {peers:?}, not {expected:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Waits for a `Resync`, which also shows the stream is still open.
    async fn resync(&mut self) {
        let reply = self.replies.message().await.unwrap().unwrap();
        assert_eq!(
            reply.message,
            Some(reflector_message::Message::Resync(proto::Resync {}))
        );
    }

    /// How the reflector ended the stream.
    async fn refusal(&mut self) -> Code {
        self.refused().await.code()
    }

    async fn refused(&mut self) -> tonic::Status {
        match self.replies.message().await {
            Err(status) => status,
            Ok(reply) => panic!("a reply, {reply:?}, and no refusal"),
        }
    }
}

fn settings() -> Settings {
    Settings::new(vec![Member {
        node: REFLECTOR.to_owned(),
        address: SocketAddr::from(([10, 0, 0, 1], 7483)),
    }])
}

#[tokio::test]
async fn members_answers_the_configured_reflectors() {
    let test = Test::start(settings()).await;
    let members = test
        .client("a")
        .await
        .members(proto::MembersRequest {})
        .await
        .unwrap()
        .into_inner()
        .members;
    assert_eq!(
        members,
        [proto::Member {
            node: REFLECTOR.to_owned(),
            address: "10.0.0.1:7483".to_owned(),
        }]
    );
}

#[tokio::test]
async fn a_client_without_a_certificate_of_the_cluster_ca_is_refused() {
    let test = Test::start(settings()).await;
    // The client trusts the reflector's CA, and presents a certificate of another.
    let other = tempfile::tempdir().unwrap();
    let credentials = credentials(&Cluster::new("other"), &other, "a");
    credentials
        .load_authority(&test.dir.path().join("ca.crt"))
        .unwrap();
    let refused = match connect(test.reflector.address(), credentials.client(REFLECTOR)).await {
        Err(_) => true,
        // TLS 1.3: the refusal arrives after the client's handshake ended.
        Ok(channel) => ReflectorClient::new(channel)
            .members(proto::MembersRequest {})
            .await
            .is_err(),
    };
    assert!(refused);
}

#[tokio::test]
async fn a_hello_for_another_node_is_refused_and_counted() {
    let test = Test::start(settings()).await;
    let mut agent = test.agent("a", "b", 1).await;
    assert_eq!(agent.refusal().await, Code::PermissionDenied);
    assert_eq!(test.rejected("identity"), "1");
}

#[tokio::test]
async fn a_reflector_accepts_the_versions_of_its_range() {
    let mut settings = settings();
    settings.versions = 1..=2;
    let test = Test::start(settings).await;
    let mut speaks_one = test.agent("a", "a", 1).await;
    speaks_one.snapshot(vec![digest(1)], 0);
    let mut speaks_zero = test.agent("b", "b", 0).await;
    assert_eq!(speaks_zero.refusal().await, Code::FailedPrecondition);
    assert_eq!(test.rejected("version"), "1");
    test.agent("c", "c", 1)
        .await
        .wait_lookup(&digest(1), &["a"])
        .await;
    speaks_one.wait_lookup(&digest(1), &[]).await;
}

#[tokio::test]
async fn a_lookup_returns_up_to_eight_holders_and_never_the_one_asking() {
    let test = Test::start(settings()).await;
    let nodes: Vec<String> = (0..10).map(|n| format!("node-{n}")).collect();
    let mut agents = Vec::new();
    for node in &nodes {
        let agent = test.agent(node, node, 1).await;
        agent.snapshot(vec![digest(1)], 0);
        agents.push(agent);
    }
    let mut others: Vec<&str> = nodes[1..].iter().map(String::as_str).collect();
    others.sort_unstable();
    let deadline = Instant::now() + Duration::from_secs(5);
    while test.metric("speculaire_reflector_pairs") != "10" {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..50 {
        let peers = agents[0].lookup(&digest(1)).await;
        assert_eq!(peers.len(), 8);
        assert!(
            peers.iter().all(|peer| others.contains(&peer.as_str())),
            "{peers:?}"
        );
        seen.extend(peers);
    }
    // A random start spreads lookups over every holder.
    assert_eq!(seen.len(), 9);
    assert_eq!(agents[0].lookup(&digest(2)).await, Vec::<String>::new());
}

#[tokio::test]
async fn the_end_of_a_stream_withdraws_what_it_announced() {
    let test = Test::start(settings()).await;
    let a = test.agent("a", "a", 1).await;
    a.snapshot(vec![digest(1), digest(2)], 0);
    let mut b = test.agent("b", "b", 1).await;
    b.wait_lookup(&digest(2), &["a"]).await;
    assert_eq!(test.metric("speculaire_reflector_agents"), "2");
    drop(a);
    b.wait_lookup(&digest(2), &[]).await;
    assert_eq!(test.metric("speculaire_reflector_agents"), "1");
    assert_eq!(test.metric("speculaire_reflector_digests"), "0");
    assert_eq!(test.metric("speculaire_reflector_pairs"), "0");
    // The client went away: no refusal.
    for reason in speculaire_reflect::metrics::Reason::ALL {
        assert_eq!(test.rejected(reason.label()), "0");
    }
}

#[tokio::test]
async fn deltas_apply_in_sequence_and_a_gap_gets_a_resync() {
    let test = Test::start(settings()).await;
    let mut a = test.agent("a", "a", 1).await;
    let mut b = test.agent("b", "b", 1).await;
    a.snapshot(vec![digest(1)], 5);
    a.delta(5, vec![digest(2)], vec![digest(1)]);
    b.wait_lookup(&digest(2), &["a"]).await;
    b.wait_lookup(&digest(1), &[]).await;
    a.delta(7, vec![digest(3)], vec![]);
    a.resync().await;
    // Until the next snapshot, deltas are of no use.
    a.delta(8, vec![digest(4)], vec![]);
    a.snapshot(vec![digest(5)], 9);
    b.wait_lookup(&digest(5), &["a"]).await;
    for gone in [2, 3, 4] {
        assert_eq!(b.lookup(&digest(gone)).await, Vec::<String>::new());
    }
}

#[tokio::test]
async fn a_snapshot_in_chunks_counts_from_its_last() {
    let test = Test::start(settings()).await;
    let a = test.agent("a", "a", 1).await;
    let mut b = test.agent("b", "b", 1).await;
    a.send(agent_message::Message::Snapshot(proto::Snapshot {
        digests: vec![digest(1)],
        last: false,
        seq: 0,
    }));
    a.snapshot(vec![digest(2)], 0);
    b.wait_lookup(&digest(1), &["a"]).await;
    b.wait_lookup(&digest(2), &["a"]).await;
}

#[tokio::test]
async fn each_limit_refuses_the_stream_and_counts() {
    let mut settings = settings();
    settings.limits = Limits {
        message: 1024,
        digests: 3,
        ..Limits::default()
    };
    let test = Test::start(settings).await;

    let mut large = test.agent("a", "a", 1).await;
    large.snapshot(digests(0..20), 0);
    let refused = large.refused().await;
    assert_eq!(refused.code(), Code::ResourceExhausted);
    assert!(refused.message().contains("node \"a\""), "{refused}");
    assert_eq!(test.rejected("size"), "1");

    let mut many = test.agent("b", "b", 1).await;
    many.snapshot(digests(0..4), 0);
    assert_eq!(many.refusal().await, Code::ResourceExhausted);
    let mut grows = test.agent("c", "c", 1).await;
    // At the limit, and still open: a gap gets its `Resync`.
    grows.snapshot(digests(0..3), 0);
    grows.delta(5, vec![], vec![]);
    grows.resync().await;
    // A digest held again takes no room, and removing first makes room.
    grows.snapshot(digests(0..3), 10);
    grows.delta(10, vec![digest(2)], vec![]);
    grows.delta(11, vec![digest(3)], vec![digest(0)]);
    grows.delta(15, vec![], vec![]);
    grows.resync().await;
    grows.snapshot(digests(1..4), 20);
    grows.delta(20, vec![digest(4)], vec![]);
    assert_eq!(grows.refusal().await, Code::ResourceExhausted);
    assert_eq!(test.rejected("digests"), "2");

    let mut client = test.client("d").await;
    let hello = proto::AgentMessage {
        message: Some(agent_message::Message::Hello(proto::Hello {
            protocol_version: 1,
            node: "d".to_owned(),
            peer_address: "node-d:7484".to_owned(),
        })),
    };
    let mut replies = client
        .announce(stream::iter([hello]).chain(stream::pending()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        replies.message().await.unwrap_err().code(),
        Code::InvalidArgument
    );
    assert_eq!(test.rejected("address"), "1");
}

#[tokio::test]
async fn a_message_that_does_not_decode_ends_the_stream_but_is_no_size_refusal() {
    let test = Test::start(settings()).await;
    let mut grpc = tonic::client::Grpc::new(test.channel("a").await);
    grpc.ready().await.unwrap();
    // Bytes 0a 01 78: an `AgentMessage` whose `Hello` holds a field tag and no value.
    let garbage = proto::LookupRequest {
        digest: "x".to_owned(),
    };
    let codec = tonic_prost::ProstCodec::<proto::LookupRequest, proto::ReflectorMessage>::default();
    let mut replies = grpc
        .streaming(
            tonic::Request::new(stream::iter([garbage]).chain(stream::pending())),
            PathAndQuery::from_static("/speculaire.reflect.v1.Reflector/Announce"),
            codec,
        )
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replies.message().await.unwrap_err().code(), Code::Internal);
    assert_eq!(test.rejected("size"), "0");
}

#[tokio::test]
async fn a_stream_must_start_with_one_hello() {
    let test = Test::start(settings()).await;
    let mut client = test.client("a").await;
    let snapshot = proto::AgentMessage {
        message: Some(agent_message::Message::Snapshot(proto::Snapshot::default())),
    };
    let mut replies = client
        .announce(stream::iter([snapshot]).chain(stream::pending()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        replies.message().await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut twice = test.agent("b", "b", 1).await;
    twice.send(agent_message::Message::Hello(proto::Hello {
        protocol_version: 1,
        node: "b".to_owned(),
        peer_address: address_of("b").to_string(),
    }));
    assert_eq!(twice.refusal().await, Code::InvalidArgument);
    assert_eq!(test.rejected("malformed"), "2");
}

#[tokio::test]
async fn a_later_stream_of_a_node_takes_its_entry_over() {
    let test = Test::start(settings()).await;
    let mut first = test.agent("a", "a", 1).await;
    first.snapshot(vec![digest(1)], 0);
    let mut b = test.agent("b", "b", 1).await;
    b.wait_lookup(&digest(1), &["a"]).await;
    let second = test.agent("a", "a", 1).await;
    second.snapshot(vec![digest(2)], 0);
    b.wait_lookup(&digest(2), &["a"]).await;
    b.wait_lookup(&digest(1), &[]).await;
    first.delta(0, vec![digest(3)], vec![]);
    assert_eq!(first.refusal().await, Code::Aborted);
    // The end of the first stream leaves the second's entry.
    drop(first);
    assert_eq!(b.lookup(&digest(2)).await, ["a"]);
    assert_eq!(test.rejected("identity"), "0");
}

#[tokio::test]
async fn a_handshake_that_never_ends_delays_no_other_and_times_out() {
    let mut settings = settings();
    settings.limits.handshake = Duration::from_secs(1);
    let test = Test::start(settings).await;
    let mut silent = TcpStream::connect(test.reflector.address()).await.unwrap();
    let start = Instant::now();
    test.client("a")
        .await
        .members(proto::MembersRequest {})
        .await
        .unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    let mut byte = [0; 1];
    let closed = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut byte)).await;
    assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
}

#[tokio::test]
async fn stopping_ends_every_stream() {
    let test = Test::start(settings()).await;
    let mut a = test.agent("a", "a", 1).await;
    a.snapshot(vec![digest(1)], 0);
    test.agent("b", "b", 1)
        .await
        .wait_lookup(&digest(1), &["a"])
        .await;
    tokio::time::timeout(Duration::from_secs(5), test.reflector.stop())
        .await
        .unwrap();
    assert_eq!(a.refusal().await, Code::Unavailable);
}
