//! The reflector over real TLS on loopback, with certificates of a test cluster CA (D2, D16, D97, D105).
#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "the helpers of a test fail it by panicking"
)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle, PrometheusRecorder};
use speculaire_pki::node::Credentials;
use speculaire_pki::testing::Cluster;
use speculaire_reflect::frame::{self, FrameError, Reader};
use speculaire_reflect::proto::{self, agent_message, reflector_message};
use speculaire_reflect::{Limits, Member, Reflector, Settings, connect};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;

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

    /// A connection to the reflector as `node`, which has sent nothing yet.
    async fn connection(&self, node: &str) -> Agent {
        let credentials = credentials(&self.cluster, &self.dir, node);
        let tls = connect(self.reflector.address(), credentials.client(REFLECTOR))
            .await
            .unwrap();
        Agent {
            tls,
            reader: Reader::new(frame::LIMIT),
            id: 0,
        }
    }

    /// A connection as `node` that announces, after its `Hello` of `version` for `hello`.
    async fn agent(&self, node: &str, hello: &str, version: u32) -> Agent {
        let mut agent = self.connection(node).await;
        agent
            .send(agent_message::Message::Hello(proto::Hello {
                protocol_version: version,
                node: hello.to_owned(),
                peer_address: address_of(node).to_string(),
            }))
            .await;
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

/// One agent's connection.
struct Agent {
    tls: TlsStream<TcpStream>,
    reader: Reader<proto::ReflectorMessage>,
    id: u64,
}

impl Agent {
    async fn send(&mut self, message: agent_message::Message) {
        let message = proto::AgentMessage {
            message: Some(message),
        };
        frame::write(&mut self.tls, &message, frame::LIMIT)
            .await
            .unwrap();
    }

    async fn snapshot(&mut self, digests: Vec<String>, seq: u64) {
        self.send(agent_message::Message::Snapshot(proto::Snapshot {
            digests,
            last: true,
            seq,
        }))
        .await;
    }

    async fn delta(&mut self, seq: u64, added: Vec<String>, removed: Vec<String>) {
        self.send(agent_message::Message::Delta(proto::Delta {
            seq,
            added,
            removed,
        }))
        .await;
    }

    /// The reflector's next message; `None` once it closed the connection.
    async fn reply(&mut self) -> Result<Option<reflector_message::Message>, FrameError> {
        let reply = tokio::time::timeout(Duration::from_secs(5), self.reader.next(&mut self.tls))
            .await
            .unwrap()?;
        Ok(reply.map(|reply| reply.message.unwrap()))
    }

    /// The nodes a lookup of `digest` returns, by this agent's node.
    async fn lookup(&mut self, digest: &str) -> Vec<String> {
        let id = self.id;
        self.id += 1;
        self.send(agent_message::Message::Lookup(proto::LookupRequest {
            digest: digest.to_owned(),
            id,
        }))
        .await;
        let Some(reflector_message::Message::Lookup(answer)) = self.reply().await.unwrap() else {
            panic!("a reply other than the lookup's answer");
        };
        assert_eq!(answer.id, id);
        let mut peers: Vec<String> = answer
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

    async fn members(&mut self) -> Result<Vec<proto::Member>, FrameError> {
        self.send(agent_message::Message::Members(proto::MembersRequest {}))
            .await;
        match self.reply().await? {
            Some(reflector_message::Message::Members(answer)) => Ok(answer.members),
            reply => panic!("{reply:?} answers `Members`"),
        }
    }

    /// Waits for a `Resync`, which also shows the connection is still open.
    async fn resync(&mut self) {
        let reply = self.reply().await.unwrap();
        assert_eq!(
            reply,
            Some(reflector_message::Message::Resync(proto::Resync {}))
        );
    }

    /// Why the reflector ended the connection, which it then closes.
    async fn refusal(&mut self) -> proto::Reason {
        self.refused().await.reason()
    }

    async fn refused(&mut self) -> proto::Refused {
        let Some(reflector_message::Message::Refused(refused)) = self.reply().await.unwrap() else {
            panic!("a reply, and no refusal");
        };
        assert!(
            matches!(self.reply().await, Ok(None)),
            "the TLS close follows"
        );
        refused
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
    let members = test.connection("a").await.members().await.unwrap();
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
        Ok(tls) => {
            let mut agent = Agent {
                tls,
                reader: Reader::new(frame::LIMIT),
                id: 0,
            };
            let request = proto::AgentMessage {
                message: Some(agent_message::Message::Members(proto::MembersRequest {})),
            };
            frame::write(&mut agent.tls, &request, frame::LIMIT)
                .await
                .is_err()
                || agent.reply().await.is_err()
        }
    };
    assert!(refused);
}

#[tokio::test]
async fn a_ping_gets_a_pong() {
    let test = Test::start(settings()).await;
    let mut agent = test.connection("a").await;
    agent
        .send(agent_message::Message::Ping(proto::Ping {}))
        .await;
    assert_eq!(
        agent.reply().await.unwrap(),
        Some(reflector_message::Message::Pong(proto::Pong {}))
    );
}

#[tokio::test]
async fn a_hello_for_another_node_is_refused_and_counted() {
    let test = Test::start(settings()).await;
    let mut agent = test.agent("a", "b", 1).await;
    assert_eq!(agent.refusal().await, proto::Reason::Identity);
    assert_eq!(test.rejected("identity"), "1");
}

#[tokio::test]
async fn a_reflector_accepts_the_versions_of_its_range() {
    let mut settings = settings();
    settings.versions = 1..=2;
    let test = Test::start(settings).await;
    let mut speaks_one = test.agent("a", "a", 1).await;
    speaks_one.snapshot(vec![digest(1)], 0).await;
    let mut speaks_zero = test.agent("b", "b", 0).await;
    assert_eq!(speaks_zero.refusal().await, proto::Reason::Version);
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
        let mut agent = test.agent(node, node, 1).await;
        agent.snapshot(vec![digest(1)], 0).await;
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
async fn lookups_are_answered_in_order_between_announcements_with_their_number() {
    let test = Test::start(settings()).await;
    let mut a = test.agent("a", "a", 1).await;
    a.snapshot(vec![digest(1)], 0).await;
    let mut b = test.agent("b", "b", 1).await;
    b.snapshot(vec![digest(2)], 0).await;
    for (id, digest) in [(7, digest(2)), (3, digest(9))] {
        a.send(agent_message::Message::Lookup(proto::LookupRequest {
            digest,
            id,
        }))
        .await;
    }
    a.delta(0, vec![digest(3)], vec![]).await;
    let mut answers = Vec::new();
    for _ in 0..2 {
        let Some(reflector_message::Message::Lookup(answer)) = a.reply().await.unwrap() else {
            panic!("a reply other than a lookup's answer");
        };
        answers.push((answer.id, answer.peers.len()));
    }
    assert_eq!(answers, [(7, 1), (3, 0)]);
    b.wait_lookup(&digest(3), &["a"]).await;
}

#[tokio::test]
async fn the_end_of_a_connection_withdraws_what_it_announced() {
    let test = Test::start(settings()).await;
    let mut a = test.agent("a", "a", 1).await;
    a.snapshot(vec![digest(1), digest(2)], 0).await;
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
    a.snapshot(vec![digest(1)], 5).await;
    a.delta(5, vec![digest(2)], vec![digest(1)]).await;
    b.wait_lookup(&digest(2), &["a"]).await;
    b.wait_lookup(&digest(1), &[]).await;
    // The delta came after the snapshot on the same connection: the first snapshot's refill is timed by now.
    assert_eq!(
        test.metric("speculaire_reflector_resync_seconds_count"),
        "1"
    );
    a.delta(7, vec![digest(3)], vec![]).await;
    a.resync().await;
    // Until the next snapshot, deltas are of no use.
    a.delta(8, vec![digest(4)], vec![]).await;
    a.snapshot(vec![digest(5)], 9).await;
    b.wait_lookup(&digest(5), &["a"]).await;
    for gone in [2, 3, 4] {
        assert_eq!(b.lookup(&digest(gone)).await, Vec::<String>::new());
    }
    // A later snapshot of the connection times nothing.
    assert_eq!(
        test.metric("speculaire_reflector_resync_seconds_count"),
        "1"
    );
}

#[tokio::test]
async fn a_snapshot_in_chunks_counts_from_its_last() {
    let test = Test::start(settings()).await;
    let mut a = test.agent("a", "a", 1).await;
    let mut b = test.agent("b", "b", 1).await;
    a.send(agent_message::Message::Snapshot(proto::Snapshot {
        digests: vec![digest(1)],
        last: false,
        seq: 0,
    }))
    .await;
    a.snapshot(vec![digest(2)], 0).await;
    b.wait_lookup(&digest(1), &["a"]).await;
    b.wait_lookup(&digest(2), &["a"]).await;
}

#[tokio::test]
async fn each_limit_refuses_the_connection_and_counts() {
    let mut settings = settings();
    settings.limits = Limits {
        message: 1024,
        digests: 3,
        ..Limits::default()
    };
    let test = Test::start(settings).await;

    let mut large = test.agent("a", "a", 1).await;
    large.snapshot(digests(0..20), 0).await;
    let refused = large.refused().await;
    assert_eq!(refused.reason(), proto::Reason::Size);
    assert!(refused.message.contains("node \"a\""), "{refused:?}");
    // The length alone refuses a frame: its body never arrives.
    let mut announced = test.agent("e", "e", 1).await;
    announced.tls.write_all(&[0, 0, 4, 1]).await.unwrap();
    assert_eq!(announced.refusal().await, proto::Reason::Size);
    assert_eq!(test.rejected("size"), "2");

    let mut many = test.agent("b", "b", 1).await;
    many.snapshot(digests(0..4), 0).await;
    assert_eq!(many.refusal().await, proto::Reason::Digests);
    let mut grows = test.agent("c", "c", 1).await;
    // At the limit, and still open: a gap gets its `Resync`.
    grows.snapshot(digests(0..3), 0).await;
    grows.delta(5, vec![], vec![]).await;
    grows.resync().await;
    // A digest held again takes no room, and removing first makes room.
    grows.snapshot(digests(0..3), 10).await;
    grows.delta(10, vec![digest(2)], vec![]).await;
    grows.delta(11, vec![digest(3)], vec![digest(0)]).await;
    grows.delta(15, vec![], vec![]).await;
    grows.resync().await;
    grows.snapshot(digests(1..4), 20).await;
    grows.delta(20, vec![digest(4)], vec![]).await;
    assert_eq!(grows.refusal().await, proto::Reason::Digests);
    assert_eq!(test.rejected("digests"), "2");

    let mut named = test.connection("d").await;
    named
        .send(agent_message::Message::Hello(proto::Hello {
            protocol_version: 1,
            node: "d".to_owned(),
            peer_address: "node-d:7484".to_owned(),
        }))
        .await;
    assert_eq!(named.refusal().await, proto::Reason::Address);
    assert_eq!(test.rejected("address"), "1");
}

#[tokio::test]
async fn a_message_that_does_not_decode_is_malformed_and_no_size_refusal() {
    let test = Test::start(settings()).await;
    let mut agent = test.connection("a").await;
    // Bytes 0a 01 78: an `AgentMessage` whose `Hello` holds a field tag and no value.
    agent
        .tls
        .write_all(&[0, 0, 0, 3, 0x0a, 0x01, 0x78])
        .await
        .unwrap();
    assert_eq!(agent.refusal().await, proto::Reason::Malformed);
    assert_eq!(test.rejected("malformed"), "1");
    assert_eq!(test.rejected("size"), "0");
}

#[tokio::test]
async fn an_announcement_must_start_with_one_hello() {
    let test = Test::start(settings()).await;
    let mut agent = test.connection("a").await;
    agent
        .send(agent_message::Message::Snapshot(proto::Snapshot::default()))
        .await;
    assert_eq!(agent.refusal().await, proto::Reason::Malformed);
    let mut twice = test.agent("b", "b", 1).await;
    twice
        .send(agent_message::Message::Hello(proto::Hello {
            protocol_version: 1,
            node: "b".to_owned(),
            peer_address: address_of("b").to_string(),
        }))
        .await;
    assert_eq!(twice.refusal().await, proto::Reason::Malformed);
    assert_eq!(test.rejected("malformed"), "2");
}

#[tokio::test]
async fn a_later_connection_of_a_node_takes_its_entry_over() {
    let test = Test::start(settings()).await;
    let mut first = test.agent("a", "a", 1).await;
    first.snapshot(vec![digest(1)], 0).await;
    let mut b = test.agent("b", "b", 1).await;
    b.wait_lookup(&digest(1), &["a"]).await;
    let mut second = test.agent("a", "a", 1).await;
    second.snapshot(vec![digest(2)], 0).await;
    b.wait_lookup(&digest(2), &["a"]).await;
    b.wait_lookup(&digest(1), &[]).await;
    first.delta(0, vec![digest(3)], vec![]).await;
    assert_eq!(first.refusal().await, proto::Reason::Superseded);
    // The end of the first connection leaves the second's entry.
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
    test.connection("a").await.members().await.unwrap();
    assert!(start.elapsed() < Duration::from_secs(1));
    let mut byte = [0; 1];
    let closed = tokio::time::timeout(Duration::from_secs(5), silent.read(&mut byte)).await;
    assert!(matches!(closed, Ok(Ok(0) | Err(_))), "{closed:?}");
}

#[tokio::test(start_paused = true)]
async fn a_connection_silent_for_forty_seconds_is_closed() {
    let test = Test::start(settings()).await;
    let mut agent = test.agent("a", "a", 1).await;
    agent.snapshot(vec![digest(1)], 0).await;
    let start = tokio::time::Instant::now();
    // With the clock paused, it jumps to the reflector's deadline once both sides wait.
    let mut byte = [0; 1];
    let closed = agent.tls.read(&mut byte).await;
    assert!(matches!(closed, Ok(0) | Err(_)), "{closed:?}");
    assert!(start.elapsed() >= frame::SILENCE, "{:?}", start.elapsed());
}

#[tokio::test]
async fn stopping_refuses_every_connection_and_waits_for_them() {
    let test = Test::start(settings()).await;
    let mut a = test.agent("a", "a", 1).await;
    a.snapshot(vec![digest(1)], 0).await;
    test.agent("b", "b", 1)
        .await
        .wait_lookup(&digest(1), &["a"])
        .await;
    tokio::time::timeout(Duration::from_secs(5), test.reflector.stop())
        .await
        .unwrap();
    assert_eq!(a.refusal().await, proto::Reason::Stopping);
}
