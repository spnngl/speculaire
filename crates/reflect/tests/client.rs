//! The agent's reflector client against two reflectors over real TLS on loopback (D2, D33, D36, D98).
#![expect(
    clippy::unwrap_used,
    reason = "the helpers of a test fail it by panicking"
)]

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle, PrometheusRecorder};
use speculaire_oci::reference::Digest;
use speculaire_pki::node::Credentials;
use speculaire_pki::testing::Cluster;
use speculaire_reflect::client::{Client, Config, Holdings, LookupError, PEER_PORT};
use speculaire_reflect::proto::LookupRequest;
use speculaire_reflect::proto::reflector_client::ReflectorClient;
use speculaire_reflect::{Member, Reflector, Settings, connect};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::time::Instant;

/// A cluster of two reflectors, the second behind the load balancer.
struct Test {
    cluster: Cluster,
    dir: TempDir,
    reflectors: Vec<Reflector>,
    members: Vec<Member>,
    metrics: PrometheusHandle,
    _recorder: ::metrics::LocalRecorderGuard<'static>,
}

impl Test {
    /// Reflectors `cp-1` and `cp-2`, each answering `Members` with `listed`, or with both when it is empty.
    async fn start(listed: &[&str]) -> Self {
        let recorder: &'static PrometheusRecorder =
            Box::leak(Box::new(PrometheusBuilder::new().build_recorder()));
        let metrics = recorder.handle();
        // Tests run on one thread each, client included: the others count into their own recorders.
        let guard = ::metrics::set_default_local_recorder(recorder);
        speculaire_reflect::metrics::describe_client();
        let cluster = Cluster::new("kubernetes");
        let dir = tempfile::tempdir().unwrap();
        let mut listeners = Vec::new();
        let mut members = Vec::new();
        for node in ["cp-1", "cp-2"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            members.push(Member {
                node: node.to_owned(),
                address: listener.local_addr().unwrap(),
            });
            listeners.push(listener);
        }
        let answered: Vec<Member> = members
            .iter()
            .filter(|member| listed.is_empty() || listed.contains(&member.node.as_str()))
            .cloned()
            .collect();
        let reflectors = listeners
            .into_iter()
            .zip(&members)
            .map(|(listener, member)| {
                let credentials = credentials(&cluster, &dir, &member.node);
                Reflector::spawn(listener, &credentials, Settings::new(answered.clone())).unwrap()
            })
            .collect();
        Self {
            cluster,
            dir,
            reflectors,
            members,
            metrics,
            _recorder: guard,
        }
    }

    /// The client of `node`, holding `holdings`, with `peer.address` set to `peer`.
    fn agent(&self, node: &str, holdings: &Arc<Holdings>, peer: Option<SocketAddr>) -> Client {
        let balancer = self.members[1].address;
        let config = Config {
            host: balancer.ip().to_string(),
            port: balancer.port(),
            peer,
        };
        Client::spawn(
            config,
            credentials(&self.cluster, &self.dir, node),
            Arc::clone(holdings),
        )
    }

    /// The nodes and addresses each reflector returns for `digest`, asked as `observer`.
    async fn lookups(&self, digest: &Digest) -> Vec<Vec<(String, String)>> {
        let credentials = credentials(&self.cluster, &self.dir, "observer");
        let mut answers = Vec::new();
        for member in &self.members {
            let channel = connect(member.address, credentials.client(&member.node))
                .await
                .unwrap();
            let request = LookupRequest {
                digest: digest.to_string(),
            };
            let response = ReflectorClient::new(channel).lookup(request).await.unwrap();
            let mut peers: Vec<(String, String)> = response
                .into_inner()
                .peers
                .into_iter()
                .map(|peer| (peer.node, peer.address))
                .collect();
            peers.sort();
            answers.push(peers);
        }
        answers
    }

    /// Waits until each reflector returns `expected` for `digest`.
    async fn wait(&self, digest: &Digest, expected: &[(&str, SocketAddr)]) {
        let expected: Vec<(String, String)> = expected
            .iter()
            .map(|(node, address)| ((*node).to_owned(), address.to_string()))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let answers = self.lookups(digest).await;
            if answers.iter().all(|answer| *answer == expected) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{digest}: {answers:?}, expected {expected:?} from each"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn metric(&self, series: &str) -> Option<String> {
        let text = self.metrics.render();
        text.lines()
            .find_map(|line| line.strip_prefix(&format!("{series} ")))
            .map(ToOwned::to_owned)
    }
}

/// The credentials of `node` in `cluster`, from files as kubelet writes them.
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

fn digest(n: u32) -> Digest {
    Digest::parse(&format!("sha256:{n:064x}")).unwrap()
}

#[tokio::test]
async fn an_agent_announces_to_every_member_and_keeps_both_maps_the_same() {
    let test = Test::start(&[]).await;
    let holdings = Arc::new(Holdings::default());
    holdings.add(digest(1));
    let a = test.agent("node-a", &holdings, None);
    // The peer address is the local IP of the first stream, on 7481 (D36).
    let peer = SocketAddr::from(([127, 0, 0, 1], PEER_PORT));
    assert_eq!(a.fixed_peer_address().await, Some(peer));
    test.wait(&digest(1), &[("node-a", peer)]).await;
    for member in ["cp-1", "cp-2"] {
        let connected = format!("speculaire_reflector_connected{{member=\"{member}\"}}");
        assert_eq!(test.metric(&connected).as_deref(), Some("1"));
        let reconnects = format!("speculaire_reflector_reconnects_total{{member=\"{member}\"}}");
        assert_eq!(test.metric(&reconnects).as_deref(), Some("0"));
    }
    // Changes follow, on both.
    holdings.replace(HashSet::from([digest(2), digest(3)]));
    test.wait(&digest(1), &[]).await;
    test.wait(&digest(2), &[("node-a", peer)]).await;
    holdings.remove(&digest(3));
    test.wait(&digest(3), &[]).await;
    // Another agent's lookup finds node-a, and node-a's own lookup does not.
    let b = test.agent("node-b", &Arc::new(Holdings::default()), None);
    let deadline = Instant::now() + Duration::from_secs(5);
    let found = loop {
        match b.lookup(&digest(2)).await {
            Ok(found) => break found,
            Err(LookupError::NoMember) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            Err(err) => panic!("{err}"),
        }
    };
    assert_eq!(found.len(), 1);
    assert_eq!((found[0].node.as_str(), found[0].address), ("node-a", peer));
    assert_eq!(a.lookup(&digest(2)).await.unwrap(), []);
    for result in ["hit", "miss"] {
        assert_eq!(
            test.metric(&format!(
                "speculaire_lookup_seconds_count{{result=\"{result}\"}}"
            ))
            .as_deref(),
            Some("1"),
            "{result}"
        );
    }
    // Stopping the client withdraws the node from both.
    a.stop().await;
    test.wait(&digest(2), &[]).await;
    b.stop().await;
}

#[tokio::test]
async fn peer_address_overrides_the_address_found() {
    let test = Test::start(&[]).await;
    let holdings = Arc::new(Holdings::default());
    holdings.add(digest(1));
    let peer: SocketAddr = "[fd00::7]:9000".parse().unwrap();
    let a = test.agent("node-a", &holdings, Some(peer));
    assert_eq!(a.fixed_peer_address().await, Some(peer));
    test.wait(&digest(1), &[("node-a", peer)]).await;
    a.stop().await;
}

#[tokio::test]
async fn a_client_stopped_before_its_first_stream_fixes_no_peer_address() {
    let test = Test::start(&[]).await;
    // Nothing listens on port 1: no stream opens.
    let config = Config {
        host: "127.0.0.1".to_owned(),
        port: 1,
        peer: None,
    };
    let a = Client::spawn(
        config,
        credentials(&test.cluster, &test.dir, "node-a"),
        Arc::new(Holdings::default()),
    );
    let fixed = a.fixed_peer_address();
    a.stop().await;
    let fixed = tokio::time::timeout(Duration::from_secs(5), fixed).await;
    assert_eq!(fixed.unwrap(), None);
}

#[tokio::test]
async fn a_load_balancer_answered_by_a_reflector_outside_the_members_is_not_trusted() {
    // The reflector behind the load balancer, cp-2, lists only cp-1.
    let test = Test::start(&["cp-1"]).await;
    let holdings = Arc::new(Holdings::default());
    holdings.add(digest(1));
    let a = test.agent("node-a", &holdings, None);
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(test.lookups(&digest(1)).await, [vec![], vec![]]);
    assert!(matches!(
        a.lookup(&digest(1)).await,
        Err(LookupError::NoMember)
    ));
    a.stop().await;
}

#[tokio::test]
async fn a_stopped_member_is_streamed_to_again_once_it_is_back() {
    let mut test = Test::start(&[]).await;
    let holdings = Arc::new(Holdings::default());
    holdings.add(digest(1));
    let a = test.agent("node-a", &holdings, None);
    let peer = SocketAddr::from(([127, 0, 0, 1], PEER_PORT));
    test.wait(&digest(1), &[("node-a", peer)]).await;
    // cp-1 stops: lookups go to cp-2, and changes reach it.
    test.reflectors.remove(0).stop().await;
    let connected = "speculaire_reflector_connected{member=\"cp-1\"}";
    let deadline = Instant::now() + Duration::from_secs(5);
    while test.metric(connected).as_deref() != Some("0") {
        assert!(Instant::now() < deadline);
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    holdings.add(digest(2));
    for _ in 0..10 {
        a.lookup(&digest(2)).await.unwrap();
    }
    // cp-1 is back on its address: the stream opens again within D33's first window, with a snapshot.
    let listener = TcpListener::bind(test.members[0].address).await.unwrap();
    let credentials = credentials(&test.cluster, &test.dir, "cp-1");
    let back =
        Reflector::spawn(listener, &credentials, Settings::new(test.members.clone())).unwrap();
    test.reflectors.insert(0, back);
    let deadline = Instant::now() + Duration::from_secs(20);
    while test.metric(connected).as_deref() != Some("1") {
        assert!(Instant::now() < deadline, "cp-1 not streamed to again");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    test.wait(&digest(2), &[("node-a", peer)]).await;
    let reconnects = "speculaire_reflector_reconnects_total{member=\"cp-1\"}";
    assert_ne!(test.metric(reconnects).as_deref(), Some("0"));
    a.stop().await;
}

#[tokio::test]
async fn a_member_the_load_balancer_no_longer_lists_is_no_longer_streamed_to() {
    let mut test = Test::start(&[]).await;
    let holdings = Arc::new(Holdings::default());
    holdings.add(digest(1));
    let a = test.agent("node-a", &holdings, None);
    let peer = SocketAddr::from(([127, 0, 0, 1], PEER_PORT));
    test.wait(&digest(1), &[("node-a", peer)]).await;
    // Past 5 s, the end of the stream to cp-2 is a drop, which asks `Members` again (D98).
    tokio::time::sleep(Duration::from_secs(6)).await;
    test.reflectors.remove(1).stop().await;
    let listener = TcpListener::bind(test.members[1].address).await.unwrap();
    let credentials = credentials(&test.cluster, &test.dir, "cp-2");
    let alone = Settings::new(vec![test.members[1].clone()]);
    test.reflectors
        .push(Reflector::spawn(listener, &credentials, alone).unwrap());
    let holder = vec![("node-a".to_owned(), peer.to_string())];
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let lookups = test.lookups(&digest(1)).await;
        if lookups == [vec![], holder.clone()] {
            break;
        }
        assert!(Instant::now() < deadline, "{lookups:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    a.stop().await;
}
