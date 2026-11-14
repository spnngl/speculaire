//! The agent's side of the reflector API (D2, D33, D36, D98): it learns the members through the load balancer, keeps
//! one `Announce` stream to each, and asks the members it streams to where a digest is.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures_util::FutureExt as _;
use futures_util::future::{self, BoxFuture};
pub use holdings::Holdings;
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use speculaire_oci::reference::Digest;
use speculaire_pki::node::{Credentials, node_subject};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tonic::Status;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, info, warn};

use crate::Member;
use crate::metrics::CLIENT_LOOKUP;
use crate::proto::reflector_client::ReflectorClient;
use crate::proto::{self};

mod announce;
mod backoff;
mod holdings;

/// The port of the peer API when `peer.address` is `"auto"` (D36, D56).
pub const PEER_PORT: u16 = 7481;

/// How long a `Lookup` waits for its first member before it asks a second too (D98).
pub const HEDGE: Duration = Duration::from_millis(20);

/// How often the agent asks the load balancer for the members (D2).
pub const REFRESH: Duration = Duration::from_secs(60);

/// The time a connection and its TLS handshake may take, as on the reflector's side (D97).
const DIAL: Duration = Duration::from_secs(5);

/// The time a `Members` or `Lookup` call may take.
const CALL: Duration = Duration::from_secs(5);

/// How long the load balancer or a member may fail before the failures are logged at `warn`: until then, a restart
/// or a rollout explains them, and they go at `info`.
const PATIENCE: Duration = Duration::from_secs(60);

/// Where the agent finds the reflectors, and what it announces.
#[derive(Clone, Debug)]
pub struct Config {
    /// The host of `reflector.url`, the load balancer: a name, or an IP address without brackets.
    pub host: String,
    /// The port of `reflector.url`.
    pub port: u16,
    /// `peer.address` when set; otherwise the local IP of the first stream, on [`PEER_PORT`] (D36, D56).
    pub peer: Option<SocketAddr>,
}

/// An agent that announced a digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peer {
    /// Its node, which its certificate must name (D16).
    pub node: String,
    /// Where its peer API listens.
    pub address: SocketAddr,
}

/// Why a [`Client::lookup`] has no answer.
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    /// No stream to a member is up.
    #[error("no reflector is connected")]
    NoMember,
    /// Every member asked failed.
    #[error("the reflectors did not answer: {0}")]
    Call(#[from] Status),
}

/// The agent's reflector client: running until [`Client::stop`].
#[derive(Debug)]
pub struct Client {
    shared: Arc<Shared>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

/// What the client's tasks share.
#[derive(Debug)]
struct Shared {
    config: Config,
    credentials: Arc<Credentials>,
    holdings: Arc<Holdings>,
    /// The channel of each member whose stream is up, by node.
    links: Mutex<HashMap<String, Channel>>,
    /// The peer address, fixed by the first stream unless set (D36): `None` until then, and never changed after.
    peer: watch::Sender<Option<SocketAddr>>,
    /// Woken when a stream drops, to ask for the members again (D2).
    dropped: tokio::sync::Notify,
}

impl Client {
    /// Starts asking for the members, and announces `holdings` to each, as this node per `credentials`.
    #[must_use]
    pub fn spawn(config: Config, credentials: Arc<Credentials>, holdings: Arc<Holdings>) -> Self {
        let peer = watch::Sender::new(config.peer);
        let shared = Arc::new(Shared {
            config,
            credentials,
            holdings,
            links: Mutex::default(),
            peer,
            dropped: tokio::sync::Notify::new(),
        });
        let stop = CancellationToken::new();
        let task = tokio::spawn(supervise(Arc::clone(&shared), stop.clone()));
        Self { shared, stop, task }
    }

    /// The address the agent announces as its peer API, once fixed: at once when set, else by the first stream (D36);
    /// `None` when the client stops first. The peer API listens only then.
    pub fn fixed_peer_address(&self) -> impl Future<Output = Option<SocketAddr>> + Send + 'static {
        let mut peer = self.shared.peer.subscribe();
        async move {
            peer.wait_for(Option::is_some)
                .await
                .ok()
                .and_then(|peer| *peer)
        }
    }

    /// Up to `LOOKUP_PEERS` agents that announced `digest`, from a member the agent streams to, hedged to a second
    /// after [`HEDGE`] (D2, D98).
    ///
    /// # Errors
    ///
    /// When no stream is up, or every member asked fails.
    pub async fn lookup(&self, digest: &Digest) -> Result<Vec<Peer>, LookupError> {
        self.lookups().lookup(digest).await
    }

    /// A handle that looks digests up for as long as the client runs; after [`Client::stop`] it finds no member.
    #[must_use]
    pub fn lookups(&self) -> Lookups {
        Lookups(Arc::clone(&self.shared))
    }

    /// Ends every stream, so that each member withdraws what the node announced (D39, step 3).
    pub async fn stop(self) {
        self.stop.cancel();
        if let Err(err) = self.task.await {
            warn!(error = %err, "reflector client task ended abnormally");
        }
    }
}

/// Looks digests up through a [`Client`]'s streams.
#[derive(Clone, Debug)]
pub struct Lookups(Arc<Shared>);

impl Lookups {
    /// As [`Client::lookup`]. The latency goes to `speculaire_lookup_seconds` with `result` `hit`, `miss`, `error`, or
    /// `no_reflector` when no stream is up and nobody was asked (D103).
    ///
    /// # Errors
    ///
    /// When no stream is up, or every member asked fails.
    pub async fn lookup(&self, digest: &Digest) -> Result<Vec<Peer>, LookupError> {
        let start = Instant::now();
        let peers = self.ask(digest).await;
        let result = match &peers {
            Ok(found) if found.is_empty() => "miss",
            Ok(_) => "hit",
            Err(LookupError::Call(_)) => "error",
            Err(LookupError::NoMember) => "no_reflector",
        };
        ::metrics::histogram!(CLIENT_LOOKUP, "result" => result)
            .record(start.elapsed().as_secs_f64());
        peers
    }

    async fn ask(&self, digest: &Digest) -> Result<Vec<Peer>, LookupError> {
        let mut channels: Vec<Channel> = self.0.links().values().cloned().collect();
        fastrand::shuffle(&mut channels);
        let mut channels = channels.into_iter();
        let first = channels.next().ok_or(LookupError::NoMember)?;
        Ok(hedged(ask(first, digest), channels.next().map(|c| ask(c, digest))).await?)
    }
}

impl Shared {
    fn links(&self) -> MutexGuard<'_, HashMap<String, Channel>> {
        self.links.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The answer of `first`, or, when it takes longer than [`HEDGE`], the first answer of `first` and `second`.
async fn hedged<T: Send>(
    first: BoxFuture<'static, Result<T, Status>>,
    second: Option<BoxFuture<'static, Result<T, Status>>>,
) -> Result<T, Status> {
    let Some(second) = second else {
        return first.await;
    };
    let mut first = first;
    match tokio::time::timeout(HEDGE, &mut first).await {
        Ok(Ok(answer)) => Ok(answer),
        Ok(Err(err)) => {
            debug!(error = %err, "lookup failed; asking another reflector");
            second.await
        }
        Err(_) => future::select_ok([first, second])
            .await
            .map(|(answer, _)| answer),
    }
}

/// A `Lookup` of `digest` on `channel`.
fn ask(channel: Channel, digest: &Digest) -> BoxFuture<'static, Result<Vec<Peer>, Status>> {
    let request = proto::LookupRequest {
        digest: digest.to_string(),
    };
    async move {
        let response = tokio::time::timeout(CALL, ReflectorClient::new(channel).lookup(request))
            .await
            .map_err(|_| Status::deadline_exceeded("the reflector did not answer the lookup"))??;
        Ok(peers(response.into_inner()))
    }
    .boxed()
}

/// The peers of a `Lookup` answer, without those whose node is empty or address is not `ip:port`.
#[must_use]
pub fn peers(response: proto::LookupResponse) -> Vec<Peer> {
    response
        .peers
        .into_iter()
        .filter_map(|peer| {
            let address = peer.address.parse().ok()?;
            (!peer.node.is_empty()).then_some(Peer {
                node: peer.node,
                address,
            })
        })
        .collect()
}

/// The members of a `Members` answer, without those whose node is empty or address is not `ip:port`.
#[must_use]
pub fn members(response: proto::MembersResponse) -> Vec<Member> {
    response
        .members
        .into_iter()
        .filter_map(|member| {
            let address = member.address.parse().ok()?;
            (!member.node.is_empty()).then_some(Member {
                node: member.node,
                address,
            })
        })
        .collect()
}

/// Since when the load balancer, or a member, has failed without a success in between (D98).
#[derive(Debug, Default)]
struct Outage(Option<tokio::time::Instant>);

impl Outage {
    /// Records a failure, which starts the outage unless one runs; whether the outage has lasted long enough to log
    /// at `warn`.
    fn failed(&mut self) -> bool {
        self.0
            .get_or_insert_with(tokio::time::Instant::now)
            .elapsed()
            >= PATIENCE
    }

    /// Ends the outage: the next failure starts another.
    const fn ended(&mut self) {
        self.0 = None;
    }
}

/// One stream per member, as the load balancer lists them every [`REFRESH`] and after a stream drops; the last list
/// stays while the load balancer fails (D2).
async fn supervise(shared: Arc<Shared>, stop: CancellationToken) {
    let mut streams: HashMap<Member, (CancellationToken, JoinHandle<()>)> = HashMap::new();
    let mut backoff = backoff::Backoff::new(fastrand::u64(..));
    let mut outage = Outage::default();
    loop {
        // A load balancer that hangs holds the call for up to `DIAL` and `CALL`: stopping does not wait for it.
        let asked = tokio::select! {
            () = stop.cancelled() => break,
            asked = ask_members(&shared) => asked,
        };
        let wait = match asked {
            Ok(members) => {
                backoff.succeeded();
                outage.ended();
                for (member, (token, task)) in
                    streams.extract_if(|member, _| !members.contains(member))
                {
                    info!(node = %member.node, address = %member.address, "reflector left the members");
                    token.cancel();
                    let _ = task.await;
                }
                for member in members {
                    streams.entry(member).or_insert_with_key(|member| {
                        let token = stop.child_token();
                        let task = tokio::spawn(announce::run(
                            member.clone(),
                            Arc::clone(&shared),
                            token.clone(),
                        ));
                        (token, task)
                    });
                }
                REFRESH
            }
            Err(err) => {
                let wait = backoff.failed();
                if outage.failed() {
                    warn!(error = %err, retry = ?wait, "the reflectors' load balancer fails; the last list of members stays");
                } else {
                    info!(error = %err, retry = ?wait, "cannot ask the reflectors' load balancer for the members");
                }
                wait
            }
        };
        tokio::select! {
            () = stop.cancelled() => break,
            () = tokio::time::sleep(wait) => {}
            () = shared.dropped.notified() => {}
        }
    }
    for (_, (_, task)) in streams {
        let _ = task.await;
    }
}

/// Why the load balancer gave no members.
#[derive(Debug, thiserror::Error)]
enum MembersError {
    #[error("cannot resolve {0}: {1}")]
    Resolve(String, io::Error),
    #[error("{0} resolves to no address")]
    NoAddress(String),
    #[error(transparent)]
    Dial(#[from] DialError),
    #[error("Members failed: {0}")]
    Call(#[from] Status),
    #[error("the reflector that answered, {0:?}, is not in the members it returned")]
    Stranger(String),
}

/// The members, from the first address of the load balancer that answers, checked against the node that answered.
async fn ask_members(shared: &Shared) -> Result<Vec<Member>, MembersError> {
    let Config { host, port, .. } = &shared.config;
    let addresses = tokio::net::lookup_host((host.as_str(), *port))
        .await
        .map_err(|err| MembersError::Resolve(host.clone(), err))?;
    let mut last = MembersError::NoAddress(host.clone());
    for address in addresses {
        match members_at(address, shared).await {
            Ok(members) => return Ok(members),
            Err(err) => last = err,
        }
    }
    Err(last)
}

async fn members_at(address: SocketAddr, shared: &Shared) -> Result<Vec<Member>, MembersError> {
    let (channel, link) = dial(address, shared.credentials.client_any()).await?;
    let response = tokio::time::timeout(
        CALL,
        ReflectorClient::new(channel).members(proto::MembersRequest {}),
    )
    .await
    .map_err(|_| Status::deadline_exceeded("the reflector did not answer Members"))??;
    let members = members(response.into_inner());
    if members.iter().any(|member| member.node == link.node) {
        Ok(members)
    } else {
        Err(MembersError::Stranger(link.node))
    }
}

/// One connection to a reflector.
#[derive(Debug)]
struct Link {
    /// The local side of the connection, whose IP is the default peer address (D36).
    local: SocketAddr,
    /// The node the reflector's certificate names.
    node: String,
}

/// Why a connection to a reflector failed.
#[derive(Debug, thiserror::Error)]
enum DialError {
    #[error("connecting: {0}")]
    Io(#[from] io::Error),
    #[error("connecting: timed out")]
    Timeout,
    #[error("the reflector's certificate names no node: {0}")]
    Node(String),
    #[error(transparent)]
    Channel(#[from] tonic::transport::Error),
}

/// A channel over one TLS connection to `address`: when the connection ends, its calls fail, and the caller dials
/// again, since it must know the local side and the node of each connection.
async fn dial(address: SocketAddr, mut tls: ClientConfig) -> Result<(Channel, Link), DialError> {
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(tls));
    let (local, stream) = tokio::time::timeout(DIAL, async {
        let tcp = TcpStream::connect(address).await?;
        // A lookup is small: Nagle's algorithm would hold it for the reflector's delayed ACK.
        tcp.set_nodelay(true)?;
        let local = tcp.local_addr()?;
        let stream = connector
            .connect(ServerName::IpAddress(address.ip().into()), tcp)
            .await?;
        Ok::<_, io::Error>((local, stream))
    })
    .await
    .map_err(|_| DialError::Timeout)??;
    let node = match stream.get_ref().1.peer_certificates() {
        Some([certificate, ..]) => {
            node_subject(certificate).map_err(|err| DialError::Node(err.to_string()))?
        }
        _ => return Err(DialError::Node("no certificate".to_owned())),
    };
    let slot = Mutex::new(Some(stream));
    // The URI only names the authority of requests: the connector hands over the connection made above, once.
    let channel = Endpoint::from_shared(format!("http://{address}"))?
        .http2_keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(10))
        .keep_alive_while_idle(true)
        .connect_with_connector(tower::service_fn(move |_| {
            let stream = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
            async move {
                stream.map(TokioIo::new).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotConnected,
                        "the connection to the reflector ended",
                    )
                })
            }
        }))
        .await?;
    Ok((channel, Link { local, node }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers_keep_only_entries_with_a_node_and_an_ip_and_port() {
        let entry = |node: &str, address: &str| (node.to_owned(), address.to_owned());
        let entries = [
            entry("a", "10.0.0.1:7481"),
            entry("", "10.0.0.2:7481"),
            entry("c", "10.0.0.3"),
            entry("d", "node-d:7481"),
            entry("e", "[fd00::5]:7481"),
        ];
        let kept = peers(proto::LookupResponse {
            peers: entries
                .iter()
                .map(|(node, address)| proto::Peer {
                    node: node.clone(),
                    address: address.clone(),
                })
                .collect(),
        });
        let nodes: Vec<&str> = kept.iter().map(|peer| peer.node.as_str()).collect();
        assert_eq!(nodes, ["a", "e"]);
        let kept = members(proto::MembersResponse {
            members: entries
                .iter()
                .map(|(node, address)| proto::Member {
                    node: node.clone(),
                    address: address.clone(),
                })
                .collect(),
        });
        let nodes: Vec<&str> = kept.iter().map(|member| member.node.as_str()).collect();
        assert_eq!(nodes, ["a", "e"]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_outage_is_long_after_sixty_seconds_of_failures_not_sixty_seconds_after_a_success() {
        let mut outage = Outage::default();
        // A success, then the next call a refresh later fails: the outage starts with that failure.
        outage.ended();
        tokio::time::advance(REFRESH + Duration::from_secs(1)).await;
        assert!(!outage.failed());
        tokio::time::advance(PATIENCE.saturating_sub(Duration::from_millis(1))).await;
        assert!(!outage.failed());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(outage.failed());
        // A success ends it.
        outage.ended();
        assert!(!outage.failed());
    }

    #[tokio::test(start_paused = true)]
    async fn a_lookup_is_hedged_after_twenty_milliseconds_and_takes_the_first_answer() {
        let after =
            |delay: u64, answer: Result<u32, Status>| -> BoxFuture<'static, Result<u32, Status>> {
                async move {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    answer
                }
                .boxed()
            };
        let start = tokio::time::Instant::now();
        // A first answer within the hedge: the second is never asked.
        let answer = hedged(after(10, Ok(1)), Some(after(0, Ok(2)))).await;
        assert_eq!(
            (answer.unwrap(), start.elapsed()),
            (1, Duration::from_millis(10))
        );
        // A slow first: the second, asked at 20 ms, answers at 25 ms.
        let start = tokio::time::Instant::now();
        let answer = hedged(after(100, Ok(1)), Some(after(5, Ok(2)))).await;
        assert_eq!(
            (answer.unwrap(), start.elapsed()),
            (2, Duration::from_millis(25))
        );
        // A slow first whose second fails: the first's answer.
        let start = tokio::time::Instant::now();
        let answer = hedged(
            after(100, Ok(1)),
            Some(after(5, Err(Status::unavailable("")))),
        );
        assert_eq!(
            (answer.await.unwrap(), start.elapsed()),
            (1, Duration::from_millis(100))
        );
        // A first that fails fast: the second at once.
        let start = tokio::time::Instant::now();
        let answer = hedged(
            after(1, Err(Status::unavailable(""))),
            Some(after(5, Ok(2))),
        )
        .await;
        assert_eq!(
            (answer.unwrap(), start.elapsed()),
            (2, Duration::from_millis(6))
        );
    }
}
