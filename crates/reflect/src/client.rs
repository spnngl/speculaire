//! The agent's side of the reflector API (D2, D33, D36, D98, D105): it learns the members through the load balancer,
//! keeps one connection to each that announces what the node holds, asks the members it is connected to where a
//! digest is, and hands over what they push (D184).

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use futures_util::FutureExt as _;
use futures_util::future::{self, BoxFuture};
pub use holdings::{Holdings, Source};
use rustls::ClientConfig;
use speculaire_oci::reference::Digest;
use speculaire_pki::node::{Credentials, node_subject};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::frame::{self, FrameError, Reader};
use crate::message::Request;
use crate::metrics::LookupSeries;
use crate::proto::{self, reflector_message};
use crate::push::Push;
use crate::{Key, Member, connect};

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

/// How many lookups may wait for a connection's writer.
const QUEUE: usize = 16;

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

/// What a member pushed (D184).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pushed {
    /// The member's node.
    pub member: String,
    /// What it pushed.
    pub push: Push,
}

/// Why a [`Client::lookup`] has no answer.
#[derive(Debug, thiserror::Error)]
pub enum LookupError {
    /// No stream to a member is up.
    #[error("no reflector is connected")]
    NoMember,
    /// Every member asked failed.
    #[error("the reflectors did not answer: {0}")]
    Call(#[from] CallError),
}

/// Why a request to a reflector has no answer.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    /// The connection ended first.
    #[error("the connection to the reflector ended")]
    Closed,
    /// The reflector took too long, or stayed silent.
    #[error("the reflector did not answer in time")]
    Timeout,
    /// A frame could not be read or written.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The reflector ended the connection, and said why.
    #[error("the reflector refused the connection, {}: {message}", reason.as_str_name())]
    Refused {
        /// Its reason.
        reason: proto::Reason,
        /// Its explanation.
        message: String,
    },
}

impl From<proto::Refused> for CallError {
    fn from(refused: proto::Refused) -> Self {
        Self::Refused {
            reason: refused.reason(),
            message: refused.message,
        }
    }
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
    /// Where the streams hand over what members push.
    pushes: mpsc::Sender<Pushed>,
    /// The lookup queue of each member whose connection is up, by node.
    links: Mutex<HashMap<String, mpsc::Sender<Ask>>>,
    /// The peer address, fixed by the first stream unless set (D36): `None` until then, and never changed after.
    peer: watch::Sender<Option<SocketAddr>>,
    /// When the latest stream came up: `None` before the first.
    last_up: watch::Sender<Option<tokio::time::Instant>>,
    /// Woken when a stream drops, to ask for the members again (D2).
    dropped: tokio::sync::Notify,
    series: LookupSeries,
}

impl Client {
    /// Starts asking for the members, and announces `holdings` to each, as this node per `credentials`. What a member
    /// pushes goes to `pushes`, whose receiver the agent reads at once: a full channel holds the member's stream, its
    /// lookups' answers included, and a closed one drops what follows.
    #[must_use]
    pub fn spawn(
        config: Config,
        credentials: Arc<Credentials>,
        holdings: Arc<Holdings>,
        pushes: mpsc::Sender<Pushed>,
    ) -> Self {
        let peer = watch::Sender::new(config.peer);
        let shared = Arc::new(Shared {
            config,
            credentials,
            holdings,
            pushes,
            links: Mutex::default(),
            peer,
            last_up: watch::Sender::new(None),
            dropped: tokio::sync::Notify::new(),
            series: LookupSeries::new(),
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

    /// When the latest stream came up, `None` before the first: from then on a lookup asks a member, which may have
    /// just restarted and not heard from every agent yet (D126, D134).
    #[must_use]
    pub fn last_up(&self) -> watch::Receiver<Option<tokio::time::Instant>> {
        self.shared.last_up.subscribe()
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
        let series = &self.0.series;
        match &peers {
            Ok(found) if found.is_empty() => &series.miss,
            Ok(_) => &series.hit,
            Err(LookupError::Call(_)) => &series.error,
            Err(LookupError::NoMember) => &series.no_reflector,
        }
        .record(start.elapsed());
        peers
    }

    async fn ask(&self, digest: &Digest) -> Result<Vec<Peer>, LookupError> {
        let mut queues: Vec<mpsc::Sender<Ask>> = self.0.links().values().cloned().collect();
        fastrand::shuffle(&mut queues);
        let mut queues = queues.into_iter();
        let first = queues.next().ok_or(LookupError::NoMember)?;
        let key = Key::from(digest);
        Ok(hedged(ask(first, key), queues.next().map(|q| ask(q, key))).await?)
    }
}

impl Shared {
    fn links(&self) -> MutexGuard<'_, HashMap<String, mpsc::Sender<Ask>>> {
        self.links.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A lookup waiting for a connection's writer, which numbers it, and its answer.
#[derive(Debug)]
struct Ask {
    digest: Key,
    answer: oneshot::Sender<Vec<Peer>>,
}

/// The answer of `first`, or, when it takes longer than [`HEDGE`], the first answer of `first` and `second`.
async fn hedged<T: Send>(
    first: BoxFuture<'static, Result<T, CallError>>,
    second: Option<BoxFuture<'static, Result<T, CallError>>>,
) -> Result<T, CallError> {
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

/// A `Lookup` of `digest` through the connection whose writer reads `queue`.
fn ask(queue: mpsc::Sender<Ask>, digest: Key) -> BoxFuture<'static, Result<Vec<Peer>, CallError>> {
    async move {
        let (answer, answered) = oneshot::channel();
        let call = async {
            queue
                .send(Ask { digest, answer })
                .await
                .map_err(|_| CallError::Closed)?;
            answered.await.map_err(|_| CallError::Closed)
        };
        tokio::time::timeout(CALL, call)
            .await
            .map_err(|_| CallError::Timeout)?
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
    Call(#[from] CallError),
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
    let Link { mut tls, node, .. } = dial(address, shared.credentials.client_any()).await?;
    let response = tokio::time::timeout(CALL, ask_once(&mut tls))
        .await
        .map_err(|_| CallError::Timeout)??;
    let members = members(response);
    if members.iter().any(|member| member.node == node) {
        Ok(members)
    } else {
        Err(MembersError::Stranger(node))
    }
}

/// The one request of a connection: `Members`, then the TLS close that tells the reflector the connection is done.
async fn ask_once(tls: &mut TlsStream<TcpStream>) -> Result<proto::MembersResponse, CallError> {
    frame::write(
        tls,
        &proto::AgentMessage::from(Request::Members),
        frame::LIMIT,
    )
    .await?;
    let mut reader = Reader::<proto::ReflectorMessage>::new(frame::LIMIT);
    loop {
        match reader.next(tls).await?.and_then(|message| message.message) {
            Some(reflector_message::Message::Members(response)) => {
                tls.shutdown().await.map_err(FrameError::from)?;
                return Ok(response);
            }
            Some(reflector_message::Message::Refused(refused)) => return Err(refused.into()),
            Some(_) => {}
            None => return Err(CallError::Closed),
        }
    }
}

/// One connection to a reflector.
#[derive(Debug)]
struct Link {
    tls: TlsStream<TcpStream>,
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
}

/// A TLS connection to `address`, with its local side and the node the reflector's certificate names: the caller
/// needs both, so it dials each connection itself (D98).
async fn dial(address: SocketAddr, tls: ClientConfig) -> Result<Link, DialError> {
    let tls = tokio::time::timeout(DIAL, connect(address, tls))
        .await
        .map_err(|_| DialError::Timeout)??;
    let local = tls.get_ref().0.local_addr()?;
    let node = match tls.get_ref().1.peer_certificates() {
        Some([certificate, ..]) => {
            node_subject(certificate).map_err(|err| DialError::Node(err.to_string()))?
        }
        _ => return Err(DialError::Node("no certificate".to_owned())),
    };
    Ok(Link { tls, local, node })
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
            id: 0,
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
        let after = |delay: u64,
                     answer: Result<u32, CallError>|
         -> BoxFuture<'static, Result<u32, CallError>> {
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
        let answer = hedged(after(100, Ok(1)), Some(after(5, Err(CallError::Closed))));
        assert_eq!(
            (answer.await.unwrap(), start.elapsed()),
            (1, Duration::from_millis(100))
        );
        // A first that fails fast: the second at once.
        let start = tokio::time::Instant::now();
        let answer = hedged(after(1, Err(CallError::Closed)), Some(after(5, Ok(2)))).await;
        assert_eq!(
            (answer.unwrap(), start.elapsed()),
            (2, Duration::from_millis(6))
        );
    }
}
