//! The reflector API over mutual TLS with node identities (D2, D16, D105): accept, handshake, then serve each
//! connection's frames in order.

use std::io;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use speculaire_pki::node::{Credentials, node_subject};
use tokio::io::AsyncWriteExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument as _, Span, debug, debug_span, field, info, warn};

use crate::frame::{self, FrameError, Reader};
use crate::index::Index;
use crate::message::{Lookup, Request};
use crate::metrics::{self, Reason, ServerSeries};
use crate::proto::{self, reflector_message};
use crate::session::{Rejection, Reply, Session};

/// The protocol version this reflector speaks (D97).
pub const PROTOCOL_VERSION: u32 = 1;

/// How many holders a `Lookup` returns at most (D97).
pub const LOOKUP_PEERS: usize = 8;

/// How many digests an agent puts in one `Snapshot` chunk at most (D97, D104): about 1.8 KB of sha256 text, 3.4 KB of
/// sha512. The reflector holds the frame it reads, so a small chunk keeps its memory per agent small.
pub const SNAPSHOT_CHUNK: usize = 25;

/// How long a stopping reflector gives a connection to take its `Refused` and the TLS close.
const FAREWELL: Duration = Duration::from_secs(1);

/// A reflector, as `reflector.members` lists it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Member {
    /// The node name its kubelet certificate holds.
    pub node: String,
    /// Where its reflector API listens.
    pub address: SocketAddr,
}

/// What a reflector serves, and what it refuses.
#[derive(Clone, Debug)]
pub struct Settings {
    /// What `Members` answers.
    pub members: Vec<Member>,
    /// The protocol versions an agent may speak: this one and the previous (D2).
    pub versions: RangeInclusive<u32>,
    /// What one agent may make the reflector hold.
    pub limits: Limits,
}

impl Settings {
    /// The settings of a reflector of `members`, at this protocol version and the default limits.
    #[must_use]
    pub fn new(members: Vec<Member>) -> Self {
        Self {
            members,
            versions: PROTOCOL_VERSION.saturating_sub(1).max(1)..=PROTOCOL_VERSION,
            limits: Limits::default(),
        }
    }
}

/// What one agent may make the reflector hold (D97).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The time a TLS handshake may take.
    pub handshake: Duration,
    /// The size of a message.
    pub message: usize,
    /// The digests one node may announce.
    pub digests: usize,
}

impl Default for Limits {
    /// 5 s, 4 MiB and 100,000 digests (D97).
    fn default() -> Self {
        Self {
            handshake: Duration::from_secs(5),
            message: frame::LIMIT,
            digests: 100_000,
        }
    }
}

/// A running reflector.
#[derive(Debug)]
pub struct Reflector {
    address: SocketAddr,
    index: Arc<Index>,
    stop: CancellationToken,
    accept: JoinHandle<()>,
    /// Ends once every connection has dropped its [`Api`], whose sender it holds.
    ended: mpsc::Receiver<()>,
}

impl Reflector {
    /// Serves the reflector API on `listener`, as this node per `credentials`.
    ///
    /// # Errors
    ///
    /// When the listener has no local address.
    pub fn spawn(
        listener: TcpListener,
        credentials: &Arc<Credentials>,
        settings: Settings,
    ) -> io::Result<Self> {
        let address = listener.local_addr()?;
        let mut tls = credentials.server();
        tls.alpn_protocols = vec![frame::ALPN.to_vec()];
        let stop = CancellationToken::new();
        let index = Arc::default();
        let (held, ended) = mpsc::channel(1);
        let api = Api {
            index: Arc::clone(&index),
            members: proto::MembersResponse {
                members: settings
                    .members
                    .iter()
                    .map(|member| proto::Member {
                        node: member.node.clone(),
                        address: member.address.to_string(),
                    })
                    .collect(),
            },
            settings: Arc::new(settings),
            series: ServerSeries::new(),
            stop: stop.clone(),
            held,
        };
        let accept = tokio::spawn(accept(
            listener,
            TlsAcceptor::from(Arc::new(tls)),
            Arc::new(api),
        ));
        info!(%address, "reflector open");
        Ok(Self {
            address,
            index,
            stop,
            accept,
            ended,
        })
    }

    /// Where the reflector listens.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Refuses every connection as stopping and waits for each to end (D39, D103): agents then announce to the
    /// other members.
    pub async fn stop(mut self) {
        self.stop.cancel();
        self.index.close();
        if let Err(err) = self.accept.await {
            warn!(error = %err, "reflector task ended abnormally");
        }
        // Nothing is ever sent: `recv` returns `None` once the last sender drops.
        while self.ended.recv().await.is_some() {}
    }
}

/// What every connection serves from.
#[derive(Debug)]
struct Api {
    index: Arc<Index>,
    settings: Arc<Settings>,
    /// What `Members` answers, built once from the settings.
    members: proto::MembersResponse,
    series: ServerSeries,
    stop: CancellationToken,
    #[expect(
        dead_code,
        reason = "never sends: dropping the last `Api` ends `Reflector::stop`'s wait"
    )]
    held: mpsc::Sender<()>,
}

/// Accepts connections, each handshaking and served in its own task, so that a slow one delays no other.
async fn accept(listener: TcpListener, acceptor: TlsAcceptor, api: Arc<Api>) {
    loop {
        let (tcp, address) = tokio::select! {
            () = api.stop.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(err) => {
                    // Out of file descriptors, most likely: let some close.
                    warn!(error = %err, "reflector accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        let accepted = Instant::now();
        // The node is known once the handshake is done.
        let span = debug_span!("reflector connection", peer = %address, node = field::Empty);
        tokio::spawn(
            serve(acceptor.clone(), tcp, address, accepted, Arc::clone(&api)).instrument(span),
        );
    }
}

/// Handshakes, then answers the agent's frames until the connection ends.
async fn serve(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    address: SocketAddr,
    accepted: Instant,
    api: Arc<Api>,
) {
    let handshake = tokio::select! {
        () = api.stop.cancelled() => return,
        handshake = tokio::time::timeout(api.settings.limits.handshake, handshake(&acceptor, tcp)) => handshake,
    };
    let (mut tls, node) = match handshake {
        Ok(Ok(handshake)) => handshake,
        Ok(Err(err)) => return debug!(%address, error = %err, "reflector handshake refused"),
        Err(_) => return debug!(%address, "reflector handshake timed out"),
    };
    Span::current().record("node", &*node);
    let mut reader = Reader::new(api.settings.limits.message);
    let mut session = Session::new(
        Arc::clone(&api.index),
        Arc::clone(&api.settings),
        Arc::clone(&node),
    );
    let refusal = loop {
        let read = tokio::select! {
            () = api.stop.cancelled() => break stopping(),
            read = tokio::time::timeout(frame::SILENCE, reader.next(&mut tls)) => read,
        };
        let message = match read {
            Ok(Ok(Some(message))) => message,
            Ok(Ok(None)) => return debug!(%node, "the agent closed its reflector connection"),
            Ok(Err(err @ FrameError::Size { .. })) => break reject(&node, Reason::Size, &err),
            Ok(Err(err @ FrameError::Decode(_))) => break reject(&node, Reason::Malformed, &err),
            Ok(Err(FrameError::Io(err))) => {
                return debug!(%node, error = %err, "reflector connection failed");
            }
            Err(_) => return debug!(%node, "reflector connection silent; closing it"),
        };
        let reply = match answer(&api, &mut session, message, accepted) {
            Ok(Some(reply)) => reply,
            Ok(None) => continue,
            Err(refusal) => break refusal,
        };
        let reply = proto::ReflectorMessage {
            message: Some(reply),
        };
        // Stopping inside a frame leaves the agent no frame to read the refusal from: the connection just closes.
        let written = tokio::select! {
            () = api.stop.cancelled() => return,
            written = tokio::time::timeout(frame::SILENCE, frame::write(&mut tls, &reply, frame::LIMIT)) => written,
        };
        match written {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return debug!(%node, error = %err, "reflector connection failed"),
            Err(_) => return debug!(%node, "reflector connection stalled; closing it"),
        }
    };
    // The session withdraws the announcement before the agent learns why.
    drop(session);
    let refused = proto::ReflectorMessage {
        message: Some(reflector_message::Message::Refused(refusal)),
    };
    let farewell = async {
        frame::write(&mut tls, &refused, frame::LIMIT).await?;
        tls.shutdown().await.map_err(FrameError::from)
    };
    if let Ok(Err(err)) = tokio::time::timeout(FAREWELL, farewell).await {
        debug!(%node, error = %err, "cannot tell the agent why the reflector ends its connection");
    }
}

async fn handshake(
    acceptor: &TlsAcceptor,
    tcp: TcpStream,
) -> io::Result<(TlsStream<TcpStream>, Arc<str>)> {
    // A lookup's answer is small: Nagle's algorithm would hold it for the client's delayed ACK.
    tcp.set_nodelay(true)?;
    let tls = acceptor.accept(tcp).await?;
    // The verifier checked the certificate's subject: reading it again only gets the name.
    let node = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .ok_or_else(|| io::Error::other("no peer certificate"))
        .and_then(|cert| node_subject(cert).map_err(io::Error::other))?;
    Ok((tls, Arc::from(node)))
}

/// The reply to one message, if it needs one; a refusal ends the connection.
fn answer(
    api: &Api,
    session: &mut Session,
    message: proto::AgentMessage,
    accepted: Instant,
) -> Result<Option<reflector_message::Message>, proto::Refused> {
    let request =
        Request::try_from(message).map_err(|err| reject(session.node(), err.reason(), &err))?;
    Ok(match request {
        Request::Announcement(announcement) => match session.handle(announcement) {
            Ok(None) => None,
            Ok(Some(Reply::Synced)) => {
                api.series.resync.record(accepted.elapsed());
                None
            }
            Ok(Some(Reply::Resync)) => Some(reflector_message::Message::Resync(proto::Resync {})),
            Err(Rejection::Superseded) => {
                return Err(refused(
                    proto::Reason::Superseded,
                    "a later connection of this node took its announcement over",
                ));
            }
            Err(Rejection::Refused(reason, why)) => {
                return Err(reject(session.node(), reason, &why));
            }
        },
        Request::Lookup(lookup) => Some(reflector_message::Message::Lookup(self::lookup(
            api,
            session.node(),
            &lookup,
        ))),
        Request::Members => Some(reflector_message::Message::Members(api.members.clone())),
        Request::Ping => Some(reflector_message::Message::Pong(proto::Pong {})),
    })
}

/// Up to [`LOOKUP_PEERS`] holders of the digest other than `node`.
fn lookup(api: &Api, node: &str, lookup: &Lookup) -> proto::LookupResponse {
    let start = Instant::now();
    let peers = api
        .index
        .lookup(&lookup.digest, node, LOOKUP_PEERS)
        .into_iter()
        .map(|holder| proto::Peer {
            node: holder.node.to_string(),
            address: holder.peer.to_string(),
        })
        .collect();
    api.series.lookup.record(start.elapsed());
    proto::LookupResponse {
        peers,
        id: lookup.id,
    }
}

fn stopping() -> proto::Refused {
    refused(proto::Reason::Stopping, "the reflector is stopping")
}

fn refused(reason: proto::Reason, message: &str) -> proto::Refused {
    proto::Refused {
        reason: reason.into(),
        message: message.to_owned(),
    }
}

/// Counts and logs a refused agent; an agent refused again reconnects at most once a minute (D33).
fn reject(node: &str, reason: Reason, why: &dyn std::fmt::Display) -> proto::Refused {
    metrics::rejected(reason);
    warn!(
        node,
        reason = reason.label(),
        why = %why,
        "announce stream refused"
    );
    let code = match reason {
        Reason::Identity => proto::Reason::Identity,
        Reason::Version => proto::Reason::Version,
        Reason::Size => proto::Reason::Size,
        Reason::Digests => proto::Reason::Digests,
        Reason::Address => proto::Reason::Address,
        Reason::Malformed => proto::Reason::Malformed,
    };
    refused(code, &format!("connection of node {node:?} refused: {why}"))
}
