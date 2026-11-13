//! The reflector API over mutual TLS with node identities (D2, D16): accept, handshake, serve.

use std::io;
use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::stream;
use rustls::ServerConfig;
use speculaire_pki::node::{Credentials, node_subject};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_util::sync::CancellationToken;
use tonic::codegen::BoxStream;
use tonic::transport::server::Connected;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, warn};

use crate::index::Index;
use crate::message::{self, Announcement};
use crate::metrics::{self, Reason};
use crate::proto::reflector_server::{self, ReflectorServer};
use crate::proto::{self, reflector_message};
use crate::session::{Rejection, Reply, Session};

/// The protocol version this reflector speaks (D97).
pub const PROTOCOL_VERSION: u32 = 1;

/// How many holders a `Lookup` returns at most (D97).
pub const LOOKUP_PEERS: usize = 8;

/// How many digests an agent puts in one `Snapshot` chunk at most (D97): about 1.3 MiB of sha512 text, well under
/// [`Limits::message`].
pub const SNAPSHOT_CHUNK: usize = 10_000;

/// A reflector, as `reflector.members` lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
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
            message: 4 * 1024 * 1024,
            digests: 100_000,
        }
    }
}

/// A running reflector.
#[derive(Debug)]
pub struct Reflector {
    address: SocketAddr,
    stop: CancellationToken,
    task: JoinHandle<()>,
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
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let stop = CancellationToken::new();
        let (links, mut incoming) = mpsc::channel(64);
        let limits = settings.limits;
        tokio::spawn(accept(
            listener,
            Arc::new(tls),
            limits.handshake,
            links,
            stop.clone(),
        ));
        let api = Api {
            index: Arc::default(),
            settings: Arc::new(settings),
            stop: stop.clone(),
        };
        let server = tonic::transport::Server::builder()
            .http2_keepalive_interval(Some(Duration::from_secs(30)))
            .http2_keepalive_timeout(Some(Duration::from_secs(10)))
            .add_service(ReflectorServer::new(api).max_decoding_message_size(limits.message));
        let incoming = stream::poll_fn(move |cx| {
            incoming
                .poll_recv(cx)
                .map(|link| link.map(Ok::<_, io::Error>))
        });
        let task = tokio::spawn({
            let stop = stop.clone();
            async move {
                if let Err(err) = server
                    .serve_with_incoming_shutdown(incoming, stop.cancelled_owned())
                    .await
                {
                    warn!(error = %err, "reflector stopped");
                }
            }
        });
        info!(%address, "reflector open");
        Ok(Self {
            address,
            stop,
            task,
        })
    }

    /// Where the reflector listens.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// Ends every stream and stops serving (D39): agents then announce to the other members.
    pub async fn stop(self) {
        self.stop.cancel();
        if let Err(err) = self.task.await {
            warn!(error = %err, "reflector task ended abnormally");
        }
    }
}

/// Accepts connections, each handshaking in its own task so that a slow one delays no other.
async fn accept(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    timeout: Duration,
    links: mpsc::Sender<Link>,
    stop: CancellationToken,
) {
    let acceptor = TlsAcceptor::from(tls);
    loop {
        let (tcp, address) = tokio::select! {
            () = stop.cancelled() => return,
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
        let acceptor = acceptor.clone();
        let links = links.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let link = tokio::select! {
                () = stop.cancelled() => return,
                link = tokio::time::timeout(timeout, handshake(&acceptor, tcp)) => link,
            };
            match link {
                Ok(Ok(link)) => {
                    // The server is gone when the receiver is.
                    let _ = links.send(link).await;
                }
                Ok(Err(err)) => debug!(%address, error = %err, "reflector handshake refused"),
                Err(_) => debug!(%address, "reflector handshake timed out"),
            }
        });
    }
}

async fn handshake(acceptor: &TlsAcceptor, tcp: TcpStream) -> io::Result<Link> {
    let tls = acceptor.accept(tcp).await?;
    // The verifier checked the certificate's subject: reading it again only gets the name.
    let node = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[_]>::first)
        .ok_or_else(|| io::Error::other("no peer certificate"))
        .and_then(|cert| node_subject(cert).map_err(io::Error::other))?;
    Ok(Link {
        tls,
        peer: Peer {
            node: Arc::from(node),
        },
    })
}

/// A connection after its handshake, with the node it proved to be.
struct Link {
    tls: TlsStream<TcpStream>,
    peer: Peer,
}

/// The node at the other end of a connection; tonic puts it in every request's extensions.
#[derive(Clone, Debug)]
struct Peer {
    node: Arc<str>,
}

impl Connected for Link {
    type ConnectInfo = Peer;

    fn connect_info(&self) -> Peer {
        self.peer.clone()
    }
}

impl AsyncRead for Link {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls).poll_read(cx, buf)
    }
}

impl AsyncWrite for Link {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.tls).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.tls).poll_shutdown(cx)
    }
}

struct Api {
    index: Arc<Index>,
    settings: Arc<Settings>,
    stop: CancellationToken,
}

fn peer<T>(request: &Request<T>) -> Result<Arc<str>, Status> {
    request
        .extensions()
        .get::<Peer>()
        .map(|peer| Arc::clone(&peer.node))
        .ok_or_else(|| Status::unauthenticated("no node identity"))
}

#[tonic::async_trait]
impl reflector_server::Reflector for Api {
    async fn members(
        &self,
        _: Request<proto::MembersRequest>,
    ) -> Result<Response<proto::MembersResponse>, Status> {
        let members = self
            .settings
            .members
            .iter()
            .map(|member| proto::Member {
                node: member.node.clone(),
                address: member.address.to_string(),
            })
            .collect();
        Ok(Response::new(proto::MembersResponse { members }))
    }

    type AnnounceStream = BoxStream<proto::ReflectorMessage>;

    async fn announce(
        &self,
        request: Request<Streaming<proto::AgentMessage>>,
    ) -> Result<Response<Self::AnnounceStream>, Status> {
        let node = peer(&request)?;
        let session = Session::new(Arc::clone(&self.index), Arc::clone(&self.settings), node);
        let state = Some((session, request.into_inner(), self.stop.clone()));
        let replies = stream::unfold(state, |state| async move {
            let (mut session, mut inbound, stop) = state?;
            match next(&mut session, &mut inbound, &stop).await {
                Some(Ok(reply)) => Some((Ok(reply), Some((session, inbound, stop)))),
                // An error ends the stream, and dropping the session withdraws what it announced.
                Some(Err(status)) => Some((Err(status), None)),
                None => None,
            }
        });
        Ok(Response::new(Box::pin(replies)))
    }

    async fn lookup(
        &self,
        request: Request<proto::LookupRequest>,
    ) -> Result<Response<proto::LookupResponse>, Status> {
        let start = Instant::now();
        let node = peer(&request)?;
        let digest = message::digest(request.into_inner().digest)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let peers = self
            .index
            .lookup(&digest, &node, LOOKUP_PEERS)
            .into_iter()
            .map(|holder| proto::Peer {
                node: holder.node.to_string(),
                address: holder.peer.to_string(),
            })
            .collect();
        ::metrics::histogram!(metrics::LOOKUP).record(start.elapsed());
        Ok(Response::new(proto::LookupResponse { peers }))
    }
}

/// The next reply of a stream, after any number of messages that need none; `None` at its end.
async fn next(
    session: &mut Session,
    inbound: &mut Streaming<proto::AgentMessage>,
    stop: &CancellationToken,
) -> Option<Result<proto::ReflectorMessage, Status>> {
    loop {
        let received = tokio::select! {
            () = stop.cancelled() => return Some(Err(Status::unavailable("the reflector is stopping"))),
            received = inbound.message() => received,
        };
        let message = match received {
            Ok(Some(message)) => message,
            Ok(None) => return None,
            // tonic refuses a message over the size limit with `OutOfRange`.
            Err(status) if status.code() == tonic::Code::OutOfRange => {
                return Some(Err(reject(session.node(), Reason::Size, status.message())));
            }
            Err(status) => return Some(Err(status)),
        };
        let reply = Announcement::try_from(message)
            .map_err(|err| Rejection::Refused(err.reason(), err.to_string()))
            .and_then(|announcement| session.handle(announcement));
        match reply {
            Ok(None) => {}
            Ok(Some(Reply::Resync)) => {
                return Some(Ok(proto::ReflectorMessage {
                    message: Some(reflector_message::Message::Resync(proto::Resync {})),
                }));
            }
            Err(Rejection::Superseded) => {
                return Some(Err(Status::aborted(
                    "a later stream of this node took over",
                )));
            }
            Err(Rejection::Refused(reason, why)) => {
                return Some(Err(reject(session.node(), reason, &why)));
            }
        }
    }
}

/// Counts and logs a refused stream; an agent refused again reconnects at most once a minute (D33).
fn reject(node: &str, reason: Reason, why: &str) -> Status {
    metrics::rejected(reason);
    warn!(
        node,
        reason = reason.label(),
        why,
        "announce stream refused"
    );
    let status = match reason {
        Reason::Identity => Status::permission_denied,
        Reason::Version => Status::failed_precondition,
        Reason::Size | Reason::Digests => Status::resource_exhausted,
        Reason::Address | Reason::Malformed => Status::invalid_argument,
    };
    status(format!("stream of node {node:?} refused: {why}"))
}
