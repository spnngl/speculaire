//! NRI's multiplexer, as `pkg/net/multiplex/mux.go` at v0.12.5 behaves (D9, D163): frames on the trunk, one bounded
//! queue per ConnID, and the trunk closed on a frame no peer writes or on a full queue.

use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::{io, mem};

use futures_util::future::{self, Either};
use tokio::io::{
    AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, DuplexStream, ReadBuf,
};
use tokio::sync::Mutex;
use zerocopy::IntoBytes as _;

use crate::frame::{HEADER, Header, Oversize};
use crate::queue::{End, Full, Queue};

/// How many payloads a connection's queue holds (`readQueueLen`, `mux.go:138`).
const QUEUE: usize = 256;

/// The largest payload this multiplexer writes: Go's connection reads a frame into ttrpc's 4096-byte buffer, and fails
/// with ENOMEM on a larger one (D9).
const CHUNK: usize = 4096;

/// A connection of the trunk (`ttrpc.go:19-24`); a frame of another ConnID is dropped, as Go drops it
/// (`mux.go:357-368`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnId {
    /// ConnID 1, `PluginServiceConn`: the plugin's services, which the runtime calls.
    PluginService,
    /// ConnID 2, `RuntimeServiceConn`: the runtime's services, which the plugin calls.
    RuntimeService,
}

impl ConnId {
    /// Its number on the trunk.
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::PluginService => 1,
            Self::RuntimeService => 2,
        }
    }

    const fn from_id(id: u32) -> Option<Self> {
        match id {
            1 => Some(Self::PluginService),
            2 => Some(Self::RuntimeService),
            _ => None,
        }
    }
}

/// Why the trunk closed.
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    /// Reading or writing the trunk failed, or the trunk ended inside a frame.
    #[error("the trunk failed: {0}")]
    Io(#[from] io::Error),
    /// A frame's payload is over [`crate::MAX_PAYLOAD`] (`mux.go:325-336`).
    #[error(transparent)]
    Oversize(#[from] Oversize),
    /// A connection's reader is a whole queue behind (`mux.go:360-367`).
    #[error("conn {}: a frame of {length} bytes, over its queue of {capacity} frames", conn.id())]
    QueueFull {
        /// The connection.
        conn: ConnId,
        /// The frame's payload length.
        length: usize,
        /// The queue's capacity, in frames.
        capacity: usize,
    },
}

/// The multiplexer of a trunk, which [`Mux::run`] carries between the runtime and the [`Connections`].
#[derive(Debug)]
pub struct Mux<R, W> {
    reader: R,
    writer: W,
    queues: Queues,
    /// What the plugin service's and the runtime service's connections write.
    outgoing: [DuplexStream; 2],
}

/// A trunk's two connections, each a byte stream for a ttrpc server or client.
#[derive(Debug)]
pub struct Connections {
    /// ConnID 1, where the plugin serves the runtime.
    pub plugin_service: Connection,
    /// ConnID 2, where the plugin calls the runtime.
    pub runtime_service: Connection,
}

/// One connection of a trunk. It reads its frames' payloads, and writes frames of at most 4096 bytes of payload.
///
/// Once the trunk ends, it reads the payloads queued, then the end of file when the trunk ended between two frames, or
/// else `ConnectionAborted`. Dropped, it drops the payloads for it, as Go drops those for a closed connection.
#[derive(Debug)]
pub struct Connection {
    queue: Arc<Queue>,
    /// The payload being read, `read` bytes of it read.
    payload: Vec<u8>,
    read: usize,
    outgoing: DuplexStream,
}

/// Both connections' queues, which end as aborted when dropped before [`Queues::end`].
#[derive(Debug)]
struct Queues {
    plugin_service: Arc<Queue>,
    runtime_service: Arc<Queue>,
}

impl<R, W> Mux<R, W> {
    /// The multiplexer of the trunk read by `reader` and written by `writer`, and its connections.
    pub fn new(reader: R, writer: W) -> (Self, Connections) {
        Self::with_queue(reader, writer, QUEUE)
    }

    fn with_queue(reader: R, writer: W, capacity: usize) -> (Self, Connections) {
        let queues = Queues {
            plugin_service: Arc::new(Queue::new(capacity)),
            runtime_service: Arc::new(Queue::new(capacity)),
        };
        let connection = |queue: &Arc<Queue>| {
            let (ours, outgoing) = tokio::io::duplex(CHUNK);
            let connection = Connection {
                queue: Arc::clone(queue),
                payload: Vec::new(),
                read: 0,
                outgoing,
            };
            (connection, ours)
        };
        let (plugin_service, plugin_outgoing) = connection(&queues.plugin_service);
        let (runtime_service, runtime_outgoing) = connection(&queues.runtime_service);
        let mux = Self {
            reader,
            writer,
            queues,
            outgoing: [plugin_outgoing, runtime_outgoing],
        };
        let connections = Connections {
            plugin_service,
            runtime_service,
        };
        (mux, connections)
    }
}

impl<R: AsyncRead + Unpin, W: AsyncWrite + Unpin> Mux<R, W> {
    /// Carries frames between the trunk and the connections until the trunk ends or must close, then ends the
    /// connections. With both connections dropped, it still reads the trunk until it ends.
    ///
    /// # Errors
    ///
    /// When the trunk fails or ends inside a frame, a frame's payload is over [`crate::MAX_PAYLOAD`], or a connection's
    /// queue is full.
    pub async fn run(self) -> Result<(), MuxError> {
        let Self {
            reader,
            writer,
            queues,
            outgoing: [plugin_outgoing, runtime_outgoing],
        } = self;
        let writer = Mutex::new(writer);
        let send = future::try_join(
            send(ConnId::PluginService, plugin_outgoing, &writer),
            send(ConnId::RuntimeService, runtime_outgoing, &writer),
        );
        let ended = match future::select(pin!(receive(reader, &queues)), pin!(send)).await {
            Either::Left((ended, _)) => ended,
            Either::Right((Ok(_), receive)) => receive.await,
            Either::Right((Err(err), _)) => Err(err),
        };
        queues.end(if ended.is_ok() {
            End::Clean
        } else {
            End::Aborted
        });
        ended
    }
}

/// Reads frames into their connection's queue, never waiting for a connection.
async fn receive<R: AsyncRead + Unpin>(mut trunk: R, queues: &Queues) -> Result<(), MuxError> {
    let mut header = Header::default();
    loop {
        let bytes = header.as_mut_bytes();
        let first = trunk.read(bytes).await?;
        if first == 0 {
            return Ok(());
        }
        trunk
            .read_exact(bytes.get_mut(first..).unwrap_or_default())
            .await?;
        let length = header.length()?;
        let conn = ConnId::from_id(header.conn());
        // An unknown ConnID's payload is read into a spare of ConnID 1's queue, and handed back to it.
        let queue = queues.get(conn.unwrap_or(ConnId::PluginService));
        let mut payload = queue.spare();
        payload.resize(length, 0);
        trunk.read_exact(&mut payload).await?;
        let Some(conn) = conn else {
            queue.recycle(payload);
            continue;
        };
        queue.push(payload).map_err(|Full| MuxError::QueueFull {
            conn,
            length,
            capacity: queue.capacity(),
        })?;
    }
}

/// Frames what `conn`'s connection writes, through one buffer for the connection's life (D107).
async fn send<W: AsyncWrite + Unpin>(
    conn: ConnId,
    mut outgoing: DuplexStream,
    trunk: &Mutex<W>,
) -> Result<(), MuxError> {
    let mut frame = vec![0; HEADER + CHUNK];
    loop {
        let (header, payload) = frame.split_at_mut(HEADER);
        let length = outgoing.read(payload).await?;
        if length == 0 {
            return Ok(());
        }
        let claimed = u32::try_from(length).expect("a chunk's length fits in u32");
        header.copy_from_slice(Header::new(conn.id(), claimed).as_bytes());
        let mut trunk = trunk.lock().await;
        trunk
            .write_all(frame.get(..HEADER + length).unwrap_or_default())
            .await?;
        trunk.flush().await?;
    }
}

impl Queues {
    fn get(&self, conn: ConnId) -> &Queue {
        match conn {
            ConnId::PluginService => &self.plugin_service,
            ConnId::RuntimeService => &self.runtime_service,
        }
    }

    fn end(&self, end: End) {
        self.plugin_service.end(end);
        self.runtime_service.end(end);
    }
}

impl Drop for Queues {
    fn drop(&mut self) {
        self.end(End::Aborted);
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // An empty payload is skipped: reading nothing would read as the end of file.
        while this.read == this.payload.len() {
            match ready!(this.queue.poll_pop(cx)) {
                Ok(payload) => {
                    this.queue.recycle(mem::replace(&mut this.payload, payload));
                    this.read = 0;
                }
                Err(End::Clean) => return Poll::Ready(Ok(())),
                Err(End::Aborted) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "the NRI trunk closed",
                    )));
                }
            }
        }
        let unread = this.payload.get(this.read..).unwrap_or_default();
        let length = unread.len().min(buf.remaining());
        buf.put_slice(unread.get(..length).unwrap_or_default());
        this.read += length;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().outgoing).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().outgoing).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().outgoing).poll_shutdown(cx)
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.queue.detach();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_PAYLOAD;

    /// A frame of `conn` carrying `payload`.
    fn frame(conn: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = Header::new(conn, u32::try_from(payload.len()).unwrap())
            .as_bytes()
            .to_vec();
        frame.extend_from_slice(payload);
        frame
    }

    /// Everything `connection` reads, and how its reading ended.
    async fn read_all(connection: &mut Connection) -> (Vec<u8>, io::Result<()>) {
        let mut read = Vec::new();
        let mut buf = [0; 3];
        loop {
            match connection.read(&mut buf).await {
                Ok(0) => return (read, Ok(())),
                Ok(length) => read.extend_from_slice(&buf[..length]),
                Err(err) => return (read, Err(err)),
            }
        }
    }

    fn aborted(ended: &io::Result<()>) -> bool {
        matches!(ended, Err(err) if err.kind() == io::ErrorKind::ConnectionAborted)
    }

    #[tokio::test]
    async fn frames_split_across_reads_or_sharing_one_decode() {
        let mut trunk = frame(1, b"ab");
        trunk.extend(frame(2, b"cd"));
        trunk.extend(frame(1, b""));
        trunk.extend(frame(1, b"efgh"));
        trunk.extend(frame(2, b"ij"));
        // Each slice is one read: three frames and 3 bytes of a header, then the header's rest and half its payload.
        let (first, rest) = trunk.split_at(HEADER * 3 + 4 + 3);
        let (second, third) = rest.split_at(HEADER - 3 + 2);
        let reader = first.chain(second).chain(third);
        let (mux, mut connections) = Mux::new(reader, tokio::io::sink());
        mux.run().await.unwrap();
        let (read, ended) = read_all(&mut connections.plugin_service).await;
        assert_eq!((read.as_slice(), ended.ok()), (&b"abefgh"[..], Some(())));
        let (read, ended) = read_all(&mut connections.runtime_service).await;
        assert_eq!((read.as_slice(), ended.ok()), (&b"cdij"[..], Some(())));
    }

    #[tokio::test]
    async fn a_frame_over_the_maximum_closes_the_trunk_before_its_payload_is_read() {
        // A payload of exactly the maximum is read and delivered.
        let full = vec![7; usize::try_from(MAX_PAYLOAD).unwrap()];
        let mut trunk = frame(1, &full);
        // One byte more, with no payload behind: refused by the header alone, not as a payload cut short.
        trunk.extend(Header::new(9, MAX_PAYLOAD + 1).as_bytes());
        let (mux, mut connections) = Mux::new(trunk.as_slice(), tokio::io::sink());
        let ended = mux.run().await;
        assert!(
            matches!(
                ended,
                Err(MuxError::Oversize(Oversize { conn: 9, length })) if length == MAX_PAYLOAD + 1
            ),
            "{ended:?}"
        );
        let (read, ended) = read_all(&mut connections.plugin_service).await;
        assert!(read == full && aborted(&ended), "{ended:?}");
        assert!(aborted(&read_all(&mut connections.runtime_service).await.1));
    }

    #[tokio::test]
    async fn a_frame_for_another_conn_is_dropped() {
        let mut trunk = frame(0, b"zero");
        trunk.extend(frame(3, b"three"));
        trunk.extend(frame(1, b"one"));
        let (mux, mut connections) = Mux::new(trunk.as_slice(), tokio::io::sink());
        mux.run().await.unwrap();
        assert_eq!(read_all(&mut connections.plugin_service).await.0, b"one");
        assert_eq!(read_all(&mut connections.runtime_service).await.0, b"");
    }

    #[tokio::test]
    async fn a_full_queue_closes_the_trunk_and_the_other_reads_what_came_before() {
        let mut trunk = Vec::new();
        for payload in [b"a", b"b", b"c"] {
            trunk.extend(frame(2, payload));
            trunk.extend(frame(1, payload));
        }
        let (mux, mut connections) = Mux::with_queue(trunk.as_slice(), tokio::io::sink(), 2);
        let ended = mux.run().await;
        assert!(
            matches!(
                ended,
                Err(MuxError::QueueFull {
                    conn: ConnId::RuntimeService,
                    length: 1,
                    capacity: 2
                })
            ),
            "{ended:?}"
        );
        let (read, ended) = read_all(&mut connections.plugin_service).await;
        assert!(read == b"ab" && aborted(&ended), "{ended:?}");
        let (read, ended) = read_all(&mut connections.runtime_service).await;
        assert!(read == b"ab" && aborted(&ended), "{ended:?}");
    }

    #[tokio::test]
    async fn a_dropped_connection_drops_its_frames_instead_of_filling_its_queue() {
        let mut trunk = Vec::new();
        for payload in [b"a", b"b", b"c"] {
            trunk.extend(frame(2, payload));
        }
        let (mux, connections) = Mux::with_queue(trunk.as_slice(), tokio::io::sink(), 2);
        drop(connections);
        mux.run().await.unwrap();
    }

    #[tokio::test]
    async fn a_trunk_ending_inside_a_frame_fails() {
        for trunk in [&frame(1, b"ab")[..3], &frame(1, b"ab")[..=HEADER]] {
            let (mux, mut connections) = Mux::new(trunk, tokio::io::sink());
            let ended = mux.run().await;
            assert!(
                matches!(&ended, Err(MuxError::Io(err)) if err.kind() == io::ErrorKind::UnexpectedEof),
                "{ended:?}"
            );
            assert!(aborted(&read_all(&mut connections.plugin_service).await.1));
        }
    }

    #[tokio::test]
    async fn a_connection_waiting_for_a_frame_wakes_when_it_comes() {
        let (ours, mut theirs) = tokio::io::duplex(64);
        let (mux, connections) = Mux::new(ours, tokio::io::sink());
        let Connections {
            mut plugin_service, ..
        } = connections;
        let reader = tokio::spawn(async move { read_all(&mut plugin_service).await });
        // The reader waits on its empty queue before the frame comes.
        tokio::task::yield_now().await;
        theirs.write_all(&frame(1, b"late")).await.unwrap();
        drop(theirs);
        mux.run().await.unwrap();
        let (read, ended) = tokio::time::timeout(std::time::Duration::from_secs(10), reader)
            .await
            .expect("the reader wakes")
            .unwrap();
        assert_eq!((read.as_slice(), ended.ok()), (&b"late"[..], Some(())));
    }

    #[tokio::test]
    async fn a_shut_down_connection_writes_no_more() {
        let (_mux, mut connections) = Mux::new(tokio::io::empty(), tokio::io::sink());
        connections.plugin_service.shutdown().await.unwrap();
        assert!(connections.plugin_service.write_all(b"late").await.is_err());
    }

    #[tokio::test]
    async fn a_dropped_multiplexer_aborts_its_connections() {
        let (mux, mut connections) = Mux::new(tokio::io::empty(), tokio::io::sink());
        drop(mux);
        assert!(aborted(&read_all(&mut connections.plugin_service).await.1));
    }

    #[tokio::test]
    async fn writes_go_out_in_frames_of_at_most_4096_bytes() {
        let (ours, mut theirs) = tokio::io::duplex(1 << 16);
        let (reader, writer) = tokio::io::split(ours);
        let (mux, mut connections) = Mux::new(reader, writer);
        let written: Vec<u8> = (0..10_000_u32).map(|i| i.to_le_bytes()[0]).collect();
        let peer = async {
            connections
                .runtime_service
                .write_all(&written)
                .await
                .unwrap();
            connections
                .plugin_service
                .write_all(b"plugin")
                .await
                .unwrap();
            let mut payloads = [Vec::new(), Vec::new()];
            let mut lengths = Vec::new();
            while payloads.iter().map(Vec::len).sum::<usize>() < written.len() + 6 {
                let mut header = Header::default();
                theirs.read_exact(header.as_mut_bytes()).await.unwrap();
                let length = header.length().unwrap();
                let index = usize::try_from(header.conn()).unwrap() - 1;
                let mut payload = vec![0; length];
                theirs.read_exact(&mut payload).await.unwrap();
                payloads[index].extend(payload);
                lengths.push(length);
            }
            assert!(lengths.iter().all(|length| *length <= CHUNK), "{lengths:?}");
            assert_eq!(payloads, [b"plugin".to_vec(), written.clone()]);
            drop(theirs);
        };
        let (ended, ()) = tokio::join!(mux.run(), peer);
        ended.unwrap();
    }

    #[tokio::test]
    async fn writing_to_a_closed_trunk_fails() {
        let (mux, mut connections) = Mux::new(tokio::io::empty(), tokio::io::sink());
        mux.run().await.unwrap();
        assert!(connections.plugin_service.write_all(b"late").await.is_err());
    }

    /// Under Shuttle's schedules (`just shuttle`): with ConnID 2's reader stalled, ConnID 1 reads its frames until
    /// ConnID 2's queue fills, then the trunk closes; no schedule deadlocks.
    #[cfg(shuttle)]
    #[test]
    fn schedules_a_stalled_connection_stalls_only_itself() {
        const CAPACITY: u8 = 3;
        shuttle::check_random(
            || {
                shuttle::future::block_on(async {
                    let (ours, mut theirs) = tokio::io::duplex(64);
                    let (reader, writer) = tokio::io::split(ours);
                    let (mux, connections) = Mux::with_queue(reader, writer, CAPACITY.into());
                    let Connections {
                        mut plugin_service,
                        runtime_service: _stalled,
                    } = connections;
                    let run = shuttle::future::spawn(mux.run());
                    let peer = shuttle::future::spawn(async move {
                        let mut trunk = Vec::new();
                        for payload in 0..=CAPACITY {
                            trunk.extend(frame(2, &[payload]));
                            trunk.extend(frame(1, &[payload]));
                        }
                        // The trunk closes on ConnID 2's last frame: writing what follows may fail.
                        let _ = theirs.write_all(&trunk).await;
                        theirs
                    });
                    let (read, ended) = read_all(&mut plugin_service).await;
                    assert!(read == [0, 1, 2] && aborted(&ended), "{read:?} {ended:?}");
                    let ended = run.await.unwrap();
                    assert!(
                        matches!(
                            ended,
                            Err(MuxError::QueueFull {
                                conn: ConnId::RuntimeService,
                                ..
                            })
                        ),
                        "{ended:?}"
                    );
                    drop(peer.await);
                });
            },
            2000,
        );
    }
}
