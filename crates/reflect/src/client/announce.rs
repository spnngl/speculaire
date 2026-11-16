//! One member's connection: it announces what the node holds and carries the node's lookups, and is opened again after
//! it ends (D2, D33, D98, D105).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Notify, broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::backoff::Backoff;
use super::holdings::Batch;
use super::{Ask, CallError, DialError, Outage, PEER_PORT, Peer, QUEUE, Shared, dial, peers};
use crate::frame::{self, FrameError, Reader};
use crate::message::{Announcement, Delta, Hello, Lookup, Request, Snapshot};
use crate::metrics::{CONNECTED, RECONNECTS};
use crate::proto::{self, reflector_message};
use crate::{Key, Member, PROTOCOL_VERSION, SNAPSHOT_CHUNK};

/// How long a connection must have been up for its end to count as a drop rather than a failed attempt (D98).
const STEADY: Duration = Duration::from_secs(5);

/// The lookups sent and not answered yet, by number.
type Pending = Mutex<HashMap<u64, oneshot::Sender<Vec<Peer>>>>;

/// Why a connection ended.
#[derive(Debug, thiserror::Error)]
enum Ended {
    #[error(transparent)]
    Dial(#[from] DialError),
    #[error(transparent)]
    Call(#[from] CallError),
    #[error("the node identity is not loaded")]
    NoIdentity,
}

impl From<FrameError> for Ended {
    fn from(err: FrameError) -> Self {
        Self::Call(err.into())
    }
}

/// Connects to `member` until `stop`, then ends its connection, which withdraws the node from it.
pub(super) async fn run(member: Member, shared: Arc<Shared>, stop: CancellationToken) {
    let mut backoff = Backoff::new(fastrand::u64(..));
    let connected = ::metrics::gauge!(CONNECTED, "member" => member.node.clone());
    let reconnects = ::metrics::counter!(RECONNECTS, "member" => member.node.clone());
    connected.set(0.0);
    reconnects.absolute(0);
    let mut up = None;
    let mut outage = Outage::default();
    loop {
        let ended = tokio::select! {
            () = stop.cancelled() => break,
            ended = connection(&member, &shared, &mut up, &connected) => ended,
        };
        shared.links().remove(&member.node);
        connected.set(0.0);
        let up_for = up.take().map(|since| since.elapsed());
        if up_for.is_some() {
            outage.ended();
        }
        let wait = if dropped(up_for) {
            shared.dropped.notify_one();
            backoff.dropped()
        } else {
            backoff.failed()
        };
        if outage.failed() {
            warn!(node = %member.node, address = %member.address, error = %ended, retry = ?wait, "no stream to the reflector");
        } else {
            info!(node = %member.node, address = %member.address, error = %ended, retry = ?wait, "reflector stream ended");
        }
        tokio::select! {
            () = stop.cancelled() => break,
            () = tokio::time::sleep(wait) => {}
        }
        reconnects.increment(1);
    }
    shared.links().remove(&member.node);
    connected.set(0.0);
}

/// Whether a connection that was up for `up_for`, `None` when it never opened, dropped rather than failed (D98).
fn dropped(up_for: Option<Duration>) -> bool {
    up_for.is_some_and(|up_for| up_for >= STEADY)
}

/// One connection, until it ends: it sends `Hello`, a snapshot, then the changes of the holdings and the lookups, and
/// reads the answers. `up` is set once the snapshot is sent.
async fn connection(
    member: &Member,
    shared: &Shared,
    up: &mut Option<Instant>,
    connected: &::metrics::Gauge,
) -> Ended {
    let link = match dial(member.address, shared.credentials.client(&member.node)).await {
        Ok(link) => link,
        Err(err) => return err.into(),
    };
    let Some(identity) = shared.credentials.identity() else {
        return Ended::NoIdentity;
    };
    let mut peer = SocketAddr::new(link.local.ip(), PEER_PORT);
    shared.peer.send_if_modified(|fixed| {
        if let Some(fixed) = fixed {
            peer = *fixed;
            return false;
        }
        info!(address = %peer, "peer address fixed from the first reflector stream");
        *fixed = Some(peer);
        true
    });
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node: identity.node().to_owned(),
        peer,
    };
    let (mut reading, writing) = tokio::io::split(link.tls);
    let pending = Pending::default();
    let resync = Notify::new();
    let (queue, asked) = mpsc::channel(QUEUE);
    let mut announcer = Announcer {
        io: writing,
        seq: 0,
        id: 0,
        pending: &pending,
    };
    let announce = async {
        let hello = Request::Announcement(Announcement::Hello(hello));
        let mut changes = match announcer.send(hello).await {
            Ok(()) => match announcer.snapshot(&shared.holdings).await {
                Ok(changes) => changes,
                Err(err) => return err.into(),
            },
            Err(err) => return err.into(),
        };
        *up = Some(Instant::now());
        shared.links().insert(member.node.clone(), queue);
        shared.linked.send_replace(true);
        connected.set(1.0);
        info!(node = %member.node, address = %member.address, "reflector stream up");
        announcer
            .follow(&shared.holdings, &mut changes, asked, &resync)
            .await
    };
    tokio::select! {
        ended = answers(&mut reading, &pending, &resync) => ended,
        ended = announce => ended,
    }
}

/// Reads the reflector's frames until the connection ends: it hands each lookup's answer over, and asks for a snapshot
/// when the reflector does.
async fn answers<R: AsyncRead + Unpin>(io: &mut R, pending: &Pending, resync: &Notify) -> Ended {
    let mut reader = Reader::<proto::ReflectorMessage>::new(frame::LIMIT);
    loop {
        let message = match tokio::time::timeout(frame::SILENCE, reader.next(io)).await {
            Err(_) => return CallError::Timeout.into(),
            Ok(Err(err)) => return err.into(),
            Ok(Ok(None)) => return CallError::Closed.into(),
            Ok(Ok(Some(message))) => message.message,
        };
        match message {
            Some(reflector_message::Message::Resync(_)) => resync.notify_one(),
            Some(reflector_message::Message::Lookup(answer)) => {
                let waiter = pending
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .remove(&answer.id);
                // The caller may have given up: its answer goes nowhere.
                if let Some(waiter) = waiter {
                    let _ = waiter.send(peers(answer));
                }
            }
            Some(reflector_message::Message::Refused(refused)) => {
                return CallError::from(refused).into();
            }
            // `Prewarm` arrives with M7 (D51); `Pong` only keeps the connection alive.
            Some(_) | None => {}
        }
    }
}

/// The sending side of a connection: the sequence number of its next `Delta` and the number of its next lookup.
struct Announcer<'a, W> {
    io: W,
    seq: u64,
    id: u64,
    pending: &'a Pending,
}

impl<W: AsyncWrite + Unpin> Announcer<'_, W> {
    /// Sends the changes of `holdings` and the lookups of `asked`, a snapshot when the reflector asks, and a ping when
    /// due, until the connection ends.
    async fn follow(
        &mut self,
        holdings: &super::Holdings,
        changes: &mut broadcast::Receiver<Arc<Batch>>,
        mut asked: mpsc::Receiver<Ask>,
        resync: &Notify,
    ) -> Ended {
        let mut ping =
            tokio::time::interval_at(tokio::time::Instant::now() + frame::PING, frame::PING);
        loop {
            let sent = tokio::select! {
                () = resync.notified() => self.snapshot(holdings).await.map(|fresh| *changes = fresh),
                batch = changes.recv() => match batch {
                    Ok(batch) => self.delta(&batch).await,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        self.snapshot(holdings).await.map(|fresh| *changes = fresh)
                    }
                    // The holdings live as long as the client.
                    Err(broadcast::error::RecvError::Closed) => return CallError::Closed.into(),
                },
                // The client keeps the queue's sender while the connection is up.
                Some(ask) = asked.recv() => self.lookup(ask).await,
                _ = ping.tick() => self.send(Request::Ping).await,
            };
            if let Err(err) = sent {
                return err.into();
            }
        }
    }

    /// Sends every digest held, in chunks, and returns the changes that follow it.
    async fn snapshot(
        &mut self,
        holdings: &super::Holdings,
    ) -> Result<broadcast::Receiver<Arc<Batch>>, FrameError> {
        let (digests, changes) = holdings.subscribe();
        let mut chunks = digests.chunks(SNAPSHOT_CHUNK).peekable();
        if chunks.peek().is_none() {
            self.send_snapshot(&[], true).await?;
        }
        while let Some(chunk) = chunks.next() {
            self.send_snapshot(chunk, chunks.peek().is_none()).await?;
        }
        Ok(changes)
    }

    async fn send_snapshot(&mut self, digests: &[Key], last: bool) -> Result<(), FrameError> {
        let snapshot = Snapshot {
            digests: digests.to_vec(),
            last,
            seq: self.seq,
        };
        self.send(Request::Announcement(Announcement::Snapshot(snapshot)))
            .await
    }

    /// Sends `batch` as deltas of at most a chunk each, removals first.
    async fn delta(&mut self, batch: &Batch) -> Result<(), FrameError> {
        for removed in batch.removed.chunks(SNAPSHOT_CHUNK) {
            self.send_delta(&[], removed).await?;
        }
        for added in batch.added.chunks(SNAPSHOT_CHUNK) {
            self.send_delta(added, &[]).await?;
        }
        Ok(())
    }

    async fn send_delta(&mut self, added: &[Key], removed: &[Key]) -> Result<(), FrameError> {
        let delta = Delta {
            seq: self.seq,
            added: added.to_vec(),
            removed: removed.to_vec(),
        };
        self.seq += 1;
        self.send(Request::Announcement(Announcement::Delta(delta)))
            .await
    }

    /// Numbers `ask`, so that its answer finds it, and sends it.
    async fn lookup(&mut self, ask: Ask) -> Result<(), FrameError> {
        let id = self.id;
        self.id += 1;
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id, ask.answer);
        self.send(Request::Lookup(Lookup {
            id,
            digest: ask.digest,
        }))
        .await
    }

    async fn send(&mut self, request: Request) -> Result<(), FrameError> {
        frame::write(
            &mut self.io,
            &proto::AgentMessage::from(request),
            frame::LIMIT,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use speculaire_oci::reference::Digest;

    use super::*;
    use crate::client::{Holdings, Source};

    fn digest(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    #[test]
    fn a_connection_up_five_seconds_or_more_dropped_and_a_shorter_one_failed() {
        assert!(!dropped(None));
        assert!(!dropped(Some(Duration::from_millis(4999))));
        assert!(dropped(Some(STEADY)));
    }

    #[tokio::test]
    async fn deltas_count_up_from_the_snapshot_and_the_next_snapshot_names_the_next_delta() {
        let holdings = Holdings::default();
        holdings.add(Source::Content, &digest(1));
        let pending = Pending::default();
        let mut announcer = Announcer {
            io: Vec::new(),
            seq: 0,
            id: 0,
            pending: &pending,
        };
        let mut changes = announcer.snapshot(&holdings).await.unwrap();
        holdings.remove(Source::Content, &digest(1));
        holdings.add(Source::Content, &digest(2));
        holdings.add(Source::Content, &digest(3));
        for _ in 0..3 {
            let batch = changes.recv().await.unwrap();
            announcer.delta(&batch).await.unwrap();
        }
        announcer.snapshot(&holdings).await.unwrap();
        let mut sent = announcer.io.as_slice();
        let mut reader = Reader::<proto::AgentMessage>::new(frame::LIMIT);
        let mut seqs = Vec::new();
        while let Some(message) = reader.next(&mut sent).await.unwrap() {
            seqs.push(match Request::try_from(message).unwrap() {
                Request::Announcement(Announcement::Snapshot(snapshot)) => {
                    ("snapshot", snapshot.seq)
                }
                Request::Announcement(Announcement::Delta(delta)) => ("delta", delta.seq),
                other => panic!("only announcements were sent, not {other:?}"),
            });
        }
        assert_eq!(
            seqs,
            [
                ("snapshot", 0),
                ("delta", 0),
                ("delta", 1),
                ("delta", 2),
                ("snapshot", 3)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_pings_once_thirty_seconds_after_it_is_up() {
        let holdings = Holdings::default();
        let (_, mut changes) = holdings.subscribe();
        let (_asks, asked) = mpsc::channel(1);
        let pending = Pending::default();
        let mut announcer = Announcer {
            io: Vec::new(),
            seq: 0,
            id: 0,
            pending: &pending,
        };
        let resync = Notify::new();
        let following = announcer.follow(&holdings, &mut changes, asked, &resync);
        // Nothing else ends the loop: the timeout stops it a second after the first ping is due.
        tokio::time::timeout(frame::PING + Duration::from_secs(1), following)
            .await
            .unwrap_err();
        let mut sent = announcer.io.as_slice();
        let mut reader = Reader::<proto::AgentMessage>::new(frame::LIMIT);
        let mut pings = 0;
        while let Some(message) = reader.next(&mut sent).await.unwrap() {
            assert!(matches!(Request::try_from(message), Ok(Request::Ping)));
            pings += 1;
        }
        assert_eq!(pings, 1);
    }

    #[tokio::test]
    async fn lookups_are_numbered_in_turn_and_each_answer_finds_its_lookup_by_number() {
        let pending = Pending::default();
        let mut announcer = Announcer {
            io: Vec::new(),
            seq: 0,
            id: 0,
            pending: &pending,
        };
        let mut waiting = Vec::new();
        for n in 1..=2 {
            let (answer, answered) = oneshot::channel();
            announcer
                .lookup(Ask {
                    digest: Key::from(&digest(n)),
                    answer,
                })
                .await
                .unwrap();
            waiting.push(answered);
        }
        let mut sent = announcer.io.as_slice();
        let mut reader = Reader::<proto::AgentMessage>::new(frame::LIMIT);
        let mut ids = Vec::new();
        while let Some(message) = reader.next(&mut sent).await.unwrap() {
            match Request::try_from(message).unwrap() {
                Request::Lookup(lookup) => ids.push((lookup.id, lookup.digest)),
                other => panic!("only lookups were sent, not {other:?}"),
            }
        }
        assert_eq!(
            ids,
            [(0, Key::from(&digest(1))), (1, Key::from(&digest(2)))]
        );

        let holder = proto::Peer {
            node: "b".to_owned(),
            address: "10.0.0.2:7481".to_owned(),
        };
        let answer = proto::ReflectorMessage {
            message: Some(reflector_message::Message::Lookup(proto::LookupResponse {
                id: 1,
                peers: vec![holder],
            })),
        };
        let mut received = Vec::new();
        frame::write(&mut received, &answer, frame::LIMIT)
            .await
            .unwrap();
        let resync = Notify::new();
        let ended = answers(&mut received.as_slice(), &pending, &resync).await;
        assert!(matches!(ended, Ended::Call(CallError::Closed)), "{ended}");
        drop(pending);
        let [first, second] = <[_; 2]>::try_from(waiting).unwrap();
        assert_eq!(
            second.await.unwrap(),
            [Peer {
                node: "b".to_owned(),
                address: "10.0.0.2:7481".parse().unwrap(),
            }]
        );
        assert!(
            first.await.is_err(),
            "an unanswered lookup ends with its connection"
        );
    }
}
