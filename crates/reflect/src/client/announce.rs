//! One member's `Announce` stream, opened again after it ends (D2, D33, D98).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::stream;
use speculaire_oci::reference::Digest;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tonic::Status;
use tracing::{info, warn};

use super::backoff::Backoff;
use super::holdings::Batch;
use super::{DialError, PEER_PORT, Shared, dial, failing_long};
use crate::message::{Announcement, Delta, Hello, Snapshot};
use crate::metrics::{CONNECTED, RECONNECTS};
use crate::proto::reflector_client::ReflectorClient;
use crate::proto::{self, reflector_message};
use crate::{Member, PROTOCOL_VERSION, SNAPSHOT_CHUNK};

/// How long a stream must have been up for its end to count as a drop rather than a failed attempt (D98).
const STEADY: Duration = Duration::from_secs(5);

/// Why a stream ended.
#[derive(Debug, thiserror::Error)]
enum Ended {
    #[error(transparent)]
    Dial(#[from] DialError),
    #[error("the reflector ended the stream: {0}")]
    Status(#[from] Status),
    #[error("the reflector closed the stream")]
    Closed,
    #[error("the node identity is not loaded")]
    NoIdentity,
}

/// Streams to `member` until `stop`, then ends its stream, which withdraws the node from it.
pub(super) async fn run(member: Member, shared: Arc<Shared>, stop: CancellationToken) {
    let mut backoff = Backoff::new(fastrand::u64(..));
    let connected = ::metrics::gauge!(CONNECTED, "member" => member.node.clone());
    let reconnects = ::metrics::counter!(RECONNECTS, "member" => member.node.clone());
    connected.set(0.0);
    reconnects.absolute(0);
    let mut up = None;
    let mut down = Instant::now();
    loop {
        let ended = tokio::select! {
            () = stop.cancelled() => break,
            ended = stream(&member, &shared, &mut up, &connected) => ended,
        };
        shared.links().remove(&member.node);
        connected.set(0.0);
        let up_for = up.take().map(|since| since.elapsed());
        if up_for.is_some() {
            down = Instant::now();
        }
        let wait = if dropped(up_for) {
            shared.dropped.notify_one();
            backoff.dropped()
        } else {
            backoff.failed()
        };
        if failing_long(down) {
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

/// Whether a stream that was up for `up_for`, `None` when it never opened, dropped rather than failed (D98).
fn dropped(up_for: Option<Duration>) -> bool {
    up_for.is_some_and(|up_for| up_for >= STEADY)
}

/// One stream: `Hello`, a snapshot, then the changes of the holdings, until it ends. `up` is set when the reflector
/// accepts it.
async fn stream(
    member: &Member,
    shared: &Shared,
    up: &mut Option<Instant>,
    connected: &::metrics::Gauge,
) -> Ended {
    let (channel, link) = match dial(member.address, shared.credentials.client(&member.node)).await
    {
        Ok(dialed) => dialed,
        Err(err) => return err.into(),
    };
    let Some(identity) = shared.credentials.identity() else {
        return Ended::NoIdentity;
    };
    let peer = *shared.peer.get_or_init(|| {
        let peer = SocketAddr::new(link.local.ip(), PEER_PORT);
        info!(address = %peer, "peer address fixed from the first reflector stream");
        peer
    });
    let (sender, mut outbound) = mpsc::channel(16);
    let outbound = stream::poll_fn(move |cx| outbound.poll_recv(cx));
    let mut replies = match ReflectorClient::new(channel.clone())
        .announce(outbound)
        .await
    {
        Ok(replies) => replies.into_inner(),
        Err(status) => return status.into(),
    };
    let hello = Hello {
        version: PROTOCOL_VERSION,
        node: identity.node().to_owned(),
        peer,
    };
    let mut announcer = Announcer { sender, seq: 0 };
    if !announcer.send(Announcement::Hello(hello)).await {
        return Ended::Closed;
    }
    let Some(mut changes) = announcer.snapshot(&shared.holdings).await else {
        return Ended::Closed;
    };
    *up = Some(Instant::now());
    shared.links().insert(member.node.clone(), channel);
    connected.set(1.0);
    info!(node = %member.node, address = %member.address, "reflector stream up");
    loop {
        let sent = tokio::select! {
            reply = replies.message() => match reply {
                Err(status) => return status.into(),
                Ok(None) => return Ended::Closed,
                Ok(Some(proto::ReflectorMessage { message: Some(reflector_message::Message::Resync(_)) })) => {
                    announcer.snapshot(&shared.holdings).await.map(|fresh| changes = fresh).is_some()
                }
                // `Prewarm` arrives with M7 (D51).
                Ok(Some(_)) => true,
            },
            batch = changes.recv() => match batch {
                Ok(batch) => announcer.delta(&batch).await,
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    announcer.snapshot(&shared.holdings).await.map(|fresh| changes = fresh).is_some()
                }
                // The holdings live as long as the client.
                Err(broadcast::error::RecvError::Closed) => return Ended::Closed,
            },
        };
        if !sent {
            return Ended::Closed;
        }
    }
}

/// The sending side of a stream, and the sequence number of its next `Delta`.
struct Announcer {
    sender: mpsc::Sender<proto::AgentMessage>,
    seq: u64,
}

impl Announcer {
    /// Sends every digest held, in chunks, and returns the changes that follow it; `None` once the stream is gone.
    async fn snapshot(
        &mut self,
        holdings: &super::Holdings,
    ) -> Option<broadcast::Receiver<Arc<Batch>>> {
        let (digests, changes) = holdings.subscribe();
        let mut chunks = digests.chunks(SNAPSHOT_CHUNK).peekable();
        if chunks.peek().is_none() {
            return self.send_snapshot(&[], true).await.then_some(changes);
        }
        while let Some(chunk) = chunks.next() {
            if !self.send_snapshot(chunk, chunks.peek().is_none()).await {
                return None;
            }
        }
        Some(changes)
    }

    async fn send_snapshot(&self, digests: &[Digest], last: bool) -> bool {
        self.send(Announcement::Snapshot(Snapshot {
            digests: digests.to_vec(),
            last,
            seq: self.seq,
        }))
        .await
    }

    /// Sends `batch` as deltas of at most a chunk each, removals first.
    async fn delta(&mut self, batch: &Batch) -> bool {
        for removed in batch.removed.chunks(SNAPSHOT_CHUNK) {
            if !self.send_delta(Vec::new(), removed.to_vec()).await {
                return false;
            }
        }
        for added in batch.added.chunks(SNAPSHOT_CHUNK) {
            if !self.send_delta(added.to_vec(), Vec::new()).await {
                return false;
            }
        }
        true
    }

    async fn send_delta(&mut self, added: Vec<Digest>, removed: Vec<Digest>) -> bool {
        let delta = Delta {
            seq: self.seq,
            added,
            removed,
        };
        self.seq += 1;
        self.send(Announcement::Delta(delta)).await
    }

    /// Whether the stream took the message.
    async fn send(&self, announcement: Announcement) -> bool {
        self.sender.send(announcement.into()).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Holdings;

    fn digest(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    #[test]
    fn a_stream_up_five_seconds_or_more_dropped_and_a_shorter_one_failed() {
        assert!(!dropped(None));
        assert!(!dropped(Some(Duration::from_millis(4999))));
        assert!(dropped(Some(STEADY)));
    }

    #[tokio::test]
    async fn deltas_count_up_from_the_snapshot_and_the_next_snapshot_names_the_next_delta() {
        let holdings = Holdings::default();
        holdings.add(digest(1));
        let (sender, mut sent) = mpsc::channel(16);
        let mut announcer = Announcer { sender, seq: 0 };
        let mut changes = announcer.snapshot(&holdings).await.unwrap();
        holdings.remove(&digest(1));
        holdings.add(digest(2));
        holdings.add(digest(3));
        for _ in 0..3 {
            let batch = changes.recv().await.unwrap();
            assert!(announcer.delta(&batch).await);
        }
        announcer.snapshot(&holdings).await.unwrap();
        let mut seqs = Vec::new();
        while let Ok(message) = sent.try_recv() {
            seqs.push(match Announcement::try_from(message).unwrap() {
                Announcement::Snapshot(snapshot) => ("snapshot", snapshot.seq),
                Announcement::Delta(delta) => ("delta", delta.seq),
                Announcement::Hello(_) => ("hello", 0),
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
}
