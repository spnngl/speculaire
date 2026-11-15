//! The mirror's metrics (D34); `docs/metrics.md` lists them.
//!
//! Each owner registers its series once, when it is built, and keeps the handles: a request never looks a series up
//! by name (D107). Registering makes a series exist from then on, at zero.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use hyper::Response;
use hyper::body::{Frame, SizeHint};
use hyper::header::CONTENT_LENGTH;
use metrics::{
    Counter, Gauge, Histogram, counter, describe_counter, describe_gauge, describe_histogram,
    gauge, histogram,
};

use crate::pulls::Body;
use crate::request::Kind;

/// `speculaire_mirror_requests_total`: requests from the runtime, by `kind` and `result`.
pub const REQUESTS: &str = "speculaire_mirror_requests_total";
/// `speculaire_mirror_bytes_total`: bytes served to the runtime, by `source`.
pub const BYTES: &str = "speculaire_mirror_bytes_total";
/// `speculaire_mirror_first_byte_seconds`: from the request to the first byte, or to the 404 of a *fall through*, by
/// `kind` and `source`.
pub const FIRST_BYTE: &str = "speculaire_mirror_first_byte_seconds";
/// `speculaire_mirror_body_seconds`: from the request to the last byte of a body, by `kind` and `source`.
pub const BODY: &str = "speculaire_mirror_body_seconds";

/// `speculaire_blob_cache_bytes`: the size of the blob cache (D67).
pub const CACHE_BYTES: &str = "speculaire_blob_cache_bytes";
/// `speculaire_blob_cache_evictions_total`: blobs evicted above `blob_cache.max_size` (D67).
pub const CACHE_EVICTIONS: &str = "speculaire_blob_cache_evictions_total";

/// `speculaire_peer_uploads_total`: requests from other agents, by `result` (D24).
pub const UPLOADS: &str = "speculaire_peer_uploads_total";
/// `speculaire_peer_uploads_in_flight`: blob bodies the peer API is sending.
pub const UPLOADS_IN_FLIGHT: &str = "speculaire_peer_uploads_in_flight";
/// `speculaire_peer_upload_bytes_total`: blob bytes the peer API sent.
pub const UPLOAD_BYTES: &str = "speculaire_peer_upload_bytes_total";
/// `speculaire_peer_upload_seconds`: from a peer's request to the last byte of the blob body sent.
pub const UPLOAD_SECONDS: &str = "speculaire_peer_upload_seconds";
/// `speculaire_peer_fetches_total`: requests to other agents, by `result`.
pub const FETCHES: &str = "speculaire_peer_fetches_total";
/// `speculaire_peer_hedges_total`: hedged extra requests to other agents.
pub const HEDGES: &str = "speculaire_peer_hedges_total";
/// Time from the start of a request to a peer to its end, by `result`.
pub const FETCH_SECONDS: &str = "speculaire_peer_fetch_seconds";

/// Where the bytes of a served answer came from: the `source` label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// This node's own content, or the relay's blob cache.
    Local,
    /// Other agents, through the fetcher (D7).
    Peer,
    /// The registry, through the relay (D66).
    Upstream,
}

impl Source {
    /// The `source` label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Peer => "peer",
            Self::Upstream => "upstream",
        }
    }
}

/// What became of a pull request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The mirror served it, from `Source`.
    Served(Source),
    /// The mirror does not hold it: a 404, and the runtime goes on.
    FallThrough,
    /// The mirror holds it, or may, and failed: also a 404.
    Error,
}

/// Describes the pull API's metrics, on every agent.
pub fn describe() {
    describe_counter!(REQUESTS, "Requests from the runtime to the local mirror");
    describe_counter!(
        BYTES,
        "Blob bytes served to the runtime, by source: local, peer or upstream"
    );
    describe_histogram!(
        FIRST_BYTE,
        "Time from request to first byte, or to the 404 of a fall through"
    );
    describe_histogram!(BODY, "Time from request to the last byte of a body");
}

/// One value for each kind of request.
struct ByKind<T> {
    manifest: T,
    blob: T,
    referrers: T,
}

impl<T> ByKind<T> {
    fn new(mut make: impl FnMut(Kind) -> T) -> Self {
        Self {
            manifest: make(Kind::Manifest),
            blob: make(Kind::Blob),
            referrers: make(Kind::Referrers),
        }
    }

    const fn get(&self, kind: Kind) -> &T {
        match kind {
            Kind::Manifest => &self.manifest,
            Kind::Blob => &self.blob,
            Kind::Referrers => &self.referrers,
        }
    }
}

/// One value for each source.
struct BySource<T> {
    local: T,
    peer: T,
    upstream: T,
}

impl<T> BySource<T> {
    fn new(mut make: impl FnMut(Source) -> T) -> Self {
        Self {
            local: make(Source::Local),
            peer: make(Source::Peer),
            upstream: make(Source::Upstream),
        }
    }

    const fn get(&self, source: Source) -> &T {
        match source {
            Source::Local => &self.local,
            Source::Peer => &self.peer,
            Source::Upstream => &self.upstream,
        }
    }
}

/// The series of one kind of request.
struct KindSeries {
    served: Counter,
    fall_through: Counter,
    error: Counter,
    first_byte: BySource<Histogram>,
    /// The first byte of a 404, whether a *fall through* or an error.
    first_404: Histogram,
    body: BySource<Histogram>,
}

/// The pull API's series.
pub(crate) struct PullSeries {
    kinds: ByKind<KindSeries>,
    bytes: BySource<Counter>,
}

impl PullSeries {
    /// Registers every series.
    pub(crate) fn new() -> Self {
        let kinds = ByKind::new(|kind| {
            let kind = kind.label();
            let requests = |result| counter!(REQUESTS, "kind" => kind, "result" => result);
            KindSeries {
                served: requests("served"),
                fall_through: requests("fall_through"),
                error: requests("error"),
                first_byte: BySource::new(
                    |source| histogram!(FIRST_BYTE, "kind" => kind, "source" => source.label()),
                ),
                first_404: histogram!(FIRST_BYTE, "kind" => kind, "source" => "fall_through"),
                body: BySource::new(
                    |source| histogram!(BODY, "kind" => kind, "source" => source.label()),
                ),
            }
        });
        let bytes = BySource::new(|source| counter!(BYTES, "source" => source.label()));
        Self { kinds, bytes }
    }

    /// Counts a request of `kind`, `started` then, whose response head is ready.
    pub(crate) fn answered(&self, kind: Kind, outcome: Outcome, started: Instant) {
        let series = self.kinds.get(kind);
        let (requests, first_byte) = match outcome {
            Outcome::Served(source) => (&series.served, series.first_byte.get(source)),
            Outcome::FallThrough => (&series.fall_through, &series.first_404),
            Outcome::Error => (&series.error, &series.first_404),
        };
        requests.increment(1);
        first_byte.record(started.elapsed());
    }

    /// `response`, served from `source`, measured: a blob's bytes are counted (D100), and the time from `started` to
    /// the body's last byte is recorded.
    pub(crate) fn measure(
        &self,
        kind: Kind,
        source: Source,
        started: Instant,
        response: Response<Body>,
    ) -> Response<Body> {
        let bytes = match kind {
            Kind::Blob => self.bytes.get(source).clone(),
            Kind::Manifest | Kind::Referrers => Counter::noop(),
        };
        let seconds = self.kinds.get(kind).body.get(source).clone();
        Metered::wrap(response, bytes, seconds, started, Body::new)
    }
}

/// A body that counts its bytes, and records the time from `started` to its end. A body that breaks off, or that
/// hyper drops before its end, records no time: the client did not get it.
pub(crate) struct Metered<B> {
    body: B,
    /// The bytes `Content-Length` says are still to come.
    left: Option<u64>,
    bytes: Counter,
    seconds: Histogram,
    /// `None` once the end is recorded.
    started: Option<Instant>,
}

impl<B> Metered<B> {
    /// `response` with its body metered, then made a `T` by `into`.
    pub(crate) fn wrap<T>(
        response: Response<B>,
        bytes: Counter,
        seconds: Histogram,
        started: Instant,
        into: impl FnOnce(Self) -> T,
    ) -> Response<T> {
        let left = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok()?.parse().ok());
        response.map(|body| {
            into(Self {
                body,
                left,
                bytes,
                seconds,
                started: Some(started),
            })
        })
    }

    fn end(&mut self) {
        if let Some(started) = self.started.take() {
            self.seconds.record(started.elapsed());
        }
    }
}

impl<B> hyper::body::Body for Metered<B>
where
    B: hyper::body::Body<Data = Bytes, Error = io::Error> + Unpin,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.body).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let sent = count(data.len());
                    this.bytes.increment(sent);
                    this.left = this.left.map(|left| left.saturating_sub(sent));
                }
                // hyper stops polling a body once it has sent `Content-Length` bytes, or once the body says it has
                // ended (hyper 1.12.0 `src/proto/h1/dispatch.rs:392`).
                if this.left == Some(0) || this.body.is_end_stream() {
                    this.end();
                }
            }
            Poll::Ready(None) => this.end(),
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
        }
        polled
    }

    // Delegated, so that hyper frames a body without `Content-Length` as it would unwrapped.
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

/// A length as a count.
fn count(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// What became of a peer request: served from what the node holds, or turned away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Uploaded {
    /// The peer API served it.
    Served,
    /// The peer API answered 503: at `peer.max_uploads`, or stopping (D24, D39).
    Busy,
}

/// Describes the peer API's metrics, on every agent.
pub fn describe_peer() {
    describe_counter!(
        UPLOADS,
        "Requests to the peer API that found what they named; busy answered 503"
    );
    describe_gauge!(UPLOADS_IN_FLIGHT, "Blob bodies now being sent");
    describe_counter!(UPLOAD_BYTES, "Blob bytes sent to other agents");
    describe_histogram!(
        UPLOAD_SECONDS,
        "Time from a peer's request to the last byte of the blob body sent"
    );
}

/// The peer API's series.
#[derive(Debug)]
pub(crate) struct PeerSeries {
    served: Counter,
    busy: Counter,
    in_flight: Gauge,
    bytes: Counter,
    seconds: Histogram,
}

impl PeerSeries {
    /// Registers every series.
    pub(crate) fn new() -> Self {
        Self {
            served: counter!(UPLOADS, "result" => "served"),
            busy: counter!(UPLOADS, "result" => "busy"),
            in_flight: gauge!(UPLOADS_IN_FLIGHT),
            bytes: counter!(UPLOAD_BYTES),
            seconds: histogram!(UPLOAD_SECONDS),
        }
    }

    /// Counts a peer request.
    pub(crate) fn upload(&self, result: Uploaded) {
        match result {
            Uploaded::Served => &self.served,
            Uploaded::Busy => &self.busy,
        }
        .increment(1);
    }

    /// Sets the blob bodies in flight.
    pub(crate) fn in_flight(&self, uploads: usize) {
        self.in_flight.set(gauge_value(count(uploads)));
    }

    /// `response`, a blob for a peer, with its body measured from `started` then made a `T` by `into`.
    pub(crate) fn measure<B, T>(
        &self,
        started: Instant,
        response: Response<B>,
        into: impl FnOnce(Metered<B>) -> T,
    ) -> Response<T> {
        Metered::wrap(
            response,
            self.bytes.clone(),
            self.seconds.clone(),
            started,
            into,
        )
    }
}

/// A gauge's value from a count.
#[expect(
    clippy::cast_precision_loss,
    reason = "counts of uploads and of cached bytes, far below 2^53 (8 PiB)"
)]
const fn gauge_value(value: u64) -> f64 {
    value as f64
}

/// How a request to a peer ended (D7, D24, D52, D73).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fetched {
    /// It gave the end of a blob whose digest matched.
    Ok,
    /// It gave the end of a blob whose digest did not match.
    DigestMismatch,
    /// It answered 503.
    Busy,
    /// It sent nothing for `peer.stall_timeout`.
    Timeout,
    /// Anything else: no connection, a refused certificate, a 404, a head that is not the one asked for, a body that
    /// broke off.
    Error,
}

impl Fetched {
    /// The `result` label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::DigestMismatch => "digest_mismatch",
            Self::Busy => "busy",
            Self::Timeout => "timeout",
            Self::Error => "error",
        }
    }
}

/// Describes the fetcher's metrics, on every agent.
pub fn describe_fetch() {
    describe_counter!(
        FETCHES,
        "Requests to other agents, by how they ended; timeout includes a stalled one"
    );
    describe_counter!(HEDGES, "Hedged extra requests to other agents");
    describe_histogram!(
        FETCH_SECONDS,
        "Time from the start of a request to another agent to its end"
    );
}

/// The fetcher's series.
pub(crate) struct FetchSeries {
    ok: Ended,
    digest_mismatch: Ended,
    busy: Ended,
    timeout: Ended,
    error: Ended,
    hedges: Counter,
}

/// The series of requests to peers that ended one way.
struct Ended {
    count: Counter,
    seconds: Histogram,
}

impl Ended {
    fn new(result: Fetched) -> Self {
        Self {
            count: counter!(FETCHES, "result" => result.label()),
            seconds: histogram!(FETCH_SECONDS, "result" => result.label()),
        }
    }
}

impl FetchSeries {
    /// Registers every series.
    pub(crate) fn new() -> Self {
        Self {
            ok: Ended::new(Fetched::Ok),
            digest_mismatch: Ended::new(Fetched::DigestMismatch),
            busy: Ended::new(Fetched::Busy),
            timeout: Ended::new(Fetched::Timeout),
            error: Ended::new(Fetched::Error),
            hedges: counter!(HEDGES),
        }
    }

    /// Counts a request to a peer that ended as `result` after `took`.
    pub(crate) fn fetched(&self, result: Fetched, took: Duration) {
        let ended = match result {
            Fetched::Ok => &self.ok,
            Fetched::DigestMismatch => &self.digest_mismatch,
            Fetched::Busy => &self.busy,
            Fetched::Timeout => &self.timeout,
            Fetched::Error => &self.error,
        };
        ended.count.increment(1);
        ended.seconds.record(took);
    }

    /// Counts a hedged request.
    pub(crate) fn hedged(&self) {
        self.hedges.increment(1);
    }
}

/// Describes the blob cache's metrics, on a node whose mirror relays (CRI-O, D66).
pub fn describe_relay() {
    describe_gauge!(CACHE_BYTES, "Size of the blob cache");
    describe_counter!(
        CACHE_EVICTIONS,
        "Blobs evicted from the blob cache above blob_cache.max_size"
    );
}

/// The blob cache's series.
#[derive(Debug)]
pub(crate) struct CacheSeries {
    bytes: Gauge,
    evictions: Counter,
}

impl CacheSeries {
    /// Registers every series.
    pub(crate) fn new() -> Self {
        Self {
            bytes: gauge!(CACHE_BYTES),
            evictions: counter!(CACHE_EVICTIONS),
        }
    }

    /// Sets the size of the blob cache.
    pub(crate) fn size(&self, bytes: u64) {
        self.bytes.set(gauge_value(bytes));
    }

    /// Counts a blob evicted from the cache.
    pub(crate) fn evicted(&self) {
        self.evictions.increment(1);
    }
}

#[cfg(test)]
mod tests;
