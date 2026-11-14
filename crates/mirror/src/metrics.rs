//! The mirror's metrics (D34); `docs/metrics.md` lists them.

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge};

use crate::request::Kind;

/// `speculaire_mirror_requests_total`: requests from the runtime, by `kind` and `result`.
pub const REQUESTS: &str = "speculaire_mirror_requests_total";
/// `speculaire_mirror_bytes_total`: bytes served to the runtime, by `source`.
pub const BYTES: &str = "speculaire_mirror_bytes_total";
/// `speculaire_mirror_first_byte_seconds`: from the request to the first byte, or to the 404 of a *fall through*.
pub const FIRST_BYTE: &str = "speculaire_mirror_first_byte_seconds";

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
/// `speculaire_peer_fetches_total`: requests to other agents, by `result`.
pub const FETCHES: &str = "speculaire_peer_fetches_total";
/// `speculaire_peer_hedges_total`: hedged extra requests to other agents.
pub const HEDGES: &str = "speculaire_peer_hedges_total";

/// What became of a pull request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The mirror served it.
    Served,
    /// The mirror does not hold it: a 404, and the runtime goes on.
    FallThrough,
    /// The mirror holds it, or may, and failed: also a 404.
    Error,
}

impl Outcome {
    /// Every result, in the order of the catalog.
    pub const ALL: [Self; 3] = [Self::Served, Self::FallThrough, Self::Error];

    /// The `result` label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::FallThrough => "fall_through",
            Self::Error => "error",
        }
    }
}

/// Describes the metrics and gives every series of the requests counter its zero, so that each exists from startup.
pub fn describe() {
    describe_counter!(REQUESTS, "Requests from the runtime to the local mirror");
    describe_counter!(
        BYTES,
        "Bytes served to the runtime, by source: local, peer or upstream"
    );
    describe_histogram!(
        FIRST_BYTE,
        "Time from request to first byte, or to the 404 of a fall through"
    );
    for kind in [Kind::Manifest, Kind::Blob, Kind::Referrers] {
        for result in Outcome::ALL {
            counter!(REQUESTS, "kind" => kind.label(), "result" => result.label()).absolute(0);
        }
        // Registering a histogram makes its series exist before the first sample.
        drop(metrics::histogram!(FIRST_BYTE, "kind" => kind.label()));
    }
    counter!(BYTES, "source" => "local").absolute(0);
}

/// What became of a peer request: served from what the node holds, or turned away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Uploaded {
    /// The peer API served it.
    Served,
    /// The peer API answered 503: at `peer.max_uploads`, or stopping (D24, D39).
    Busy,
}

impl Uploaded {
    /// The `result` label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::Busy => "busy",
        }
    }
}

/// Describes the peer API's metrics and gives each its zero, on every agent.
pub fn describe_peer() {
    describe_counter!(
        UPLOADS,
        "Requests to the peer API that found what they named; busy answered 503"
    );
    describe_gauge!(UPLOADS_IN_FLIGHT, "Blob bodies now being sent");
    describe_counter!(UPLOAD_BYTES, "Blob bytes sent to other agents");
    for result in [Uploaded::Served, Uploaded::Busy] {
        counter!(UPLOADS, "result" => result.label()).absolute(0);
    }
    gauge!(UPLOADS_IN_FLIGHT).set(0.0);
    counter!(UPLOAD_BYTES).absolute(0);
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
    /// Every result, in the order of the catalog.
    pub const ALL: [Self; 5] = [
        Self::Ok,
        Self::DigestMismatch,
        Self::Busy,
        Self::Timeout,
        Self::Error,
    ];

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

/// Describes the fetcher's metrics and gives each its zero, on every agent.
pub fn describe_fetch() {
    describe_counter!(
        FETCHES,
        "Requests to other agents, by how they ended; timeout includes a stalled one"
    );
    describe_counter!(HEDGES, "Hedged extra requests to other agents");
    for result in Fetched::ALL {
        counter!(FETCHES, "result" => result.label()).absolute(0);
    }
    counter!(HEDGES).absolute(0);
    counter!(BYTES, "source" => "peer").absolute(0);
}

/// Counts how a request to a peer ended.
pub fn fetched(result: Fetched) {
    counter!(FETCHES, "result" => result.label()).increment(1);
}

/// Counts a hedged request.
pub fn hedged() {
    counter!(HEDGES).increment(1);
}

/// Counts bytes served to the runtime that came from peers.
pub fn peer_bytes(bytes: usize) {
    counter!(BYTES, "source" => "peer").increment(bytes as u64);
}

/// Counts a peer request.
pub fn upload(result: Uploaded) {
    counter!(UPLOADS, "result" => result.label()).increment(1);
}

/// Sets the blob bodies in flight.
#[expect(
    clippy::cast_precision_loss,
    reason = "a count of uploads, far below 2^53"
)]
pub fn uploads_in_flight(uploads: usize) {
    gauge!(UPLOADS_IN_FLIGHT).set(uploads as f64);
}

/// Counts bytes sent to another agent.
pub fn upload_bytes(bytes: usize) {
    counter!(UPLOAD_BYTES).increment(bytes as u64);
}

/// Describes the relay's metrics and gives each its zero, on a node whose mirror relays (CRI-O, D66).
pub fn describe_relay() {
    describe_gauge!(CACHE_BYTES, "Size of the blob cache");
    describe_counter!(
        CACHE_EVICTIONS,
        "Blobs evicted from the blob cache above blob_cache.max_size"
    );
    counter!(BYTES, "source" => "upstream").absolute(0);
    counter!(CACHE_EVICTIONS).absolute(0);
    gauge!(CACHE_BYTES).set(0.0);
}

/// Sets the size of the blob cache.
#[expect(
    clippy::cast_precision_loss,
    reason = "a gauge of bytes: a cache of 2^53 bytes is 8 PiB"
)]
pub fn cache_bytes(bytes: u64) {
    gauge!(CACHE_BYTES).set(bytes as f64);
}

/// Counts a blob evicted from the cache.
pub fn cache_eviction() {
    counter!(CACHE_EVICTIONS).increment(1);
}

/// Counts bytes relayed from upstream.
pub fn upstream_bytes(bytes: usize) {
    counter!(BYTES, "source" => "upstream").increment(bytes as u64);
}

/// Counts a request.
pub fn request(kind: Kind, result: Outcome) {
    counter!(REQUESTS, "kind" => kind.label(), "result" => result.label()).increment(1);
}

/// Counts bytes sent from this node's own content.
pub fn local_bytes(bytes: usize) {
    counter!(BYTES, "source" => "local").increment(bytes as u64);
}

/// Records the time to the first byte.
pub fn first_byte(kind: Kind, seconds: f64) {
    metrics::histogram!(FIRST_BYTE, "kind" => kind.label()).record(seconds);
}
