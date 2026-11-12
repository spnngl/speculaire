//! The mirror's metrics (D34); `docs/metrics.md` lists them.

use metrics::{counter, describe_counter, describe_histogram};

use crate::request::Kind;

/// `speculaire_mirror_requests_total`: requests from the runtime, by `kind` and `result`.
pub const REQUESTS: &str = "speculaire_mirror_requests_total";
/// `speculaire_mirror_bytes_total`: bytes served to the runtime, by `source`.
pub const BYTES: &str = "speculaire_mirror_bytes_total";
/// `speculaire_mirror_first_byte_seconds`: from the request to the first byte, or to the 404 of a *fall through*.
pub const FIRST_BYTE: &str = "speculaire_mirror_first_byte_seconds";

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
