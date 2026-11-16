//! The artifact metrics of `docs/metrics.md`.

use metrics::{counter, describe_counter, describe_gauge, gauge};

/// `speculaire_artifact_fetches_total`: requests for artifacts, by `source`, `upstream` and `result` (D38, D50).
pub const FETCHES: &str = "speculaire_artifact_fetches_total";
/// `speculaire_artifact_store_bytes`: the size of the artifact store.
pub const STORE_BYTES: &str = "speculaire_artifact_store_bytes";

/// The `upstream` label of a registry the registry config has no entry of (D50).
pub const OTHER: &str = "other";

/// Describes the artifact metrics to the recorder.
pub fn describe() {
    describe_counter!(FETCHES, "Requests for artifacts, by source and result");
    describe_gauge!(STORE_BYTES, "The size of the artifact store");
}

/// What one request for an artifact came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The registry answered what was asked.
    Ok,
    /// The registry has no such thing.
    NotFound,
    /// The content is not what its digest says.
    DigestMismatch,
    /// The registry answered 429 (D38).
    RateLimited,
    /// Anything else: no answer, another status, a body too large.
    Error,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotFound => "not_found",
            Self::DigestMismatch => "digest_mismatch",
            Self::RateLimited => "rate_limited",
            Self::Error => "error",
        }
    }
}

/// Counts one request to the upstream labelled `upstream`.
pub(crate) fn fetched(upstream: &str, result: Outcome) {
    counter!(
        FETCHES,
        "source" => "upstream",
        "upstream" => upstream.to_owned(),
        "result" => result.label(),
    )
    .increment(1);
}

pub(crate) fn store_bytes(bytes: u64) {
    #[expect(
        clippy::cast_precision_loss,
        reason = "a gauge is a float; a store below 2^53 bytes is exact"
    )]
    gauge!(STORE_BYTES).set(bytes as f64);
}

#[cfg(test)]
mod tests;
