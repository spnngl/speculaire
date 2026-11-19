//! The verification metrics of `docs/metrics.md`.

use std::time::Duration;

use metrics::{
    Unit, counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram,
};

/// `speculaire_verifications_total`: verifications, by `result` and `trigger`.
pub const VERIFICATIONS: &str = "speculaire_verifications_total";
/// `speculaire_verification_seconds`: the time from what triggered a verification to its verdict.
pub const SECONDS: &str = "speculaire_verification_seconds";
/// `speculaire_verdicts`: the verdicts kept, by `state`.
pub const VERDICTS: &str = "speculaire_verdicts";

/// Describes the verification metrics to the recorder.
pub fn describe() {
    describe_counter!(VERIFICATIONS, "Verifications, by result and trigger");
    describe_histogram!(
        SECONDS,
        Unit::Seconds,
        "The time from a verification's trigger to its verdict"
    );
    describe_gauge!(VERDICTS, "The verdicts kept, by state");
}

/// Counts one verification, started by `trigger`, that came to `result` in `took`.
pub(crate) fn verified(result: &'static str, trigger: &'static str, took: Duration) {
    counter!(VERIFICATIONS, "result" => result, "trigger" => trigger).increment(1);
    histogram!(SECONDS).record(took.as_secs_f64());
}

/// Sets how many verdicts are kept in `state`.
#[expect(
    clippy::cast_precision_loss,
    reason = "a count of verdicts stays far below 2^52"
)]
pub(crate) fn verdicts(state: &'static str, count: usize) {
    gauge!(VERDICTS, "state" => state).set(count as f64);
}
