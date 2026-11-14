//! The metrics of the reflector and of its client (D34); `docs/metrics.md` lists them.

use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge};

/// `speculaire_reflector_agents`: agents with an open `Announce` stream.
pub const AGENTS: &str = "speculaire_reflector_agents";
/// `speculaire_reflector_digests`: distinct digests in the index.
pub const DIGESTS: &str = "speculaire_reflector_digests";
/// `speculaire_reflector_pairs`: (digest, node) pairs in the index.
pub const PAIRS: &str = "speculaire_reflector_pairs";
/// `speculaire_reflector_lookup_seconds`: the time a `Lookup` takes in the reflector.
pub const LOOKUP: &str = "speculaire_reflector_lookup_seconds";
/// `speculaire_reflector_announce_rejected_total`: `Announce` streams refused, by `reason`.
pub const REJECTED: &str = "speculaire_reflector_announce_rejected_total";

/// `speculaire_reflector_connected`: 1 while the `Announce` stream to the `member` is up.
pub const CONNECTED: &str = "speculaire_reflector_connected";
/// `speculaire_reflector_reconnects_total`: streams opened again to the `member` (D33).
pub const RECONNECTS: &str = "speculaire_reflector_reconnects_total";
/// `speculaire_lookup_seconds`: the time a `Lookup` takes for the agent, hedge included, by `result`: `hit`, `miss`
/// or `error`.
pub const CLIENT_LOOKUP: &str = "speculaire_lookup_seconds";

/// Why the reflector ended an `Announce` stream; `docs/operations.md` explains each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The `Hello` names another node than the TLS peer's certificate.
    Identity,
    /// The `Hello` speaks a protocol version the reflector does not accept.
    Version,
    /// The peer address in the `Hello` is not an IP address with a port.
    Address,
    /// A message is larger than the limit.
    Size,
    /// The agent announces more digests than the limit.
    Digests,
    /// A message is not one the protocol allows there: no `Hello` first, a second `Hello`, an empty message or a
    /// string that is no digest.
    Malformed,
}

impl Reason {
    /// Every reason, in the order of the catalog.
    pub const ALL: [Self; 6] = [
        Self::Identity,
        Self::Version,
        Self::Address,
        Self::Size,
        Self::Digests,
        Self::Malformed,
    ];

    /// The `reason` label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Version => "version",
            Self::Address => "address",
            Self::Size => "size",
            Self::Digests => "digests",
            Self::Malformed => "malformed",
        }
    }
}

/// Describes the metrics and gives each series its zero, so that each exists from startup.
pub fn describe() {
    describe_gauge!(AGENTS, "Agents with an open Announce stream");
    describe_gauge!(DIGESTS, "Distinct digests in the reflector's index");
    describe_gauge!(PAIRS, "(digest, node) pairs in the reflector's index");
    describe_histogram!(LOOKUP, "Time a Lookup takes in the reflector");
    describe_counter!(REJECTED, "Announce streams the reflector refused");
    for gauge in [AGENTS, DIGESTS, PAIRS] {
        gauge!(gauge).set(0.0);
    }
    // Registering a histogram makes its series exist before the first sample.
    drop(metrics::histogram!(LOOKUP));
    for reason in Reason::ALL {
        counter!(REJECTED, "reason" => reason.label()).absolute(0);
    }
}

/// Describes the client's metrics. Its series are by member, so they appear with the first `Members` answer.
pub fn describe_client() {
    describe_gauge!(CONNECTED, "1 while the Announce stream to the member is up");
    describe_counter!(RECONNECTS, "Announce streams opened again to the member");
    describe_histogram!(
        CLIENT_LOOKUP,
        "Time a Lookup takes for the agent, hedge included"
    );
    for result in ["hit", "miss", "error"] {
        drop(metrics::histogram!(CLIENT_LOOKUP, "result" => result));
    }
}

/// Counts a refused stream.
pub(crate) fn rejected(reason: Reason) {
    counter!(REJECTED, "reason" => reason.label()).increment(1);
}

/// Sets the size of the index.
#[expect(
    clippy::cast_precision_loss,
    reason = "a gauge is an f64; the index never nears 2^52 entries"
)]
pub(crate) fn index(agents: usize, digests: usize, pairs: u64) {
    gauge!(AGENTS).set(agents as f64);
    gauge!(DIGESTS).set(digests as f64);
    gauge!(PAIRS).set(pairs as f64);
}
