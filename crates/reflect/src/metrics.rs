//! The metrics of the reflector and of its client (D34); `docs/metrics.md` lists them.

use metrics::{
    Gauge, Histogram, counter, describe_counter, describe_gauge, describe_histogram, gauge,
    histogram,
};

/// `speculaire_reflector_agents`: agents with an open `Announce` stream.
pub const AGENTS: &str = "speculaire_reflector_agents";
/// `speculaire_reflector_digests`: distinct digests in the index.
pub const DIGESTS: &str = "speculaire_reflector_digests";
/// `speculaire_reflector_pairs`: (digest, node) pairs in the index.
pub const PAIRS: &str = "speculaire_reflector_pairs";
/// `speculaire_reflector_lookup_seconds`: the time a `Lookup` takes in the reflector.
pub const LOOKUP: &str = "speculaire_reflector_lookup_seconds";
/// `speculaire_reflector_resync_seconds`: the time from accepting an agent's connection to holding its first
/// snapshot.
pub const RESYNC: &str = "speculaire_reflector_resync_seconds";
/// `speculaire_reflector_announce_rejected_total`: `Announce` streams refused, by `reason`.
pub const REJECTED: &str = "speculaire_reflector_announce_rejected_total";
/// `speculaire_reflector_prewarm_sent_total`: `Prewarm`s queued for agents, by `stage`: `seed` or `release` (D186).
pub const PREWARM_SENT: &str = "speculaire_reflector_prewarm_sent_total";
/// `speculaire_reflector_prewarm_rounds_total`: rounds of a wave ended, by `release`: `announced` or `timeout`
/// (D185).
pub const PREWARM_ROUNDS: &str = "speculaire_reflector_prewarm_rounds_total";
/// `speculaire_reflector_prewarm_waves_total`: waves started, by `cause`: `list`, `refresh` or `start` (D186).
pub const PREWARM_WAVES: &str = "speculaire_reflector_prewarm_waves_total";
/// `speculaire_reflector_prewarm_resolve_failures_total`: resolutions of a `prewarm.images` entry that failed (D186).
pub const PREWARM_RESOLVE_FAILURES: &str = "speculaire_reflector_prewarm_resolve_failures_total";

/// `speculaire_reflector_connected`: 1 while the `Announce` stream to the `member` is up.
pub const CONNECTED: &str = "speculaire_reflector_connected";
/// `speculaire_reflector_reconnects_total`: streams opened again to the `member` (D33).
pub const RECONNECTS: &str = "speculaire_reflector_reconnects_total";
/// `speculaire_lookup_seconds`: the time a `Lookup` takes for the agent, hedge included, by `result`: `hit`, `miss`,
/// `error` or `no_reflector`.
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

/// Which `Prewarm` of a wave: one to a seed, or one released to the other agents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Seed,
    Release,
}

/// How a round of a wave ended: each agent of it announced the image, or `prewarm.seed_timeout` passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Release {
    Announced,
    Timeout,
}

/// Why a wave started: its entry joined `prewarm.images`, a refresh found new platform manifests, or the reflector
/// started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cause {
    List,
    Refresh,
    Start,
}

impl Stage {
    const ALL: [Self; 2] = [Self::Seed, Self::Release];

    const fn label(self) -> &'static str {
        match self {
            Self::Seed => "seed",
            Self::Release => "release",
        }
    }
}

impl Release {
    const ALL: [Self; 2] = [Self::Announced, Self::Timeout];

    const fn label(self) -> &'static str {
        match self {
            Self::Announced => "announced",
            Self::Timeout => "timeout",
        }
    }
}

impl Cause {
    const ALL: [Self; 3] = [Self::List, Self::Refresh, Self::Start];

    const fn label(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Refresh => "refresh",
            Self::Start => "start",
        }
    }
}

/// Counts `count` `Prewarm`s queued at `stage`.
pub(crate) fn sent(stage: Stage, count: u64) {
    counter!(PREWARM_SENT, "stage" => stage.label()).increment(count);
}

/// Counts a round ended.
pub(crate) fn round(release: Release) {
    counter!(PREWARM_ROUNDS, "release" => release.label()).increment(1);
}

/// Counts a wave started.
pub(crate) fn wave(cause: Cause) {
    counter!(PREWARM_WAVES, "cause" => cause.label()).increment(1);
}

/// Counts a resolution failed.
pub(crate) fn resolve_failed() {
    counter!(PREWARM_RESOLVE_FAILURES).increment(1);
}

/// Describes the metrics and gives each series its zero, so that each exists from startup.
pub fn describe() {
    describe_gauge!(AGENTS, "Agents with an open Announce stream");
    describe_gauge!(DIGESTS, "Distinct digests in the reflector's index");
    describe_gauge!(PAIRS, "(digest, node) pairs in the reflector's index");
    describe_histogram!(LOOKUP, "Time a Lookup takes in the reflector");
    describe_histogram!(
        RESYNC,
        "Time from accepting an agent's connection to holding its first snapshot"
    );
    describe_counter!(REJECTED, "Announce streams the reflector refused");
    for gauge in [AGENTS, DIGESTS, PAIRS] {
        gauge!(gauge).set(0.0);
    }
    // Registering a histogram makes its series exist before the first sample.
    drop(histogram!(LOOKUP));
    drop(histogram!(RESYNC));
    for reason in Reason::ALL {
        counter!(REJECTED, "reason" => reason.label()).absolute(0);
    }
    describe_counter!(PREWARM_SENT, "Prewarm messages queued for agents");
    describe_counter!(PREWARM_ROUNDS, "Rounds of a prewarm wave ended");
    describe_counter!(PREWARM_WAVES, "Prewarm waves started");
    describe_counter!(
        PREWARM_RESOLVE_FAILURES,
        "Resolutions of a prewarm image that failed"
    );
    for stage in Stage::ALL {
        counter!(PREWARM_SENT, "stage" => stage.label()).absolute(0);
    }
    for release in Release::ALL {
        counter!(PREWARM_ROUNDS, "release" => release.label()).absolute(0);
    }
    for cause in Cause::ALL {
        counter!(PREWARM_WAVES, "cause" => cause.label()).absolute(0);
    }
    counter!(PREWARM_RESOLVE_FAILURES).absolute(0);
}

/// Describes the client's metrics. Its series are by member, so they appear with the first `Members` answer.
pub fn describe_client() {
    describe_gauge!(CONNECTED, "1 while the Announce stream to the member is up");
    describe_counter!(RECONNECTS, "Announce streams opened again to the member");
    describe_histogram!(
        CLIENT_LOOKUP,
        "Time a Lookup takes for the agent, hedge included"
    );
}

/// The client's `Lookup` times, by result.
#[derive(Debug)]
pub(crate) struct LookupSeries {
    pub(crate) hit: Histogram,
    pub(crate) miss: Histogram,
    pub(crate) error: Histogram,
    pub(crate) no_reflector: Histogram,
}

impl LookupSeries {
    /// Registers every series.
    pub(crate) fn new() -> Self {
        Self {
            hit: histogram!(CLIENT_LOOKUP, "result" => "hit"),
            miss: histogram!(CLIENT_LOOKUP, "result" => "miss"),
            error: histogram!(CLIENT_LOOKUP, "result" => "error"),
            no_reflector: histogram!(CLIENT_LOOKUP, "result" => "no_reflector"),
        }
    }
}

/// The reflector's series that its connections record.
#[derive(Debug)]
pub(crate) struct ServerSeries {
    pub(crate) lookup: Histogram,
    pub(crate) resync: Histogram,
}

impl ServerSeries {
    /// Registers every series.
    pub(crate) fn new() -> Self {
        Self {
            lookup: histogram!(LOOKUP),
            resync: histogram!(RESYNC),
        }
    }
}

/// Counts a refused stream.
pub(crate) fn rejected(reason: Reason) {
    counter!(REJECTED, "reason" => reason.label()).increment(1);
}

/// The size of the index.
#[derive(Debug)]
pub(crate) struct IndexSeries {
    agents: Gauge,
    digests: Gauge,
    pairs: Gauge,
}

impl Default for IndexSeries {
    /// Registers every series.
    fn default() -> Self {
        Self {
            agents: gauge!(AGENTS),
            digests: gauge!(DIGESTS),
            pairs: gauge!(PAIRS),
        }
    }
}

impl IndexSeries {
    /// Sets the size of the index.
    #[expect(
        clippy::cast_precision_loss,
        reason = "a gauge is an f64; the index never nears 2^52 entries"
    )]
    pub(crate) fn set(&self, agents: usize, digests: usize, pairs: u64) {
        self.agents.set(agents as f64);
        self.digests.set(digests as f64);
        self.pairs.set(pairs as f64);
    }
}
