//! `speculaire-load`: D33's load scenario against one reflector, and whether it meets D33's targets (D104); and a blob
//! pulled from a peer again and again, for profiles ([`pull`], D116).
//!
//! [`run`] starts the reflector as a process of its own on a fake containerd, connects the simulated agents, each a
//! reflector client (D98) with its own node certificate, and then:
//!
//! 1. waits until the reflector holds every agent's digests;
//! 2. sends lookups and deltas at the scenario's rates, warms up, and measures over the steady phase the reflector's
//!    lookup p99 from its native histogram and its RSS from `/proc`;
//! 3. stops the deltas, restarts the reflector with SIGTERM, and times until it holds every digest again;
//! 4. stops the agents, then the reflector, which must exit with success.
//!
//! It runs on Linux only: the RSS comes from `/proc/<pid>/status`.

mod agents;
mod exposition;
mod node;
mod peer;
mod report;

use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context as _, ensure};
pub use peer::{Pulls, Timings, pull};
pub use report::{Measured, Report};
use speculaire_pki::testing::Cluster;
use speculaire_reflect::client::Config;
use tokio::time::Instant;

use crate::agents::Counts;
use crate::node::{Agent, Node};

/// The load applied.
#[derive(Clone, Debug)]
pub struct Scenario {
    /// Simulated agents, each a client with its own stream.
    pub agents: usize,
    /// The digests each agent announces.
    pub blobs: usize,
    /// The digests the agents draw theirs from, and the lookups ask for.
    pub pool: usize,
    /// Lookups a second, through random agents.
    pub lookups: u32,
    /// Deltas a second: a digest added or removed, as one `Delta` message.
    pub deltas: u32,
    /// The time over which the agents connect.
    pub join: Duration,
    /// Load before the measures start.
    pub warmup: Duration,
    /// Load over which the measures are taken.
    pub steady: Duration,
    /// The seed of every random choice: digests, holdings, and which agent does what.
    pub seed: u64,
}

impl Scenario {
    /// D33's scenario: 10k agents with 2k blobs each, 5k lookups and 1k deltas a second. Each digest of the pool has
    /// a hundred holders on average, more than `LOOKUP_PEERS`, so the lookups do the full work.
    pub const D33: Self = Self {
        agents: 10_000,
        blobs: 2_000,
        pool: 200_000,
        lookups: 5_000,
        deltas: 1_000,
        join: Duration::from_secs(30),
        warmup: Duration::from_secs(10),
        steady: Duration::from_mins(1),
        seed: 33,
    };
}

/// What a run must meet.
#[derive(Clone, Copy, Debug)]
pub struct Targets {
    /// The reflector's peak RSS, in bytes.
    pub rss: u64,
    /// The RSS goal, reported and never failing.
    pub rss_goal: u64,
    /// The reflector's lookup p99, server side.
    pub lookup_p99: Duration,
    /// From a reflector restart to every agent resynced.
    pub resync: Duration,
}

impl Targets {
    /// D33's targets.
    pub const D33: Self = Self {
        rss: 1 << 30,
        rss_goal: 256 << 20,
        lookup_p99: Duration::from_micros(500),
        resync: Duration::from_mins(1),
    };
}

/// What [`run`] does.
#[derive(Clone, Debug)]
pub struct Settings {
    /// The load.
    pub scenario: Scenario,
    /// What it must meet.
    pub targets: Targets,
    /// The reflector's command, before `agent --config <file>`: the `speculaire` binary, or a wrapper such as Valgrind
    /// followed by it.
    pub reflector: Vec<OsString>,
}

/// How long a fill may take after the last agent connected: past it, the first fails the run, and a resync is reported
/// missing.
const FILL: Duration = Duration::from_mins(5);

/// Runs the scenario against a reflector and measures it; missed targets are in the report, not errors.
///
/// # Errors
///
/// When the run cannot go on: too few file descriptors, the reflector does not start, exits with failure, or never
/// holds every agent's digests at first.
pub async fn run(settings: &Settings) -> anyhow::Result<Report> {
    let scenario = &settings.scenario;
    let mut report = Report {
        scenario: scenario.clone(),
        targets: settings.targets,
        measured: Measured::default(),
        cpus: std::thread::available_parallelism().map_or(1, usize::from),
    };
    let limits = std::fs::read_to_string("/proc/self/limits")
        .context("cannot read /proc/self/limits: the load runs on Linux")?;
    ensure_descriptors(&limits, scenario.agents)?;
    let cluster = Arc::new(Cluster::new("speculaire-load"));
    let node = Node::new(&cluster)?;
    let mut reflector = Agent::start(&settings.reflector, &node).await?;
    tracing::info!(agents = scenario.agents, "building the agents");
    let fleet = agents::build(scenario.clone(), cluster, node.ca(), node.path().to_owned()).await?;
    let config = Config {
        host: node.address.ip().to_string(),
        port: node.address.port(),
        peer: None,
    };
    tracing::info!("connecting the agents");
    let start = Instant::now();
    let fleet = fleet.connect(&config, scenario.join).await;
    let pairs = scenario.agents * scenario.blobs;
    reflector
        .settled(scenario.agents, pairs, FILL)
        .await?
        .context("the reflector never held every agent's digests")?;
    report.measured.first_fill = Some(start.elapsed());
    tracing::info!(first_fill = ?report.measured.first_fill, "the reflector holds every digest; loading");

    let counts = Arc::new(Counts::default());
    let mut rng = fastrand::Rng::with_seed(scenario.seed);
    let lookups = fleet.look_up(scenario.lookups, rng.fork(), &counts);
    let deltas = fleet.swap(scenario.deltas, rng.fork(), &counts);
    tokio::time::sleep(scenario.warmup).await;
    let before = reflector.lookups().await?;
    counts.failed.store(0, Ordering::Relaxed);
    counts.deltas.store(0, Ordering::Relaxed);
    tokio::time::sleep(scenario.steady).await;
    let answered = before.since(&reflector.lookups().await?)?;
    let seconds = scenario.steady.as_secs_f64();
    let m = &mut report.measured;
    #[expect(clippy::cast_precision_loss, reason = "counts stay far below 2^53")]
    {
        m.lookups_per_second = Some(answered.count() as f64 / seconds);
        m.deltas_per_second = Some(counts.deltas.load(Ordering::Relaxed) as f64 / seconds);
    }
    m.failed_lookups = Some(counts.failed.load(Ordering::Relaxed));
    m.lookup_p99 = answered.quantile(0.99);
    m.steady_rss = Some(reflector.memory("VmRSS")?);
    tracing::info!(measured = ?m, "steady phase done; restarting the reflector");

    deltas.abort();
    // The swaps in flight land, and the reflector's count of pairs is exact again.
    reflector.settled(scenario.agents, pairs, FILL).await?;
    let mut peak = reflector.memory("VmHWM")?;
    let stopping = Instant::now();
    reflector.stop().await?;
    let restart = Instant::now();
    tracing::info!(took = ?restart - stopping, peak, "the reflector stopped; starting it again");
    reflector = Agent::start(&settings.reflector, &node).await?;
    tracing::info!(took = ?restart.elapsed(), "the reflector is ready");
    m.resync = reflector
        .settled(scenario.agents, pairs, FILL)
        .await?
        .map(|_| restart.elapsed());
    lookups.abort();
    tracing::info!(resync = ?m.resync, "stopping");
    fleet.stop().await;
    let resync_peak = reflector.memory("VmHWM")?;
    tracing::info!(resync_peak, "the agents stopped");
    peak = peak.max(resync_peak);
    m.peak_rss = Some(peak);
    reflector.stop().await?;
    Ok(report)
}

/// Fails unless this process may open a socket for each agent's stream and one for its members, with room to spare;
/// the reflector, its child, inherits the same limit. `limits` is `/proc/self/limits`.
fn ensure_descriptors(limits: &str, agents: usize) -> anyhow::Result<()> {
    let soft = open_files(limits).context("no open-files limit in /proc/self/limits")?;
    let needed = 2 * agents + 1024;
    ensure!(
        soft >= needed,
        "the open-files limit is {soft}, and {agents} agents need {needed}: raise it with `ulimit -n`"
    );
    Ok(())
}

/// The soft limit of `Max open files` in `/proc/<pid>/limits`; `unlimited` is `usize::MAX`.
fn open_files(limits: &str) -> Option<usize> {
    let soft = limits
        .lines()
        .find_map(|line| line.strip_prefix("Max open files"))?
        .split_whitespace()
        .next()?;
    if soft == "unlimited" {
        Some(usize::MAX)
    } else {
        soft.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_soft_open_files_limit_is_read() {
        let limits = "Limit                     Soft Limit           Hard Limit           Units\n\
                      Max processes             63204                63204                processes\n\
                      Max open files            1024                 524288               files\n";
        assert_eq!(open_files(limits), Some(1024));
        assert_eq!(
            open_files(
                "Max open files            unlimited            unlimited            files\n"
            ),
            Some(usize::MAX)
        );
        assert_eq!(open_files("Max processes 1 1 processes\n"), None);
    }

    #[test]
    fn three_agents_need_two_descriptors_each_and_1024_to_spare() {
        let limits = |soft: usize| {
            format!("Max open files            {soft}                 524288               files\n")
        };
        assert!(ensure_descriptors(&limits(1030), 3).is_ok());
        assert!(ensure_descriptors(&limits(1029), 3).is_err());
        assert!(ensure_descriptors("Max processes 1 1 processes\n", 0).is_err());
    }
}
