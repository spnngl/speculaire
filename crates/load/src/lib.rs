//! `speculaire-load`: D33's load scenario against one reflector, or two with a prewarm wave, and whether it meets D33's
//! targets (D104, D193); and a blob pulled from a peer again and again, for profiles ([`pull`], D116).
//!
//! [`run`] starts the reflector as a process of its own on a fake containerd, two members of one set with
//! [`Scenario::prewarm`], connects the simulated agents, each a reflector client (D98) with its own node certificate,
//! and then:
//!
//! 1. waits until each reflector holds every agent's digests;
//! 2. sends lookups and deltas at the scenario's rates, warms up, and measures over the steady phase the reflectors'
//!    lookup p99 from their native histograms and their RSS from `/proc`. With [`Scenario::prewarm`], the steady
//!    phase starts a wave of one image on both and lasts until every agent announced it (D185);
//! 3. stops the deltas and, with one reflector, restarts it with SIGTERM and times until it holds every digest again;
//! 4. stops the agents, then the reflectors, which must exit with success.
//!
//! It runs on Linux only: the RSS comes from `/proc/<pid>/status`.

mod agents;
mod exposition;
mod node;
mod peer;
mod prewarm;
mod report;

use std::ffi::OsString;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::{Context as _, ensure};
pub use peer::{Pulls, Timings, pull};
pub use prewarm::Wave;
pub use report::{Measured, Report};
use speculaire_pki::testing::Cluster;
use speculaire_reflect::client::Config;
use tokio::time::Instant;

use crate::agents::Counts;
use crate::node::{Agent, Node};
use crate::prewarm::{Received, Registry};

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
    /// Two reflectors, and a wave of one image over the steady phase (D193).
    pub prewarm: bool,
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
        prewarm: false,
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

/// Runs the scenario against the reflectors and measures them; missed targets are in the report, not errors.
///
/// # Errors
///
/// When the run cannot go on: too few file descriptors, a reflector does not start, exits with failure, or never
/// holds every agent's digests at first.
pub async fn run(settings: &Settings) -> anyhow::Result<Report> {
    let scenario = &settings.scenario;
    let mut report = Report {
        scenario: scenario.clone(),
        targets: settings.targets,
        measured: Measured::default(),
        cpus: std::thread::available_parallelism().map_or(1, usize::from),
    };
    let names = names(scenario.prewarm);
    let limits = std::fs::read_to_string("/proc/self/limits")
        .context("cannot read /proc/self/limits: the load runs on Linux")?;
    ensure_descriptors(&limits, scenario.agents, names.len())?;
    let cluster = Arc::new(Cluster::new("speculaire-load"));
    let nodes = Node::reflectors(&cluster, names)?;
    let first = nodes.first().context("no reflector")?;
    let mut reflectors = start(&settings.reflector, &nodes).await?;
    // Another seed than the pool's: the image's layers are none of the digests the deltas swap.
    let registry = if scenario.prewarm {
        Some(Registry::start(scenario.seed.wrapping_add(1)).await?)
    } else {
        None
    };
    tracing::info!(agents = scenario.agents, "building the agents");
    let fleet = agents::build(
        scenario.clone(),
        cluster,
        first.ca(),
        first.path().to_owned(),
    )
    .await?;
    let config = Config {
        host: first.address.ip().to_string(),
        port: first.address.port(),
        peer: None,
    };
    tracing::info!("connecting the agents");
    let begin = Instant::now();
    let received = Arc::new(Received::default());
    let pushes = |agent, holdings: &_| match &registry {
        Some(registry) => prewarm::answer_prewarm(agent, holdings, &registry.layers, &received),
        None => agents::drop_pushes(agent, holdings),
    };
    let fleet = fleet.connect(&config, scenario.join, pushes).await;
    let mut pairs = scenario.agents * scenario.blobs;
    settled(&reflectors, scenario.agents, pairs)
        .await?
        .context("a reflector never held every agent's digests")?;
    report.measured.first_fill = Some(begin.elapsed());
    tracing::info!(first_fill = ?report.measured.first_fill, "the reflectors hold every digest; loading");

    let counts = Arc::new(Counts::default());
    let mut rng = fastrand::Rng::with_seed(scenario.seed);
    let lookups = fleet.look_up(scenario.lookups, rng.fork(), &counts);
    let deltas = fleet.swap(scenario.deltas, rng.fork(), &counts);
    tokio::time::sleep(scenario.warmup).await;
    measure(
        scenario,
        &nodes,
        &reflectors,
        registry.as_ref(),
        &received,
        &counts,
        &mut report.measured,
    )
    .await?;
    if scenario.prewarm {
        pairs += scenario.agents * prewarm::LAYERS;
    }
    let m = &mut report.measured;
    tracing::info!(measured = ?m, "steady phase done");

    deltas.abort();
    // The swaps in flight land, and the reflectors' count of pairs is exact again.
    settled(&reflectors, scenario.agents, pairs).await?;
    let mut peak = peak_rss(&reflectors)?;
    // The resync is the run of one reflector's: two restarted share the runner with twice the streams (D193).
    if !scenario.prewarm {
        let stopping = Instant::now();
        for reflector in reflectors {
            reflector.stop().await?;
        }
        let restart = Instant::now();
        tracing::info!(took = ?restart - stopping, peak, "the reflector stopped; starting it again");
        reflectors = start(&settings.reflector, &nodes).await?;
        tracing::info!(took = ?restart.elapsed(), "the reflector is ready");
        m.resync = settled(&reflectors, scenario.agents, pairs)
            .await?
            .map(|_| restart.elapsed());
    }
    lookups.abort();
    tracing::info!(resync = ?m.resync, "stopping");
    fleet.stop().await;
    let resync_peak = peak_rss(&reflectors)?;
    tracing::info!(resync_peak, "the agents stopped");
    peak = peak.max(resync_peak);
    m.peak_rss = Some(peak);
    for reflector in reflectors {
        reflector.stop().await?;
    }
    Ok(report)
}

/// Measures the steady phase into `m`: the lookups the reflectors answer and the deltas in `counts`, over
/// [`Scenario::steady`] and, with a `registry`, the wave of its image until every agent announced it.
async fn measure(
    scenario: &Scenario,
    nodes: &[Node],
    reflectors: &[Agent],
    registry: Option<&Registry>,
    received: &Received,
    counts: &Counts,
    m: &mut Measured,
) -> anyhow::Result<()> {
    let mut before = Vec::with_capacity(reflectors.len());
    for reflector in reflectors {
        before.push(reflector.lookups().await?);
    }
    counts.failed.store(0, Ordering::Relaxed);
    counts.deltas.store(0, Ordering::Relaxed);
    let steady = Instant::now();
    if let Some(registry) = registry {
        tracing::info!(image = registry.image(), "starting the wave");
        for (node, reflector) in nodes.iter().zip(reflectors) {
            node.prewarm(registry.address, &registry.image())?;
            reflector.hang_up().await?;
        }
    }
    tokio::time::sleep(scenario.steady).await;
    if let Some(registry) = registry {
        // An agent announces the layers 4 s after its first `Prewarm`, and the other reflector releases the same
        // round within a second or two: by the time the last agent announced, each sent it its `Prewarm`.
        let all = async {
            while received.announced() < scenario.agents {
                tokio::time::sleep(POLL).await;
            }
        };
        if tokio::time::timeout(FILL, all).await.is_err() {
            tracing::warn!(within = ?FILL, "not every agent announced the image");
        }
        let names = names(scenario.prewarm);
        m.wave = Some(received.wave(&registry.image(), names, scenario.agents));
        tracing::info!(wave = ?m.wave, "the wave is done");
    }
    let mut answered = 0;
    let seconds = steady.elapsed().as_secs_f64();
    for (before, reflector) in before.iter().zip(reflectors) {
        let theirs = before.since(&reflector.lookups().await?)?;
        m.lookup_p99 = m.lookup_p99.max(theirs.quantile(0.99));
        answered += theirs.count();
        m.steady_rss = m.steady_rss.max(Some(reflector.memory("VmRSS")?));
    }
    #[expect(clippy::cast_precision_loss, reason = "counts stay far below 2^53")]
    {
        m.lookups_per_second = Some(answered as f64 / seconds);
        m.deltas_per_second = Some(counts.deltas.load(Ordering::Relaxed) as f64 / seconds);
    }
    m.failed_lookups = Some(counts.failed.load(Ordering::Relaxed));
    Ok(())
}

/// The reflectors' node names: two members of one set for a wave, else one.
fn names(prewarm: bool) -> &'static [&'static str] {
    if prewarm { &node::PAIR } else { &[node::NODE] }
}

/// How often the run checks on the wave.
const POLL: Duration = Duration::from_millis(250);

/// Starts a reflector on each of `nodes`.
async fn start(command: &[OsString], nodes: &[Node]) -> anyhow::Result<Vec<Agent>> {
    let mut reflectors = Vec::with_capacity(nodes.len());
    for node in nodes {
        reflectors.push(Agent::start(command, node).await?);
    }
    Ok(reflectors)
}

/// Waits until each reflector holds `pairs` digests of `agents` agents, and returns how long that took; `None` when
/// one still does not [`FILL`] after the others.
async fn settled(
    reflectors: &[Agent],
    agents: usize,
    pairs: usize,
) -> anyhow::Result<Option<Duration>> {
    let start = Instant::now();
    for reflector in reflectors {
        if reflector.settled(agents, pairs, FILL).await?.is_none() {
            return Ok(None);
        }
    }
    Ok(Some(start.elapsed()))
}

/// The largest peak RSS of the reflectors, `VmHWM`.
fn peak_rss(reflectors: &[Agent]) -> anyhow::Result<u64> {
    reflectors.iter().try_fold(
        0,
        |peak, reflector| Ok(peak.max(reflector.memory("VmHWM")?)),
    )
}

/// Fails unless this process may open a socket for each agent's stream to each of `reflectors` and one for its
/// members, with room to spare; the reflectors, its children, inherit the same limit. `limits` is
/// `/proc/self/limits`.
fn ensure_descriptors(limits: &str, agents: usize, reflectors: usize) -> anyhow::Result<()> {
    let soft = open_files(limits).context("no open-files limit in /proc/self/limits")?;
    let needed = (reflectors + 1) * agents + 1024;
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
    fn each_agent_needs_a_descriptor_per_reflector_and_one_more_with_1024_to_spare() {
        let limits = |soft: usize| {
            format!("Max open files            {soft}                 524288               files\n")
        };
        assert!(ensure_descriptors(&limits(1030), 3, 1).is_ok());
        assert!(ensure_descriptors(&limits(1029), 3, 1).is_err());
        assert!(ensure_descriptors(&limits(1033), 3, 2).is_ok());
        assert!(ensure_descriptors(&limits(1032), 3, 2).is_err());
        assert!(ensure_descriptors("Max processes 1 1 processes\n", 0, 1).is_err());
    }
}
