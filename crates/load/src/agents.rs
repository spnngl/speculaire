//! D33's simulated agents: each a reflector client of its own (D98), with its own node certificate, announcing its
//! share of a pool of digests, and the paced lookups and deltas they send.

use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Context as _;
use speculaire_oci::reference::Digest;
use speculaire_pki::node::Credentials;
use speculaire_pki::testing::Cluster;
use speculaire_reflect::client::{Client, Config, Holdings, Lookups, Pushed, Source};
use tokio::sync::mpsc;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::Scenario;

/// How often a pacer catches up with its rate.
const TICK: Duration = Duration::from_millis(1);

/// The agents' certificates and digests, before any connects.
pub(crate) struct Fleet {
    pool: Arc<[Digest]>,
    agents: Vec<Agent>,
}

/// One simulated agent's identity and digests.
struct Agent {
    credentials: Arc<Credentials>,
    holdings: Arc<Holdings>,
    /// What `holdings` holds, as indices into the pool, for the deltas to swap.
    held: Mutex<Vec<usize>>,
}

impl Fleet {
    /// `scenario.agents` agents, each with a certificate from `cluster` and `scenario.blobs` distinct digests drawn
    /// from a pool of `scenario.pool`, the same for the same seed. `dir` holds a scratch file.
    pub(crate) fn new(
        scenario: &Scenario,
        cluster: &Cluster,
        ca: &Path,
        dir: &Path,
    ) -> anyhow::Result<Self> {
        // The lookups draw an agent and a pool digest at random: an empty range has none to draw.
        anyhow::ensure!(
            scenario.agents > 0 && scenario.pool > 0,
            "a load needs at least one agent and one pool digest"
        );
        anyhow::ensure!(
            scenario.blobs <= scenario.pool,
            "each agent's {} blobs must come from a pool of at least as many digests",
            scenario.blobs
        );
        let mut rng = fastrand::Rng::with_seed(scenario.seed);
        let pool: Arc<[Digest]> = (0..scenario.pool)
            .map(|_| digest(&mut rng))
            .collect::<Result<_, _>>()?;
        let pem = dir.join("agent.pem");
        let mut agents = Vec::with_capacity(scenario.agents);
        for index in 0..scenario.agents {
            std::fs::write(&pem, cluster.kubelet(&name(index)))?;
            let credentials = Arc::new(Credentials::default());
            credentials.load_identity(&pem)?;
            credentials.load_authority(ca)?;
            let mut held = HashSet::with_capacity(scenario.blobs);
            while held.len() < scenario.blobs {
                held.insert(rng.usize(..pool.len()));
            }
            let holdings = Arc::new(Holdings::default());
            holdings.replace(Source::Content, held.iter().map(|&i| &pool[i]));
            agents.push(Agent {
                credentials,
                holdings,
                held: Mutex::new(held.into_iter().collect()),
            });
        }
        Ok(Self { pool, agents })
    }

    /// Starts each agent's client with `config`, evenly over `join`. Each hands what members push to the channel
    /// `pushes` gives for the agent's index and holdings.
    pub(crate) async fn connect(
        self,
        config: &Config,
        join: Duration,
        mut pushes: impl FnMut(usize, &Arc<Holdings>) -> mpsc::Sender<Pushed>,
    ) -> Connected {
        let start = Instant::now();
        let count = u32::try_from(self.agents.len()).unwrap_or(u32::MAX);
        let mut clients = Vec::with_capacity(self.agents.len());
        for (index, agent) in self.agents.iter().enumerate() {
            let nth = u32::try_from(index).unwrap_or(u32::MAX);
            tokio::time::sleep_until(start + join / count.max(1) * nth).await;
            clients.push(Client::spawn(
                config.clone(),
                Arc::clone(&agent.credentials),
                Arc::clone(&agent.holdings),
                pushes(index, &agent.holdings),
            ));
        }
        Connected {
            fleet: Arc::new(self),
            clients,
        }
    }
}

/// No channel: a closed one drops what members push, as D33's agents take no pushes.
pub(crate) fn drop_pushes(_: usize, _: &Arc<Holdings>) -> mpsc::Sender<Pushed> {
    mpsc::channel(1).0
}

/// A random sha256 digest drawn from `rng`.
pub(crate) fn digest(rng: &mut fastrand::Rng) -> anyhow::Result<Digest> {
    let [a, b, c, d] = std::array::from_fn::<u64, 4, _>(|_| rng.u64(..));
    Ok(Digest::parse(&format!(
        "sha256:{a:016x}{b:016x}{c:016x}{d:016x}"
    ))?)
}

/// The node name of the agent at `index`.
pub(crate) fn name(index: usize) -> String {
    format!("load-agent-{index:05}")
}

/// The fleet with its clients running.
pub(crate) struct Connected {
    fleet: Arc<Fleet>,
    clients: Vec<Client>,
}

/// What the pacers have done so far.
#[derive(Debug, Default)]
pub(crate) struct Counts {
    /// Lookups that failed.
    pub(crate) failed: AtomicU64,
    /// Deltas sent: each digest added or removed.
    pub(crate) deltas: AtomicU64,
}

impl Connected {
    /// Looks a random pool digest up through a random agent, `rate` times a second, until aborted.
    pub(crate) fn look_up(
        &self,
        rate: u32,
        mut rng: fastrand::Rng,
        counts: &Arc<Counts>,
    ) -> JoinHandle<()> {
        let lookups: Arc<[Lookups]> = self.clients.iter().map(Client::lookups).collect();
        let pool = Arc::clone(&self.fleet.pool);
        let counts = Arc::clone(counts);
        tokio::spawn(pace(rate, move || {
            let agent = lookups[rng.usize(..lookups.len())].clone();
            let digest = pool[rng.usize(..pool.len())].clone();
            let counts = Arc::clone(&counts);
            tokio::spawn(async move {
                if agent.lookup(&digest).await.is_err() {
                    counts.failed.fetch_add(1, Ordering::Relaxed);
                }
            });
        }))
    }

    /// Swaps one digest of a random agent for one it does not hold, a delta removing then a delta adding,
    /// `rate / 2` times a second, until aborted.
    pub(crate) fn swap(
        &self,
        rate: u32,
        mut rng: fastrand::Rng,
        counts: &Arc<Counts>,
    ) -> JoinHandle<()> {
        let fleet = Arc::clone(&self.fleet);
        let counts = Arc::clone(counts);
        tokio::spawn(pace(rate / 2, move || {
            let agent = &fleet.agents[rng.usize(..fleet.agents.len())];
            let mut held = agent.held.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(slot) = (!held.is_empty()).then(|| rng.usize(..held.len())) else {
                return;
            };
            let Some(new) = (0..64)
                .map(|_| rng.usize(..fleet.pool.len()))
                .find(|i| !held.contains(i))
            else {
                return;
            };
            let old = std::mem::replace(&mut held[slot], new);
            agent.holdings.remove(Source::Content, &fleet.pool[old]);
            agent.holdings.add(Source::Content, &fleet.pool[new]);
            counts.deltas.fetch_add(2, Ordering::Relaxed);
        }))
    }

    /// Stops every client at once: each ends its stream, and the reflector withdraws its digests.
    pub(crate) async fn stop(self) {
        let mut stopping: JoinSet<()> = self.clients.into_iter().map(Client::stop).collect();
        while stopping.join_next().await.is_some() {}
    }
}

/// Calls `act` `rate` times a second, evenly, catching up after a late tick.
async fn pace(rate: u32, mut act: impl FnMut()) {
    let start = Instant::now();
    let mut done = 0_u128;
    let mut tick = tokio::time::interval(TICK);
    loop {
        tick.tick().await;
        let due = start.elapsed().as_micros() * u128::from(rate) / 1_000_000;
        for _ in done..due {
            act();
        }
        done = due;
    }
}

/// Builds the fleet off the runtime: its certificates and digests take seconds at D33's scale.
pub(crate) async fn build(
    scenario: Scenario,
    cluster: Arc<Cluster>,
    ca: std::path::PathBuf,
    dir: std::path::PathBuf,
) -> anyhow::Result<Fleet> {
    tokio::task::spawn_blocking(move || Fleet::new(&scenario, &cluster, &ca, &dir))
        .await
        .context("building the agents panicked")?
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fleet of `agents` with `blobs` digests each from a pool of `pool`, drawn with `seed`.
    fn fleet(agents: usize, blobs: usize, pool: usize, seed: u64) -> anyhow::Result<Fleet> {
        let scenario = Scenario {
            agents,
            blobs,
            pool,
            seed,
            ..Scenario::D33
        };
        let cluster = Cluster::new("speculaire-load");
        let dir = tempfile::tempdir()?;
        let ca = dir.path().join("ca.crt");
        std::fs::write(&ca, cluster.ca())?;
        Fleet::new(&scenario, &cluster, &ca, dir.path())
    }

    /// Each agent's digests as sorted indices into the pool.
    fn held(fleet: &Fleet) -> Vec<Vec<usize>> {
        let sorted = |agent: &Agent| {
            let mut held = agent
                .held
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone();
            held.sort_unstable();
            held
        };
        fleet.agents.iter().map(sorted).collect()
    }

    #[test]
    fn a_seed_draws_the_same_distinct_digests_again() {
        let drawn = fleet(3, 5, 20, 7).expect("the scenario is valid");
        let held = held(&drawn);
        for digests in &held {
            assert_eq!(digests.len(), 5);
            assert!(digests.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(digests.iter().all(|&i| i < 20));
        }
        let again = fleet(3, 5, 20, 7).expect("the scenario is valid");
        assert_eq!(drawn.pool, again.pool);
        assert_eq!(held, self::held(&again));
        let other = fleet(3, 5, 20, 8).expect("the scenario is valid");
        assert_ne!(drawn.pool, other.pool);
    }

    #[test]
    fn a_fleet_needs_an_agent_and_a_pool_as_large_as_each_agents_blobs() {
        assert!(fleet(0, 1, 1, 7).is_err());
        assert!(fleet(1, 0, 0, 7).is_err());
        assert!(fleet(1, 3, 2, 7).is_err());
        assert!(fleet(1, 2, 2, 7).is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn a_swap_keeps_each_agent_holding_as_many_distinct_digests() {
        let fleet = fleet(2, 5, 20, 7).expect("the scenario is valid");
        let before = held(&fleet);
        let connected = Connected {
            fleet: Arc::new(fleet),
            clients: Vec::new(),
        };
        let counts = Arc::new(Counts::default());
        let swapping = connected.swap(2_000, fastrand::Rng::with_seed(7), &counts);
        tokio::time::sleep(Duration::from_millis(100)).await;
        swapping.abort();
        let after = held(&connected.fleet);
        assert_ne!(before, after);
        for digests in &after {
            assert_eq!(digests.len(), 5);
            assert!(digests.windows(2).all(|pair| pair[0] < pair[1]));
        }
        let deltas = counts.deltas.load(Ordering::Relaxed);
        assert!(deltas > 0 && deltas.is_multiple_of(2), "{deltas} deltas");
    }

    #[test]
    fn names_sort_in_index_order() {
        assert_eq!(name(7), "load-agent-00007");
        assert!(name(9) < name(10));
    }

    #[tokio::test(start_paused = true)]
    async fn a_pacer_acts_its_rate_times_a_second_even_when_a_tick_owes_several() {
        let mut acts = 0;
        // Ten acts a tick. The timeout polls the pacer before its own deadline, so the pacer's tick at 100 ms is its
        // last.
        let paced =
            tokio::time::timeout(Duration::from_millis(100), pace(10_000, || acts += 1)).await;
        assert!(paced.is_err());
        assert_eq!(acts, 1_000);
    }
}
