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
use speculaire_reflect::client::{Client, Config, Holdings, Lookups};
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
    held: Mutex<Vec<u32>>,
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
        anyhow::ensure!(
            scenario.blobs <= scenario.pool && u32::try_from(scenario.pool).is_ok(),
            "each agent's {} blobs must come from a pool of at least as many digests, under 2^32",
            scenario.blobs
        );
        let mut rng = fastrand::Rng::with_seed(scenario.seed);
        let pool: Arc<[Digest]> = (0..scenario.pool)
            .map(|_| {
                let [a, b, c, d] = std::array::from_fn::<u64, 4, _>(|_| rng.u64(..));
                Digest::parse(&format!("sha256:{a:016x}{b:016x}{c:016x}{d:016x}"))
            })
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
                held.insert(rng.u32(..pool_len(&pool)));
            }
            let holdings = Arc::new(Holdings::default());
            holdings.replace(held.iter().map(|&i| pool[i as usize].clone()).collect());
            agents.push(Agent {
                credentials,
                holdings,
                held: Mutex::new(held.into_iter().collect()),
            });
        }
        Ok(Self { pool, agents })
    }

    /// Starts each agent's client with `config`, evenly over `join`.
    pub(crate) async fn connect(self, config: &Config, join: Duration) -> Connected {
        let start = Instant::now();
        let count = u32::try_from(self.agents.len()).unwrap_or(u32::MAX);
        let mut clients = Vec::with_capacity(self.agents.len());
        for (index, agent) in (0..).zip(&self.agents) {
            tokio::time::sleep_until(start + join / count.max(1) * index).await;
            clients.push(Client::spawn(
                config.clone(),
                Arc::clone(&agent.credentials),
                Arc::clone(&agent.holdings),
            ));
        }
        Connected {
            fleet: Arc::new(self),
            clients,
        }
    }
}

/// The node name of the agent at `index`.
fn name(index: usize) -> String {
    format!("load-agent-{index:05}")
}

fn pool_len(pool: &[Digest]) -> u32 {
    u32::try_from(pool.len()).unwrap_or(u32::MAX)
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
                .map(|_| rng.u32(..pool_len(&fleet.pool)))
                .find(|i| !held.contains(i))
            else {
                return;
            };
            let old = std::mem::replace(&mut held[slot], new);
            agent.holdings.remove(&fleet.pool[old as usize]);
            agent.holdings.add(fleet.pool[new as usize].clone());
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
