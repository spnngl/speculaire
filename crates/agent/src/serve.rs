//! The agent process: loads the config, then serves until SIGTERM, reloading on SIGHUP and on file changes (D30).

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context as _;
use speculaire_mirror::Local;
use speculaire_mirror::cache::Cache;
use speculaire_mirror::relay::{CriImages, Relay};
use speculaire_mirror::tls::Tls;
use speculaire_runtime::registries::Registries;
use speculaire_runtime::watch::Watch;
use speculaire_runtime::{Fallback, Node as RuntimeNode};
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Duration, Interval, MissedTickBehavior, interval};
use tracing::{debug, error, info, warn};

use crate::config::{self, Config};
use crate::identity::Identity;
use crate::log::{self, Logs};
use crate::node::Node;
use crate::status::{self, Status};
use crate::{systemd, telemetry};

/// Runs the agent with the config at `path`.
///
/// # Errors
///
/// When the config is invalid, which stops startup before any listener opens (D30), or a listener cannot open.
pub fn run(path: &Path) -> anyhow::Result<()> {
    // Stamped before the first read, so that a write during it is a change the first poll finds (D93).
    let watch = Watch::new(vec![path.to_owned()]);
    let config = config::load(path)?;
    let logs = log::install(&config.log, &config.audit)?;
    let node = Node::new(&config);
    let node = preflight(&node)?;
    tokio::runtime::Runtime::new()
        .context("starting the runtime")?
        .block_on(serve(path, watch, config, logs, node))
}

/// Refuses to start on a node where the agent would mirror or gate wrongly (D86), naming each file and key; returns the
/// node as the runtime it has runs on it.
fn preflight(node: &Node) -> anyhow::Result<RuntimeNode> {
    let runtime = node.runtime()?;
    let on = node.on(runtime);
    let problems = speculaire_configure::preflight(on.settings(), &node.target, SystemTime::now());
    if problems.is_empty() {
        info!(%runtime, "preflight passed");
        return Ok(on);
    }
    let lines: Vec<String> = problems
        .iter()
        .map(|problem| format!("  {problem}"))
        .collect();
    anyhow::bail!(
        "{} problem{} on this node keep{} the agent from starting ({runtime}):\n{}",
        problems.len(),
        if problems.len() == 1 { "" } else { "s" },
        if problems.len() == 1 { "s" } else { "" },
        lines.join("\n")
    )
}

async fn serve(
    path: &Path,
    mut watch: Watch,
    mut config: Config,
    logs: Logs,
    node: RuntimeNode,
) -> anyhow::Result<()> {
    // Before any listener opens and before READY=1: a signal's default action would end the agent, and a signal that
    // arrives during startup is handled once it is done.
    let mut hangup = signal(SignalKind::hangup()).context("handling SIGHUP")?;
    let mut terminate = signal(SignalKind::terminate()).context("handling SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("handling SIGINT")?;
    let metrics = telemetry::install()?;
    let status = Arc::new(Status::new(metrics.clone()));
    let address = *config.metrics.address.get();
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("listening on metrics.address {address}"))?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(
        axum::serve(listener, status::router(Arc::clone(&status)))
            .with_graceful_shutdown(async {
                // An error means the sender is gone, which also means stop.
                let _ = stopped.await;
            })
            .into_future(),
    );
    tokio::spawn(async move {
        let mut upkeep = tokio::time::interval(telemetry::UPKEEP_PERIOD);
        loop {
            upkeep.tick().await;
            metrics.run_upkeep();
        }
    });
    info!(%address, "status listener open");
    // P2P waits for the identity; readiness does not (D16, D45).
    let mut identity = Identity::load(&config.identity);
    // `/readyz` answers 503 until the mirror listens (D45); an agent that cannot open it stops (D55).
    let registries = node.registries();
    reload_registries(&*registries);
    let mirror = start_mirror(&config, &node, Arc::clone(&registries)).await?;
    status.mirror_listening();
    systemd::watchdog();
    systemd::ready();

    let mut period = config.config.poll_interval.get();
    let mut poll = polls(period);
    // D93: a poll reads a file again when it differs from its stamp, taken before the last read; SIGHUP always does.
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = hangup.recv() => {
                watch = watch.again();
                reload(path, &mut config, &logs);
                mirror.apply(&config);
                reload_registries(&*registries);
                identity.reload();
            }
            _ = poll.tick() => {
                if watch.changed() {
                    watch = watch.again();
                    reload(path, &mut config, &logs);
                    mirror.apply(&config);
                }
                if registries.changed() {
                    reload_registries(&*registries);
                }
                identity.poll();
            }
        }
        if config.config.poll_interval.get() != period {
            period = config.config.poll_interval.get();
            poll = polls(period);
        }
    }

    // D39, step 1. Steps 2 to 6 arrive with peers, reflector, cache and gate.
    systemd::stopping();
    status.stop();
    info!("stopping");
    mirror.stop().await;
    // An error means the server already ended; its result says why.
    let _ = stop.send(());
    server
        .await
        .context("the status listener panicked")?
        .context("serving the status listener")
}

/// Swaps in the config at `path`, or keeps `running` and counts the failure (D30).
fn reload(path: &Path, running: &mut Config, logs: &Logs) {
    match config::load(path) {
        Err(err) => {
            metrics::counter!(telemetry::CONFIG_RELOAD_FAILURES).increment(1);
            let err = anyhow::Error::from(err);
            error!(
                error = format_args!("{err:#}"),
                "config reload failed; the previous config stays in use"
            );
        }
        Ok(mut new) => {
            for key in new.keep_restart_keys(running) {
                warn!(
                    key,
                    "config reload: this key changes only on restart; the running value stays"
                );
            }
            logs.apply(&new.log, &new.audit);
            *running = new;
            debug!(path = %path.display(), "config reloaded");
        }
    }
}

/// Reads the registry config again (D91). A config that is not valid stays unread: the one held serves, and the failure
/// is logged and counted. A credential, certificate or key file that cannot be used does not fail the read: each is
/// logged, and the reload counts as one failure however many there are (D92).
fn reload_registries(registries: &dyn Registries) {
    match registries.reload() {
        Ok(reloaded) => {
            debug!("registry config reloaded");
            if !reloaded.problems.is_empty() {
                metrics::counter!(telemetry::CONFIG_RELOAD_FAILURES).increment(1);
            }
            for problem in &reloaded.problems {
                error!(
                    error = %problem,
                    "registry config reloaded with a file left out"
                );
            }
        }
        Err(err) => {
            metrics::counter!(telemetry::CONFIG_RELOAD_FAILURES).increment(1);
            error!(
                error = %err,
                "registry config reload failed; the previous registry config stays in use"
            );
        }
    }
}

/// The mirror, listening, and what stops it.
struct Mirror {
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
    /// The relay, where the node has one.
    relay: Option<Arc<Relay<CriImages>>>,
}

impl Mirror {
    /// Gives the mirror the live keys of `config`: a lowered `blob_cache.max_size` evicts at the next blob kept (D91).
    fn apply(&self, config: &Config) {
        if let Some(relay) = &self.relay {
            relay.cache().set_max_size(config.blob_cache.max_size.get());
        }
    }

    async fn stop(self) {
        // An error means the mirror already ended.
        let _ = self.stop.send(());
        if let Err(err) = self.task.await {
            error!(error = %err, "the mirror panicked");
        }
    }
}

/// Opens the mirror on `mirror.address` with the certificates of `configure` (D14, D55). On containerd it serves what
/// the node holds; on CRI-O it relays pulls through the blob cache (D66, D67).
async fn start_mirror(
    config: &Config,
    node: &RuntimeNode,
    registries: Arc<dyn Registries>,
) -> anyhow::Result<Mirror> {
    let directory = config.mirror.directory.get().get();
    let tls = Tls::load(directory).with_context(|| {
        format!(
            "loading the mirror's certificates from {}: run `speculaire configure`",
            directory.display()
        )
    })?;
    let address = config.mirror.address.get().get();
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .with_context(|| format!("listening on mirror.address {address}"))?;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let stopped = async {
        // An error means the sender is gone, which also means stop.
        let _ = stopped.await;
    };
    let tls = Arc::new(tls);
    let (task, relay) = match node.fallback() {
        Fallback::PerBlob => (
            tokio::spawn(speculaire_mirror::serve(
                listener,
                tls,
                Arc::new(Local::new(node.content())),
                stopped,
            )),
            None,
        ),
        Fallback::Relay => {
            let blobs = config.blob_cache.directory.get().get();
            let cache = Cache::open(blobs, config.blob_cache.max_size.get())
                .with_context(|| format!("opening the blob cache {}", blobs.display()))?;
            let relay = Arc::new(Relay::new(
                cache,
                registries,
                CriImages::new(node.socket(), node.name()),
            ));
            speculaire_mirror::metrics::describe_relay();
            tokio::spawn({
                let relay = Arc::clone(&relay);
                async move { relay.evict_when_over().await }
            });
            let task = tokio::spawn(speculaire_mirror::serve(
                listener,
                tls,
                Arc::clone(&relay),
                stopped,
            ));
            (task, Some(relay))
        }
    };
    info!(%address, "mirror open");
    Ok(Mirror { stop, task, relay })
}

/// The config polls (D30): the first one period from now.
fn polls(period: Duration) -> Interval {
    // `interval` caps a period past the clock's range, and `reset` moves its immediate first tick a period away.
    let mut poll = interval(period);
    poll.reset();
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    poll
}

#[cfg(test)]
mod tests {
    use speculaire_runtime::registries::ContainerdRegistries;

    use super::*;

    #[test]
    fn a_poll_interval_past_the_clocks_range_starts_the_polls() {
        // humantime reads up to `u64::MAX` seconds; `Instant` holds fewer.
        let config = config::parse("[config]\npoll_interval = \"500000000000y\"\n").unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            polls(config.config.poll_interval.get());
        });
    }

    #[test]
    fn the_live_keys_of_a_config_reach_the_relays_cache() {
        let dir = tempfile::tempdir().unwrap();
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let relay = Arc::new(Relay::new(
                Cache::open(dir.path(), 1 << 30).unwrap(),
                Arc::new(ContainerdRegistries::new(dir.path().join("config.toml"))),
                CriImages::new(dir.path().join("crio.sock"), "cri-o"),
            ));
            let (stop, _stopped) = tokio::sync::oneshot::channel();
            let mirror = Mirror {
                stop,
                task: tokio::spawn(async {}),
                relay: Some(Arc::clone(&relay)),
            };
            let config = Config::default();
            assert_ne!(config.blob_cache.max_size.get(), 1 << 30);
            mirror.apply(&config);
            assert_eq!(relay.cache().max_size(), config.blob_cache.max_size.get());
        });
    }
}
