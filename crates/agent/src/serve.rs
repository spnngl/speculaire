//! The agent process: loads the config, then serves until SIGTERM, reloading on SIGHUP and on file changes (D30).

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Context as _;
use tokio::signal::unix::{SignalKind, signal};
use tokio::time::{Instant, MissedTickBehavior, interval_at};
use tracing::{debug, error, info, warn};

use crate::config::{self, Config};
use crate::log::{self, Logs};
use crate::status::{self, Status};
use crate::{systemd, telemetry};

/// Runs the agent with the config at `path`.
///
/// # Errors
///
/// When the config is invalid, which stops startup before any listener opens (D30), or a listener cannot open.
pub fn run(path: &Path) -> anyhow::Result<()> {
    let config = config::load(path)?;
    let logs = log::install(&config.log, &config.audit)?;
    tokio::runtime::Runtime::new()
        .context("starting the runtime")?
        .block_on(serve(path, config, logs))
}

async fn serve(path: &Path, mut config: Config, logs: Logs) -> anyhow::Result<()> {
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
    systemd::watchdog();
    systemd::ready();

    let mut hangup = signal(SignalKind::hangup()).context("handling SIGHUP")?;
    let mut terminate = signal(SignalKind::terminate()).context("handling SIGTERM")?;
    let mut interrupt = signal(SignalKind::interrupt()).context("handling SIGINT")?;
    let mut period = config.config.poll_interval.get();
    let mut poll = interval_at(Instant::now() + period, period);
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // D30: a poll reloads when the file changed at or after the start of the previous read, so a file
    // SIGHUP already read is not read again.
    let mut last_check = SystemTime::now();
    loop {
        tokio::select! {
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
            _ = hangup.recv() => {
                last_check = SystemTime::now();
                reload(path, &mut config, &logs);
            }
            _ = poll.tick() => {
                let start = SystemTime::now();
                // A file that cannot be stat'ed is left to SIGHUP, which reports why.
                let modified = std::fs::metadata(path).and_then(|m| m.modified());
                if modified.is_ok_and(|m| m >= last_check) {
                    reload(path, &mut config, &logs);
                }
                last_check = start;
            }
        }
        if config.config.poll_interval.get() != period {
            period = config.config.poll_interval.get();
            poll = interval_at(Instant::now() + period, period);
            poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
        }
    }

    // D39, step 1. Steps 2 to 6 arrive with the mirror, peers, reflector, cache and gate.
    systemd::stopping();
    status.stop();
    info!("stopping");
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
