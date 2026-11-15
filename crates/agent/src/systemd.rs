//! What the agent tells systemd (D39): readiness, stopping, and the watchdog. Outside systemd, where
//! `NOTIFY_SOCKET` is unset, each call does nothing.

use std::time::Duration;

use sd_notify::NotifyState;
use tracing::warn;

/// Tells systemd the agent is ready: `/readyz` answers 200 from now on.
pub(crate) fn ready() {
    send(NotifyState::Ready);
}

/// Tells systemd the agent is stopping (D39, step 1).
pub(crate) fn stopping() {
    send(NotifyState::Stopping);
}

/// Pings the watchdog every half of `WATCHDOG_USEC`, from a task of the runtime: a stalled runtime misses the pings
/// and systemd kills it. Does nothing when the unit sets no `WatchdogSec`, or sets it to 0 or infinity
/// (`u64::MAX`), as `sd_watchdog_enabled` does: systemd v259.10, `src/libsystemd/sd-daemon/sd-daemon.c:841`.
pub(crate) fn watchdog() {
    let infinity = Duration::from_micros(u64::MAX);
    let Some(timeout) = sd_notify::watchdog_enabled().filter(|t| !t.is_zero() && *t != infinity)
    else {
        return;
    };
    tokio::spawn(async move {
        let mut ping = tokio::time::interval(timeout / 2);
        loop {
            ping.tick().await;
            send(NotifyState::Watchdog);
        }
    });
}

fn send(state: NotifyState<'_>) {
    if let Err(err) = sd_notify::notify(&[state]) {
        warn!(%err, "cannot notify systemd");
    }
}
