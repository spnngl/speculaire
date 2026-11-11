//! What the agent tells systemd (D39): readiness, stopping, and the watchdog. Outside systemd, where
//! `NOTIFY_SOCKET` is unset, each call does nothing.

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
/// and systemd kills it. Does nothing when the unit sets no `WatchdogSec`.
pub(crate) fn watchdog() {
    let Some(timeout) = sd_notify::watchdog_enabled() else {
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
