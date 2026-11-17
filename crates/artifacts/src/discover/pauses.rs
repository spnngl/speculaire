//! The registry hosts that refused to serve more for now, shared by every discovery (D38).

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use speculaire_registry::Refusal;
use tokio::time::Instant;

/// The first backoff step of a host's refusals, doubled at each refusal in a row.
const FIRST: Duration = Duration::from_secs(30);

/// The largest backoff step (D20).
const LARGEST: Duration = Duration::from_secs(300);

/// The longest pause, whatever `Retry-After` asks (D38).
const LONGEST: Duration = Duration::from_secs(3600);

/// The paused hosts, by authority. The lock is never held across an await.
#[derive(Default)]
pub(super) struct Pauses {
    hosts: Mutex<HashMap<String, Pause>>,
}

/// One host's pause.
struct Pause {
    until: Instant,
    /// The refusals in a row, which set the next backoff step.
    refusals: u32,
}

impl Pauses {
    /// When `host` may be asked again, while it is paused at `now`.
    pub(super) fn until(&self, host: &str, now: Instant) -> Option<Instant> {
        let hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        hosts
            .get(host)
            .map(|pause| pause.until)
            .filter(|until| *until > now)
    }

    /// Pauses `host` after `refusal` at `now`, until the later of the next backoff step and `Retry-After`, 1 h at most.
    pub(super) fn refused(&self, host: &str, refusal: Refusal, now: Instant) -> Instant {
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        let refusals = hosts.get(host).map_or(0, |pause| pause.refusals);
        let step = FIRST.saturating_mul(1 << refusals.min(4)).min(LARGEST);
        let wait = refusal.retry_after.map_or(step, |asked| asked.max(step));
        let until = now + wait.min(LONGEST);
        hosts.insert(
            host.to_owned(),
            Pause {
                until,
                refusals: refusals.saturating_add(1),
            },
        );
        until
    }

    /// `host` answered: its next refusal starts the backoff over.
    pub(super) fn answered(&self, host: &str) {
        let mut hosts = self.hosts.lock().unwrap_or_else(PoisonError::into_inner);
        hosts.remove(host);
    }
}

#[cfg(test)]
mod tests;
