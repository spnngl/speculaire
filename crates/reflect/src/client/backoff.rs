//! The delays before an agent opens a stream again (D33).

use std::time::Duration;

/// The window a dropped stream waits in, so that the agents of a restarted reflector come back spread out.
const SPREAD: Duration = Duration::from_secs(5);
/// The first bound of the backoff, doubled at each failure.
const FIRST: Duration = Duration::from_secs(1);
/// The largest bound of the backoff.
const CAP: Duration = Duration::from_secs(60);

/// The delays of one stream's retries: random within bounds, from a generator that tests seed.
#[derive(Debug)]
pub(crate) struct Backoff {
    rng: fastrand::Rng,
    failures: u32,
}

impl Backoff {
    /// The delays drawn from `seed`.
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            rng: fastrand::Rng::with_seed(seed),
            failures: 0,
        }
    }

    /// The wait after a stream that was up drops: anywhere in [`SPREAD`]. The backoff starts over.
    pub(crate) fn dropped(&mut self) -> Duration {
        self.failures = 0;
        self.draw(SPREAD)
    }

    /// The wait after an attempt that failed: full jitter below a bound that doubles from [`FIRST`] up to [`CAP`].
    pub(crate) fn failed(&mut self) -> Duration {
        let bound = FIRST.saturating_mul(1 << self.failures.min(6)).min(CAP);
        self.failures = self.failures.saturating_add(1);
        self.draw(bound)
    }

    /// The next attempt starts the backoff over.
    pub(crate) const fn succeeded(&mut self) {
        self.failures = 0;
    }

    fn draw(&mut self, bound: Duration) -> Duration {
        let millis = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX);
        Duration::from_millis(self.rng.u64(0..=millis))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dropped_stream_waits_anywhere_in_the_first_five_seconds() {
        let mut backoff = Backoff::new(7);
        let mut seconds = [0_u32; 5];
        for _ in 0..1000 {
            let delay = backoff.dropped();
            assert!(delay <= SPREAD, "{delay:?}");
            let second = usize::try_from(delay.as_secs().min(4)).unwrap();
            seconds[second] += 1;
        }
        // Every second of the window gets about a fifth of the 1000 waits.
        for count in seconds {
            assert!((150..=250).contains(&count), "{seconds:?}");
        }
    }

    #[test]
    fn failures_wait_below_a_bound_that_doubles_from_one_second_to_sixty() {
        let mut backoff = Backoff::new(11);
        let bounds = [1, 2, 4, 8, 16, 32, 60, 60, 60];
        for _ in 0..200 {
            backoff.succeeded();
            for bound in bounds {
                let delay = backoff.failed();
                assert!(delay <= Duration::from_secs(bound), "{delay:?} > {bound} s");
            }
        }
        // Full jitter: the waits below the cap span it.
        let waits: Vec<Duration> = (0..200).map(|_| backoff.failed()).collect();
        assert!(waits.iter().any(|w| *w < Duration::from_secs(10)));
        assert!(waits.iter().any(|w| *w > Duration::from_secs(50)));
        // A drop starts the backoff over.
        backoff.dropped();
        assert!(backoff.failed() <= FIRST);
    }
}
