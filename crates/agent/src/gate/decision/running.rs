//! The containers the runtime has when the gate registers, as NRI `Synchronize` lists them (D175). The gate asks the
//! engine to verify each one's image under `trigger="synchronize"`, and warns once of each verdict that lands on one
//! as anything but `Allow`, again only when it changes. It stops none: the gate only answers `CreateContainer`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future;
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use speculaire_nri::api::{Container, PodSandbox};
use speculaire_runtime::identity::annotation::NOT_STORED;
use speculaire_runtime::identity::{Identified, Identity};
use speculaire_verify::Verdict;
use speculaire_verify::engine::Asking;
use tokio::sync::watch;
use tokio::time::{Instant, sleep};
use tracing::warn;

use super::{Decider, Decision, Settings};

/// How long the image list waits for the gate's asks, and the gate reads again an identity read before the image
/// list or store loaded (D175).
pub const SYNCHRONIZE_WAIT: Duration = Duration::from_secs(5);

/// How often the gate reads again an identity [`is_early`], within [`SYNCHRONIZE_WAIT`].
const REREAD: Duration = Duration::from_millis(100);

/// A container `Synchronize` listed, and its pod.
#[derive(Debug)]
pub struct Running {
    pod: PodSandbox,
    container: Container,
}

impl Running {
    /// Each of `containers` with its pod among `pods`: NRI always sends it, and a missing one is on the default
    /// runtime handler, as an empty one.
    #[must_use]
    pub fn listed(pods: Vec<PodSandbox>, containers: Vec<Container>) -> Vec<Self> {
        let pods: HashMap<String, PodSandbox> =
            pods.into_iter().map(|pod| (pod.id.clone(), pod)).collect();
        containers
            .into_iter()
            .map(|container| Self {
                pod: pods
                    .get(&container.pod_sandbox_id)
                    .cloned()
                    .unwrap_or_default(),
                container,
            })
            .collect()
    }
}

/// What the gate read of a running container.
#[derive(Default)]
struct Seen<'a> {
    /// Its image identity, read again while [`is_early`].
    identified: Option<Identified<'a>>,
    /// The reason last warned of; none while the verdict allows, or none landed.
    warned: Option<String>,
}

impl Decider {
    /// Watches the containers of the latest `Synchronize` in `synchronized`, until the gate stops.
    pub async fn watch_running(&self, mut synchronized: watch::Receiver<Arc<Vec<Running>>>) {
        // The channel's first value comes before any `Synchronize`.
        let mut changed = synchronized.changed().await;
        loop {
            // The gate is stopping: its connection holds the sender.
            if changed.is_err() {
                return future::pending().await;
            }
            let running = Arc::clone(&synchronized.borrow_and_update());
            changed = tokio::select! {
                never = self.watch(&running) => match never {},
                changed = synchronized.changed() => changed,
            };
        }
    }

    /// Asks for the image of each of `running` once identified, then tells the image list it may start, and warns of
    /// each verdict as it lands.
    async fn watch(&self, running: &[Running]) -> Infallible {
        let mut seen: Vec<Seen<'_>> = running.iter().map(|_| Seen::default()).collect();
        let until = Instant::now() + SYNCHRONIZE_WAIT;
        let mut told = false;
        loop {
            // Enabled before the lookups, so that no verdict or list kept after them is missed.
            let mut landed = pin!(self.verifier.verdicts.changed());
            landed.as_mut().enable();
            let mut listed = pin!(self.listed.notified());
            listed.as_mut().enable();
            let settings = self.settings();
            let mut early = false;
            for (running, seen) in running.iter().zip(&mut seen) {
                if settings.namespaces.contains(&running.pod.namespace) {
                    continue;
                }
                if seen.identified.as_ref().is_none_or(is_early) {
                    let identified = self
                        .identity
                        .identify(&running.pod, &running.container)
                        .await;
                    if identified.identity().is_some() {
                        self.verifier.ask(&identified, Asking::Synchronize);
                    }
                    early |= is_early(&identified);
                    seen.identified = Some(identified);
                }
                self.report(running, seen, &settings);
            }
            if !early && !told {
                self.verifier.synchronized.notify_one();
                told = true;
            }
            tokio::select! {
                () = landed => {}
                () = listed => {}
                () = sleep(REREAD), if early && Instant::now() < until => {}
            }
        }
    }

    /// Warns of the verdict on `running` when it landed as anything but `Allow`, unless `seen` warned of it last. An
    /// image without an identity, exempt or no policy matches has no verdict.
    fn report(&self, running: &Running, seen: &mut Seen<'_>, settings: &Settings) {
        let Some(identified) = seen
            .identified
            .as_ref()
            .filter(|identified| identified.identity().is_some())
        else {
            return;
        };
        let reason = match self.verifier.decide(settings, identified) {
            Decision::Verdict(lookup) => match lookup.verdict {
                Verdict::Pending => return,
                Verdict::Allow => None,
                verdict @ (Verdict::Rejected { .. } | Verdict::Unverifiable { .. }) => {
                    Some(verdict.to_string())
                }
            },
            Decision::Exempt(_) | Decision::Unmatched | Decision::Overloaded => None,
        };
        if reason == seen.warned {
            return;
        }
        if let Some(reason) = &reason {
            warn!(
                namespace = running.pod.namespace,
                pod = running.pod.name,
                container = running.container.name,
                image = self
                    .identity
                    .image_name(&running.container, Some(identified)),
                reason,
                "a container running since before the gate registered has a verdict that does not allow it: the gate \
                 leaves it running, and decides its next start (D175)"
            );
        }
        seen.warned = reason;
    }
}

/// Whether the identity may come later: the image list or containerd's image store had not loaded when it was read.
fn is_early(identified: &Identified<'_>) -> bool {
    matches!(
        identified,
        Identified::Unlisted | Identified::Unknown(NOT_STORED)
    )
}
