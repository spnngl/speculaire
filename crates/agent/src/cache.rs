//! `cache.bin` (D31, D165, D176): the verdicts and the signature results, loaded before the gate registers, saved at
//! most once a second while the verdicts change, and once more at stop.

use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use metrics::counter;
use speculaire_verify::cache::{self, Current, Refused};
use speculaire_verify::{Held, MatchHash, Policies, Signatures, Verdicts};
use tokio::sync::futures::Notified;
use tokio::sync::{oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep};
use tracing::{info, warn};

use crate::telemetry::CACHE_LOADS;

/// The least time between two saves (D31).
const PERIOD: Duration = Duration::from_secs(1);

/// The caches `cache.bin` holds, where it is, and what keys its verdicts.
#[derive(Debug, Clone)]
pub(crate) struct Caches {
    /// `verify.cache`.
    pub(crate) path: PathBuf,
    /// The engine's verdicts.
    pub(crate) verdicts: Arc<Verdicts>,
    /// The engine's signature results.
    pub(crate) signatures: Arc<Signatures>,
    /// The policies in use.
    pub(crate) policies: watch::Receiver<Arc<Policies>>,
    /// The trust root in use.
    pub(crate) trust: watch::Receiver<Held>,
}

/// Why a file was not loaded.
#[derive(Debug, thiserror::Error)]
enum Discarded {
    #[error("it cannot be read: {0}")]
    Read(io::Error),
    #[error(transparent)]
    Refused(#[from] Refused),
}

impl Caches {
    /// Loads the file into the caches, replacing what they hold; must come before the engine runs. A missing file
    /// loads nothing; one that cannot be read or that `load` refuses is discarded, and the caches stay empty.
    pub(crate) fn load(&self) {
        let path = self.path.display();
        let loaded = match std::fs::read(&self.path) {
            Ok(bytes) => self.load_bytes(&bytes).map_err(Discarded::from),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                info!(%path, "no verdicts saved: the agent starts with none");
                return;
            }
            Err(e) => Err(Discarded::Read(e)),
        };
        match loaded {
            Ok(loaded) => {
                counter!(CACHE_LOADS, "result" => "loaded").increment(1);
                info!(
                    %path,
                    verdicts = loaded.verdicts,
                    signatures = loaded.signatures,
                    "saved verdicts loaded"
                );
            }
            Err(cause) => {
                counter!(CACHE_LOADS, "result" => "discarded").increment(1);
                warn!(%path, %cause, "saved verdicts discarded: the agent starts with none");
            }
        }
    }

    fn load_bytes(&self, bytes: &[u8]) -> Result<cache::Loaded, Refused> {
        let current = Current {
            policies: self.match_hash(),
            root: self.trust.borrow().as_ref().ok().map(|root| root.hash()),
        };
        cache::load(
            bytes,
            current,
            Instant::now(),
            &self.verdicts,
            &self.signatures,
        )
    }

    /// The hash of all the policies in use, read before the verdicts: a policy change between the two leaves the
    /// file under the previous hash, whose verdicts load stale (D165).
    fn match_hash(&self) -> MatchHash {
        MatchHash::of(self.policies.borrow().iter())
    }

    /// Saves the caches at most once a [`PERIOD`] while the verdicts change, until [`Saver::stop`].
    #[must_use]
    pub(crate) fn save(self) -> Saver {
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut bytes = Vec::new();
            let mut failing = false;
            let mut pace = Pace::new(&self.verdicts, stopped);
            loop {
                let tick = pace.next().await;
                bytes = self.write(std::mem::take(&mut bytes), &mut failing).await;
                if let Tick::Last = tick {
                    break;
                }
            }
        });
        Saver { stop, task }
    }

    /// Writes the caches through `bytes`, and returns it for the next write; warns of a failure unless the last write
    /// failed too, as `failing` keeps.
    async fn write(&self, mut bytes: Vec<u8>, failing: &mut bool) -> Vec<u8> {
        let policies = self.match_hash();
        cache::save(
            &self.verdicts,
            &self.signatures,
            policies,
            Instant::now(),
            &mut bytes,
        );
        let path = self.path.clone();
        let written = tokio::task::spawn_blocking(move || {
            let written = cache::write(&path, &bytes);
            (bytes, written)
        })
        .await;
        let (bytes, written) = match written {
            Ok(done) => done,
            Err(e) => {
                warn!(error = %e, "saving the verdicts panicked");
                return Vec::new();
            }
        };
        match written {
            Ok(()) => *failing = false,
            Err(e) if !*failing => {
                warn!(path = %self.path.display(), error = %e, "the verdicts could not be saved");
                *failing = true;
            }
            Err(_) => {}
        }
        bytes
    }
}

/// When to save: at a change of the verdicts, a [`PERIOD`] at least after the last save, and once more at the stop.
struct Pace<'a> {
    verdicts: &'a Verdicts,
    changed: Pin<Box<Notified<'a>>>,
    stop: oneshot::Receiver<()>,
    saved: bool,
}

/// What [`Pace::next`] tells.
enum Tick {
    /// Save, then ask again.
    Save,
    /// Save one last time: the stop was told, or its sender dropped.
    Last,
}

impl<'a> Pace<'a> {
    fn new(verdicts: &'a Verdicts, stop: oneshot::Receiver<()>) -> Self {
        let mut changed = Box::pin(verdicts.changed());
        changed.as_mut().enable();
        Self {
            verdicts,
            changed,
            stop,
            saved: false,
        }
    }

    /// Resolves when the next save is due.
    async fn next(&mut self) -> Tick {
        if self.saved {
            tokio::select! {
                () = sleep(PERIOD) => {}
                _ = &mut self.stop => return Tick::Last,
            }
        }
        tokio::select! {
            () = self.changed.as_mut() => {}
            _ = &mut self.stop => return Tick::Last,
        }
        // Enabled before the save reads the verdicts, so that no change after the read is missed.
        self.changed.set(self.verdicts.changed());
        self.changed.as_mut().enable();
        self.saved = true;
        Tick::Save
    }
}

/// The task saving the caches.
#[derive(Debug)]
pub(crate) struct Saver {
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl Saver {
    /// Saves the caches once more and stops (D39 step 5).
    pub(crate) async fn stop(self) {
        // An error means the task already ended; its result says how.
        let _ = self.stop.send(());
        if let Err(e) = self.task.await {
            warn!(error = %e, "the task saving the verdicts panicked");
        }
    }
}

#[cfg(test)]
mod tests;
