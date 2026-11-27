//! Pulls the images members push, through the runtime's CRI as the kubelet would: they land where it looks, and come
//! through the mirror like any pull (D51, D188).
//!
//! One pull runs at a time, fresh pushes first, in the order they came. A push of an image the runtime lists, or that
//! is queued, pulling, waiting for a retry or pulled within [`RELIST`], is dropped. No pull starts while the image
//! filesystem is fuller than `prewarm.max_disk_percent`. A failed or skipped pull is retried after a backoff from 30 s
//! to 10 minutes, or at once on a member's next `PrewarmList`, while some member's latest list names the image.
//!
//! A pulled image that a list names is pinned, so that the kubelet's image garbage collection keeps it; the agent
//! unpins an image it pinned once no member's latest list names it (D191). The runtime marks the pins the agent
//! made, which outlive it: the worker starts from those.
//!
//! A pull that went through is followed, before the next one starts, by what [`Then`] does: the refetch of the layers
//! the node held without a blob (D195).

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use metrics::counter;
use speculaire_oci::reference::Reference;
use speculaire_reflect::client::Pushed;
use speculaire_reflect::push::{PrewarmList, Push};
use speculaire_runtime::cri;
use speculaire_runtime::images::RELIST;
use speculaire_runtime::pull::Pull;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::Percent;
use crate::telemetry::PREWARM_PULLS;

/// The wait before the first retry; each one after doubles it.
const FIRST_BACKOFF: Duration = Duration::from_secs(30);
/// The longest wait between retries.
const MAX_BACKOFF: Duration = Duration::from_mins(10);

/// What runs once a pull of the image went through, before the next pull starts.
pub(crate) type Then =
    Arc<dyn Fn(Reference) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// The worker, on a task of its own until stopped.
pub(crate) struct Prewarm {
    limit: Arc<AtomicU8>,
    task: JoinHandle<()>,
}

impl Prewarm {
    /// Pulls with `pull` what members push on `pushes`, but what `held` says the runtime lists, while the image
    /// filesystem is at most `limit` full; `then` follows each pull that went through.
    pub(crate) fn spawn(
        pushes: mpsc::Receiver<Pushed>,
        pull: Arc<dyn Pull>,
        then: Then,
        held: impl Fn(&Reference) -> bool + Send + 'static,
        limit: Percent,
    ) -> Self {
        let limit = Arc::new(AtomicU8::new(limit.get()));
        let task = tokio::spawn(run(
            pushes,
            pull,
            then,
            State::new(Box::new(held)),
            Arc::clone(&limit),
        ));
        Self { limit, task }
    }

    /// `prewarm.max_disk_percent`, from the next pull on.
    pub(crate) fn set_limit(&self, limit: Percent) {
        self.limit.store(limit.get(), Ordering::Relaxed);
    }

    /// Cuts the pull in flight, which the runtime then cancels (D39).
    pub(crate) async fn stop(self) {
        self.task.abort();
        // A cancelled task has nothing to say; a panic would already have been logged.
        let _ = self.task.await;
    }
}

/// What became of an attempt to pull.
#[derive(Debug)]
enum Outcome {
    Pulled,
    Failed(cri::Error),
    /// The image filesystem was this full, in percent: the pull was skipped.
    Full(u8),
}

/// An attempt to pull, running.
type Attempt = Pin<Box<dyn Future<Output = (Reference, Outcome)> + Send>>;

/// Takes the pushes and runs one attempt at a time, until the pushes end.
async fn run(
    mut pushes: mpsc::Receiver<Pushed>,
    pull: Arc<dyn Pull>,
    then: Then,
    mut state: State,
    limit: Arc<AtomicU8>,
) {
    match pull.marked().await {
        Ok(images) => state.pinned.extend(images),
        Err(err) => {
            warn!(error = %err, "the images pinned before stay pinned until a list names them again");
        }
    }
    let mut running: Option<Attempt> = None;
    loop {
        if running.is_none()
            && let Some(image) = state.next(Instant::now())
        {
            running = Some(Box::pin(attempt(
                Arc::clone(&pull),
                Arc::clone(&then),
                image,
                limit.load(Ordering::Relaxed),
            )));
        }
        // A retry that comes due while a pull runs waits for it to end.
        let wake = running.is_none().then(|| state.wake()).flatten();
        tokio::select! {
            received = pushes.recv() => match received {
                Some(received) => {
                    for change in state.take(received, Instant::now()) {
                        change.apply(&*pull, &mut state.pinned).await;
                    }
                }
                None => return,
            },
            (image, outcome) = async { running.as_mut().expect("polled only while running").await },
                if running.is_some() => {
                running = None;
                if let Some(change) = state.done(image, outcome, Instant::now()) {
                    change.apply(&*pull, &mut state.pinned).await;
                }
            }
            () = tokio::time::sleep_until(wake.unwrap_or_else(Instant::now)), if wake.is_some() => {}
        }
    }
}

/// Pulls `image` unless the image filesystem is fuller than `limit` percent, then runs `then` if the pull went through.
async fn attempt(
    pull: Arc<dyn Pull>,
    then: Then,
    image: Reference,
    limit: u8,
) -> (Reference, Outcome) {
    match pull.usage().await {
        Ok(usage) if usage > limit => return (image, Outcome::Full(usage)),
        Ok(_) => {}
        // The kubelet's image garbage collection still guards the disk.
        Err(err) => {
            warn!(error = %err, %image, "prewarming without knowing how full the image filesystem is");
        }
    }
    let outcome = match pull.pull(&image).await {
        Ok(()) => {
            then(image.clone()).await;
            Outcome::Pulled
        }
        Err(err) => Outcome::Failed(err),
    };
    (image, outcome)
}

/// A pin to set or take off.
#[derive(Debug, PartialEq, Eq)]
enum Pinning {
    /// A held image that a list names: the kubelet's image garbage collection keeps it.
    Pin(Reference),
    /// An image the agent pinned that no list names any more.
    Unpin(Reference),
}

impl Pinning {
    /// Sets or takes off the pin, and keeps `pinned`, the images that carry the agent's pin, up to date.
    async fn apply(self, pull: &dyn Pull, pinned: &mut HashSet<Reference>) {
        match self {
            Self::Pin(image) => match pull.pin(&image).await {
                Ok(true) => {
                    debug!(%image, "pinned");
                    pinned.insert(image);
                }
                Ok(false) => {}
                // The kubelet may then remove it, and the next pod pulls it from peers.
                Err(err) => warn!(%image, error = %err, "a prewarmed image stays unpinned"),
            },
            Self::Unpin(image) => match pull.unpin(&image).await {
                Ok(()) => {
                    info!(%image, "unpinned: no list names it");
                    pinned.remove(&image);
                }
                // It stays in `pinned`: the next list tries again.
                Err(err) => warn!(%image, error = %err, "an image no list names stays pinned"),
            },
        }
    }
}

/// A pull to try again.
#[derive(Debug)]
struct Retry {
    image: Reference,
    /// When.
    at: Instant,
    /// The wait that led there.
    backoff: Duration,
}

/// What the worker knows, apart from the pull in flight.
struct State {
    /// Whether the runtime lists an image.
    held: Box<dyn Fn(&Reference) -> bool + Send>,
    /// Each member's latest `PrewarmList`.
    lists: HashMap<String, PrewarmList>,
    /// Pushed images, in the order they came.
    queue: VecDeque<Reference>,
    /// The image whose attempt runs.
    pulling: Option<Reference>,
    /// Images whose pull failed or was skipped, in the order they first did: retries due together go in that order.
    retries: Vec<Retry>,
    /// Images pulled, and when: the runtime's list may not show them before its next relist.
    pulled: HashMap<Reference, Instant>,
    /// Whether a full image filesystem was warned of since the last pull went through.
    warned: bool,
    /// Images the agent pinned.
    pinned: HashSet<Reference>,
}

impl State {
    fn new(held: Box<dyn Fn(&Reference) -> bool + Send>) -> Self {
        Self {
            held,
            lists: HashMap::new(),
            queue: VecDeque::new(),
            pulling: None,
            retries: Vec::new(),
            pulled: HashMap::new(),
            warned: false,
            pinned: HashSet::new(),
        }
    }

    /// Takes what a member pushed, and answers the pins it changes: on for a held image a list names, off for the
    /// pinned images it leaves no list naming.
    fn take(&mut self, pushed: Pushed, now: Instant) -> Vec<Pinning> {
        match pushed.push {
            Push::Prewarm(image) => {
                self.pulled.retain(|_, at| now.duration_since(*at) < RELIST);
                let held = (self.held)(&image);
                if self.in_flight(&image) || self.pulled.contains_key(&image) || held {
                    counter!(PREWARM_PULLS, "result" => "dropped").increment(1);
                    debug!(%image, member = pushed.member, "dropped a prewarm of an image held or in flight");
                    // Held before a list named it, from a pod's pull, or pulled while the pin failed.
                    if held && !self.pinned.contains(&image) && named(&self.lists, &image) {
                        return vec![Pinning::Pin(image)];
                    }
                } else {
                    self.queue.push_back(image);
                }
                Vec::new()
            }
            Push::List(list) => {
                self.lists.insert(pushed.member, list);
                let lists = &self.lists;
                self.retries.retain_mut(|retry| {
                    retry.at = now;
                    named(lists, &retry.image)
                });
                self.pinned
                    .iter()
                    .filter(|image| !named(lists, image))
                    .map(|image| Pinning::Unpin(image.clone()))
                    .collect()
            }
        }
    }

    /// Whether `image` is queued, pulling or waiting for a retry.
    fn in_flight(&self, image: &Reference) -> bool {
        self.pulling.as_ref() == Some(image)
            || self.queue.contains(image)
            || self.retries.iter().any(|retry| retry.image == *image)
    }

    /// The next image to pull, if one is due: the first pushed, else the retry due first.
    fn next(&mut self, now: Instant) -> Option<Reference> {
        let image = self.queue.pop_front().or_else(|| {
            self.retries
                .iter()
                .filter(|retry| retry.at <= now)
                .min_by_key(|retry| retry.at)
                .map(|retry| retry.image.clone())
        })?;
        self.pulling = Some(image.clone());
        Some(image)
    }

    /// When the next retry comes due.
    fn wake(&self) -> Option<Instant> {
        self.retries.iter().map(|retry| retry.at).min()
    }

    /// Counts the attempt on `image`, and keeps it to retry while a member's list names it. Answers the pin of a pulled
    /// image that a list names.
    fn done(&mut self, image: Reference, outcome: Outcome, now: Instant) -> Option<Pinning> {
        self.pulling = None;
        match outcome {
            Outcome::Pulled => {
                counter!(PREWARM_PULLS, "result" => "ok").increment(1);
                info!(%image, "prewarmed");
                self.retries.retain(|retry| retry.image != image);
                self.pulled.insert(image.clone(), now);
                self.warned = false;
                return named(&self.lists, &image).then_some(Pinning::Pin(image));
            }
            Outcome::Failed(err) => {
                counter!(PREWARM_PULLS, "result" => "failed").increment(1);
                warn!(%image, error = %err, "a prewarm pull failed");
                self.retry(image, now);
            }
            Outcome::Full(usage) => {
                counter!(PREWARM_PULLS, "result" => "no_space").increment(1);
                if !self.warned {
                    warn!(
                        %image,
                        usage,
                        "prewarm pulls are skipped while the image filesystem is fuller than prewarm.max_disk_percent"
                    );
                    self.warned = true;
                }
                self.retry(image, now);
            }
        }
        None
    }

    /// Waits a doubled backoff before trying `image` again, if a member's list names it.
    fn retry(&mut self, image: Reference, now: Instant) {
        // A list that stops naming an image drops its retry at once, in `take`.
        if !named(&self.lists, &image) {
            return;
        }
        match self.retries.iter().position(|retry| retry.image == image) {
            None => self.retries.push(Retry {
                image,
                at: now + FIRST_BACKOFF,
                backoff: FIRST_BACKOFF,
            }),
            Some(index) => {
                let retry = &mut self.retries[index];
                retry.backoff = (retry.backoff * 2).min(MAX_BACKOFF);
                retry.at = now + retry.backoff;
            }
        }
    }
}

/// Whether a member's latest list names `image`.
fn named(lists: &HashMap<String, PrewarmList>, image: &Reference) -> bool {
    lists.values().any(|list| list.images().contains(image))
}

#[cfg(test)]
mod tests;
