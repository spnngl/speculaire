//! The trigger of discovery at M4: every manifest digest the runtime's image list names is a root (D121). The store
//! keeps only what the roots listed name (D131).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use speculaire_oci::reference::Digest;
use speculaire_runtime::images::{Images, List, Update};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep_until};
use tracing::{info, warn};

use crate::discover::{Discovery, Error, RETRY, Reason};
use crate::store::{Artifact, Store};

/// How long after a reflector stream comes up a discovery that starts is asked again soon when no source serves its
/// root (D134).
const FRESH: Duration = Duration::from_secs(10);

/// How long a root asked again soon waits before each of its tries (D134).
const SOON: Duration = Duration::from_secs(20);

/// How many times a root is asked again soon, before it waits [`RETRY`] (D134).
const TRIES: u8 = 3;

/// The roots each listed manifest digest has, by root: the names the list gives it, once each, in the list's order.
pub type Roots = HashMap<Digest, Vec<String>>;

/// What discovery tells verification, in order (D20): each change of the roots listed, and how each discovery ends.
#[derive(Debug)]
pub enum Found {
    /// The roots listed now; a root it lacks left the list.
    Listed(Roots),
    /// The discovery of `root` ended, or found it recorded by an earlier run.
    Ended {
        /// The root.
        root: Digest,
        /// Whether its artifacts are recorded.
        discovered: Result<(), Error>,
    },
}

/// What discovery came to for a root this run.
enum Done {
    Discovered,
    /// Discovered again from this time on.
    Retry(Instant),
}

/// A discovery under way: its root, when it started, and what it comes to.
struct Running {
    root: Digest,
    started: Instant,
    discovered: Pin<Box<dyn Future<Output = Result<Vec<Artifact>, Error>> + Send>>,
}

/// The roots queued for discovery, and the one discovered, if any: a lane discovers one root at a time (D146).
#[derive(Default)]
struct Lane {
    queue: VecDeque<Digest>,
    running: Option<Running>,
}

impl Lane {
    /// Starts discovering the first root queued that is due, listed and not recorded, unless a discovery runs already.
    /// A root that `elsewhere` discovers is dropped: that discovery records it. A root found recorded is told to `found`.
    async fn start(
        &mut self,
        discovery: &Arc<Discovery>,
        listed: &Roots,
        done: &mut HashMap<Digest, Done>,
        elsewhere: Option<&Digest>,
        found: &mpsc::UnboundedSender<Found>,
    ) {
        while self.running.is_none() {
            let Some(root) = self.queue.pop_front() else {
                return;
            };
            let due = match done.get(&root) {
                None => true,
                Some(Done::Discovered) => false,
                Some(Done::Retry(at)) => *at <= Instant::now(),
            };
            let Some(names) = listed.get(&root).cloned() else {
                continue;
            };
            if !due || elsewhere == Some(&root) {
                continue;
            }
            let recorded = match discovery.store().recorded(&root).await {
                Ok(recorded) => recorded.is_some(),
                Err(e) => {
                    warn!(%root, error = %e, "a root's record cannot be read: its artifacts are discovered again");
                    false
                }
            };
            if recorded {
                done.insert(root.clone(), Done::Discovered);
                // Nobody verifies when the receiver is gone.
                let _ = found.send(Found::Ended {
                    root,
                    discovered: Ok(()),
                });
                continue;
            }
            let discovery = Arc::clone(discovery);
            let asked = root.clone();
            self.running = Some(Running {
                root,
                started: Instant::now(),
                discovered: Box::pin(async move { discovery.discover(&asked, &names).await }),
            });
        }
    }

    /// The root discovered, when its discovery started, and what it came to, once it ends; never while none runs.
    async fn ended(&mut self) -> (Digest, Instant, Result<Vec<Artifact>, Error>) {
        let Some(running) = &mut self.running else {
            return std::future::pending().await;
        };
        let discovered = running.discovered.as_mut().await;
        let (root, started) = (running.root.clone(), running.started);
        self.running = None;
        (root, started, discovered)
    }

    /// The root discovered, if any.
    fn root(&self) -> Option<&Digest> {
        self.running.as_ref().map(|running| &running.root)
    }
}

/// The roots asked again soon after a reflector stream came up (D134).
struct Soon {
    /// When the latest reflector stream came up.
    last_up: watch::Receiver<Option<Instant>>,
    /// The tries left of each root asked again soon.
    left: HashMap<Digest, u8>,
}

impl Soon {
    /// When `root`, whose discovery started at `started` and ended in `error`, is asked again soon, if it is: when no
    /// source served it, [`SOON`] from now while its tries last, which a discovery started at most [`FRESH`] after the
    /// latest stream came up begins.
    fn next(&mut self, root: &Digest, started: Instant, error: &Error) -> Option<Instant> {
        let left = self.left.remove(root);
        let Error::Unverifiable {
            reason: Reason::Unreachable,
            ..
        } = error
        else {
            return None;
        };
        let fresh = self
            .last_up
            .borrow()
            .is_some_and(|up| started <= up + FRESH);
        let after = left.or(fresh.then_some(TRIES))?.checked_sub(1)?;
        self.left.insert(root.clone(), after);
        Some(Instant::now() + SOON)
    }

    /// What the discovery of `root`, started at `started`, came to, logged.
    fn ended(
        &mut self,
        root: &Digest,
        started: Instant,
        discovered: &Result<Vec<Artifact>, Error>,
    ) -> Done {
        match discovered {
            Ok(artifacts) => {
                info!(%root, artifacts = artifacts.len(), "artifacts discovered");
                Done::Discovered
            }
            // An image pulled with a pull secret only is unreachable by design (D17), and a rate limit is upstream's
            // to set (D38): no warning.
            Err(e @ Error::Unverifiable { retry_at, .. }) => {
                info!("discovery of {root}: {e}");
                Done::Retry(self.next(root, started, e).unwrap_or(*retry_at))
            }
            Err(e @ Error::Store(_)) => {
                warn!(%root, error = %e, "artifacts not discovered");
                Done::Retry(Instant::now() + RETRY)
            }
        }
    }
}

/// Discovers the artifacts of each root the image list of `images` names, once per run, until the list ends.
///
/// Discovery starts once `linked` completes. The store is collected at each listing and whenever a root leaves the
/// list, from the first listing on, a discovery running or not (D144): it announces nothing until then.
///
/// A root recorded by an earlier run is not discovered again; one whose discovery failed is tried again at the time
/// its error gives, or after [`RETRY`] when the store failed. A root no source served, in a discovery that started at
/// most 10 s after `last_up`, the time the latest reflector stream came up, is tried again 3 times 20 s apart first
/// (D134): a reflector that just restarted names no holder until each agent's stream to it is back. A root that leaves the list loses its artifacts, and is discovered again if it comes back.
///
/// The roots of an image just listed have a lane of their own, beside that of the roots a listing or a retry queued
/// (D146): a pull waits at most for the discovery of another image just listed, not for a root that a listing found
/// and whose sources do not answer.
///
/// `found` is told the roots listed as they change, then how each discovery ends, and each root found recorded.
pub async fn follow(
    discovery: Arc<Discovery>,
    images: Arc<dyn Images>,
    linked: impl Future<Output = ()> + Send,
    last_up: watch::Receiver<Option<Instant>>,
    found: mpsc::UnboundedSender<Found>,
) {
    let (sender, mut updates) = mpsc::channel(16);
    let following = tokio::spawn(images.follow(sender));
    let mut linked = std::pin::pin!(linked);
    let mut is_linked = false;
    let mut list = List::default();
    let (mut pulled, mut backlog) = (Lane::default(), Lane::default());
    let mut done: HashMap<Digest, Done> = HashMap::new();
    let mut soon = Soon {
        last_up,
        left: HashMap::new(),
    };
    // The roots listed, and whether the store may hold what they do not name: a listing came since the last
    // collection, or a root that left was recorded.
    let mut listed = Roots::new();
    let mut stale = false;
    loop {
        while let Ok(update) = updates.try_recv() {
            stale |= enqueue(&mut list, &mut pulled.queue, &mut backlog.queue, update);
        }
        // The store is collected as a root leaves the list, discoveries running or not: one may wait on peers and
        // upstream for seconds (D144).
        if roots_left(&list, &mut listed, &found) || stale {
            collect(discovery.store(), &listed, &mut done, &mut soon).await;
            stale = false;
        }
        if is_linked {
            pulled
                .start(&discovery, &listed, &mut done, backlog.root(), &found)
                .await;
            backlog
                .start(&discovery, &listed, &mut done, pulled.root(), &found)
                .await;
        }
        let next = done
            .values()
            .filter_map(|done| match done {
                Done::Retry(at) => Some(*at),
                Done::Discovered => None,
            })
            .min();
        let wake = async {
            match next {
                Some(at) => sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        let (root, started, discovered) = tokio::select! {
            ended = pulled.ended() => ended,
            ended = backlog.ended() => ended,
            update = updates.recv() => {
                match update {
                    Some(update) => stale |= enqueue(&mut list, &mut pulled.queue, &mut backlog.queue, update),
                    None => break,
                }
                continue;
            }
            () = &mut linked, if !is_linked => {
                is_linked = true;
                continue;
            }
            () = wake => {
                // Due roots are forgotten, so that one which left the list is not woken for again.
                let now = Instant::now();
                done.retain(|root, done| match done {
                    Done::Retry(at) if *at <= now => {
                        backlog.queue.push_back(root.clone());
                        false
                    }
                    Done::Retry(_) | Done::Discovered => true,
                });
                continue;
            }
        };
        // Recorded after it left the list: collected at the next turn.
        stale |= !listed.contains_key(&root);
        let ended = soon.ended(&root, started, &discovered);
        done.insert(root.clone(), ended);
        let _ = found.send(Found::Ended {
            root,
            discovered: discovered.map(drop),
        });
    }
    following.abort();
}

/// Applies `update` to `list` and queues its roots, and tells whether `update` is a listing.
///
/// The roots of an image listed go in `pulled`, those of a listing in `backlog`.
fn enqueue(
    list: &mut List,
    pulled: &mut VecDeque<Digest>,
    backlog: &mut VecDeque<Digest>,
    update: Update,
) -> bool {
    let listing = matches!(update, Update::Listing(_));
    match &update {
        Update::Listed(image) => {
            pulled.extend(
                image
                    .repo_digests
                    .iter()
                    .map(|repo_digest| repo_digest.digest.clone()),
            );
        }
        Update::Listing(images) => {
            for repo_digest in images.iter().flat_map(|image| &image.repo_digests) {
                if !backlog.contains(&repo_digest.digest) {
                    backlog.push_back(repo_digest.digest.clone());
                }
            }
        }
        Update::Removed(_) => {}
    }
    list.apply(update);
    listing
}

/// Sets `listed` to the roots `list` names, telling `found` when they changed, and tells whether one it held left.
fn roots_left(list: &List, listed: &mut Roots, found: &mpsc::UnboundedSender<Found>) -> bool {
    let now = roots(list);
    if now == *listed {
        return false;
    }
    let left = listed.keys().any(|root| !now.contains_key(root));
    let _ = found.send(Found::Listed(now.clone()));
    *listed = now;
    left
}

/// Collects `store` down to what the roots `listed` name, and forgets the others in `done` and `soon`: a root collected
/// is discovered again when it comes back.
async fn collect(
    store: &Arc<Store>,
    listed: &Roots,
    done: &mut HashMap<Digest, Done>,
    soon: &mut Soon,
) {
    if let Err(e) = store.collect(listed.keys().cloned().collect()).await {
        warn!(error = %e, "the artifact store cannot be collected: what it holds stays until the next listing");
    }
    done.retain(|root, _| listed.contains_key(root));
    soon.left.retain(|root, _| listed.contains_key(root));
}

/// The roots `list` names, each with its names once each, in the list's order: on CRI-O, every repository of an image
/// with every digest it was pulled by (D65).
#[must_use]
pub fn roots(list: &List) -> Roots {
    let mut roots = Roots::new();
    for repo_digest in list.images().flat_map(|image| &image.repo_digests) {
        let names = roots.entry(repo_digest.digest.clone()).or_default();
        if !names.contains(&repo_digest.repository) {
            names.push(repo_digest.repository.clone());
        }
    }
    roots
}

#[cfg(test)]
mod tests;
