//! The triggers of discovery: every manifest digest the runtime's image list names is a root (D121), and so is each
//! manifest fetched through the mirror before it is listed (D152). The store keeps only what the roots listed name,
//! and a root fetched for a grace (D131, D153).

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use speculaire_mirror::Fetched;
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

/// What discovery tells verification, in order (D20): each change of the roots, and how each discovery ends.
#[derive(Debug)]
pub enum Found {
    /// The roots now; a root neither lists left.
    Roots {
        /// The roots listed.
        listed: Roots,
        /// The roots fetched through the mirror and not listed, with the names they were fetched under (D152).
        fetched: Roots,
    },
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
    /// Starts discovering the first root queued that is due, listed or fetched, and not recorded, unless a discovery
    /// runs already. A root that `elsewhere` discovers is dropped: that discovery records it. A root found recorded is
    /// told to `found`.
    async fn start(
        &mut self,
        discovery: &Arc<Discovery>,
        listed: &Roots,
        fetched: &Roots,
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
            let Some(names) = listed.get(&root).or_else(|| fetched.get(&root)).cloned() else {
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

/// The manifests fetched through the mirror, and how long the store keeps a root fetched and not listed (D152, D153).
pub struct Fetching {
    /// Each manifest fetched, as the mirror tells it.
    pub fetched: mpsc::UnboundedReceiver<Fetched>,
    /// How long after its fetch a root not listed keeps its artifacts.
    pub grace: Duration,
}

/// The roots fetched through the mirror and not listed (D152).
#[derive(Default)]
struct Unlisted {
    /// Each root, with the names it was fetched under.
    roots: Roots,
    /// When the first grace the store keeps ends (D153).
    ends: Option<SystemTime>,
    /// The manifests each root names, once read: those an index names are its own to discover (D22).
    children: HashMap<Digest, Vec<Digest>>,
}

impl Unlisted {
    /// Takes in `fetch`, marked in the store and kept for `grace`, and tells whether it is a root: one neither `listed`
    /// nor fetched, that no root names.
    async fn take(
        &mut self,
        discovery: &Discovery,
        listed: &Roots,
        grace: Duration,
        fetch: Fetched,
    ) -> bool {
        let Fetched { digest, name } = fetch;
        if listed.contains_key(&digest) || self.roots.contains_key(&digest) {
            return false;
        }
        for root in listed.keys().chain(self.roots.keys()) {
            if !self.children.contains_key(root)
                && let Some(children) = discovery.children(root).await
            {
                self.children.insert(root.clone(), children);
            }
        }
        if self
            .children
            .values()
            .flatten()
            .any(|child| *child == digest)
        {
            return false;
        }
        if let Err(e) = discovery.store().fetched(&digest).await {
            warn!(root = %digest, error = %e, "a root fetched cannot be marked: its artifacts go at the next collection");
        }
        let ends = SystemTime::now() + grace;
        self.ends = Some(self.ends.map_or(ends, |first| first.min(ends)));
        self.roots.insert(digest, vec![name]);
        true
    }

    /// Whether `root` is listed or fetched.
    fn known(&self, listed: &Roots, root: &Digest) -> bool {
        listed.contains_key(root) || self.roots.contains_key(root)
    }
}

/// Discovers the artifacts of each root the image list of `images` names, and of each manifest `fetching` tells of
/// that the list does not name, once per run, until the list ends.
///
/// Discovery starts once `linked` completes. The store is collected at each listing, whenever a root leaves the list
/// or a root fetched is listed, and as a root fetched ends its grace, from the first listing on, a discovery running or
/// not (D144): it announces nothing until then.
///
/// A root recorded by an earlier run is not discovered again; one whose discovery failed is tried again at the time
/// its error gives, or after [`RETRY`] when the store failed. A root no source served, in a discovery that started at
/// most 10 s after `last_up`, the time the latest reflector stream came up, is tried again 3 times 20 s apart first
/// (D134): a reflector that just restarted names no holder until each agent's stream to it is back. A root that leaves the list loses its artifacts, and is discovered again if it comes back.
///
/// The roots of an image just listed or fetched have a lane of their own, beside that of the roots a listing or a
/// retry queued (D146): a pull waits at most for the discovery of another image just listed, not for a root that a
/// listing found and whose sources do not answer. A manifest fetched that is listed, fetched already, or named by an
/// index root is no root (D152).
///
/// `found` is told the roots as they change, then how each discovery ends, and each root found recorded.
pub async fn follow(
    discovery: Arc<Discovery>,
    images: Arc<dyn Images>,
    fetching: Fetching,
    linked: impl Future<Output = ()> + Send,
    last_up: watch::Receiver<Option<Instant>>,
    found: mpsc::UnboundedSender<Found>,
) {
    let Fetching { mut fetched, grace } = fetching;
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
    // The roots listed and fetched, and whether the store may hold what they do not name: a listing came since the
    // last collection, a root that left was recorded, or a grace ended.
    let mut listed = Roots::new();
    let mut unlisted = Unlisted::default();
    let mut stale = false;
    // A grace ending before the first listing collects nothing: the store would lose what the list names.
    let mut listing_came = false;
    loop {
        while let Ok(update) = updates.try_recv() {
            stale |= enqueue(&mut list, &mut pulled.queue, &mut backlog.queue, update);
        }
        listing_came |= stale;
        // The store is collected as a root leaves the list, discoveries running or not: one may wait on peers and
        // upstream for seconds (D144).
        if roots_left(&list, &mut listed, &mut unlisted, &found) || stale {
            collect(
                discovery.store(),
                &listed,
                &mut unlisted,
                grace,
                &mut done,
                &mut soon,
                &found,
            )
            .await;
            stale = false;
        }
        if is_linked {
            let roots = (&listed, &unlisted.roots);
            start(
                &discovery,
                &mut pulled,
                &mut backlog,
                roots,
                &mut done,
                &found,
            )
            .await;
        }
        let graced = unlisted.ends.filter(|_| listing_came).map(|ends| {
            Instant::now() + ends.duration_since(SystemTime::now()).unwrap_or_default()
        });
        let wake = wake(retry(&done).into_iter().chain(graced).min());
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
            Some(fetch) = fetched.recv() => {
                let root = fetch.digest.clone();
                if unlisted.take(&discovery, &listed, grace, fetch).await {
                    pulled.queue.push_back(root);
                    tell(&found, &listed, &unlisted);
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
                stale |= graced.is_some_and(|ends| ends <= now);
                continue;
            }
        };
        // Recorded after it left the list or its grace: collected at the next turn.
        stale |= !unlisted.known(&listed, &root);
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
/// Starts the next root of each idle lane, the roots just listed or fetched first, each skipping the root under way in
/// the other (D146). `roots` are the roots listed, then those fetched.
async fn start(
    discovery: &Arc<Discovery>,
    pulled: &mut Lane,
    backlog: &mut Lane,
    (listed, fetched): (&Roots, &Roots),
    done: &mut HashMap<Digest, Done>,
    found: &mpsc::UnboundedSender<Found>,
) {
    pulled
        .start(discovery, listed, fetched, done, backlog.root(), found)
        .await;
    backlog
        .start(discovery, listed, fetched, done, pulled.root(), found)
        .await;
}

/// The time of the first retry due.
fn retry(done: &HashMap<Digest, Done>) -> Option<Instant> {
    done.values()
        .filter_map(|done| match done {
            Done::Retry(at) => Some(*at),
            Done::Discovered => None,
        })
        .min()
}

/// Wakes at `at`, or never.
async fn wake(at: Option<Instant>) {
    match at {
        Some(at) => sleep_until(at).await,
        None => std::future::pending().await,
    }
}

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

/// Sets `listed` to the roots `list` names, a root fetched then listed being listed alone from then on, telling `found`
/// when they changed; tells whether one listed left or one fetched is listed now, which the store need not keep for its
/// grace any more.
fn roots_left(
    list: &List,
    listed: &mut Roots,
    unlisted: &mut Unlisted,
    found: &mpsc::UnboundedSender<Found>,
) -> bool {
    let now = roots(list);
    if now == *listed {
        return false;
    }
    let left = listed.keys().any(|root| !now.contains_key(root));
    let fetched = unlisted.roots.len();
    unlisted.roots.retain(|root, _| !now.contains_key(root));
    *listed = now;
    tell(found, listed, unlisted);
    left || unlisted.roots.len() != fetched
}

/// Tells `found` the roots listed and fetched.
fn tell(found: &mpsc::UnboundedSender<Found>, listed: &Roots, unlisted: &Unlisted) {
    // Nobody verifies when the receiver is gone.
    let _ = found.send(Found::Roots {
        listed: listed.clone(),
        fetched: unlisted.roots.clone(),
    });
}

/// Collects `store` down to what the roots `listed`, and those fetched within `grace`, name, and forgets the others in
/// `unlisted`, `done` and `soon`, telling `found` of a root fetched that is gone: a root collected is discovered again
/// when it comes back.
async fn collect(
    store: &Arc<Store>,
    listed: &Roots,
    unlisted: &mut Unlisted,
    grace: Duration,
    done: &mut HashMap<Digest, Done>,
    soon: &mut Soon,
    found: &mpsc::UnboundedSender<Found>,
) {
    match store.collect(listed.keys().cloned().collect(), grace).await {
        Ok(graced) => {
            unlisted.ends = graced.ends;
            let fetched = unlisted.roots.len();
            unlisted.roots.retain(|root, _| graced.roots.contains(root));
            if unlisted.roots.len() != fetched {
                tell(found, listed, unlisted);
            }
        }
        Err(e) => {
            // No wake for a grace until then: the next collection would fail alike.
            unlisted.ends = None;
            warn!(error = %e, "the artifact store cannot be collected: what it holds stays until the next listing");
        }
    }
    done.retain(|root, _| unlisted.known(listed, root));
    soon.left.retain(|root, _| unlisted.known(listed, root));
    let Unlisted {
        roots, children, ..
    } = unlisted;
    children.retain(|root, _| listed.contains_key(root) || roots.contains_key(root));
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
