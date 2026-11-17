//! The trigger of discovery at M4: every manifest digest the runtime's image list names is a root (D121). The store
//! keeps only what the roots listed name (D131).

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use speculaire_oci::reference::Digest;
use speculaire_runtime::images::{Images, List, Update};
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep_until};
use tracing::{info, warn};

use crate::discover::{Discovery, Error, RETRY, Reason};
use crate::store::Store;

/// How long after a reflector stream comes up a discovery that starts is asked again soon when no source serves its
/// root (D134).
const FRESH: Duration = Duration::from_secs(10);

/// How long a root asked again soon waits before each of its tries (D134).
const SOON: Duration = Duration::from_secs(20);

/// How many times a root is asked again soon, before it waits [`RETRY`] (D134).
const TRIES: u8 = 3;

/// What discovery came to for a root this run.
enum Done {
    Discovered,
    /// Discovered again from this time on.
    Retry(Instant),
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
}

/// Discovers the artifacts of each root the image list of `images` names, once per run, until the list ends.
///
/// Discovery starts once `linked` completes. The store is collected at each listing and whenever a root leaves the
/// list, from the first listing on: it announces nothing until then.
///
/// A root recorded by an earlier run is not discovered again; one whose discovery failed is tried again at the time
/// its error gives, or after [`RETRY`] when the store failed. A root no source served, in a discovery that started at
/// most 10 s after `last_up`, the time the latest reflector stream came up, is tried again 3 times 20 s apart first
/// (D134): a reflector that just restarted names no holder until each agent's stream to it is back. A root that leaves the list loses its artifacts, and is discovered again if it comes back.
///
/// The roots of an image just listed go before those a listing queued: a pull waits for one discovery at most, not
/// for every root a restart finds unrecorded.
pub async fn follow(
    discovery: Arc<Discovery>,
    images: Arc<dyn Images>,
    linked: impl Future<Output = ()> + Send,
    last_up: watch::Receiver<Option<Instant>>,
) {
    let (sender, mut updates) = mpsc::channel(16);
    let following = tokio::spawn(images.follow(sender));
    let mut linked = std::pin::pin!(linked);
    let mut is_linked = false;
    let mut list = List::default();
    let mut queue = VecDeque::new();
    let mut done: HashMap<Digest, Done> = HashMap::new();
    let mut soon = Soon {
        last_up,
        left: HashMap::new(),
    };
    // The roots listed, and whether a listing came since the last collection.
    let mut listed = HashSet::new();
    let mut relisted = false;
    loop {
        while let Ok(update) = updates.try_recv() {
            relisted |= enqueue(&mut list, &mut queue, update);
        }
        if roots_left(&list, &mut listed) || relisted {
            collect(discovery.store(), &listed).await;
            // A root collected is discovered again when it comes back.
            done.retain(|root, _| listed.contains(root));
            soon.left.retain(|root, _| listed.contains(root));
            relisted = false;
        }
        let next = if is_linked { queue.pop_front() } else { None };
        let Some(root) = next else {
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
            tokio::select! {
                update = updates.recv() => match update {
                    Some(update) => relisted |= enqueue(&mut list, &mut queue, update),
                    None => break,
                },
                () = &mut linked, if !is_linked => is_linked = true,
                () = wake => {
                    // Due roots are forgotten, so that one which left the list is not woken for again.
                    let now = Instant::now();
                    done.retain(|root, done| match done {
                        Done::Retry(at) if *at <= now => {
                            queue.push_back(root.clone());
                            false
                        }
                        Done::Retry(_) | Done::Discovered => true,
                    });
                }
            }
            continue;
        };
        let due = match done.get(&root) {
            None => true,
            Some(Done::Discovered) => false,
            Some(Done::Retry(at)) => *at <= Instant::now(),
        };
        let names = names(&list, &root);
        if !due || names.is_empty() {
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
            done.insert(root, Done::Discovered);
            continue;
        }
        let started = Instant::now();
        match discovery.discover(&root, &names).await {
            Ok(artifacts) => {
                info!(%root, artifacts = artifacts.len(), "artifacts discovered");
                done.insert(root, Done::Discovered);
            }
            // An image pulled with a pull secret only is unreachable by design (D17), and a rate limit is upstream's
            // to set (D38): no warning.
            Err(e @ Error::Unverifiable { retry_at, .. }) => {
                info!("discovery of {root}: {e}");
                let at = soon.next(&root, started, &e).unwrap_or(retry_at);
                done.insert(root, Done::Retry(at));
            }
            Err(e @ Error::Store(_)) => {
                warn!(%root, error = %e, "artifacts not discovered");
                done.insert(root, Done::Retry(Instant::now() + RETRY));
            }
        }
    }
    following.abort();
}

/// Applies `update` to `list` and queues its roots, and tells whether `update` is a listing.
///
/// The roots of an image listed go in front, those of a listing behind.
fn enqueue(list: &mut List, queue: &mut VecDeque<Digest>, update: Update) -> bool {
    let listing = matches!(update, Update::Listing(_));
    match &update {
        Update::Listed(image) => {
            for repo_digest in image.repo_digests.iter().rev() {
                queue.push_front(repo_digest.digest.clone());
            }
        }
        Update::Listing(images) => {
            for repo_digest in images.iter().flat_map(|image| &image.repo_digests) {
                if !queue.contains(&repo_digest.digest) {
                    queue.push_back(repo_digest.digest.clone());
                }
            }
        }
        Update::Removed(_) => {}
    }
    list.apply(update);
    listing
}

/// Sets `listed` to the roots `list` names, and tells whether one it held left.
fn roots_left(list: &List, listed: &mut HashSet<Digest>) -> bool {
    let now: HashSet<Digest> = list
        .images()
        .flat_map(|image| &image.repo_digests)
        .map(|repo_digest| repo_digest.digest.clone())
        .collect();
    let left = !listed.is_subset(&now);
    *listed = now;
    left
}

/// Collects `store` down to what the roots `listed` name.
async fn collect(store: &Arc<Store>, listed: &HashSet<Digest>) {
    if let Err(e) = store.collect(listed.clone()).await {
        warn!(error = %e, "the artifact store cannot be collected: what it holds stays until the next listing");
    }
}

/// The names the list gives the manifest digest `root`, once each, in the list's order; none once it left the list.
fn names(list: &List, root: &Digest) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let listed = list.images().flat_map(|image| &image.repo_digests);
    for repo_digest in listed.filter(|repo_digest| repo_digest.digest == *root) {
        if !names.contains(&repo_digest.repository) {
            names.push(repo_digest.repository.clone());
        }
    }
    names
}

#[cfg(test)]
mod tests;
