//! The trigger of discovery at M4: every manifest digest the runtime's image list names is a root (D121).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use speculaire_oci::reference::Digest;
use speculaire_runtime::images::{Images, List, Update};
use tokio::sync::mpsc;
use tokio::time::{Instant, sleep_until};
use tracing::{info, warn};

use crate::discover::{Discovery, Error, RETRY};

/// What discovery came to for a root this run.
enum Done {
    Discovered,
    /// Discovered again from this time on.
    Retry(Instant),
}

/// Discovers the artifacts of each root the image list of `images` names, once per run, until the list ends.
///
/// A root recorded by an earlier run is not discovered again; one whose discovery failed is tried again at the time
/// its error gives, or after [`RETRY`] when the store failed. A root that leaves the list keeps its artifacts.
///
/// The roots of an image just listed go before those a listing queued: a pull waits for one discovery at most, not
/// for every root a restart finds unrecorded.
pub async fn follow(discovery: Arc<Discovery>, images: Arc<dyn Images>) {
    let (sender, mut updates) = mpsc::channel(16);
    let following = tokio::spawn(images.follow(sender));
    let mut list = List::default();
    let mut queue = VecDeque::new();
    let mut done: HashMap<Digest, Done> = HashMap::new();
    loop {
        while let Ok(update) = updates.try_recv() {
            enqueue(&mut list, &mut queue, update);
        }
        let Some(root) = queue.pop_front() else {
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
                    Some(update) => enqueue(&mut list, &mut queue, update),
                    None => break,
                },
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
        match discovery.discover(&root, &names).await {
            Ok(artifacts) => {
                info!(%root, artifacts = artifacts.len(), "artifacts discovered");
                done.insert(root, Done::Discovered);
            }
            // An image pulled with a pull secret only is unreachable by design (D17), and a rate limit is upstream's
            // to set (D38): no warning.
            Err(e @ Error::Unverifiable { retry_at, .. }) => {
                info!("discovery of {root}: {e}");
                done.insert(root, Done::Retry(retry_at));
            }
            Err(e @ Error::Store(_)) => {
                warn!(%root, error = %e, "artifacts not discovered");
                done.insert(root, Done::Retry(Instant::now() + RETRY));
            }
        }
    }
    following.abort();
}

/// Applies `update` to `list` and queues its roots: those of an image listed in front, those of a listing behind.
fn enqueue(list: &mut List, queue: &mut VecDeque<Digest>, update: Update) {
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
