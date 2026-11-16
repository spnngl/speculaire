//! The trigger of discovery at M4: every manifest digest the runtime's image list names is a root (D119).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use speculaire_oci::reference::Digest;
use speculaire_runtime::images::{Images, List, Update};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{info, warn};

use crate::discover::{Discovery, Error};

/// How long a root whose discovery failed waits before it is tried again.
pub const RETRY: Duration = Duration::from_secs(600);

/// What discovery came to for a root this run.
enum Done {
    Discovered,
    Failed(Instant),
}

/// Discovers the artifacts of each root the image list of `images` names, once per run, until the list ends.
///
/// A root recorded by an earlier run is not discovered again; one whose discovery failed is tried again after
/// [`RETRY`], at a later listing. A root that leaves the list keeps its artifacts.
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
            match updates.recv().await {
                Some(update) => {
                    enqueue(&mut list, &mut queue, update);
                    continue;
                }
                None => break,
            }
        };
        let due = match done.get(&root) {
            None => true,
            Some(Done::Discovered) => false,
            Some(Done::Failed(at)) => at.elapsed() >= RETRY,
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
            // An image pulled with a pull secret only is unreachable by design (D17): no warning.
            Err(Error::Unreachable) => {
                info!(%root, "artifacts unreachable: no source served the root");
                done.insert(root, Done::Failed(Instant::now()));
            }
            Err(e @ Error::Store(_)) => {
                warn!(%root, error = %e, "artifacts not discovered");
                done.insert(root, Done::Failed(Instant::now()));
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
