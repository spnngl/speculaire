//! The trigger of discovery at M4: every manifest digest the runtime's image list names is a root (D114).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use speculaire_oci::reference::Digest;
use speculaire_runtime::images::{Images, List};
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
/// [`RETRY`], at the next update of the list. A root that leaves the list keeps its artifacts.
pub async fn follow(discovery: Arc<Discovery>, images: Arc<dyn Images>) {
    let (sender, mut updates) = mpsc::channel(16);
    let following = tokio::spawn(images.follow(sender));
    let mut list = List::default();
    let mut done: HashMap<Digest, Done> = HashMap::new();
    while let Some(update) = updates.recv().await {
        list.apply(update);
        for (root, names) in roots(&list) {
            let due = match done.get(&root) {
                None => true,
                Some(Done::Discovered) => false,
                Some(Done::Failed(at)) => at.elapsed() >= RETRY,
            };
            if !due {
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
    }
    following.abort();
}

/// Each manifest digest of the list, with the names it is listed under in the order the list gives them.
fn roots(list: &List) -> Vec<(Digest, Vec<String>)> {
    let mut roots: Vec<(Digest, Vec<String>)> = Vec::new();
    let mut at: HashMap<&Digest, usize> = HashMap::new();
    for image in list.images() {
        for repo_digest in &image.repo_digests {
            let i = *at.entry(&repo_digest.digest).or_insert_with(|| {
                roots.push((repo_digest.digest.clone(), Vec::new()));
                roots.len() - 1
            });
            let names = &mut roots[i].1;
            if !names.contains(&repo_digest.repository) {
                names.push(repo_digest.repository.clone());
            }
        }
    }
    roots
}

#[cfg(test)]
mod tests;
