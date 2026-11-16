//! The runtime's image list, followed once for the relay's eviction (D67), the tags the node announces and the tags its
//! peer API resolves (D123).

use std::collections::HashSet;
use std::sync::Arc;

use speculaire_oci::reference::Digest;
use speculaire_oci::tagged::Tagged;
use speculaire_runtime::images::{Images, List};
use tokio::sync::{mpsc, watch};

/// The image list as last read; a handle, cheap to clone.
#[derive(Clone)]
pub struct Listed(watch::Receiver<Option<List>>);

impl Listed {
    /// Follows `images` on a task of its own, which ends once every handle is dropped.
    #[must_use]
    pub fn follow(images: Arc<dyn Images>) -> Self {
        let (list, listed) = watch::channel(None);
        tokio::spawn(follow(images, list));
        Self(listed)
    }

    /// The list; `None` until it is first read.
    pub(crate) fn borrow(&self) -> watch::Ref<'_, Option<List>> {
        self.0.borrow()
    }

    /// Gives `apply` the keys of the tags listed (D123), then again at each change, until the runtime's list ends.
    pub async fn tag_keys(mut self, mut apply: impl FnMut(HashSet<Digest>)) {
        loop {
            let keys = self.borrow().as_ref().map_or_else(HashSet::new, |list| {
                list.images()
                    .flat_map(|image| image.tags.iter().map(Tagged::key).cloned())
                    .collect()
            });
            apply(keys);
            if self.0.changed().await.is_err() {
                return;
            }
        }
    }

    /// The digests `tagged` was pulled by, in list order: the repository digests, in its repository, of the images
    /// listing it.
    pub(crate) fn digests(&self, tagged: &Tagged) -> Vec<Digest> {
        let name = tagged.name();
        let mut digests = Vec::new();
        if let Some(list) = self.borrow().as_ref() {
            let repo_digests = list
                .images()
                .filter(|image| image.tags.contains(tagged))
                .flat_map(|image| &image.repo_digests)
                .filter(|repo| repo.repository == name);
            for repo in repo_digests {
                if !digests.contains(&repo.digest) {
                    digests.push(repo.digest.clone());
                }
            }
        }
        digests
    }

    /// A list of `images` that never changes.
    #[cfg(test)]
    pub(crate) fn of(images: Vec<speculaire_runtime::images::Image>) -> Self {
        let mut list = List::default();
        list.apply(speculaire_runtime::images::Update::Listing(images));
        Self(watch::channel(Some(list)).1)
    }

    /// Waits until the list is read.
    #[cfg(test)]
    pub(crate) async fn read(&self) {
        let mut listed = self.0.clone();
        listed
            .wait_for(Option::is_some)
            .await
            .expect("the list is followed while a handle lives");
    }
}

/// Keeps `list` as `images` says, until every handle on it is gone.
async fn follow(images: Arc<dyn Images>, list: watch::Sender<Option<List>>) {
    let (sender, mut updates) = mpsc::channel(16);
    let mut following = images.follow(sender);
    loop {
        tokio::select! {
            () = list.closed() => return,
            // Polled here, since it is what sends the updates; it ends only once they close.
            () = &mut following => return,
            update = updates.recv() => match update {
                Some(update) => list.send_modify(|list| list.get_or_insert_default().apply(update)),
                None => return,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use futures_util::future::BoxFuture;
    use speculaire_runtime::images::{Image, Update};
    use tokio::sync::Notify;

    use super::*;

    /// A runtime that lists an untagged image, then a tagged one once notified.
    struct Tagging(Arc<Notify>);

    impl Images for Tagging {
        fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
            let image = |byte: u8, tags: Vec<Tagged>| Image {
                id: Digest::parse(&format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
                repo_digests: Vec::new(),
                tags,
            };
            Box::pin(async move {
                let untagged = image(1, Vec::new());
                updates.send(Update::Listing(vec![untagged])).await.unwrap();
                self.0.notified().await;
                let tagged = image(2, vec![Tagged::parse("reg.test/app:1").unwrap()]);
                updates.send(Update::Listed(tagged)).await.unwrap();
                updates.closed().await;
            })
        }
    }

    #[tokio::test]
    async fn the_tag_keys_follow_the_list() {
        let tagging = Arc::new(Notify::new());
        let (sender, mut applied) = mpsc::unbounded_channel();
        let listed = Listed::follow(Arc::new(Tagging(Arc::clone(&tagging))));
        tokio::spawn(listed.tag_keys(move |keys| sender.send(keys).unwrap()));
        assert_eq!(applied.recv().await, Some(HashSet::new()));
        tagging.notify_one();
        let keys = loop {
            let keys = applied.recv().await.expect("the keys follow the list");
            if !keys.is_empty() {
                break keys;
            }
        };
        let key = Tagged::parse("reg.test/app:1").unwrap().key().clone();
        assert_eq!(keys, HashSet::from([key]));
    }
}
