//! The runtime's image list, followed once for the relay's eviction (D67), the tags the node announces and the tags its
//! peer API resolves (D123).

use std::collections::HashSet;
use std::sync::Arc;

use speculaire_oci::reference::Digest;
use speculaire_oci::tagged::Tagged;
use speculaire_runtime::images::{Image, Images, List};
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

    /// Gives `apply` the keys of the tags listed with a repository digest in their repository, which the peer API
    /// resolves (D123, D127), then again at each change, until the runtime's list ends.
    pub async fn tag_keys(mut self, mut apply: impl FnMut(HashSet<Digest>)) {
        loop {
            let keys = self.borrow().as_ref().map_or_else(HashSet::new, |list| {
                list.images()
                    .flat_map(|image| {
                        image
                            .tags
                            .iter()
                            .filter(|tagged| pulled_by(image, tagged).next().is_some())
                            .map(Tagged::key)
                            .cloned()
                    })
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
        let mut digests = Vec::new();
        if let Some(list) = self.borrow().as_ref() {
            let pulled = list
                .images()
                .filter(|image| image.tags.contains(tagged))
                .flat_map(|image| pulled_by(image, tagged));
            for digest in pulled {
                if !digests.contains(digest) {
                    digests.push(digest.clone());
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

/// The digests `image` was pulled by in the repository of `tagged`, in list order.
fn pulled_by<'a>(image: &'a Image, tagged: &'a Tagged) -> impl Iterator<Item = &'a Digest> {
    image
        .repo_digests
        .iter()
        .filter(move |repo| repo.repository == tagged.name())
        .map(|repo| &repo.digest)
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
    use speculaire_runtime::images::{RepoDigest, Update};
    use tokio::sync::Notify;

    use super::*;

    fn digest(byte: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    /// An image with ID `byte`, `tag` and repository digests in `repositories`.
    fn image(byte: u8, tag: Option<&str>, repositories: &[&str]) -> Image {
        Image {
            id: digest(byte),
            repo_digests: repositories
                .iter()
                .map(|repository| RepoDigest {
                    repository: (*repository).to_owned(),
                    digest: digest(0xff),
                })
                .collect(),
            tags: tag.into_iter().filter_map(Tagged::parse).collect(),
        }
    }

    /// A runtime that lists an untagged image, then a tagged one once notified.
    struct Tagging(Arc<Notify>);

    impl Images for Tagging {
        fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
            Box::pin(async move {
                let untagged = image(1, None, &[]);
                updates.send(Update::Listing(vec![untagged])).await.unwrap();
                self.0.notified().await;
                let tagged = image(2, Some("reg.test/app:1"), &["reg.test/app"]);
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

    /// containerd's CRI plugin lists a pulled image's tag before its repository digest: the tag is announced once the
    /// peer API resolves it.
    #[tokio::test]
    async fn a_tag_is_announced_only_with_a_repo_digest_in_its_repository() {
        let listed = Listed::of(vec![
            image(1, Some("reg.test/app:1"), &["reg.test/app"]),
            image(2, Some("reg.test/pulling:1"), &[]),
            image(3, Some("reg.test/moved:1"), &["reg.test/elsewhere"]),
        ]);
        let mut keys = None;
        listed.tag_keys(|applied| keys = Some(applied)).await;
        let key = Tagged::parse("reg.test/app:1").unwrap().key().clone();
        assert_eq!(keys, Some(HashSet::from([key])));
    }
}
