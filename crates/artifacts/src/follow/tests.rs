//! The image list as the trigger of discovery, with registry config that names no source of anything.

use std::sync::Mutex;

use futures_util::future::BoxFuture;
use speculaire_oci::platform::Host;
use speculaire_runtime::images::{Image, RepoDigest, Update};
use speculaire_runtime::registries::{
    Error as ConfigError, Reference, Registries, Reloaded, Source,
};

use super::*;
use crate::discover::Limits;
use crate::store::Store;

fn digest(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
}

fn image(id: u8, repo_digests: &[(&str, u8)]) -> Image {
    Image {
        id: digest(id),
        repo_digests: repo_digests
            .iter()
            .map(|(repository, n)| RepoDigest {
                repository: (*repository).to_owned(),
                digest: digest(*n),
            })
            .collect(),
    }
}

/// An image list whose updates the test sends.
struct Scripted(Mutex<Option<mpsc::Receiver<Update>>>);

impl Images for Scripted {
    fn follow(self: Arc<Self>, updates: mpsc::Sender<Update>) -> BoxFuture<'static, ()> {
        let mut script = self.0.lock().unwrap().take().unwrap();
        Box::pin(async move {
            while let Some(update) = script.recv().await {
                if updates.send(update).await.is_err() {
                    return;
                }
            }
        })
    }
}

/// Registry config that has no source of any name, and logs each name asked.
#[derive(Default)]
struct Asked(Mutex<Vec<String>>);

impl Registries for Asked {
    fn sources(&self, name: &str, _: Reference<'_>) -> Result<Vec<Source>, ConfigError> {
        self.0.lock().unwrap().push(name.to_owned());
        Ok(Vec::new())
    }

    fn configured(&self, _: &str) -> bool {
        false
    }

    fn poll(&self) -> Option<Result<Reloaded, ConfigError>> {
        None
    }

    fn reload(&self) -> Result<Reloaded, ConfigError> {
        Ok(Reloaded::default())
    }
}

#[test]
fn each_manifest_digest_is_a_root_with_its_names_in_order_once_each() {
    let mut list = List::default();
    list.apply(Update::Listing(vec![image(
        1,
        &[
            ("reg.test/a", 10),
            ("reg.test/b", 10),
            ("reg.test/a", 10),
            ("reg.test/a", 11),
        ],
    )]));
    let mut roots = roots(&list);
    roots.sort_by_key(|(root, _)| root.to_string());
    assert_eq!(
        roots,
        [
            (
                digest(10),
                vec!["reg.test/a".to_owned(), "reg.test/b".to_owned()]
            ),
            (digest(11), vec!["reg.test/a".to_owned()]),
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn a_recorded_root_is_skipped_and_a_failed_one_waits_before_it_is_tried_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(dir.path()).unwrap());
    store.record(&digest(10), &[]).await.unwrap();
    let asked = Arc::new(Asked::default());
    let discovery = Arc::new(Discovery::new(
        store,
        Arc::clone(&asked) as Arc<dyn Registries>,
        "127.0.0.1:7480".to_owned(),
        Host::current(),
        Limits::new(1024),
    ));
    let (script, receiver) = mpsc::channel(4);
    let followed = tokio::spawn(follow(
        discovery,
        Arc::new(Scripted(Mutex::new(Some(receiver)))),
    ));
    let listing = || {
        Update::Listing(vec![
            image(1, &[("reg.test/old", 10)]),
            image(2, &[("reg.test/new", 20)]),
        ])
    };
    let settle = || tokio::time::sleep(Duration::from_millis(10));

    script.send(listing()).await.unwrap();
    settle().await;
    assert_eq!(*asked.0.lock().unwrap(), ["reg.test/new"]);

    script.send(listing()).await.unwrap();
    settle().await;
    assert_eq!(asked.0.lock().unwrap().len(), 1);

    tokio::time::advance(RETRY).await;
    script.send(listing()).await.unwrap();
    settle().await;
    assert_eq!(*asked.0.lock().unwrap(), ["reg.test/new", "reg.test/new"]);

    drop(script);
    followed.await.unwrap();
}
