use std::collections::HashMap;
use std::future::Future;

use axum::body::Bytes;
use speculaire_oci::tagged::Tagged;
use speculaire_runtime::content::Blob;
use speculaire_runtime::images::RepoDigest;

use super::*;

const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const INDEX: &str = "application/vnd.oci.image.index.v1+json";

/// The digest whose hash is `n` repeated.
fn digest(n: u8) -> Digest {
    Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
}

/// An image manifest with a layer per digest of `layers`.
fn image(layers: &[u8]) -> String {
    let layers: Vec<String> = layers
        .iter()
        .map(|&n| {
            format!(
                r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"{}","size":1}}"#,
                digest(n)
            )
        })
        .collect();
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{}","size":1}},"layers":[{}]}}"#,
        digest(0xff),
        layers.join(",")
    )
}

/// An index of the manifests `entries` names, each for its architecture on Linux.
fn index(entries: &[(&str, u8)]) -> String {
    let entries: Vec<String> = entries
        .iter()
        .map(|(arch, n)| {
            format!(
                r#"{{"mediaType":"{MANIFEST}","digest":"{}","size":1,"platform":{{"os":"linux","architecture":"{arch}"}}}}"#,
                digest(*n)
            )
        })
        .collect();
    format!(
        r#"{{"schemaVersion":2,"mediaType":"{INDEX}","manifests":[{}]}}"#,
        entries.join(",")
    )
}

fn amd64() -> Host {
    Host {
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        variant: String::new(),
    }
}

/// The blobs a node holds, by digest.
struct Held(HashMap<Digest, Bytes>);

impl Held {
    fn of(blobs: &[(u8, String)]) -> Self {
        Self(
            blobs
                .iter()
                .map(|(n, text)| (digest(*n), Bytes::from(text.clone())))
                .collect(),
        )
    }
}

impl Content for Held {
    fn open(
        &self,
        digest: &Digest,
    ) -> impl Future<Output = Result<Option<Blob>, content::Error>> + Send {
        std::future::ready(Ok(self.0.get(digest).cloned().map(Blob::from_bytes)))
    }
}

#[tokio::test]
async fn the_layers_missing_are_those_of_the_image_manifest_held_without_a_blob_once_each_in_order()
{
    let held = Held::of(&[
        (1, image(&[0x10, 0x11, 0x12, 0x10, 0x13])),
        (0x11, String::new()),
    ]);
    let missing = missing(&held, &digest(1), &amd64()).await.unwrap();
    assert_eq!(missing, [digest(0x10), digest(0x12), digest(0x13)]);
}

#[tokio::test]
async fn an_index_leads_to_the_manifest_of_the_node_s_platform() {
    let held = Held::of(&[
        (1, index(&[("arm64", 2), ("amd64", 3)])),
        (2, image(&[0x20])),
        (3, image(&[0x30])),
    ]);
    let missing = missing(&held, &digest(1), &amd64()).await.unwrap();
    assert_eq!(missing, [digest(0x30)]);
}

#[tokio::test]
async fn a_node_holding_every_blob_misses_nothing() {
    let held = Held::of(&[(1, image(&[0x10])), (0x10, String::new())]);
    assert_eq!(
        missing(&held, &digest(1), &amd64()).await.unwrap(),
        Vec::<Digest>::new()
    );
}

#[tokio::test]
async fn a_root_or_platform_manifest_not_held_reads_nothing() {
    let absent = Held::of(&[]);
    assert!(matches!(
        missing(&absent, &digest(1), &amd64()).await,
        Err(Unread::Absent(absent)) if absent == digest(1).to_string()
    ));
    let no_platform = Held::of(&[(1, index(&[("arm64", 2)])), (2, image(&[0x20]))]);
    assert!(matches!(
        missing(&no_platform, &digest(1), &amd64()).await,
        Err(Unread::NoPlatform(_))
    ));
    let unpulled = Held::of(&[(1, index(&[("amd64", 2)]))]);
    assert!(matches!(
        missing(&unpulled, &digest(1), &amd64()).await,
        Err(Unread::Absent(absent)) if absent == digest(2).to_string()
    ));
}

/// An image the runtime lists under `tags`, pulled by `repo_digests` (`repository@digest`).
fn listed(tags: &[&str], repo_digests: &[(&str, u8)]) -> Image {
    Image {
        id: digest(0xee),
        repo_digests: repo_digests
            .iter()
            .map(|(repository, n)| RepoDigest {
                repository: (*repository).to_owned(),
                digest: digest(*n),
            })
            .collect(),
        tags: tags
            .iter()
            .map(|text| Tagged::parse(text).unwrap())
            .collect(),
    }
}

#[test]
fn a_tag_pulled_leads_to_the_repository_digest_of_the_image_listed_under_it() {
    let listed = [
        listed(
            &["docker.io/library/app:1"],
            &[("docker.io/library/app", 1)],
        ),
        listed(
            &["docker.io/library/app:2", "reg.test/other:2"],
            &[("reg.test/other", 3), ("docker.io/library/app", 2)],
        ),
    ];
    let image = Reference::parse_docker_ref("app:2").unwrap();
    assert_eq!(root(&listed, &image), Some(digest(2)));
}

#[test]
fn a_tag_the_runtime_does_not_list_leads_nowhere() {
    let listed = [listed(
        &["docker.io/library/app:1"],
        &[("docker.io/library/app", 1)],
    )];
    let image = Reference::parse_docker_ref("app:2").unwrap();
    assert_eq!(root(&listed, &image), None);
    let other = Reference::parse_docker_ref("reg.test/app:1").unwrap();
    assert_eq!(root(&listed, &other), None);
}

#[tokio::test]
async fn each_layer_is_fetched_and_only_those_fetched_count() {
    let image = Reference::parse_docker_ref("app:1").unwrap();
    let asked = std::sync::Mutex::new(Vec::new());
    let fetched = fetch_each(&image, vec![digest(1), digest(2), digest(3)], |layer| {
        asked.lock().unwrap().push(layer.clone());
        std::future::ready(if layer == digest(2) {
            Err(Unfetched::Nowhere)
        } else {
            Ok(())
        })
    })
    .await;
    assert_eq!(fetched, 2);
    assert_eq!(*asked.lock().unwrap(), [digest(1), digest(2), digest(3)]);
}

/// A fake registry that serves `blob` under `/v2/app/blobs/` when `serves`, else 404, and logs each path asked.
#[derive(Clone)]
struct Registry {
    serves: bool,
    blob: Bytes,
    log: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Registry {
    fn new(serves: bool, blob: &'static [u8]) -> Self {
        Self {
            serves,
            blob: Bytes::from_static(blob),
            log: Arc::default(),
        }
    }

    async fn start(&self) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let registry = self.clone();
        let app = axum::Router::new().fallback(move |asked: axum::extract::Request| {
            let registry = registry.clone();
            async move {
                registry
                    .log
                    .lock()
                    .unwrap()
                    .push(asked.uri().path().to_owned());
                if registry.serves && asked.uri().path().starts_with("/v2/app/blobs/") {
                    (StatusCode::OK, registry.blob.clone())
                } else {
                    (StatusCode::NOT_FOUND, Bytes::new())
                }
            }
        });
        tokio::spawn(async move { axum::serve(listener, app).await });
        address
    }

    fn asked(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

/// Registry config with one source for every name: `candidates`, anonymous.
struct Fixed(Vec<String>);

impl Registries for Fixed {
    fn sources(
        &self,
        _: &str,
        _: registries::Reference<'_>,
    ) -> Result<Vec<registries::Source>, registries::Error> {
        Ok(vec![registries::Source {
            candidates: self
                .0
                .iter()
                .map(|at| registries::Endpoint::new(false, at))
                .collect(),
            repository: "app".to_owned(),
            credentials: registries::Credentials::Anonymous,
        }])
    }

    fn configured(&self, _: &str) -> bool {
        false
    }

    fn poll(&self) -> Option<Result<registries::Reloaded, registries::Error>> {
        None
    }

    fn reload(&self) -> Result<registries::Reloaded, registries::Error> {
        Ok(registries::Reloaded::default())
    }
}

#[tokio::test]
async fn upstream_is_the_first_source_besides_the_mirror_that_serves_the_blob() {
    let mirror = Registry::new(true, b"from the mirror");
    let without = Registry::new(false, b"");
    let with = Registry::new(true, b"the layer");
    let at = [
        mirror.start().await,
        without.start().await,
        with.start().await,
    ];
    let upstream = Upstream {
        registries: Arc::new(Fixed(at.to_vec())),
        client: Client::new(),
        mirror: at[0].clone(),
    };
    let response = upstream
        .blob("docker.io/library/app", &digest(1))
        .await
        .unwrap();
    assert_eq!(
        response.body.collect().await.unwrap().to_bytes(),
        "the layer"
    );
    let path = format!("/v2/app/blobs/{}", digest(1));
    assert_eq!(mirror.asked(), Vec::<String>::new());
    assert_eq!(without.asked(), std::slice::from_ref(&path));
    assert_eq!(with.asked(), [path]);
}

#[tokio::test]
async fn a_blob_no_source_serves_is_nowhere() {
    let without = Registry::new(false, b"");
    let upstream = Upstream {
        registries: Arc::new(Fixed(vec![without.start().await])),
        client: Client::new(),
        mirror: "127.0.0.1:1".to_owned(),
    };
    assert!(matches!(
        upstream.blob("docker.io/library/app", &digest(1)).await,
        Err(Unfetched::Nowhere)
    ));
}

/// D195 on containerd: a tag pulled leads to the repository digest the runtime lists; the layer it holds no blob of,
/// which no peer holds, is fetched from upstream, written to the content store, and counted.
#[tokio::test]
async fn on_containerd_a_layer_held_without_a_blob_is_fetched_upstream_into_the_content_store() {
    use metrics_exporter_prometheus::PrometheusBuilder;
    use speculaire_fake_runtime::{Answers, Fake};
    use speculaire_mirror::fetch::Settings;
    use speculaire_mirror::space::Space;
    use speculaire_runtime::paths::Paths;

    let node = tempfile::tempdir().unwrap();
    let socket = node.path().join("containerd.sock");
    let manifest = image(&[1, 2]);
    let root = speculaire_oci::hash::of("sha256", manifest.as_bytes()).unwrap();
    let fake = Fake::start(
        &socket,
        Answers {
            images: vec![(
                digest(9).to_string(),
                vec!["docker.io/library/app:1".to_owned()],
                vec![format!("docker.io/library/app@{root}")],
            )],
            ..Answers::containerd("2.4.2")
        },
    )
    .unwrap();
    let blobs = node
        .path()
        .join("var/lib/containerd/io.containerd.content.v1.content/blobs/sha256");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(root.encoded()), &manifest).unwrap();
    std::fs::write(blobs.join(digest(1).encoded()), b"held").unwrap();
    let registry = Registry::new(true, b"the layer");
    let fetcher = Fetcher::new(
        node.path().join("staging"),
        Space::new(1 << 20),
        Settings {
            stall_timeout: std::time::Duration::from_secs(1),
            deny_ttl: std::time::Duration::from_secs(1),
            resolve_tags: false,
        },
    );
    let refetch = Refetch::store(
        Containerd::new(Paths::under(node.path()), &socket, None),
        fetcher,
        Arc::new(Fixed(vec![registry.start().await])),
        "127.0.0.1:1".to_owned(),
    );
    let recorder = PrometheusBuilder::new().build_recorder();
    let handle = recorder.handle();
    let _local = metrics::set_default_local_recorder(&recorder);

    refetch
        .run(&Reference::parse_docker_ref("app:1").unwrap())
        .await;

    assert_eq!(registry.asked(), [format!("/v2/app/blobs/{}", digest(2))]);
    assert_eq!(
        fake.written(),
        [(digest(2).to_string(), b"the layer".to_vec())]
    );
    assert!(
        handle
            .render()
            .contains("speculaire_prewarm_refetched_total 1")
    );
}
