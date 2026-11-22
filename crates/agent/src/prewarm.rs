//! How a reflector resolves `prewarm.images`: through the node's registry config (D17), its own mirror left out, to
//! the platform manifests of each image and their layers, which agents announce once they pulled it (D185).

use std::sync::Arc;

use axum::body::Bytes;
use http::header::ACCEPT;
use http::{HeaderValue, Method, StatusCode};
use http_body_util::{BodyExt as _, Limited};
use speculaire_oci::index::Index;
use speculaire_oci::manifest::{self, Children};
use speculaire_oci::reference::{Digest, Reference};
use speculaire_reflect::Key;
use speculaire_reflect::prewarm::{Failure, Platform, Resolution, Resolve, Resolving};
use speculaire_registry::{Client, Request, Response};
use speculaire_runtime::registries::{self, Endpoint, Registries, Source};

/// What a manifest may be, as the mirror asks for it.
const MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json";
/// The largest manifest read, as the mirror's.
const MAX_MANIFEST: usize = 4 << 20;
/// The most platform manifests of one image fetched: the rest are not waited for.
const MAX_PLATFORMS: usize = 32;
/// The header a registry names a manifest's digest in.
const CONTENT_DIGEST: &str = "docker-content-digest";

/// Resolves images upstream.
pub(crate) struct Resolver {
    registries: Arc<dyn Registries>,
    client: Client,
    /// The authority of the node's own mirror, which the registry config may list first.
    mirror: String,
}

impl Resolver {
    /// Resolves through `registries`, leaving out the endpoint `mirror`.
    pub(crate) fn new(registries: Arc<dyn Registries>, mirror: String) -> Self {
        Self {
            registries,
            client: Client::new(),
            mirror,
        }
    }

    async fn run(
        &self,
        image: &Reference,
        known: Option<&Resolution>,
    ) -> Result<Resolution, Failure> {
        let by = image.digest().map_or_else(
            || image.tag().unwrap_or("latest").to_owned(),
            ToString::to_string,
        );
        let asked = if image.digest().is_some() {
            registries::Reference::Digest(&by)
        } else {
            registries::Reference::Tag(&by)
        };
        let mut last: Failure = format!("no source of {} besides the mirror", image.name()).into();
        for mut source in self.registries.sources(image.name(), asked)? {
            source
                .candidates
                .retain(|endpoint| endpoint.authority != self.mirror);
            for endpoint in &source.candidates {
                let at = At {
                    endpoint,
                    source: &source,
                };
                match self.from(at, &by, image.digest(), known).await {
                    Ok(resolution) => return Ok(resolution),
                    Err(err) => last = err,
                }
            }
        }
        Err(last)
    }

    /// Resolves the manifest `by` at `at`; a tag whose digest `HEAD` finds unchanged keeps `known`, as a `HEAD` does
    /// not count against Docker Hub's pull limit.
    async fn from(
        &self,
        at: At<'_>,
        by: &str,
        digest: Option<&Digest>,
        known: Option<&Resolution>,
    ) -> Result<Resolution, Failure> {
        if digest.is_none()
            && let Some(known) = known
        {
            let head = self.send(at, Method::HEAD, by).await?;
            let unchanged = head.status == StatusCode::OK
                && head
                    .headers
                    .get(CONTENT_DIGEST)
                    .and_then(|value| value.to_str().ok())
                    .and_then(Key::parse)
                    .is_some_and(|root| root == known.root);
            if unchanged {
                return Ok(known.clone());
            }
        }
        let (root, bytes) = self.manifest(at, by, digest).await?;
        let platforms = match manifest::children(&bytes)? {
            Children::Image { layers, .. } => vec![platform(&root, &layers)],
            Children::Index { .. } => {
                let index = Index::parse(&bytes)?;
                let mut platforms = Vec::new();
                for digest in index.images().take(MAX_PLATFORMS) {
                    let (_, bytes) = self.manifest(at, &digest.to_string(), Some(digest)).await?;
                    let Children::Image { layers, .. } = manifest::children(&bytes)? else {
                        return Err(format!("the image manifest {digest} is an index").into());
                    };
                    platforms.push(platform(digest, &layers));
                }
                platforms
            }
        };
        Ok(Resolution {
            root: Key::from(&root),
            platforms,
        })
    }

    /// The manifest `by` and its digest, which is `digest` when given.
    async fn manifest(
        &self,
        at: At<'_>,
        by: &str,
        digest: Option<&Digest>,
    ) -> Result<(Digest, Bytes), Failure> {
        let response = self.send(at, Method::GET, by).await?;
        if response.status != StatusCode::OK {
            return Err(format!(
                "{} answered {} for the manifest {by}",
                at.endpoint.authority, response.status
            )
            .into());
        }
        let bytes = Limited::new(response.body, MAX_MANIFEST)
            .collect()
            .await?
            .to_bytes();
        let algorithm = digest.map_or("sha256", Digest::algorithm);
        let got = speculaire_oci::hash::of(algorithm, &bytes)
            .ok_or_else(|| format!("no hash {algorithm}"))?;
        if let Some(digest) = digest
            && got != *digest
        {
            return Err(format!("{} served {got} as {digest}", at.endpoint.authority).into());
        }
        Ok((got, bytes))
    }

    async fn send(&self, at: At<'_>, method: Method, by: &str) -> Result<Response, Failure> {
        let request = Request {
            method,
            path: format!("/{}/manifests/{by}", at.source.repository),
            repository: at.source.repository.clone(),
            headers: vec![(ACCEPT, HeaderValue::from_static(MANIFESTS))],
        };
        Ok(self
            .client
            .send(at.endpoint, &at.source.credentials, &request)
            .await?)
    }
}

impl Resolve for Resolver {
    fn resolve<'a>(&'a self, image: &'a Reference, known: Option<&'a Resolution>) -> Resolving<'a> {
        Box::pin(self.run(image, known))
    }
}

/// The endpoint of a source asked.
#[derive(Clone, Copy)]
struct At<'a> {
    endpoint: &'a Endpoint,
    source: &'a Source,
}

fn platform(manifest: &Digest, layers: &[Digest]) -> Platform {
    Platform {
        manifest: Key::from(manifest),
        layers: layers.iter().map(Key::from).collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use axum::Router;
    use axum::extract::{Request as Asked, State};
    use axum::response::{IntoResponse as _, Response as Answer};
    use speculaire_runtime::registries::{Credentials, Error, Reloaded};
    use tokio::net::TcpListener;

    use super::*;

    const INDEX: &str = "application/vnd.oci.image.index.v1+json";
    const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

    /// A fake registry: each path below `/v2` answers its body, and every request is logged.
    #[derive(Clone, Default)]
    struct Registry {
        bodies: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Registry {
        async fn start(&self) -> String {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let app = Router::new().fallback(answer).with_state(self.clone());
            tokio::spawn(async move { axum::serve(listener, app).await });
            address
        }

        /// Serves `bytes` at `/app/manifests/{by}`, and by digest; returns the digest.
        fn put(&self, by: &str, bytes: &str) -> Digest {
            let digest = speculaire_oci::hash::of("sha256", bytes.as_bytes()).unwrap();
            let mut bodies = self.bodies.lock().unwrap();
            for at in [by.to_owned(), digest.to_string()] {
                bodies.insert(format!("/v2/app/manifests/{at}"), bytes.as_bytes().to_vec());
            }
            digest
        }

        fn requests(&self) -> Vec<String> {
            std::mem::take(&mut self.log.lock().unwrap())
        }
    }

    async fn answer(State(registry): State<Registry>, asked: Asked) -> Answer {
        let path = asked.uri().path().to_owned();
        registry
            .log
            .lock()
            .unwrap()
            .push(format!("{} {path}", asked.method()));
        let Some(body) = registry.bodies.lock().unwrap().get(&path).cloned() else {
            return StatusCode::NOT_FOUND.into_response();
        };
        let digest = speculaire_oci::hash::of("sha256", &body)
            .unwrap()
            .to_string();
        ([(CONTENT_DIGEST, digest)], body).into_response()
    }

    /// Registry config with one source for every name: `candidates`, anonymous.
    struct Fixed(Vec<String>);

    impl Registries for Fixed {
        fn sources(&self, _: &str, _: registries::Reference<'_>) -> Result<Vec<Source>, Error> {
            Ok(vec![Source {
                candidates: self.0.iter().map(|at| Endpoint::new(false, at)).collect(),
                repository: "app".to_owned(),
                credentials: Credentials::Anonymous,
            }])
        }

        fn configured(&self, _: &str) -> bool {
            false
        }

        fn poll(&self) -> Option<Result<Reloaded, Error>> {
            None
        }

        fn reload(&self) -> Result<Reloaded, Error> {
            Ok(Reloaded::default())
        }
    }

    fn image(layers: &[u8]) -> String {
        let layers: Vec<String> = layers
            .iter()
            .map(|n| {
                format!(
                    r#"{{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:{}","size":1}}"#,
                    format!("{n:02x}").repeat(32)
                )
            })
            .collect();
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{MANIFEST}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{}","size":1}},"layers":[{}]}}"#,
            "ff".repeat(32),
            layers.join(",")
        )
    }

    fn index(entries: &[(&str, &Digest)]) -> String {
        let entries: Vec<String> = entries
            .iter()
            .map(|(media_type, digest)| {
                format!(
                    r#"{{"mediaType":"{media_type}","digest":"{digest}","size":1,"platform":{{"os":"linux","architecture":"amd64"}}}}"#
                )
            })
            .collect();
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{INDEX}","manifests":[{}]}}"#,
            entries.join(",")
        )
    }

    fn keys(layers: &[u8]) -> Vec<Key> {
        layers.iter().map(|&n| Key::Sha256([n; 32])).collect()
    }

    fn reference(text: &str) -> Reference {
        Reference::parse_docker_ref(text).unwrap()
    }

    #[tokio::test]
    async fn an_index_resolves_to_its_image_manifests_and_the_mirror_is_left_out() {
        let (upstream, mirror) = (Registry::default(), Registry::default());
        let amd = upstream.put("amd", &image(&[1, 2]));
        let arm = upstream.put("arm", &image(&[3]));
        let nested = upstream.put("nested", &index(&[]));
        let root = upstream.put(
            "1",
            &index(&[(MANIFEST, &amd), (INDEX, &nested), (MANIFEST, &arm)]),
        );
        mirror.put("1", &image(&[9]));
        let at = mirror.start().await;
        let resolver = Resolver::new(
            Arc::new(Fixed(vec![at.clone(), upstream.start().await])),
            at,
        );
        let found = resolver
            .resolve(&reference("registry.example/app:1"), None)
            .await
            .unwrap();
        assert_eq!(found.root, Key::from(&root));
        let platforms: Vec<_> = found
            .platforms
            .iter()
            .map(|platform| (platform.manifest, platform.layers.clone()))
            .collect();
        assert_eq!(
            platforms,
            [
                (Key::from(&amd), keys(&[1, 2])),
                (Key::from(&arm), keys(&[3]))
            ]
        );
        assert_eq!(mirror.requests(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_tag_unchanged_is_kept_after_a_head_and_a_changed_one_fetched() {
        let upstream = Registry::default();
        upstream.put("1", &image(&[1]));
        let resolver = Resolver::new(Arc::new(Fixed(vec![upstream.start().await])), String::new());
        let tag = reference("registry.example/app:1");
        let known = resolver.resolve(&tag, None).await.unwrap();
        assert_eq!(known.platforms[0].layers, keys(&[1]));
        upstream.requests();
        let again = resolver.resolve(&tag, Some(&known)).await.unwrap();
        assert_eq!(again, known);
        assert_eq!(upstream.requests(), ["HEAD /v2/app/manifests/1"]);
        upstream.put("1", &image(&[2]));
        let changed = resolver.resolve(&tag, Some(&known)).await.unwrap();
        assert_eq!(changed.platforms[0].layers, keys(&[2]));
    }

    #[tokio::test]
    async fn a_digest_is_fetched_by_digest_and_must_match_it() {
        let upstream = Registry::default();
        let digest = upstream.put("1", &image(&[1]));
        let resolver = Resolver::new(Arc::new(Fixed(vec![upstream.start().await])), String::new());
        let pinned = reference(&format!("registry.example/app@{digest}"));
        let found = resolver.resolve(&pinned, None).await.unwrap();
        assert_eq!(found.root, Key::from(&digest));
        assert_eq!(
            upstream.requests(),
            [format!("GET /v2/app/manifests/{digest}")]
        );
        // Served under another digest's name.
        let other = Digest::parse(&format!("sha256:{}", "ab".repeat(32))).unwrap();
        upstream.bodies.lock().unwrap().insert(
            format!("/v2/app/manifests/{other}"),
            image(&[1]).into_bytes(),
        );
        let wrong = reference(&format!("registry.example/app@{other}"));
        let err = resolver.resolve(&wrong, None).await.unwrap_err();
        assert!(err.to_string().contains("as sha256:abab"), "{err}");
        let missing = reference("registry.example/app:2");
        let err = resolver.resolve(&missing, None).await.unwrap_err();
        assert!(err.to_string().contains("404"), "{err}");
    }

    #[tokio::test]
    async fn an_image_with_no_source_besides_the_mirror_fails() {
        let resolver = Resolver::new(
            Arc::new(Fixed(vec!["mirror:1".to_owned()])),
            "mirror:1".to_owned(),
        );
        let err = resolver
            .resolve(&reference("registry.example/app:1"), None)
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "no source of registry.example/app besides the mirror"
        );
    }
}
