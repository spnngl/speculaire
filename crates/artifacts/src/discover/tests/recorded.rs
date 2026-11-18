//! Discovery of each recorded fixture (D141), from a fake registry that serves its layout, keeps and records what
//! [`Fixture::load`] does.

use super::*;
use crate::testing::{self, Fixture, Layout};

/// Serves `layout` under `app` as zot does, the referrers API answering what each fallback tag lists, or as
/// `registry:3` does, with the fallback tags and no API.
fn serve(registry: &Registry, layout: &Layout, api: bool) {
    for (digest, bytes) in layout.blobs() {
        let manifest = serde_json::from_slice::<Value>(&bytes)
            .is_ok_and(|json| json["mediaType"] == MANIFEST || json["mediaType"] == INDEX);
        if manifest {
            registry.manifest(&bytes);
        }
        registry.put(&format!("/app/blobs/{digest}"), 200, bytes);
    }
    for (tag, digest) in layout.tags() {
        let bytes = layout.blob(digest);
        match tag.strip_prefix("sha256-") {
            Some(target) if api && !target.contains('.') => {
                registry.put(&format!("/app/referrers/sha256:{target}"), 200, bytes);
            }
            _ => registry.put(&format!("/app/manifests/{tag}"), 200, bytes),
        }
    }
}

#[tokio::test]
async fn every_case_is_discovered_as_its_fixture_loads_it_with_the_referrers_api_and_without() {
    let mut kinds = Vec::new();
    for case in testing::cases() {
        let fixture = Fixture::load(&case).await;
        let layout = Layout::open(&case);
        for api in [true, false] {
            let test = Test::with(Limits::new(1 << 20), |registry| vec![registry.endpoint()]).await;
            serve(&test.registry, &layout, api);

            let artifacts = test.discover(&fixture.root).await.unwrap();

            assert_eq!(artifacts, fixture.artifacts, "{case}, referrers API: {api}");
            let store = test.discovery.store();
            assert_eq!(
                store.recorded(&fixture.root).await.unwrap(),
                Some(fixture.artifacts.clone())
            );
            let kept = std::iter::once(&fixture.root).chain(
                artifacts
                    .iter()
                    .flat_map(|a| std::iter::once(&a.manifest).chain(&a.blobs)),
            );
            for digest in kept {
                assert_eq!(
                    store.read(digest).await.unwrap(),
                    fixture.store.read(digest).await.unwrap(),
                    "{case}: {digest}"
                );
            }
        }
        kinds.extend(fixture.artifacts.iter().map(|artifact| artifact.kind));
    }
    for kind in [Kind::Bundle, Kind::Signature, Kind::Attestation] {
        assert!(kinds.contains(&kind), "no case records a {kind:?}");
    }
}
