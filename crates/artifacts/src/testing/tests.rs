//! The negative cases built from the recordings.

use super::*;

#[tokio::test]
async fn the_sig_of_another_case_is_recorded_as_the_roots_only_artifact() {
    let signature = Layout::open("legacy-sig")
        .artifacts()
        .into_iter()
        .find(|artifact| artifact.kind == Kind::Signature)
        .unwrap();

    let fixture = Fixture::signature_of("legacy-sig", "keyless").await;

    assert_eq!(fixture.root, *Layout::open("keyless").root());
    let grafted = Artifact {
        target: fixture.root.clone(),
        ..signature
    };
    assert_eq!(fixture.artifacts, [grafted]);
    assert_eq!(
        fixture.store.recorded(&fixture.root).await.unwrap(),
        Some(fixture.artifacts.clone())
    );
    let artifact = &fixture.artifacts[0];
    for digest in std::iter::once(&artifact.manifest).chain(&artifact.blobs) {
        assert!(fixture.store.contains(digest), "{digest}");
    }
}

#[tokio::test]
async fn a_flipped_bundle_differs_in_one_byte_and_its_new_manifest_names_it() {
    let recorded = Fixture::load("keyless").await;

    let flipped = Fixture::flipped("keyless").await;

    let ([old], [new]) = (&recorded.artifacts[..], &flipped.artifacts[..]) else {
        panic!("keyless has one bundle: {:?}", recorded.artifacts);
    };
    assert_eq!((new.kind, &new.target), (Kind::Bundle, &old.target));
    assert_eq!(new.blobs[0], old.blobs[0], "the config is the recorded one");
    let read = async |store: &Store, digest: &Digest| store.read(digest).await.unwrap().unwrap();
    let (before, after) = (
        read(&recorded.store, &old.blobs[1]).await,
        read(&flipped.store, &new.blobs[1]).await,
    );
    assert_eq!(before.len(), after.len());
    let changed = before.iter().zip(&after).filter(|(a, b)| a != b).count();
    assert_eq!(changed, 1);
    let referrer = Referrer::parse(&read(&flipped.store, &new.manifest).await).unwrap();
    assert_eq!(referrer.layers[0].digest, new.blobs[1]);
    assert_eq!(referrer.subject.as_ref(), Some(&flipped.root));
    assert_eq!(
        flipped.store.recorded(&flipped.root).await.unwrap(),
        Some(flipped.artifacts.clone())
    );
}

#[test]
fn every_case_has_a_layout_and_the_private_bundle_is_a_bundle() {
    let cases = cases();
    assert_eq!(cases.len(), 13);
    for case in &cases {
        let layout = Layout::open(case);
        assert_eq!(layout.tag(case), Some(layout.root()), "{case}");
    }
    let bundle: Value = serde_json::from_str(GITHUB_PRIVATE).unwrap();
    assert_eq!(bundle["mediaType"], referrers::BUNDLE);
}
