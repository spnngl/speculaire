//! The SBOM check over the recorded fixtures of step 01, under a policy requiring an SBOM (D12, D150).

use std::num::NonZeroUsize;

use speculaire_artifacts::Artifact;
use speculaire_artifacts::testing::Layout;
use speculaire_verify::policy::Sbom;
use speculaire_verify::sbom::{Failure, Listed};
use speculaire_verify::signature;

use super::*;

/// One policy over every image requiring an SBOM, keyless by the workflow whose subject is `subject`.
fn required(subject: &str) -> Policy {
    // `spec.sbom` follows the authorities, indented as they are.
    let policy = policy(&[
        keyless(&format!("subject: {subject}")),
        "  sbom: required\n".to_owned(),
    ]);
    assert_eq!(policy.sbom(), Sbom::Required);
    policy
}

async fn sbom(fixture: &Fixture, policy: &Policy, max_size: u64) -> Result<Listed, Failure> {
    Signatures::new(max_size)
        .sbom(
            &fixture.store,
            &fixture.root,
            &fixture.artifacts,
            policy,
            &pinned(),
        )
        .await
        .expect("the store holds what discovery kept")
}

fn listed(packages: usize) -> Listed {
    Listed {
        signed: workflow(),
        packages: NonZeroUsize::new(packages).expect("a listed SBOM has a package"),
    }
}

#[tokio::test]
async fn a_signed_spdx_cyclonedx_or_github_attestation_passes_with_its_packages() {
    for (case, packages) in [("spdx", 1), ("cyclonedx", 2), ("attest-sbom", 1)] {
        let fixture = Fixture::load(case).await;

        let result = sbom(&fixture, &required(SAN), MAX_SIZE).await;

        assert_eq!(result, Ok(listed(packages)), "{case}");
    }
}

#[tokio::test]
async fn an_sbom_attestation_by_another_signer_is_unsigned() {
    let fixture = Fixture::load("spdx").await;

    let result = sbom(&fixture, &required("https://example.com/other"), MAX_SIZE).await;

    assert_eq!(
        result,
        Err(Failure::Unsigned(signature::Failure::Mismatch(workflow())))
    );
}

#[tokio::test]
async fn a_buildkit_sbom_passes_through_its_signed_index_only() {
    let signed = Fixture::load("buildkit-signed").await;
    let unsigned = Fixture::load("buildkit-unsigned").await;

    let passed = sbom(&signed, &required(SAN), MAX_SIZE).await;
    let failed = sbom(&unsigned, &required(SAN), MAX_SIZE).await;

    assert_eq!(passed, Ok(listed(1)));
    assert_eq!(
        failed.map_err(|e| e.to_string()),
        Err("SBOM unsigned: no signature".to_owned())
    );
}

#[tokio::test]
async fn an_sbom_tag_alone_is_missing() {
    let fixture = Fixture::load("sbom-tag").await;

    let result = sbom(&fixture, &required(SAN), MAX_SIZE).await;

    assert_eq!(
        result.map_err(|e| e.to_string()),
        Err("SBOM missing".to_owned())
    );
}

#[tokio::test]
async fn an_spdx_sbom_that_lists_only_the_image_it_describes_has_no_packages() {
    let fixture = Fixture::load("spdx-empty").await;

    let result = sbom(&fixture, &required(SAN), MAX_SIZE).await;

    assert_eq!(
        result.map_err(|e| e.to_string()),
        Err("SBOM without packages".to_owned())
    );
}

/// `spdx`'s SBOM bundle is 16 250 bytes and its signature bundle 10 702: discovery keeps the latter only, as its test
/// of the same cap checks (D150).
#[tokio::test]
async fn an_sbom_discovery_left_out_as_over_sbom_max_size_is_over_it() {
    let fixture = Fixture::capped("spdx", 12_000).await;

    let result = sbom(&fixture, &required(SAN), 12_000).await;

    assert_eq!(
        result.map_err(|e| e.to_string()),
        Err("SBOM over sbom.max_size: 16250 bytes".to_owned())
    );
}

/// A record is untrusted: a BuildKit attestation manifest the signed index does not list holds no SBOM of it (D49).
#[tokio::test]
async fn a_buildkit_sbom_the_signed_index_does_not_list_is_missing() {
    let mut fixture = Fixture::load("buildkit-signed").await;
    let other = Layout::open("buildkit-unsigned");
    let attestation = other
        .artifacts()
        .into_iter()
        .find(|artifact| artifact.kind == Kind::Attestation)
        .expect("a BuildKit case records its attestation manifest");
    for blob in std::iter::once(&attestation.manifest).chain(&attestation.blobs) {
        fixture
            .store
            .keep(blob, &other.blob(blob))
            .await
            .expect("the store keeps a blob");
    }
    fixture
        .artifacts
        .retain(|artifact| artifact.kind != Kind::Attestation);
    fixture.artifacts.push(attestation);

    let result = sbom(&fixture, &required(SAN), MAX_SIZE).await;

    assert_eq!(result, Err(Failure::Missing));
}

/// The search ends at the first BuildKit SBOM that passes: a later attestation manifest, listed but not stored, is
/// never read (D150).
#[tokio::test]
async fn a_buildkit_sbom_that_passes_ends_the_search() {
    let mut fixture = Fixture::load("buildkit-signed").await;
    let attestation = fixture
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == Kind::Attestation)
        .cloned()
        .expect("a BuildKit case records its attestation manifest");
    // The platform manifest the attestation describes: the signed index lists it, the store does not hold it.
    fixture.artifacts.push(Artifact {
        manifest: attestation.target.clone(),
        blobs: Vec::new(),
        ..attestation
    });

    let result = sbom(&fixture, &required(SAN), MAX_SIZE).await;

    assert_eq!(result, Ok(listed(1)));
}

/// `buildkit-signed` without its in-toto layer, 3 472 bytes, and with the index's signature bundle, 10 792.
async fn buildkit_without_layer() -> Fixture {
    let fixture = Fixture::capped("buildkit-signed", 3_000).await;
    let layout = Layout::open("buildkit-signed");
    for artifact in fixture.artifacts.iter().filter(|a| a.kind == Kind::Bundle) {
        for blob in &artifact.blobs {
            fixture
                .store
                .keep(blob, &layout.blob(blob))
                .await
                .expect("the store keeps a blob");
        }
    }
    fixture
}

/// The index signature still verifies when discovery left the BuildKit layer out: the listed size names the reason.
#[tokio::test]
async fn a_buildkit_layer_discovery_left_out_as_over_sbom_max_size_is_over_it() {
    let fixture = buildkit_without_layer().await;

    let result = sbom(&fixture, &required(SAN), 3_000).await;

    assert_eq!(result, Err(Failure::Oversize(3_472)));
}

/// Discovery keeps every blob listed within `sbom.max_size`, at it included: one the store lacks leaves the check
/// unverifiable.
#[tokio::test]
async fn a_buildkit_layer_listed_within_sbom_max_size_and_not_stored_is_unverifiable() {
    let fixture = buildkit_without_layer().await;

    for max_size in [3_472, MAX_SIZE] {
        let unverifiable = Signatures::new(max_size)
            .sbom(
                &fixture.store,
                &fixture.root,
                &fixture.artifacts,
                &required(SAN),
                &pinned(),
            )
            .await
            .expect_err("the layer is listed within the cap");

        assert!(
            unverifiable
                .to_string()
                .ends_with("is not in the artifact store"),
            "{max_size}: {unverifiable}"
        );
    }
}
