//! The signature check over the recorded fixtures of step 01 (D139), offline: which authorities a bundle satisfies,
//! with the attestations they require (D149), and the SBOM a policy can require (D150).

mod recorded;
#[path = "signature/sbom.rs"]
mod sbom;

use std::path::Path;

use recorded::{Recorded, at, pinned};
use sigstore_verify::types::Bundle;
use speculaire_artifacts::Kind;
use speculaire_artifacts::testing::{FIXTURES, Fixture, GITHUB_PRIVATE};
use speculaire_verify::signature::{AuthorityResult, Failure, Signatures, Signed, Unmet};
use speculaire_verify::statement::Statement;
use speculaire_verify::{Policies, Policy, TrustRoot};

/// The workflow that signed every keyless case.
const SAN: &str =
    "https://github.com/spnngl/speculaire/.github/workflows/fixtures.yml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";

/// `sbom.max_size`'s default (D12).
const MAX_SIZE: u64 = 64 << 20;

/// One policy over every image, with `authorities` (each a list item, indented as one) as its authorities.
fn policy(authorities: &[String]) -> Policy {
    let text = format!(
        "apiVersion: policy.sigstore.dev/v1beta1\nkind: ClusterImagePolicy\nmetadata:\n  name: p\nspec:\n  \
         images:\n  - glob: \"**\"\n  authorities:\n{}",
        authorities.concat()
    );
    let policies = Policies::parse(&text).expect("the test policy parses");
    policies.iter().next().expect("one policy").clone()
}

/// A keyless authority whose identity is `subject` (a key such as `subject` or `subjectRegExp`) from GitHub Actions.
fn keyless(subject: &str) -> String {
    format!("  - keyless:\n      identities:\n      - issuer: {ISSUER}\n        {subject}\n")
}

/// A key authority holding `cosign.pub`.
fn key() -> String {
    let pem = std::fs::read_to_string(Path::new(FIXTURES).join("cosign.pub")).expect("cosign.pub");
    pem.lines()
        .fold("  - key:\n      data: |\n".to_owned(), |text, line| {
            text + "        " + line + "\n"
        })
}

async fn check(
    signatures: &Signatures,
    fixture: &Fixture,
    policy: &Policy,
) -> Vec<AuthorityResult> {
    signatures
        .check(
            &fixture.store,
            &fixture.root,
            &fixture.artifacts,
            policy,
            Ok(&pinned()),
        )
        .await
        .expect("the store and the trust root are there")
}

fn workflow() -> Signed {
    Signed::Certificate {
        subject: SAN.to_owned(),
        issuer: ISSUER.to_owned(),
    }
}

#[tokio::test]
async fn a_keyless_bundle_passes_the_policy_naming_its_workflow() {
    let fixture = Fixture::load("keyless").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(results, [Ok(workflow())]);
}

#[tokio::test]
async fn a_legacy_sig_with_its_set_passes_the_policy_naming_its_workflow() {
    let fixture = Fixture::load("legacy-sig").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(results, [Ok(workflow())]);
}

#[tokio::test]
async fn a_sig_served_for_another_image_names_the_image_it_signs() {
    let fixture = Fixture::signature_of("legacy-sig", "keyless").await;
    let signed = Fixture::load("legacy-sig").await.root;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(
        results,
        [Err(Unmet::Signature(Failure::Invalid(format!(
            "the .sig signs {signed}, not this image"
        ))))]
    );
}

#[tokio::test]
async fn a_sig_without_its_set_names_the_missing_set() {
    let fixture = Fixture::unlogged("legacy-sig").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(
        results,
        [Err(Unmet::Signature(Failure::Invalid(
            "the .sig has no SET (annotation dev.sigstore.cosign/bundle)".to_owned()
        )))]
    );
}

#[tokio::test]
async fn a_key_bundle_passes_the_policy_holding_its_key() {
    let fixture = Fixture::load("key").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}")), key()]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(
        results,
        [
            Err(Unmet::Signature(Failure::Mismatch(Signed::Key))),
            Ok(Signed::Key)
        ]
    );
}

#[tokio::test]
async fn another_workflow_or_a_pattern_over_part_of_the_san_fails_naming_the_signer() {
    let fixture = Fixture::load("keyless").await;
    let policy = policy(&[
        keyless(
            "subject: https://github.com/spnngl/speculaire/.github/workflows/release.yml@refs/heads/main",
        ),
        keyless(r"subjectRegExp: https://github\.com/spnngl/speculaire/"),
        key(),
    ]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    let mismatch = Err(Unmet::Signature(Failure::Mismatch(workflow())));
    assert_eq!(results, [mismatch.clone(), mismatch.clone(), mismatch]);
    let reason = results[0].as_ref().expect_err("a mismatch").to_string();
    assert!(reason.contains(SAN) && reason.contains(ISSUER), "{reason}");
}

#[tokio::test]
async fn a_tampered_bundle_has_an_invalid_signature() {
    let fixture = Fixture::flipped("keyless").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert!(
        matches!(&results[..], [Err(Unmet::Signature(Failure::Invalid(_)))]),
        "{results:?}"
    );
}

#[tokio::test]
async fn a_bundle_of_githubs_private_instance_names_its_unknown_issuer() {
    let fixture = Fixture::bundled("keyless", GITHUB_PRIVATE).await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(
        results,
        [Err(Unmet::Signature(Failure::UnknownIssuer(
            "O=GitHub, Inc., CN=Fulcio Intermediate l1".to_owned()
        )))]
    );
    let reason = results[0].as_ref().expect_err("unknown").to_string();
    assert!(reason.contains("GitHub, Inc."), "{reason}");
}

#[tokio::test]
async fn an_image_without_a_bundle_has_no_signature() {
    let fixture = Fixture::load("unsigned").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(results, [Err(Unmet::Signature(Failure::Missing))]);
    assert_eq!(Failure::Missing.to_string(), "no signature");
}

#[tokio::test]
async fn no_trust_root_leaves_the_check_unverifiable() {
    let fixture = Fixture::load("keyless").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);
    let absent = speculaire_verify::Absent::new("TUF: unreachable");

    let unverifiable = Signatures::new(MAX_SIZE)
        .check(
            &fixture.store,
            &fixture.root,
            &fixture.artifacts,
            &policy,
            Err(&absent),
        )
        .await
        .expect_err("no trust root");

    assert_eq!(unverifiable.to_string(), "trust root: TUF: unreachable");
}

#[tokio::test]
async fn a_second_policy_over_the_same_bundle_reuses_its_verification() {
    let fixture = Fixture::load("keyless").await;
    let signatures = Signatures::new(MAX_SIZE);
    let first = policy(&[keyless(&format!("subject: {SAN}"))]);
    let second = policy(&[keyless(r"subjectRegExp: https://github\.com/spnngl/.+")]);

    assert_eq!(check(&signatures, &fixture, &first).await, [Ok(workflow())]);
    assert_eq!(signatures.hits(), 0);
    assert_eq!(
        check(&signatures, &fixture, &second).await,
        [Ok(workflow())]
    );

    assert_eq!(signatures.hits(), 1, "the keyless case holds one bundle");
}

#[tokio::test]
async fn an_expired_tuf_repository_leaves_the_check_unverifiable() {
    let fixture = Fixture::load("keyless").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);
    let cache = tempfile::tempdir().expect("a temporary directory");
    let absent = TrustRoot::fetch(Recorded, cache.path(), at("2026-11-25T00:00:00Z"))
        .await
        .expect_err("the recorded timestamp role has expired");

    let unverifiable = Signatures::new(MAX_SIZE)
        .check(
            &fixture.store,
            &fixture.root,
            &fixture.artifacts,
            &policy,
            Err(&absent),
        )
        .await
        .expect_err("no trust root");

    let reason = unverifiable.to_string();
    assert!(
        reason.starts_with("trust root: ") && reason.contains("expired"),
        "{reason}"
    );
}

#[tokio::test]
async fn another_trust_root_verifies_the_bundle_again() {
    let fixture = Fixture::load("keyless").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);
    let signatures = Signatures::new(MAX_SIZE);
    let mut bytes =
        std::fs::read(Path::new(FIXTURES).join("trusted_root.json")).expect("the recorded root");
    bytes.push(b'\n');
    let other = TrustRoot::parse(&bytes).expect("the recorded root with one more newline");
    assert_ne!(other.hash(), pinned().hash());

    let first = pinned();
    for root in [&first, &other, &other] {
        let results = signatures
            .check(
                &fixture.store,
                &fixture.root,
                &fixture.artifacts,
                &policy,
                Ok(root),
            )
            .await
            .expect("the store and the trust root are there");
        assert_eq!(results, [Ok(workflow())]);
    }

    assert_eq!(
        signatures.hits(),
        1,
        "only the second check under the same root reuses its verification"
    );
}

#[tokio::test]
async fn only_a_signature_of_the_image_counts() {
    let fixture = Fixture::load("keyless").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);
    let other = Fixture::load("key").await.root;
    let mut attestation = fixture.artifacts.clone();
    for artifact in &mut attestation {
        artifact.kind = Kind::Attestation;
    }
    let mut elsewhere = fixture.artifacts.clone();
    for artifact in &mut elsewhere {
        artifact.target = other.clone();
    }

    for artifacts in [attestation, elsewhere] {
        let results = Signatures::new(MAX_SIZE)
            .check(
                &fixture.store,
                &fixture.root,
                &artifacts,
                &policy,
                Ok(&pinned()),
            )
            .await
            .expect("the store and the trust root are there");
        assert_eq!(results, [Err(Unmet::Signature(Failure::Missing))]);
    }
}

#[tokio::test]
async fn an_authority_fails_with_the_reason_of_the_closest_bundle() {
    let tampered = Fixture::flipped("keyless").await;
    let intact = Fixture::load("keyless").await.artifacts;
    let policy = policy(&[keyless(
        "subject: https://github.com/spnngl/speculaire/.github/workflows/release.yml@refs/heads/main",
    )]);

    let signatures = Signatures::new(MAX_SIZE);

    for artifacts in [
        [intact[0].clone(), tampered.artifacts[0].clone()],
        [tampered.artifacts[0].clone(), intact[0].clone()],
    ] {
        let results = signatures
            .check(
                &tampered.store,
                &tampered.root,
                &artifacts,
                &policy,
                Ok(&pinned()),
            )
            .await
            .expect("the store holds both bundles");
        assert_eq!(
            results,
            [Err(Unmet::Signature(Failure::Mismatch(workflow())))],
            "{artifacts:?}"
        );
    }

    assert_eq!(
        signatures.hits(),
        2,
        "the second check reuses both bundles' results"
    );
}
const PROVENANCE: &str = "https://slsa.dev/provenance/v1";

/// `authority` requiring an attestation of each of `predicate_types`.
fn attesting(authority: String, predicate_types: &[&str]) -> String {
    predicate_types
        .iter()
        .fold(authority + "    attestations:\n", |text, predicate_type| {
            text + "    - name: a\n      predicateType: " + predicate_type + "\n"
        })
}

/// The reason of an authority missing an attestation of `predicate_type`.
fn missing(predicate_type: &str) -> AuthorityResult {
    Err(Unmet::Attestation {
        predicate_type: predicate_type.to_owned(),
        failure: Failure::Missing,
    })
}

#[tokio::test]
async fn a_github_provenance_passes_the_policy_requiring_it_from_its_workflow() {
    let fixture = Fixture::load("provenance").await;
    let policy = policy(&[attesting(
        keyless(&format!("subject: {SAN}")),
        &[PROVENANCE],
    )]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(results, [Ok(workflow())]);
}

#[tokio::test]
async fn an_attestation_only_in_an_att_tag_or_absent_is_missing() {
    let policy = policy(&[attesting(
        keyless(&format!("subject: {SAN}")),
        &[PROVENANCE],
    )]);

    for case in ["att-only", "keyless", "legacy-sig", "unsigned"] {
        let fixture = Fixture::load(case).await;

        let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

        assert_eq!(results, [missing(PROVENANCE)], "{case}");
        let reason = results[0].as_ref().expect_err("missing").to_string();
        assert_eq!(
            reason,
            "attestation https://slsa.dev/provenance/v1 missing (.att tags are not supported)"
        );
    }
}

#[tokio::test]
async fn an_attestation_by_another_identity_fails_naming_its_signer() {
    let fixture = Fixture::load("provenance").await;
    let policy = policy(&[attesting(
        keyless(
            "subject: https://github.com/spnngl/speculaire/.github/workflows/release.yml@refs/heads/main",
        ),
        &[PROVENANCE],
    )]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(
        results,
        [Err(Unmet::Attestation {
            predicate_type: PROVENANCE.to_owned(),
            failure: Failure::Mismatch(workflow()),
        })]
    );
    let reason = results[0].as_ref().expect_err("a mismatch").to_string();
    assert!(
        reason.starts_with(
            "attestation https://slsa.dev/provenance/v1: identity mismatch: signed by "
        ) && reason.contains(SAN),
        "{reason}"
    );
}

#[tokio::test]
async fn every_required_attestation_must_pass() {
    let fixture = Fixture::load("provenance").await;
    let spdx = "https://spdx.dev/Document";
    let policy = policy(&[attesting(
        keyless(&format!("subject: {SAN}")),
        &[PROVENANCE, spdx],
    )]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(results, [missing(spdx)]);
}

#[tokio::test]
async fn a_cosign_signature_is_never_an_attestation() {
    let fixture = Fixture::load("keyless").await;
    let signature = "https://sigstore.dev/cosign/sign/v1";
    let policy = policy(&[attesting(keyless(&format!("subject: {SAN}")), &[signature])]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert_eq!(results, [missing(signature)]);
}

#[tokio::test]
async fn a_tampered_attestation_is_invalid() {
    let fixture = Fixture::flipped("provenance").await;
    let policy = policy(&[attesting(
        keyless(&format!("subject: {SAN}")),
        &[PROVENANCE],
    )]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert!(
        matches!(
            &results[..],
            [Err(Unmet::Attestation { predicate_type, failure: Failure::Invalid(_) })] if predicate_type == PROVENANCE
        ),
        "{results:?}"
    );
}

#[tokio::test]
async fn an_attested_sbom_gives_its_bundle_whose_statement_holds_the_predicate() {
    let fixture = Fixture::load("attest-sbom").await;
    let spdx = "https://spdx.dev/Document/v2.3";
    let signer = policy(&[keyless(&format!("subject: {SAN}"))]).authorities()[0]
        .signer
        .clone();

    let attested = Signatures::new(MAX_SIZE)
        .attested(
            &fixture.store,
            &fixture.root,
            &fixture.artifacts,
            &signer,
            &pinned(),
            spdx,
        )
        .await
        .expect("the store holds the bundle")
        .expect("attest-sbom attests an SPDX 2.3 document");

    assert_eq!(attested.signed, workflow());
    let text = fixture
        .store
        .read(&attested.bundle)
        .await
        .expect("the store reads")
        .expect("the bundle is stored");
    let bundle =
        Bundle::from_json(std::str::from_utf8(&text).expect("JSON")).expect("the bundle parses");
    let statement = Statement::of(&bundle).expect("its statement");
    assert_eq!(statement.predicate_type(), spdx);
    let predicate = statement.predicate().expect("a predicate");
    assert!(predicate.contains("\"packages\""), "{predicate}");
}

#[tokio::test]
async fn a_blob_that_is_no_bundle_is_an_invalid_signature() {
    let fixture = Fixture::bundled("keyless", "{}").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

    assert!(
        matches!(
            &results[..],
            [Err(Unmet::Signature(Failure::Invalid(reason)))] if reason.starts_with("not a Sigstore bundle: ")
        ),
        "{results:?}"
    );
}

/// `spdx`'s SBOM bundle is 16 250 bytes and its signature bundle 10 702 (D150).
#[tokio::test]
async fn a_bundle_discovery_left_out_as_over_sbom_max_size_fails_as_over_it_and_attests_its_annotation()
 {
    let fixture = Fixture::capped("spdx", 12_000).await;
    let spdx = "https://spdx.dev/Document";
    let policy = policy(&[attesting(keyless(&format!("subject: {SAN}")), &[spdx])]);

    let results = check(&Signatures::new(12_000), &fixture, &policy).await;

    assert_eq!(
        results,
        [Err(Unmet::Attestation {
            predicate_type: spdx.to_owned(),
            failure: Failure::Oversize(16_250),
        })]
    );
    assert_eq!(
        results[0].as_ref().expect_err("over").to_string(),
        "attestation https://spdx.dev/Document: signature over sbom.max_size: 16250 bytes"
    );
}

#[tokio::test]
async fn a_sig_payload_discovery_left_out_as_over_sbom_max_size_fails_as_over_it() {
    let fixture = Fixture::capped("legacy-sig", 100).await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::new(100), &fixture, &policy).await;

    assert!(
        matches!(results[..], [Err(Unmet::Signature(Failure::Oversize(size)))] if size > 100),
        "{results:?}"
    );
}

#[tokio::test]
async fn a_bundle_missing_from_the_store_below_sbom_max_size_is_unverifiable() {
    let fixture = Fixture::capped("spdx", 12_000).await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let unverifiable = Signatures::new(MAX_SIZE)
        .check(
            &fixture.store,
            &fixture.root,
            &fixture.artifacts,
            &policy,
            Ok(&pinned()),
        )
        .await
        .expect_err("the store lacks a bundle its manifest lists below the cap");

    assert_eq!(
        unverifiable.to_string(),
        "sha256:91a29456c904110df51d06e019af70aafcf04838c47951760bb887232119d36a is not in the artifact store"
    );
}
