//! The signature check over the recorded fixtures of step 01 (D139), offline: which authorities a bundle satisfies.

mod recorded;

use std::path::Path;

use recorded::{Recorded, at, pinned};
use speculaire_artifacts::testing::{FIXTURES, Fixture, GITHUB_PRIVATE};
use speculaire_verify::signature::{AuthorityResult, Failure, Signatures, Signed};
use speculaire_verify::{Policies, Policy, TrustRoot};

/// The workflow that signed every keyless case.
const SAN: &str =
    "https://github.com/spnngl/speculaire/.github/workflows/fixtures.yml@refs/heads/main";
const ISSUER: &str = "https://token.actions.githubusercontent.com";

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

    let results = check(&Signatures::default(), &fixture, &policy).await;

    assert_eq!(results, [Ok(workflow())]);
}

#[tokio::test]
async fn a_key_bundle_passes_the_policy_holding_its_key() {
    let fixture = Fixture::load("key").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}")), key()]);

    let results = check(&Signatures::default(), &fixture, &policy).await;

    assert_eq!(
        results,
        [Err(Failure::Mismatch(Signed::Key)), Ok(Signed::Key)]
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

    let results = check(&Signatures::default(), &fixture, &policy).await;

    let mismatch = Err(Failure::Mismatch(workflow()));
    assert_eq!(results, [mismatch.clone(), mismatch.clone(), mismatch]);
    let reason = results[0].as_ref().expect_err("a mismatch").to_string();
    assert!(reason.contains(SAN) && reason.contains(ISSUER), "{reason}");
}

#[tokio::test]
async fn a_tampered_bundle_has_an_invalid_signature() {
    let fixture = Fixture::flipped("keyless").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::default(), &fixture, &policy).await;

    assert!(
        matches!(&results[..], [Err(Failure::Invalid(_))]),
        "{results:?}"
    );
}

#[tokio::test]
async fn a_bundle_of_githubs_private_instance_names_its_unknown_issuer() {
    let fixture = Fixture::bundled("keyless", GITHUB_PRIVATE).await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::default(), &fixture, &policy).await;

    assert_eq!(
        results,
        [Err(Failure::UnknownIssuer(
            "O=GitHub, Inc., CN=Fulcio Intermediate l1".to_owned()
        ))]
    );
    let reason = results[0].as_ref().expect_err("unknown").to_string();
    assert!(reason.contains("GitHub, Inc."), "{reason}");
}

#[tokio::test]
async fn an_image_without_a_bundle_has_no_signature() {
    let fixture = Fixture::load("unsigned").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);

    let results = check(&Signatures::default(), &fixture, &policy).await;

    assert_eq!(results, [Err(Failure::Missing)]);
    assert_eq!(Failure::Missing.to_string(), "no signature");
}

#[tokio::test]
async fn no_trust_root_leaves_the_check_unverifiable() {
    let fixture = Fixture::load("keyless").await;
    let policy = policy(&[keyless(&format!("subject: {SAN}"))]);
    let absent = speculaire_verify::Absent::new("TUF: unreachable");

    let unverifiable = Signatures::default()
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
    let signatures = Signatures::default();
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

    let unverifiable = Signatures::default()
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
