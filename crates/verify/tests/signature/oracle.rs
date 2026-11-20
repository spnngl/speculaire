//! What the recording workflow's oracle found (D141), found again under the pinned trusted root: each check of each
//! case, and the runnable image on each platform it holds.

use speculaire_artifacts::testing::{Check, Expected, Layout, Signer};
use speculaire_oci::index::Index;
use speculaire_oci::platform::Host;
use speculaire_verify::Report;

use super::*;

/// The case a pod runs: busybox for `linux/amd64` and `linux/arm64`, signed keyless.
const RUNNABLE: &str = "runnable";

/// The authority that names `signer`; one no image meets when no one signed.
fn authority(signer: Option<&Signer>) -> String {
    match signer {
        Some(Signer::Keyless { san, issuer }) => format!(
            "  - keyless:\n      identities:\n      - issuer: {issuer}\n        subject: {san}\n"
        ),
        Some(Signer::Key { .. }) => key(),
        None => keyless("subjectRegExp: .*"),
    }
}

/// The predicate type of cosign's `--type`.
#[expect(clippy::panic, reason = "a test names the type it cannot map")]
fn predicate_type(kind: &str) -> &'static str {
    match kind {
        "spdxjson" => "https://spdx.dev/Document",
        "cyclonedx" => "https://cyclonedx.org/bom",
        other => panic!("no predicate type for cosign's {other}"),
    }
}

#[tokio::test]
async fn every_check_of_every_case_meets_the_oracles_finding() {
    for expected in Expected::all() {
        let fixture = Fixture::load(&expected.case).await;
        let authority = authority(expected.signer.as_ref());
        for checked in expected.checks {
            let policy = match &checked.check {
                Check::Signature | Check::SignatureLegacy => {
                    policy(std::slice::from_ref(&authority))
                }
                Check::Attestation(kind) => {
                    policy(&[attesting(authority.clone(), &[predicate_type(kind)])])
                }
                Check::Github(predicate_type) => {
                    policy(&[attesting(authority.clone(), &[predicate_type])])
                }
                // `.att` tags are not read (D43).
                Check::AttestationLegacy(_) => continue,
            };

            let results = check(&Signatures::new(MAX_SIZE), &fixture, &policy).await;

            assert_eq!(
                results[0].is_ok(),
                checked.ok,
                "{} {:?}: {results:?}",
                expected.case,
                checked.check
            );
        }
    }
}

#[tokio::test]
async fn the_runnable_image_is_allowed_on_amd64_and_arm64_under_its_signers_policy() {
    let layout = Layout::open(RUNNABLE);
    let index = Index::parse(&layout.blob(layout.root())).expect("runnable is an image index");
    let policy = policy(&[authority(Expected::of(RUNNABLE).signer.as_ref())]);

    for arch in ["amd64", "arm64"] {
        let host = Host {
            os: "linux".to_owned(),
            arch: arch.to_owned(),
            variant: String::new(),
        };
        assert!(index.platform_manifest(&host).is_some(), "linux/{arch}");
        let fixture = Fixture::on(RUNNABLE, &host).await;

        let report = Report::check(
            format!("{RUNNABLE}@{}", fixture.root),
            &Signatures::new(MAX_SIZE),
            &fixture.store,
            &fixture.root,
            &fixture.artifacts,
            &[&policy],
            Ok(&pinned()),
        )
        .await;

        assert!(report.allowed(), "linux/{arch}: {report}");
    }
}
