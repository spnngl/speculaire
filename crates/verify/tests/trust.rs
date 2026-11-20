//! The trust root over the recorded TUF repository of step 01 (D141), served in process: no socket.

mod recorded;

use std::path::Path;

use jiff::{SignedDuration, Timestamp};
use recorded::{Recorded, expired, expiry, pinned};
use sigstore_tuf::Repository;
use sigstore_tuf::transport::FetchFuture;
use speculaire_artifacts::testing::FIXTURES;
use speculaire_verify::TrustRoot;
use speculaire_verify::trust::{LoadError, ParseError};

/// A time the recorded TUF metadata is valid at: a day before the timestamp role's expiry.
fn valid() -> Timestamp {
    expiry()
        .checked_sub(SignedDuration::from_hours(24))
        .expect("in range")
}

/// A repository whose every fetch fails, as when the CDN is unreachable.
struct Unreachable;

impl Repository for Unreachable {
    fn fetch_metadata<'a>(&'a self, _: &'a str, _: u64) -> FetchFuture<'a> {
        Box::pin(async { Err(sigstore_tuf::Error::transport("unreachable")) })
    }

    fn fetch_target<'a>(&'a self, _: &'a str, _: u64) -> FetchFuture<'a> {
        Box::pin(async { Err(sigstore_tuf::Error::transport("unreachable")) })
    }
}

#[tokio::test]
async fn tuf_loads_the_recorded_root_and_serves_it_from_the_cache_when_every_fetch_fails() {
    let cache = tempfile::tempdir().expect("a temporary directory");

    let fetched = TrustRoot::fetch(Recorded, cache.path(), valid())
        .await
        .expect("the recorded repository serves a trusted root");
    assert_eq!(fetched.hash(), pinned().hash());
    assert_eq!(fetched.expiry(), Some(expiry()));
    assert!(cache.path().join("timestamp.json").is_file());

    let cached = TrustRoot::fetch(Unreachable, cache.path(), valid())
        .await
        .expect("the cache serves the trusted root");
    assert_eq!(cached.hash(), fetched.hash());
    assert_eq!(cached.expiry(), fetched.expiry());
}

#[tokio::test]
async fn tuf_metadata_past_its_expiry_leaves_no_trust_root_and_names_the_expiry() {
    let cache = tempfile::tempdir().expect("a temporary directory");
    let after = expired();

    let absent = TrustRoot::fetch(Recorded, cache.path(), after)
        .await
        .expect_err("expired metadata gives no trust root");
    assert!(
        absent.to_string().contains("timestamp metadata expired"),
        "{absent}"
    );

    TrustRoot::fetch(Recorded, cache.path(), valid())
        .await
        .expect("the recorded repository serves a trusted root");
    let absent = TrustRoot::fetch(Unreachable, cache.path(), after)
        .await
        .expect_err("an expired cache gives no trust root");
    assert!(
        absent
            .to_string()
            .contains("the cache: timestamp metadata expired"),
        "{absent}"
    );
}

#[test]
fn a_pinned_root_loads_with_its_hash_and_the_latest_end_of_its_keys() {
    let bytes = std::fs::read(Path::new(FIXTURES).join("trusted_root.json"))
        .expect("the recorded trusted root");
    let root = pinned();

    // The SHA-256 that names the target in the recorded TUF repository.
    let target = format!("{}.trusted_root.json", root.hash());
    assert!(
        Path::new(FIXTURES)
            .join("tuf/targets")
            .join(&target)
            .is_file(),
        "{target}"
    );
    assert!(
        format!("{root:?}").starts_with("TrustRoot { hash: "),
        "its debug text names its hash, not its keys"
    );
    assert_eq!(
        root.hash(),
        TrustRoot::parse(&bytes).expect("parses").hash()
    );
    assert_eq!(
        root.root().tlogs.len(),
        TrustRoot::parse(&bytes).expect("parses").root().tlogs.len()
    );
    let end = root.expiry().expect("the recorded root's certificates end");
    assert!(end > expiry(), "{end}");
}

#[test]
fn a_corrupt_pinned_root_is_refused_naming_its_file() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join("trusted_root.json");
    std::fs::write(&path, "{\"tlogs\": 1}").expect("writes");

    let error = TrustRoot::load(&path).expect_err("a corrupt root is refused");
    assert!(
        matches!(&error, LoadError::Parse { path: p, source: ParseError::Json(_) } if *p == path),
        "{error:?}"
    );

    let missing =
        TrustRoot::load(&dir.path().join("missing.json")).expect_err("a missing root is refused");
    assert!(matches!(missing, LoadError::Read { .. }), "{missing:?}");
}

#[test]
fn a_pinned_root_whose_certificate_is_not_x509_is_refused_naming_it() {
    let recorded =
        std::fs::read(format!("{FIXTURES}/trusted_root.json")).expect("the recorded root");
    let mut root: serde_json::Value = serde_json::from_slice(&recorded).expect("JSON");
    *root
        .pointer_mut("/certificateAuthorities/0/certChain/certificates/0/rawBytes")
        .expect("a CA with a certificate") = "AAAA".into();

    let error = TrustRoot::parse(root.to_string().as_bytes()).expect_err("refused");
    assert!(
        matches!(error, ParseError::Certificate { certificate: 0, .. }),
        "{error:?}"
    );
    assert!(
        error.to_string().starts_with("certificate 0 of "),
        "{error}"
    );
}
