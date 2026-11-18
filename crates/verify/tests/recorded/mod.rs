//! What the integration tests share: the recorded trusted root and TUF repository of step 01 (D141), served in process.

use std::path::{Path, PathBuf};

use jiff::Timestamp;
use sigstore_tuf::Repository;
use sigstore_tuf::transport::FetchFuture;
use speculaire_artifacts::testing::FIXTURES;
use speculaire_verify::TrustRoot;

/// The recorded repository, read from `fixtures/sigstore/tuf/`.
pub(crate) struct Recorded;

impl Repository for Recorded {
    fn fetch_metadata<'a>(&'a self, name: &'a str, _: u64) -> FetchFuture<'a> {
        Box::pin(async move { Ok(read(&tuf().join(name))) })
    }

    fn fetch_target<'a>(&'a self, path: &'a str, _: u64) -> FetchFuture<'a> {
        Box::pin(async move { Ok(read(&tuf().join("targets").join(path))) })
    }
}

fn tuf() -> PathBuf {
    Path::new(FIXTURES).join("tuf")
}

/// The file, or `None` when it does not exist: the end of the root chain.
fn read(path: &Path) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// `time`, an RFC 3339 timestamp.
pub(crate) fn at(time: &str) -> Timestamp {
    time.parse().expect("the test times are RFC 3339")
}

/// The recorded trusted root, pinned.
pub(crate) fn pinned() -> TrustRoot {
    TrustRoot::load(&Path::new(FIXTURES).join("trusted_root.json"))
        .expect("the recorded trusted root parses")
}
