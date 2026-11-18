//! The recorded Sigstore fixtures (D139, D141), loaded into an artifact store as discovery records them, for the tests
//! of any crate.
//!
//! Each case of `expected.json` is an OCI layout, read by [`Layout`]. [`Fixture::load`] keeps a case's artifacts in a
//! store of its own; [`Fixture::signature_of`] and [`Fixture::flipped`] build the negative cases no recording holds.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::Value;
use speculaire_oci::index::Index;
use speculaire_oci::platform::Host;
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::{self, Referrer};
use tempfile::TempDir;

use crate::{Artifact, Kind, Store};

/// The recorded fixtures, at the top of the repository (D141).
pub const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/sigstore");

// Copied from sigstore-rust tag sigstore-verify-v0.16.0,
// `crates/sigstore-verify/test_data/bundles/github-private-attestation.sigstore.json`.
/// A GitHub attestation bundle from GitHub's private Sigstore instance, whose issuer no public-good root knows.
pub const GITHUB_PRIVATE: &str =
    include_str!("../../../fixtures/sigstore/github-private-attestation.sigstore.json");

/// The annotation of an OCI layout's index that names a manifest's tag.
const TAG: &str = "org.opencontainers.image.ref.name";

/// The cases `expected.json` lists, in its order.
///
/// # Panics
///
/// When `expected.json` cannot be read.
#[must_use]
pub fn cases() -> Vec<String> {
    let expected: Value = serde_json::from_slice(&read(&Path::new(FIXTURES).join("expected.json")))
        .expect("expected.json is JSON");
    expected
        .as_array()
        .expect("expected.json lists the cases")
        .iter()
        .map(|case| {
            case["case"]
                .as_str()
                .expect("each case has a name")
                .to_owned()
        })
        .collect()
}

/// The platform the fixtures were built for: discovery picks its manifest from an image index.
#[must_use]
pub fn platform() -> Host {
    Host {
        os: "linux".to_owned(),
        arch: "amd64".to_owned(),
        variant: String::new(),
    }
}

/// A case's OCI layout: its blobs, and its tags with the manifests they name.
pub struct Layout {
    dir: PathBuf,
    root: Digest,
    tags: Vec<(String, Digest)>,
}

impl Layout {
    /// Opens the layout of `case`.
    ///
    /// # Panics
    ///
    /// When the case has no layout, or its index names no manifest tagged with the case's name.
    #[must_use]
    pub fn open(case: &str) -> Self {
        let dir = Path::new(FIXTURES).join("layouts").join(case);
        let index: Value =
            serde_json::from_slice(&read(&dir.join("index.json"))).expect("index.json is JSON");
        let tags: Vec<(String, Digest)> = index["manifests"]
            .as_array()
            .expect("an OCI layout's index lists manifests")
            .iter()
            .filter_map(|listed| {
                let tag = listed["annotations"][TAG].as_str()?;
                let digest = Digest::parse(listed["digest"].as_str()?).ok()?;
                Some((tag.to_owned(), digest))
            })
            .collect();
        let root = tags
            .iter()
            .find(|(tag, _)| tag == case)
            .map(|(_, digest)| digest.clone())
            .expect("the case's image is tagged with its name");
        Self { dir, root, tags }
    }

    /// The case's image: the manifest its name tags.
    #[must_use]
    pub fn root(&self) -> &Digest {
        &self.root
    }

    /// Every tag and the manifest it names: the case's name, the referrers fallback tags and cosign's legacy tags.
    #[must_use]
    pub fn tags(&self) -> &[(String, Digest)] {
        &self.tags
    }

    /// The manifest `tag` names.
    #[must_use]
    pub fn tag(&self, tag: &str) -> Option<&Digest> {
        self.tags
            .iter()
            .find(|(name, _)| name == tag)
            .map(|(_, digest)| digest)
    }

    /// The bytes of the blob or manifest `digest`.
    ///
    /// # Panics
    ///
    /// When the layout does not hold it.
    #[must_use]
    pub fn blob(&self, digest: &Digest) -> Vec<u8> {
        read(
            &self
                .dir
                .join("blobs")
                .join(digest.algorithm())
                .join(digest.encoded()),
        )
    }

    /// Every blob and manifest the layout holds.
    ///
    /// # Panics
    ///
    /// When the layout's blobs cannot be listed.
    #[must_use]
    pub fn blobs(&self) -> Vec<(Digest, Vec<u8>)> {
        let dir = self.dir.join("blobs").join("sha256");
        let entries = std::fs::read_dir(&dir).expect("an OCI layout has sha256 blobs");
        entries
            .map(|entry| {
                let path = entry.expect("a blob can be listed").path();
                let name = path.file_name().and_then(|name| name.to_str());
                let digest = Digest::parse(&format!("sha256:{}", name.unwrap_or_default()))
                    .expect("a blob is named by its hex digest");
                (digest, read(&path))
            })
            .collect()
    }

    /// What discovery records of the root on the fixtures' platform, in its order: the attestation manifests of an
    /// image index's platform manifest, then for each target its Sigstore bundle referrers and its `.sig` (D121).
    ///
    /// # Panics
    ///
    /// When a manifest the layout tags cannot be parsed.
    #[must_use]
    pub fn artifacts(&self) -> Vec<Artifact> {
        let mut targets = vec![self.root.clone()];
        let mut artifacts = Vec::new();
        if let Some(index) = self.index()
            && let Some(platform) = index.platform_manifest(&platform())
        {
            targets.push(platform.clone());
            for attestation in index.attestations(platform) {
                let referrer = self.referrer(attestation);
                artifacts.push(artifact(
                    platform,
                    attestation,
                    Kind::Attestation,
                    &referrer,
                ));
                targets.push(attestation.clone());
            }
        }
        for target in &targets {
            let listed = self
                .tag(&referrers::fallback_tag(target))
                .map(|index| referrers::index(&self.blob(index)).expect("a referrers index"));
            // Every bundle the recordings list names its target as subject: discovery's check of it keeps them all.
            let bundles = listed
                .into_iter()
                .flatten()
                .filter(referrers::Descriptor::may_be_bundle);
            for descriptor in bundles {
                let referrer = self.referrer(&descriptor.digest);
                artifacts.push(artifact(
                    target,
                    &descriptor.digest,
                    Kind::Bundle,
                    &referrer,
                ));
            }
            if let Some(signature) = self.tag(&referrers::signature_tag(target)) {
                let referrer = self.referrer(signature);
                artifacts.push(artifact(target, signature, Kind::Signature, &referrer));
            }
        }
        artifacts
    }

    /// The root as an image index, when it is one.
    fn index(&self) -> Option<Index> {
        let bytes = self.blob(&self.root);
        let manifest: Value = serde_json::from_slice(&bytes).expect("a manifest is JSON");
        (manifest["mediaType"] == referrers::INDEX)
            .then(|| Index::parse(&bytes).expect("an image index"))
    }

    fn referrer(&self, digest: &Digest) -> Referrer {
        Referrer::parse(&self.blob(digest)).expect("a referrer is an image manifest")
    }
}

/// The artifact of `target` that the manifest `referrer`, at `digest`, holds.
fn artifact(target: &Digest, digest: &Digest, kind: Kind, referrer: &Referrer) -> Artifact {
    Artifact {
        target: target.clone(),
        manifest: digest.clone(),
        kind,
        blobs: referrer.blobs().map(|blob| blob.digest.clone()).collect(),
    }
}

#[expect(
    clippy::panic,
    reason = "a test helper names the fixture file it misses"
)]
fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| panic!("{} cannot be read: {e}", path.display()))
}

/// A case kept in a store of its own, in a temporary directory, as discovery keeps it.
pub struct Fixture {
    /// The store: the root's record, its manifest when it is an index, and each artifact's manifest and blobs.
    pub store: Arc<Store>,
    /// The case's image.
    pub root: Digest,
    /// The root's record.
    pub artifacts: Vec<Artifact>,
    _dir: TempDir,
}

impl Fixture {
    /// Keeps the artifacts of `case` and records them as its root's.
    ///
    /// # Panics
    ///
    /// When the case's layout cannot be read or the store fails.
    pub async fn load(case: &str) -> Self {
        let layout = Layout::open(case);
        let dir = tempfile::tempdir().expect("a temporary directory");
        let store = Store::open(dir.path().join("store")).expect("a new store opens");
        let mut fixture = Self {
            store: Arc::new(store),
            root: layout.root.clone(),
            artifacts: Vec::new(),
            _dir: dir,
        };
        if layout.index().is_some() {
            fixture.keep(&layout.root, &layout.blob(&layout.root)).await;
        }
        for artifact in layout.artifacts() {
            fixture.add(&layout, artifact).await;
        }
        fixture.record().await;
        fixture
    }

    /// The root of `case` whose only artifact is the `.sig` of `other`: a legacy signature whose payload names another
    /// image (D8).
    ///
    /// # Panics
    ///
    /// When `other` has no `.sig`, or as [`Fixture::load`].
    pub async fn signature_of(other: &str, case: &str) -> Self {
        let mut fixture = Self::load(case).await;
        let layout = Layout::open(other);
        let signature = layout
            .artifacts()
            .into_iter()
            .find(|artifact| artifact.kind == Kind::Signature)
            .expect("the other case has a .sig");
        fixture.artifacts.clear();
        let artifact = Artifact {
            target: fixture.root.clone(),
            ..signature
        };
        fixture.add(&layout, artifact).await;
        fixture.record().await;
        fixture
    }

    /// `case` with one byte of its first bundle's signature flipped: that bundle, and the referrer manifest that names
    /// it, are new blobs of the same sizes.
    ///
    /// # Panics
    ///
    /// When `case` has no bundle, or as [`Fixture::load`].
    pub async fn flipped(case: &str) -> Self {
        let mut fixture = Self::load(case).await;
        let artifact = fixture
            .artifacts
            .iter()
            .position(|artifact| artifact.kind == Kind::Bundle)
            .expect("the case has a bundle");
        let layer = fixture.artifacts[artifact].blobs.len() - 1;
        let old = fixture.artifacts[artifact].blobs[layer].clone();
        let bundle = fixture.text(&old).await;
        let parsed: Value = serde_json::from_str(&bundle).expect("a bundle is JSON");
        let signature = parsed["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .expect("every recorded bundle holds a DSSE envelope");
        // The first base64 digit carries the top 6 bits of the first byte: one byte changes, and no length.
        let first = if signature.starts_with('A') { "B" } else { "A" };
        let flipped = format!("{first}{}", signature.get(1..).unwrap_or_default());
        let new = fixture
            .keep_text(&bundle.replacen(signature, &flipped, 1))
            .await;
        let manifest = fixture.artifacts[artifact].manifest.clone();
        let referrer = fixture.text(&manifest).await;
        let manifest = fixture
            .keep_text(&referrer.replacen(&old.to_string(), &new.to_string(), 1))
            .await;
        let changed = &mut fixture.artifacts[artifact];
        changed.manifest = manifest;
        changed.blobs[layer] = new;
        fixture.record().await;
        fixture
    }

    /// Keeps the manifest and blobs of `artifact` from `layout`, and adds it to the record.
    async fn add(&mut self, layout: &Layout, artifact: Artifact) {
        for blob in std::iter::once(&artifact.manifest).chain(&artifact.blobs) {
            self.keep(blob, &layout.blob(blob)).await;
        }
        self.artifacts.push(artifact);
    }

    async fn keep(&self, digest: &Digest, bytes: &[u8]) {
        self.store
            .keep(digest, bytes)
            .await
            .expect("the store keeps a blob");
    }

    /// Keeps `text` and returns its digest.
    async fn keep_text(&self, text: &str) -> Digest {
        let digest = speculaire_oci::hash::of("sha256", text.as_bytes())
            .expect("sha256 is an algorithm the agent hashes");
        self.keep(&digest, text.as_bytes()).await;
        digest
    }

    async fn text(&self, digest: &Digest) -> String {
        let bytes = self
            .store
            .read(digest)
            .await
            .expect("the store reads")
            .expect("the store holds what the fixture kept");
        String::from_utf8(bytes).expect("a manifest or bundle is UTF-8")
    }

    async fn record(&self) {
        self.store
            .record(&self.root, &self.artifacts)
            .await
            .expect("the store records the root");
    }
}

#[cfg(test)]
mod tests;
