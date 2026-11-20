//! The recorded Sigstore fixtures (D139, D141), loaded into an artifact store as discovery records them, for the tests
//! of any crate.
//!
//! Each case of `expected.json`, read by [`Expected`], is an OCI layout, read by [`Layout`]. [`Fixture::load`] keeps a
//! case's artifacts in a store of its own; [`Fixture::signature_of`] and [`Fixture::flipped`] build the negative cases
//! no recording holds.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
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
/// As [`Expected::all`].
#[must_use]
pub fn cases() -> Vec<String> {
    Expected::all().into_iter().map(|case| case.case).collect()
}

/// A case as the recording workflow's oracle left it in `expected.json`: who signed it, and what cosign and gh found.
#[derive(Debug, Deserialize)]
pub struct Expected {
    /// The case's name, which tags its image.
    pub case: String,
    /// Who signed the image, or `None` when no one did.
    pub signer: Option<Signer>,
    /// Each check the oracle ran, in its order.
    pub checks: Vec<Checked>,
}

impl Expected {
    /// Every case, in the order `expected.json` lists them.
    ///
    /// # Panics
    ///
    /// When `expected.json` cannot be read or parsed.
    #[must_use]
    pub fn all() -> Vec<Self> {
        serde_json::from_slice(&read(&Path::new(FIXTURES).join("expected.json")))
            .expect("expected.json lists the cases as the oracle writes them")
    }

    /// The case named `case`.
    ///
    /// # Panics
    ///
    /// When `expected.json` does not list it, or as [`Expected::all`].
    #[must_use]
    pub fn of(case: &str) -> Self {
        Self::all()
            .into_iter()
            .find(|expected| expected.case == case)
            .expect("expected.json lists the case")
    }
}

/// Who signed a case.
#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Signer {
    /// A certificate from Fulcio for the workflow `san`, whose OIDC token `issuer` issued.
    Keyless {
        /// The certificate's subject alternative name: the signing workflow's URL at its ref.
        san: String,
        /// The OIDC issuer: GitHub Actions'.
        issuer: String,
    },
    /// The key pair whose public key is the file `key`, beside `expected.json`.
    Key {
        /// The file's name.
        key: String,
    },
}

/// A check the oracle ran, and whether it passed.
#[derive(Debug, Deserialize)]
pub struct Checked {
    /// What it ran.
    pub check: Check,
    /// Whether cosign or gh accepted the image.
    pub ok: bool,
}

/// A check of the oracle: a cosign or gh command, against the case's signer.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum Check {
    /// `signature`: `cosign verify`.
    Signature,
    /// `signature-legacy`: `cosign verify --new-bundle-format=false`, which reads `.sig` tags.
    SignatureLegacy,
    /// `attestation:<type>`: `cosign verify-attestation --type <type>`, `<type>` in cosign's names such as `spdxjson`.
    Attestation(String),
    /// `attestation-legacy:<type>`: as [`Check::Attestation`], from `.att` tags.
    AttestationLegacy(String),
    /// `github:<predicate type>`: `gh attestation verify --predicate-type <predicate type>`.
    Github(String),
}

impl TryFrom<String> for Check {
    type Error = String;

    fn try_from(check: String) -> Result<Self, String> {
        match check.split_once(':') {
            None if check == "signature" => Ok(Self::Signature),
            None if check == "signature-legacy" => Ok(Self::SignatureLegacy),
            Some(("attestation", kind)) => Ok(Self::Attestation(kind.to_owned())),
            Some(("attestation-legacy", kind)) => Ok(Self::AttestationLegacy(kind.to_owned())),
            Some(("github", predicate_type)) => Ok(Self::Github(predicate_type.to_owned())),
            _ => Err(format!("no check {check:?}")),
        }
    }
}

/// When the recorded TUF repository's timestamp metadata expires, in RFC 3339: the first of its roles to.
///
/// # Panics
///
/// When `tuf/timestamp.json` cannot be read or names no expiry.
#[must_use]
pub fn tuf_expiry() -> String {
    let path = Path::new(FIXTURES).join("tuf").join("timestamp.json");
    let timestamp: Value = serde_json::from_slice(&read(&path)).expect("TUF metadata is JSON");
    timestamp["signed"]["expires"]
        .as_str()
        .expect("TUF metadata names its expiry")
        .to_owned()
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

    /// What discovery records of the root on the fixtures' [`platform`].
    ///
    /// # Panics
    ///
    /// As [`Layout::artifacts_on`].
    #[must_use]
    pub fn artifacts(&self) -> Vec<Artifact> {
        self.artifacts_on(&platform())
    }

    /// Whether a node on `host` can pull the root: an image, or an image index holding a manifest for `host`.
    #[must_use]
    pub fn runs_on(&self, host: &Host) -> bool {
        self.index()
            .is_none_or(|index| index.platform_manifest(host).is_some())
    }

    /// What discovery records of the root on `host`, in its order: the attestation manifests of an image index's
    /// platform manifest, then for each target its Sigstore bundle referrers and its `.sig` (D121).
    ///
    /// # Panics
    ///
    /// When a manifest the layout tags cannot be parsed.
    #[must_use]
    pub fn artifacts_on(&self, host: &Host) -> Vec<Artifact> {
        let mut targets = vec![self.root.clone()];
        let mut artifacts = Vec::new();
        if let Some(index) = self.index()
            && let Some(platform) = index.platform_manifest(host)
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
        Self::capped(case, u64::MAX).await
    }

    /// As [`Fixture::load`], as discovery records it on `host`.
    ///
    /// # Panics
    ///
    /// As [`Fixture::load`].
    pub async fn on(case: &str, host: &Host) -> Self {
        Self::kept(case, host, u64::MAX).await
    }

    /// As [`Fixture::load`], with `sbom.max_size` at `max_size`: as discovery does, a blob larger stays named by its
    /// artifact and out of the store (D150).
    ///
    /// # Panics
    ///
    /// As [`Fixture::load`].
    pub async fn capped(case: &str, max_size: u64) -> Self {
        Self::kept(case, &platform(), max_size).await
    }

    /// The artifacts of `case` that discovery records on `host`, kept with each blob up to `max_size` bytes.
    async fn kept(case: &str, host: &Host, max_size: u64) -> Self {
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
        for artifact in layout.artifacts_on(host) {
            fixture.add(&layout, artifact, max_size).await;
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
        fixture.add(&layout, artifact, u64::MAX).await;
        fixture.record().await;
        fixture
    }

    /// `case` with the SET annotation, `dev.sigstore.cosign/bundle`, removed from each layer of its `.sig`: a legacy
    /// signature cosign never logged, as `--tlog-upload=false` makes.
    ///
    /// # Panics
    ///
    /// When `case` has no `.sig`, or as [`Fixture::load`].
    pub async fn unlogged(case: &str) -> Self {
        let mut fixture = Self::load(case).await;
        let artifact = fixture
            .artifacts
            .iter()
            .position(|artifact| artifact.kind == Kind::Signature)
            .expect("the case has a .sig");
        let text = fixture.text(&fixture.artifacts[artifact].manifest).await;
        let mut manifest: Value = serde_json::from_str(&text).expect("a manifest is JSON");
        for layer in manifest["layers"]
            .as_array_mut()
            .expect("a .sig manifest names its layers")
        {
            layer["annotations"]
                .as_object_mut()
                .expect("a .sig layer has annotations")
                .remove("dev.sigstore.cosign/bundle");
        }
        fixture.artifacts[artifact].manifest = fixture.keep_text(&manifest.to_string()).await;
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
        let layer = fixture.artifacts[artifact].blobs.last().cloned();
        let bundle = fixture
            .text(&layer.expect("a referrer manifest names its bundle"))
            .await;
        let parsed: Value = serde_json::from_str(&bundle).expect("a bundle is JSON");
        let signature = parsed["dsseEnvelope"]["signatures"][0]["sig"]
            .as_str()
            .expect("every recorded bundle holds a DSSE envelope");
        // The first base64 digit carries the top 6 bits of the first byte: one byte changes, and no length.
        let first = if signature.starts_with('A') { "B" } else { "A" };
        let flipped = format!("{first}{}", signature.get(1..).unwrap_or_default());
        fixture
            .replace(artifact, &bundle.replacen(signature, &flipped, 1))
            .await;
        fixture.record().await;
        fixture
    }

    /// The root of `case` whose only artifact is a bundle of `bundle`, such as [`GITHUB_PRIVATE`], in place of the
    /// case's first.
    ///
    /// # Panics
    ///
    /// When `case` has no bundle, or as [`Fixture::load`].
    pub async fn bundled(case: &str, bundle: &str) -> Self {
        let mut fixture = Self::load(case).await;
        let artifact = fixture
            .artifacts
            .iter()
            .position(|artifact| artifact.kind == Kind::Bundle)
            .expect("the case has a bundle");
        fixture.artifacts.swap(0, artifact);
        fixture.artifacts.truncate(1);
        fixture.replace(0, bundle).await;
        fixture.record().await;
        fixture
    }

    /// Keeps `bundle` in place of the bundle of the artifact at `artifact`, and a referrer manifest that names it.
    async fn replace(&mut self, artifact: usize, bundle: &str) {
        let layer = self.artifacts[artifact].blobs.len() - 1;
        let old = self.artifacts[artifact].blobs[layer].clone();
        let new = self.keep_text(bundle).await;
        let referrer = self.text(&self.artifacts[artifact].manifest).await;
        let manifest = self
            .keep_text(&referrer.replacen(&old.to_string(), &new.to_string(), 1))
            .await;
        let changed = &mut self.artifacts[artifact];
        changed.manifest = manifest;
        changed.blobs[layer] = new;
    }

    /// Keeps the manifest of `artifact` from `layout`, and each of its blobs up to `max_size` bytes, and adds it to the
    /// record.
    async fn add(&mut self, layout: &Layout, artifact: Artifact, max_size: u64) {
        self.keep(&artifact.manifest, &layout.blob(&artifact.manifest))
            .await;
        for blob in &artifact.blobs {
            let bytes = layout.blob(blob);
            if u64::try_from(bytes.len()).is_ok_and(|len| len <= max_size) {
                self.keep(blob, &bytes).await;
            }
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
