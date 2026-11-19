//! The signature check (D8, D11, D20, D145): which authorities of a policy the Sigstore bundles that name an image
//! satisfy, and why the others fail.
//!
//! A bundle counts as a signature of the image its in-toto subject or message digest names, whatever its predicate
//! type, as for `cosign verify` (D145), and so does each layer of a `.sig` whose payload names it (D147). A signature
//! is verified against the trust root once, with any identity, and its signer matched against each authority
//! afterwards: a policy change matches identities again without verifying again.
//!
//! An authority that requires attestations passes on them alone (D149): each needs a bundle signing an in-toto
//! statement of its predicate type, and such a bundle is a signature of the image too.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use sigstore_verify::types::bundle::VerificationMaterialContent;
use sigstore_verify::types::{ArtifactDigest, Bundle, DerPublicKey, DigestBytes, HashAlgorithm};
use sigstore_verify::{PublicKeyVerificationPolicy, VerificationPolicy};
use speculaire_artifacts::{Artifact, Kind, Store};
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::Referrer;

use crate::legacy;
use crate::policy::{Authority, PublicKey, Signer, sha256};
use crate::statement::Statement;
use crate::trust::{Absent, RootHash, TrustRoot, chain};

/// The signature results kept at most: past it the cache starts over, and each signature is verified again once.
const LIMIT: usize = 16_384;

/// The predicate type of a cosign v3 signature (cosign v3.1.3 `pkg/types/predicate.go:19`): never an attestation.
const COSIGN_SIGNATURE: &str = "https://sigstore.dev/cosign/sign/v1";

/// The annotation of a bundle's referrer manifest naming the predicate type it signs, set by cosign and GitHub.
const PREDICATE_TYPE: &str = "dev.sigstore.bundle.predicateType";

/// One signature's result: who signed it, or why it does not count.
pub type SignatureResult = Result<Signed, Failure>;

/// One authority's result: who signed what satisfies it, or what it lacks.
pub type AuthorityResult = Result<Signed, Unmet>;

/// Who signed a bundle whose signature verifies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signed {
    /// A Fulcio certificate.
    Certificate {
        /// Its subject alternative name, such as a workflow URI or an email address.
        subject: String,
        /// The OIDC issuer it names.
        issuer: String,
    },
    /// A public key: the authority's own, when the check passes.
    Key,
}

impl fmt::Display for Signed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate { subject, issuer } => write!(f, "{subject} (issuer {issuer})"),
            Self::Key => f.write_str("a key"),
        }
    }
}

/// Why no bundle satisfies an authority: the reason of the bundle that came closest, in the order below.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    /// No bundle names the image.
    #[error("no signature")]
    Missing,
    /// The bundle does not verify against the trust root, or does not name the image.
    #[error("signature invalid: {0}")]
    Invalid(String),
    /// The bundle, or the `.sig` payload, is larger than `sbom.max_size`: its size, as its manifest lists it (D150).
    #[error("signature over sbom.max_size: {0} bytes")]
    Oversize(u64),
    /// The bundle's certificate comes from a certificate authority the trust root does not hold, such as GitHub's
    /// private Sigstore instance (D43): its issuer's name.
    #[error("certificate issuer {0} is unknown to the trust root")]
    UnknownIssuer(String),
    /// The bundle verifies, but another signer than the authority's signed it.
    #[error("identity mismatch: signed by {0}")]
    Mismatch(Signed),
}

impl Failure {
    /// How close the bundle came to satisfying the authority.
    const fn closeness(&self) -> u8 {
        match self {
            Self::Missing => 0,
            Self::Invalid(_) | Self::Oversize(_) => 1,
            Self::UnknownIssuer(_) => 2,
            Self::Mismatch(_) => 3,
        }
    }
}

/// What an authority lacks: a signature, or one of the attestations it requires (D11, D149).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Unmet {
    /// Its signature, when it requires no attestation.
    Signature(Failure),
    /// The first of its attestations that fails, and why.
    Attestation {
        /// The attestation's predicate type, as the policy names it.
        predicate_type: String,
        /// The reason of the bundle attesting it that came closest; [`Failure::Missing`] when none does.
        failure: Failure,
    },
}

impl fmt::Display for Unmet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature(failure) => write!(f, "{failure}"),
            // The reason D43 names: a `.att` tag is never read, so it is missing too.
            Self::Attestation {
                predicate_type,
                failure: Failure::Missing,
            } => write!(
                f,
                "attestation {predicate_type} missing (.att tags are not supported)"
            ),
            Self::Attestation {
                predicate_type,
                failure,
            } => write!(f, "attestation {predicate_type}: {failure}"),
        }
    }
}

impl std::error::Error for Unmet {}

/// A bundle that attests the image by an authority's signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attested {
    /// Who signed it.
    pub signed: Signed,
    /// The bundle, in the artifact store: [`Statement::of`] reads its statement.
    pub bundle: Digest,
}

/// Why no check ran: no trust root, or a bundle the artifact store cannot give. Retried, never final (D20).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unverifiable(String);

/// The signature check, with each bundle's result kept per trust root (D20).
#[derive(Debug)]
pub struct Signatures {
    cache: Mutex<Cache>,
    hits: AtomicU64,
    /// `sbom.max_size`: discovery leaves out a blob larger, its manifest still listing it (D150).
    max_size: u64,
}

/// The results of one trust root.
#[derive(Debug, Default)]
struct Cache {
    root: Option<RootHash>,
    results: HashMap<Entry, Kept>,
}

/// A signature's result, and the predicate type of the attestation it signs.
#[derive(Clone, Debug)]
struct Kept {
    signed: SignatureResult,
    /// Read whether or not the signature verifies, so that a bundle that fails names the attestation it fails.
    attests: Option<String>,
}

/// One signature of one image, verified by the key of a key authority or else by its certificate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Entry {
    target: Digest,
    source: Source,
    /// The SHA-256 of the key's DER, for a key authority.
    public_key: Option<[u8; 32]>,
}

/// Where a signature is, in the artifact store.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Source {
    /// The Sigstore bundle of the referrer manifest `manifest`.
    Bundle { manifest: Digest, bundle: Digest },
    /// Layer `index` of a `.sig` manifest, whose blob is `payload`.
    Layer {
        manifest: Digest,
        index: usize,
        payload: Digest,
    },
}

impl Signatures {
    /// A check that reads no blob larger than `max_size`, `sbom.max_size` (D12).
    #[must_use]
    pub fn new(max_size: u64) -> Self {
        Self {
            cache: Mutex::default(),
            hits: AtomicU64::default(),
            max_size,
        }
    }

    /// The largest blob it reads, `sbom.max_size`.
    pub(crate) const fn max_size(&self) -> u64 {
        self.max_size
    }

    /// The result of each authority of `policy`, in order, over the bundles and `.sig` layers among `artifacts` whose
    /// target is `target`, read from `store` and verified against `root`. The policy's check passes when one authority
    /// passes (D11).
    ///
    /// # Errors
    ///
    /// When there is no trust root, or the store cannot give a signature it was not asked before.
    pub async fn check(
        &self,
        store: &Store,
        target: &Digest,
        artifacts: &[Artifact],
        policy: &crate::Policy,
        root: Result<&TrustRoot, &Absent>,
    ) -> Result<Vec<AuthorityResult>, Unverifiable> {
        let root = root.map_err(|absent| Unverifiable(format!("trust root: {absent}")))?;
        let sources = sources(target, artifacts);
        let mut results = Vec::with_capacity(policy.authorities().len());
        for authority in policy.authorities() {
            results.push(
                self.authority(store, root, target, &sources, authority)
                    .await?,
            );
        }
        Ok(results)
    }

    /// The result of `authority`: on its attestations when it requires some, else on its signature.
    async fn authority(
        &self,
        store: &Store,
        root: &TrustRoot,
        target: &Digest,
        sources: &[Source],
        authority: &Authority,
    ) -> Result<AuthorityResult, Unverifiable> {
        let mut signed = None;
        // All of them, the first that fails naming the authority's reason (D11).
        for attestation in &authority.attestations {
            let predicate_type = &attestation.predicate_type;
            match self
                .attests(
                    store,
                    root,
                    target,
                    sources,
                    &authority.signer,
                    predicate_type,
                )
                .await?
            {
                Ok(attested) => signed = signed.or(Some(attested.signed)),
                Err(failure) => {
                    return Ok(Err(Unmet::Attestation {
                        predicate_type: predicate_type.clone(),
                        failure,
                    }));
                }
            }
        }
        Ok(match signed {
            Some(signed) => Ok(signed),
            None => self
                .signature(store, root, target, sources, &authority.signer)
                .await?
                .map_err(Unmet::Signature),
        })
    }

    /// The first bundle among `artifacts` whose target is `target` that attests `predicate_type` by `signer`, verified
    /// against `root`: how step 07 finds an SBOM (D12). A cosign signature attests nothing (D149).
    ///
    /// # Errors
    ///
    /// When the store cannot give a bundle it was not asked before. The inner error is the reason of the bundle
    /// attesting `predicate_type` that came closest, [`Failure::Missing`] when none does.
    pub async fn attested(
        &self,
        store: &Store,
        target: &Digest,
        artifacts: &[Artifact],
        signer: &Signer,
        root: &TrustRoot,
        predicate_type: &str,
    ) -> Result<Result<Attested, Failure>, Unverifiable> {
        let sources = sources(target, artifacts);
        self.attests(store, root, target, &sources, signer, predicate_type)
            .await
    }

    /// The first of `sources` whose signature satisfies `signer`, else the reason of the one that came closest.
    pub(crate) async fn signature(
        &self,
        store: &Store,
        root: &TrustRoot,
        target: &Digest,
        sources: &[Source],
        signer: &Signer,
    ) -> Result<SignatureResult, Unverifiable> {
        let mut closest = Failure::Missing;
        for source in sources {
            let kept = self
                .signed(store, root, entry(target, source.clone(), signer), signer)
                .await?;
            match judge(kept.signed, signer) {
                Ok(by) => return Ok(Ok(by)),
                Err(failure) => closest = closer(closest, failure),
            }
        }
        Ok(Err(closest))
    }

    /// The first bundle of `sources` that attests `predicate_type` by `signer`, else the reason of the bundle attesting
    /// it that came closest.
    async fn attests(
        &self,
        store: &Store,
        root: &TrustRoot,
        target: &Digest,
        sources: &[Source],
        signer: &Signer,
        predicate_type: &str,
    ) -> Result<Result<Attested, Failure>, Unverifiable> {
        let mut closest = Failure::Missing;
        // A `.sig` layer signs a simple signing payload, never a statement.
        for (source, bundle) in sources.iter().filter_map(|source| match source {
            Source::Bundle { bundle, .. } => Some((source, bundle)),
            Source::Layer { .. } => None,
        }) {
            let kept = self
                .signed(store, root, entry(target, source.clone(), signer), signer)
                .await?;
            if kept.attests.as_deref() != Some(predicate_type) {
                continue;
            }
            match judge(kept.signed, signer) {
                Ok(by) => {
                    return Ok(Ok(Attested {
                        signed: by,
                        bundle: bundle.clone(),
                    }));
                }
                Err(failure) => closest = closer(closest, failure),
            }
        }
        Ok(Err(closest))
    }

    /// The signatures whose result was kept from an earlier check, counted once per authority checked.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Who signed the signature of `entry`, and what it attests: kept, or read from `store` and verified.
    async fn signed(
        &self,
        store: &Store,
        root: &TrustRoot,
        entry: Entry,
        signer: &Signer,
    ) -> Result<Kept, Unverifiable> {
        if let Some(kept) = self.kept(root.hash(), &entry) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(kept);
        }
        let public_key = match signer {
            Signer::Key { public_key } => Some(public_key),
            Signer::Keyless { .. } => None,
        };
        let kept = match &entry.source {
            Source::Bundle { manifest, bundle } => {
                match blob(store, manifest, bundle, self.max_size).await? {
                    Blob::Kept(bytes) => match parse(&bytes) {
                        Ok(bundle) => Kept {
                            signed: verified(root, artifact(&entry.target), &bundle, public_key),
                            attests: attests(&bundle),
                        },
                        Err(failure) => Kept {
                            signed: Err(failure),
                            attests: None,
                        },
                    },
                    // Read only to pick the reason, as the predicate type of a bundle that fails (D149).
                    Blob::Oversize {
                        size,
                        predicate_type,
                    } => Kept {
                        signed: Err(Failure::Oversize(size)),
                        attests: predicate_type
                            .filter(|predicate_type| predicate_type != COSIGN_SIGNATURE),
                    },
                }
            }
            Source::Layer {
                manifest,
                index,
                payload,
            } => Kept {
                signed: match blob(store, manifest, payload, self.max_size).await? {
                    Blob::Kept(payload) => legacy::verify(
                        root,
                        &entry.target,
                        &read(store, manifest).await?,
                        *index,
                        &payload,
                        public_key,
                    ),
                    Blob::Oversize { size, .. } => Err(Failure::Oversize(size)),
                },
                attests: None,
            },
        };
        self.keep(root.hash(), entry, kept.clone());
        Ok(kept)
    }

    fn kept(&self, root: RootHash, entry: &Entry) -> Option<Kept> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.root == Some(root) {
            cache.results.get(entry).cloned()
        } else {
            None
        }
    }

    fn keep(&self, root: RootHash, entry: Entry, kept: Kept) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.root != Some(root) || cache.results.len() >= LIMIT {
            cache.root = Some(root);
            cache.results.clear();
        }
        cache.results.insert(entry, kept);
    }
}

/// The signature at `source` of `target`, verified by the key of a key `signer` or else by its certificate.
fn entry(target: &Digest, source: Source, signer: &Signer) -> Entry {
    Entry {
        target: target.clone(),
        source,
        public_key: match signer {
            Signer::Key { public_key } => Some(sha256(public_key.der())),
            Signer::Keyless { .. } => None,
        },
    }
}

/// The closer of two bundles' reasons.
pub(crate) fn closer(closest: Failure, failure: Failure) -> Failure {
    std::cmp::max_by_key(closest, failure, Failure::closeness)
}

/// The predicate type of the in-toto statement `bundle` signs, unless it signs none or is a cosign signature (D149).
fn attests(bundle: &Bundle) -> Option<String> {
    let statement = Statement::of(bundle).ok()?;
    (statement.predicate_type() != COSIGN_SIGNATURE).then(|| statement.predicate_type().to_owned())
}

/// Verifies `bundle`, the JSON of a Sigstore bundle, as a signature of `target` against `root`, with a transparency log
/// entry required (D142): by the certificate it holds, whatever its identity, or by `key` when it holds a public key.
///
/// # Errors
///
/// [`Failure::Invalid`] when it does not parse or verify, [`Failure::UnknownIssuer`] when its certificate's issuer is
/// no certificate authority of `root`, and [`Failure::Mismatch`] when it holds a key and `key` is `None`.
pub fn verify(
    root: &TrustRoot,
    target: &Digest,
    bundle: &[u8],
    key: Option<&PublicKey>,
) -> SignatureResult {
    verified(root, artifact(target), &parse(bundle)?, key)
}

/// Parses `bundle`, the JSON of a Sigstore bundle.
fn parse(bundle: &[u8]) -> Result<Bundle, Failure> {
    std::str::from_utf8(bundle)
        .map_err(|e| e.to_string())
        .and_then(|text| Bundle::from_json(text).map_err(|e| chain(&e)))
        .map_err(|e| Failure::Invalid(format!("not a Sigstore bundle: {e}")))
}

/// Verifies `bundle` as a signature of `signed`, the artifact or its digest, as [`verify`] does.
pub(crate) fn verified<'a>(
    root: &TrustRoot,
    signed: impl Into<sigstore_verify::types::Artifact<'a>>,
    bundle: &Bundle,
    key: Option<&PublicKey>,
) -> SignatureResult {
    if !matches!(
        bundle.verification_material.content,
        VerificationMaterialContent::PublicKey(_)
    ) {
        return by_certificate(root, signed, bundle);
    }
    let Some(key) = key else {
        return Err(Failure::Mismatch(Signed::Key));
    };
    let policy = PublicKeyVerificationPolicy::new(DerPublicKey::new(key.der().to_vec()));
    root.verifier()
        .verify(signed, bundle, &policy)
        .map(|_| Signed::Key)
        .map_err(|e| Failure::Invalid(chain(&e)))
}

/// Verifies `bundle` by its certificate, after checking that `root` knows its issuer.
fn by_certificate<'a>(
    root: &TrustRoot,
    signed: impl Into<sigstore_verify::types::Artifact<'a>>,
    bundle: &Bundle,
) -> SignatureResult {
    let certificate = bundle
        .signing_certificate()
        .ok_or_else(|| Failure::Invalid("the bundle holds no certificate".to_owned()))?;
    let (_, certificate) = x509_parser::parse_x509_certificate(certificate.as_bytes())
        .map_err(|e| Failure::Invalid(format!("its certificate: {e}")))?;
    if !root.knows_issuer(certificate.issuer().as_raw()) {
        return Err(Failure::UnknownIssuer(certificate.issuer().to_string()));
    }
    let verified = root
        .verifier()
        .verify(signed, bundle, &VerificationPolicy::any_identity())
        .map_err(|e| Failure::Invalid(chain(&e)))?;
    match (verified.identity(), verified.issuer()) {
        (Some(subject), Some(issuer)) => Ok(Signed::Certificate {
            subject: subject.as_str().to_owned(),
            issuer: issuer.to_owned(),
        }),
        _ => Err(Failure::Invalid(
            "its certificate names no identity or no OIDC issuer".to_owned(),
        )),
    }
}

/// The signatures among `artifacts` whose target is `target`: each bundle, and each layer of each `.sig`.
pub(crate) fn sources(target: &Digest, artifacts: &[Artifact]) -> Vec<Source> {
    let mut sources = Vec::new();
    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.target == *target)
    {
        match artifact.kind {
            Kind::Bundle => sources.extend(artifact.blobs.last().map(|bundle| Source::Bundle {
                manifest: artifact.manifest.clone(),
                bundle: bundle.clone(),
            })),
            // Its blobs are its config, then its layers.
            Kind::Signature => sources.extend(artifact.blobs.iter().skip(1).enumerate().map(
                |(index, payload)| Source::Layer {
                    manifest: artifact.manifest.clone(),
                    index,
                    payload: payload.clone(),
                },
            )),
            Kind::Attestation => {}
        }
    }
    sources
}

/// The blob `digest` of `store`.
pub(crate) async fn read(store: &Store, digest: &Digest) -> Result<Vec<u8>, Unverifiable> {
    store
        .read(digest)
        .await
        .map_err(|e| Unverifiable(format!("artifact store: {e}")))?
        .ok_or_else(|| absent(digest))
}

fn absent(digest: &Digest) -> Unverifiable {
    Unverifiable(format!("{digest} is not in the artifact store"))
}

/// A blob of an artifact, as the artifact store gives it.
pub(crate) enum Blob {
    /// Its bytes.
    Kept(Vec<u8>),
    /// Left out by discovery: its size, as its manifest lists it above `sbom.max_size` (D150), and the predicate type
    /// that manifest's annotation names, unverified.
    Oversize {
        size: u64,
        predicate_type: Option<String>,
    },
}

/// The blob `digest` that the manifest `manifest` lists, read from `store`.
///
/// # Errors
///
/// When the store cannot give it, and its manifest does not list it above `max_size`.
pub(crate) async fn blob(
    store: &Store,
    manifest: &Digest,
    digest: &Digest,
    max_size: u64,
) -> Result<Blob, Unverifiable> {
    if let Some(bytes) = store
        .read(digest)
        .await
        .map_err(|e| Unverifiable(format!("artifact store: {e}")))?
    {
        return Ok(Blob::Kept(bytes));
    }
    let manifest = Referrer::parse(&read(store, manifest).await?).map_err(|_| absent(digest))?;
    let size = manifest
        .blobs()
        .find(|blob| blob.digest == *digest)
        .map(|listed| listed.size);
    match size {
        Some(size) if size > max_size => Ok(Blob::Oversize {
            size,
            predicate_type: manifest.annotations.get(PREDICATE_TYPE).cloned(),
        }),
        _ => Err(absent(digest)),
    }
}

/// Whether `verified` satisfies `signer`: a certificate whose issuer and subject match one identity, or the key it was
/// verified with.
fn judge(verified: SignatureResult, signer: &Signer) -> SignatureResult {
    match (verified?, signer) {
        (Signed::Certificate { subject, issuer }, Signer::Keyless { identities })
            if identities.iter().any(|identity| {
                identity.issuer.matches(&issuer) && identity.subject.matches(&subject)
            }) =>
        {
            Ok(Signed::Certificate { subject, issuer })
        }
        (Signed::Key, Signer::Key { .. }) => Ok(Signed::Key),
        (other, _) => Err(Failure::Mismatch(other)),
    }
}

/// `target` as the artifact a bundle names.
fn artifact(target: &Digest) -> ArtifactDigest {
    let hex = target.encoded();
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|at| {
            u8::from_str_radix(&hex[at..at + 2], 16)
                .expect("a digest is lower-case hex, two digits a byte")
        })
        .collect::<Vec<u8>>();
    let algorithm = match target.algorithm() {
        "sha256" => HashAlgorithm::Sha2256,
        "sha384" => HashAlgorithm::Sha2384,
        _ => HashAlgorithm::Sha2512,
    };
    ArtifactDigest::new(algorithm, DigestBytes::new(bytes))
        .expect("a digest holds a hash of its algorithm's size")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_target_keeps_its_algorithm_and_hash() {
        for (algorithm, expected, size) in [
            ("sha256", HashAlgorithm::Sha2256, 32),
            ("sha384", HashAlgorithm::Sha2384, 48),
            ("sha512", HashAlgorithm::Sha2512, 64),
        ] {
            let bytes: Vec<u8> = (0..size).map(|at| at + 0xa0).collect();
            let hex = bytes
                .iter()
                .fold(String::new(), |hex, byte| hex + &format!("{byte:02x}"));
            let target = Digest::parse(&format!("{algorithm}:{hex}")).expect("a digest");

            let artifact = artifact(&target);

            assert_eq!(artifact.algorithm(), expected);
            assert_eq!(artifact.as_bytes(), bytes);
        }
    }
}
