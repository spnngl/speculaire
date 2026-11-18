//! The signature check (D8, D11, D20, D145): which authorities of a policy the Sigstore bundles that name an image
//! satisfy, and why the others fail.
//!
//! A bundle counts as a signature of the image its in-toto subject or message digest names, whatever its predicate
//! type, as for `cosign verify` (D145), and so does each layer of a `.sig` whose payload names it (D147). A signature
//! is verified against the trust root once, with any identity, and its signer matched against each authority
//! afterwards: a policy change matches identities again without verifying again.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use sigstore_verify::types::bundle::VerificationMaterialContent;
use sigstore_verify::types::{ArtifactDigest, Bundle, DerPublicKey, DigestBytes, HashAlgorithm};
use sigstore_verify::{PublicKeyVerificationPolicy, VerificationPolicy};
use speculaire_artifacts::{Artifact, Kind, Store};
use speculaire_oci::reference::Digest;

use crate::legacy;
use crate::policy::{PublicKey, Signer, sha256};
use crate::trust::{Absent, RootHash, TrustRoot, chain};

/// The signature results kept at most: past it the cache starts over, and each signature is verified again once.
const LIMIT: usize = 16_384;

/// One authority's signature check: who signed the bundle that satisfies it, or why none does.
pub type AuthorityResult = Result<Signed, Failure>;

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
            Self::Invalid(_) => 1,
            Self::UnknownIssuer(_) => 2,
            Self::Mismatch(_) => 3,
        }
    }
}

/// Why no check ran: no trust root, or a bundle the artifact store cannot give. Retried, never final (D20).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Unverifiable(String);

/// The signature check, with each bundle's result kept per trust root (D20).
#[derive(Debug, Default)]
pub struct Signatures {
    cache: Mutex<Cache>,
    hits: AtomicU64,
}

/// The results of one trust root.
#[derive(Debug, Default)]
struct Cache {
    root: Option<RootHash>,
    results: HashMap<Entry, AuthorityResult>,
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
enum Source {
    /// A Sigstore bundle.
    Bundle(Digest),
    /// Layer `index` of a `.sig` manifest, whose blob is `payload`.
    Layer {
        manifest: Digest,
        index: usize,
        payload: Digest,
    },
}

impl Signatures {
    /// The result of each authority of `policy`, in order, over the bundles and `.sig` layers among `artifacts` whose
    /// target is `target`, read from `store` and verified against `root`. The policy's signature check passes when one
    /// authority passes (D11).
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
            let mut satisfied = None;
            let mut closest = Failure::Missing;
            for source in &sources {
                let entry = Entry {
                    target: target.clone(),
                    source: source.clone(),
                    public_key: match &authority.signer {
                        Signer::Key { public_key } => Some(sha256(public_key.der())),
                        Signer::Keyless { .. } => None,
                    },
                };
                let signed = self.signed(store, root, entry, &authority.signer).await?;
                match judge(signed, &authority.signer) {
                    Ok(signed) => {
                        satisfied = Some(signed);
                        break;
                    }
                    Err(failure) => {
                        closest = std::cmp::max_by_key(closest, failure, Failure::closeness);
                    }
                }
            }
            results.push(satisfied.ok_or(closest));
        }
        Ok(results)
    }

    /// The signatures whose result was kept from an earlier check, counted once per authority checked.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Who signed the signature of `entry`: kept, or read from `store` and verified.
    async fn signed(
        &self,
        store: &Store,
        root: &TrustRoot,
        entry: Entry,
        signer: &Signer,
    ) -> Result<AuthorityResult, Unverifiable> {
        if let Some(kept) = self.kept(root.hash(), &entry) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(kept);
        }
        let public_key = match signer {
            Signer::Key { public_key } => Some(public_key),
            Signer::Keyless { .. } => None,
        };
        let result = match &entry.source {
            Source::Bundle(bundle) => {
                verify(root, &entry.target, &read(store, bundle).await?, public_key)
            }
            Source::Layer {
                manifest,
                index,
                payload,
            } => legacy::verify(
                root,
                &entry.target,
                &read(store, manifest).await?,
                *index,
                &read(store, payload).await?,
                public_key,
            ),
        };
        self.keep(root.hash(), entry, result.clone());
        Ok(result)
    }

    fn kept(&self, root: RootHash, entry: &Entry) -> Option<AuthorityResult> {
        let cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.root == Some(root) {
            cache.results.get(entry).cloned()
        } else {
            None
        }
    }

    fn keep(&self, root: RootHash, entry: Entry, result: AuthorityResult) {
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.root != Some(root) || cache.results.len() >= LIMIT {
            cache.root = Some(root);
            cache.results.clear();
        }
        cache.results.insert(entry, result);
    }
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
) -> AuthorityResult {
    let bundle = std::str::from_utf8(bundle)
        .map_err(|e| e.to_string())
        .and_then(|text| Bundle::from_json(text).map_err(|e| chain(&e)))
        .map_err(|e| Failure::Invalid(format!("not a Sigstore bundle: {e}")))?;
    verified(root, artifact(target), &bundle, key)
}

/// Verifies `bundle` as a signature of `signed`, the artifact or its digest, as [`verify`] does.
pub(crate) fn verified<'a>(
    root: &TrustRoot,
    signed: impl Into<sigstore_verify::types::Artifact<'a>>,
    bundle: &Bundle,
    key: Option<&PublicKey>,
) -> AuthorityResult {
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
) -> AuthorityResult {
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
fn sources(target: &Digest, artifacts: &[Artifact]) -> Vec<Source> {
    let mut sources = Vec::new();
    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.target == *target)
    {
        match artifact.kind {
            Kind::Bundle => sources.extend(artifact.blobs.last().cloned().map(Source::Bundle)),
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
async fn read(store: &Store, digest: &Digest) -> Result<Vec<u8>, Unverifiable> {
    store
        .read(digest)
        .await
        .map_err(|e| Unverifiable(format!("artifact store: {e}")))?
        .ok_or_else(|| Unverifiable(format!("{digest} is not in the artifact store")))
}

/// Whether `verified` satisfies `signer`: a certificate whose issuer and subject match one identity, or the key it was
/// verified with.
fn judge(verified: AuthorityResult, signer: &Signer) -> AuthorityResult {
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
