//! The signature check (D8, D11, D20, D144): which authorities of a policy the Sigstore bundles that name an image
//! satisfy, and why the others fail.
//!
//! A bundle counts as a signature of the image its in-toto subject or message digest names, whatever its predicate
//! type, as for `cosign verify` (D144). It is verified against the trust root once, with any identity, and its signer
//! matched against each authority afterwards: a policy change matches identities again without verifying again.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use sigstore_verify::types::bundle::VerificationMaterialContent;
use sigstore_verify::types::{ArtifactDigest, Bundle, DerPublicKey, DigestBytes, HashAlgorithm};
use sigstore_verify::{PublicKeyVerificationPolicy, VerificationPolicy};
use speculaire_artifacts::{Artifact, Kind, Store};
use speculaire_oci::reference::Digest;

use crate::policy::{PublicKey, Signer, sha256};
use crate::trust::{Absent, RootHash, TrustRoot, chain};

/// The bundle results kept at most: past it the cache starts over, and each bundle is verified again once.
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

/// One bundle as a signature of one image, verified by the key of a key authority or else by its certificate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Entry {
    target: Digest,
    bundle: Digest,
    /// The SHA-256 of the key's DER, for a key authority.
    public_key: Option<[u8; 32]>,
}

impl Signatures {
    /// The result of each authority of `policy`, in order, over the bundles among `artifacts` whose subject is
    /// `target`, read from `store` and verified against `root`. The policy's signature check passes when one authority
    /// passes (D11).
    ///
    /// # Errors
    ///
    /// When there is no trust root, or the store cannot give a bundle it was not asked before.
    pub async fn check(
        &self,
        store: &Store,
        target: &Digest,
        artifacts: &[Artifact],
        policy: &crate::Policy,
        root: Result<&TrustRoot, &Absent>,
    ) -> Result<Vec<AuthorityResult>, Unverifiable> {
        let root = root.map_err(|absent| Unverifiable(format!("trust root: {absent}")))?;
        let bundles: Vec<&Digest> = artifacts
            .iter()
            .filter(|artifact| artifact.kind == Kind::Bundle && artifact.target == *target)
            .filter_map(|artifact| artifact.blobs.last())
            .collect();
        let mut results = Vec::with_capacity(policy.authorities().len());
        for authority in policy.authorities() {
            let mut result = Err(Failure::Missing);
            for bundle in &bundles {
                let entry = Entry {
                    target: target.clone(),
                    bundle: (*bundle).clone(),
                    public_key: match &authority.signer {
                        Signer::Key { public_key } => Some(sha256(public_key.der())),
                        Signer::Keyless { .. } => None,
                    },
                };
                let signed = self.signed(store, root, entry, &authority.signer).await?;
                match judge(signed, &authority.signer) {
                    Ok(signed) => {
                        result = Ok(signed);
                        break;
                    }
                    Err(failure) => {
                        if result
                            .as_ref()
                            .is_err_and(|closest| failure.closeness() > closest.closeness())
                        {
                            result = Err(failure);
                        }
                    }
                }
            }
            results.push(result);
        }
        Ok(results)
    }

    /// The bundles whose result was kept from an earlier check, counted once per authority checked.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Who signed the bundle of `entry`: kept, or read from `store` and verified.
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
        let bytes = store
            .read(&entry.bundle)
            .await
            .map_err(|e| Unverifiable(format!("artifact store: {e}")))?
            .ok_or_else(|| {
                Unverifiable(format!(
                    "bundle {} is not in the artifact store",
                    entry.bundle
                ))
            })?;
        let public_key = match signer {
            Signer::Key { public_key } => Some(public_key),
            Signer::Keyless { .. } => None,
        };
        let result = verify(root, &entry.target, &bytes, public_key);
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
    let target = artifact(target);
    if !matches!(
        bundle.verification_material.content,
        VerificationMaterialContent::PublicKey(_)
    ) {
        return by_certificate(root, target, &bundle);
    }
    let Some(key) = key else {
        return Err(Failure::Mismatch(Signed::Key));
    };
    let policy = PublicKeyVerificationPolicy::new(DerPublicKey::new(key.der().to_vec()));
    root.verifier()
        .verify(target, &bundle, &policy)
        .map(|_| Signed::Key)
        .map_err(|e| Failure::Invalid(chain(&e)))
}

/// Verifies `bundle` by its certificate, after checking that `root` knows its issuer.
fn by_certificate(root: &TrustRoot, target: ArtifactDigest, bundle: &Bundle) -> AuthorityResult {
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
        .verify(target, bundle, &VerificationPolicy::any_identity())
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
