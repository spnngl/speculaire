//! The Sigstore trust root (D26, D143): a pinned `trusted_root.json`, or the one Sigstore's TUF repository serves, with
//! its hash (D20) and its expiry.

use std::fmt;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use sigstore_trust_root::TrustedRoot;
use sigstore_trust_root::trusted_root::CertChain;
use sigstore_tuf::{FileStore, Repository, StoreRepository, TrustedMetadataSet, Updater};
use sigstore_verify::Verifier;

use crate::policy::sha256;

/// The TUF root a refresh starts from when the cache holds none: version 16 of the public-good repository, a copy of
/// sigstore-rust's `crates/sigstore-trust-root/repository/tuf_root.json` at `sigstore-verify-v0.16.0` (D143).
const TUF_ROOT: &[u8] = include_bytes!("tuf_root.json");

/// The TUF target that holds the trusted root.
const TARGET: &str = "trusted_root.json";

/// A trusted root the agent verifies against: the parsed `trusted_root.json`, its hash and its expiry.
pub struct TrustRoot {
    root: TrustedRoot,
    hash: RootHash,
    expiry: Option<Timestamp>,
    /// The root's keys and certificates, prepared once for every bundle.
    verifier: Verifier,
    /// The DER subject of each certificate of its certificate authorities: the issuers a signing certificate may name.
    issuers: Vec<Vec<u8>>,
}

impl fmt::Debug for TrustRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustRoot")
            .field("hash", &self.hash)
            .field("expiry", &self.expiry)
            .finish_non_exhaustive()
    }
}

/// The SHA-256 of a `trusted_root.json` as read, the trust-root part of a verdict's key (D20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RootHash([u8; 32]);

impl fmt::Display for RootHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Why a pinned `trusted_root.json` was refused.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file cannot be read.
    #[error("reading the trusted root {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        source: std::io::Error,
    },
    /// The file is not a trusted root.
    #[error("the trusted root {}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// Why.
        source: ParseError,
    },
}

/// Why bytes are not a trusted root.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// Not the JSON of a trusted root.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// A certificate of an authority's chain is not X.509 DER.
    #[error("certificate {certificate} of {authority} is not X.509")]
    Certificate {
        /// Which authority, such as `timestamp authority 1`, counted from 0.
        authority: String,
        /// Its place in the chain, from 0.
        certificate: usize,
    },
    /// sigstore-rust refuses the root's keys or certificates, as malformed, duplicated or unsupported.
    #[error(transparent)]
    Material(#[from] sigstore_verify::Error),
}

/// Why the agent holds no trust root: every verification ends `unverifiable` with this reason.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct Absent(String);

impl Absent {
    /// No trust root, for `reason`.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

impl TrustRoot {
    /// Reads a pinned `trusted_root.json` (D26).
    ///
    /// # Errors
    ///
    /// When the file cannot be read or is not a trusted root: a pinned root that is missing is an error, not a fallback.
    pub fn load(path: &Path) -> Result<Self, LoadError> {
        let bytes = std::fs::read(path).map_err(|source| LoadError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&bytes).map_err(|source| LoadError::Parse {
            path: path.to_owned(),
            source,
        })
    }

    /// Parses the bytes of a `trusted_root.json`.
    ///
    /// # Errors
    ///
    /// When they are not the JSON of a trusted root, or a certificate of an authority is not X.509 DER.
    pub fn parse(bytes: &[u8]) -> Result<Self, ParseError> {
        let root: TrustedRoot = serde_json::from_slice(bytes)?;
        let hash = RootHash(sha256(bytes));
        let expiry = expiry(&root)?;
        let verifier = Verifier::new(&root)?;
        let issuers = root
            .certificate_authorities
            .iter()
            .flat_map(|ca| &ca.cert_chain.certificates)
            .filter_map(|entry| {
                x509_parser::parse_x509_certificate(entry.raw_bytes.as_bytes()).ok()
            })
            .map(|(_, cert)| cert.subject().as_raw().to_vec())
            .collect();
        Ok(Self {
            root,
            hash,
            expiry,
            verifier,
            issuers,
        })
    }

    /// The trusted root that `repository` serves through TUF at `now`, its metadata kept in `cache`; when that fails,
    /// the one `cache` holds, verified again at `now` with no fetch.
    ///
    /// # Errors
    ///
    /// When both fail, naming both reasons: then no trust root is valid at `now`.
    pub async fn fetch(
        repository: impl Repository + 'static,
        cache: &Path,
        now: Timestamp,
    ) -> Result<Self, Absent> {
        let online = match Self::update(repository, cache, now).await {
            Ok(root) => return Ok(root),
            Err(reason) => reason,
        };
        let offline = StoreRepository::new(FileStore::new(cache));
        Self::update(offline, cache, now)
            .await
            .map_err(|cached| Absent(format!("TUF: {online}; the cache: {cached}")))
    }

    /// One TUF refresh at `now` from `repository`, with `cache` as its store, then the trusted root it lists.
    async fn update(
        repository: impl Repository + 'static,
        cache: &Path,
        now: Timestamp,
    ) -> Result<Self, String> {
        let mut updater = Updater::new(repository, TUF_ROOT)
            .map_err(|e| chain(&e))?
            .with_store(FileStore::new(cache));
        updater.refresh(now).await.map_err(|e| chain(&e))?;
        let bytes = updater
            .get_target(TARGET, now)
            .await
            .map_err(|e| chain(&e))?;
        let mut root = Self::parse(&bytes).map_err(|e| format!("{TARGET}: {e}"))?;
        let metadata = metadata_expiry(updater.trusted());
        root.expiry = Some(root.expiry.map_or(metadata, |keys| keys.min(metadata)));
        Ok(root)
    }

    /// The trusted root.
    #[must_use]
    pub const fn root(&self) -> &TrustedRoot {
        &self.root
    }

    /// The SHA-256 of the file as read (D20).
    #[must_use]
    pub const fn hash(&self) -> RootHash {
        self.hash
    }

    /// When the root stops verifying (D143): the latest end among its keys whose end is known, and for a root from TUF
    /// no later than the first expiry of the TUF metadata it came with. `None` for a pinned root with no such key.
    #[must_use]
    pub const fn expiry(&self) -> Option<Timestamp> {
        self.expiry
    }

    /// The verifier over the root's keys and certificates.
    pub(crate) const fn verifier(&self) -> &Verifier {
        &self.verifier
    }

    /// Whether `issuer`, the DER name a certificate gives as its issuer, is the subject of one of the root's certificate
    /// authorities (D43).
    pub(crate) fn knows_issuer(&self, issuer: &[u8]) -> bool {
        self.issuers.iter().any(|subject| subject == issuer)
    }
}

/// The latest end among the keys of `root` whose end is known: a key's `validFor.end`, and for a certificate authority
/// or a timestamp authority also the earliest `notAfter` of its chain.
fn expiry(root: &TrustedRoot) -> Result<Option<Timestamp>, ParseError> {
    let logs = root
        .tlogs
        .iter()
        .map(|log| &log.public_key)
        .chain(root.ctlogs.iter().map(|log| &log.public_key))
        .map(|key| key.valid_for.as_ref().and_then(|range| range.end));
    let authorities = root
        .certificate_authorities
        .iter()
        .enumerate()
        .map(|(n, ca)| {
            let end = ca.valid_for.as_ref().and_then(|range| range.end);
            chain_end(end, &ca.cert_chain, || format!("certificate authority {n}"))
        })
        .chain(
            root.timestamp_authorities
                .iter()
                .enumerate()
                .map(|(n, tsa)| {
                    let end = tsa.valid_for.as_ref().and_then(|range| range.end);
                    chain_end(end, &tsa.cert_chain, || format!("timestamp authority {n}"))
                }),
        );
    let ends = logs
        .map(Ok)
        .chain(authorities)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ends.into_iter().flatten().max())
}

/// `end`, brought forward to the earliest `notAfter` of `chain`.
fn chain_end(
    end: Option<Timestamp>,
    chain: &CertChain,
    authority: impl Fn() -> String,
) -> Result<Option<Timestamp>, ParseError> {
    chain
        .certificates
        .iter()
        .enumerate()
        .try_fold(end, |end, (certificate, entry)| {
            let not_after = x509_parser::parse_x509_certificate(entry.raw_bytes.as_bytes())
                .ok()
                .and_then(|(_, cert)| {
                    Timestamp::from_second(cert.validity().not_after.timestamp()).ok()
                })
                .ok_or_else(|| ParseError::Certificate {
                    authority: authority(),
                    certificate,
                })?;
            Ok(Some(end.map_or(not_after, |end| end.min(not_after))))
        })
}

/// The first expiry among the top-level TUF metadata that `trusted` holds.
fn metadata_expiry(trusted: &TrustedMetadataSet) -> Timestamp {
    [
        trusted.timestamp().map(|timestamp| timestamp.expires),
        trusted.snapshot().map(|snapshot| snapshot.expires),
        trusted
            .targets_role("targets")
            .map(|targets| targets.expires),
    ]
    .into_iter()
    .flatten()
    .fold(trusted.root().expires, Timestamp::min)
}

/// An error and its sources on one line: sigstore-tuf's `Display` leaves out the cause.
pub(crate) fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}
