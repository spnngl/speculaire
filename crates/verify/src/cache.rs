//! `cache.bin` (D31, D165): the verdicts and the signature results, saved across an agent restart.
//!
//! The file is a header, the verdicts, the signature results, then the SHA-256 of all before it. Integers are
//! little-endian and fixed-size parts are read in place (D107); a string is its length as a `u32` then its UTF-8, and a
//! digest is its length as a byte then its text. Both caches are saved sorted, so the same caches save the same bytes.

use std::collections::HashMap;
use std::io::{self, Write as _};
use std::path::Path;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use aws_lc_rs::digest::{SHA256, digest};
use speculaire_oci::reference::Digest;
use tokio::time::Instant;
use zerocopy::little_endian::{U32, U64};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::engine::{Kept, Verdict, Verdicts};
use crate::policy::MatchHash;
use crate::signature::{self, Cache, Entry, Failure, Signatures, Signed, Source};
use crate::trust::RootHash;

/// The format's version. A file of another is refused whole.
const VERSION: u32 = 1;

/// The size of the trailing SHA-256.
const CHECKSUM: usize = 32;

/// The size of the smallest file: a header and a checksum.
const SMALLEST: usize = size_of::<Header>() + CHECKSUM;

/// What the file starts with.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Header {
    version: U32,
    /// The file's size, checksum included: a file cut short says so rather than failing its checksum.
    size: U64,
    /// The hash of all the policies held at save.
    policies: [u8; 32],
    /// The trust root of the signature results.
    root: Hash,
    verdicts: U32,
    signatures: U32,
}

/// A hash, or none: `present` is 0 and the hash zeros.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Hash {
    present: u8,
    hash: [u8; 32],
}

/// A verdict's fixed-size part, after its image's digest and before a rejection's reason.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
#[repr(C)]
struct Head {
    policies: [u8; 32],
    root: Hash,
    /// [`ALLOW`] or [`REJECTED`].
    state: u8,
    /// 1 when stale, `age` then how long since, in nanoseconds; 0 and 0 otherwise.
    stale: u8,
    age: U64,
}

/// [`Head::state`] of an allow.
const ALLOW: u8 = 0;
/// [`Head::state`] of a rejection.
const REJECTED: u8 = 1;

/// Why a file was refused. Nothing is loaded from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Refused {
    /// It is of another format version, such as a later agent's.
    #[error("format version {0}, where this agent reads {VERSION}")]
    Version(u32),
    /// It is not the size its header says, such as a file cut short.
    #[error("{found} bytes, where {expected} are expected")]
    Size {
        /// Its size.
        found: u64,
        /// The size its header says, or the smallest file's.
        expected: u64,
    },
    /// Its checksum does not match its content.
    #[error("the checksum does not match")]
    Checksum,
    /// It passes its checksum, but a part of it does not parse.
    #[error("malformed {0}")]
    Malformed(&'static str),
}

/// The hashes the agent holds at load: a verdict saved under others loads stale (D31).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Current {
    /// The hash of all the policies held, [`MatchHash::of`] them all.
    pub policies: MatchHash,
    /// The trust root's hash.
    pub root: Option<RootHash>,
}

/// What a load put in the caches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Loaded {
    /// The verdicts.
    pub verdicts: usize,
    /// The signature results.
    pub signatures: usize,
}

/// Writes into `out` the allows and rejections `verdicts` keeps and the results `signatures` keeps.
///
/// `policies` is [`MatchHash::of`] all the policies the verdicts were kept under, and a stale verdict saves how long
/// before `now` it went stale.
///
/// # Panics
///
/// Never: a cache holds fewer than 2^32 entries, and a string fewer than 2^32 bytes.
pub fn save(
    verdicts: &Verdicts,
    signatures: &Signatures,
    policies: MatchHash,
    now: Instant,
    out: &mut Vec<u8>,
) {
    out.clear();
    out.resize(size_of::<Header>(), 0);
    let saved = {
        let kept = verdicts.kept.read().unwrap_or_else(PoisonError::into_inner);
        let mut sorted: Vec<(&Digest, &Kept, Option<&str>)> = kept
            .iter()
            .flat_map(|(image, kept)| kept.iter().map(move |kept| (image, kept)))
            .filter_map(|(image, kept)| match &kept.verdict {
                Verdict::Allow => Some((image, kept, None)),
                Verdict::Rejected { reason } => Some((image, kept, Some(&**reason))),
                Verdict::Unverifiable { .. } | Verdict::Pending => None,
            })
            .collect();
        sorted.sort_unstable_by_key(|&(image, kept, _)| (image, kept.policies));
        for &(image, kept, reason) in &sorted {
            put_digest(out, image);
            let age = kept
                .stale_since
                .map(|since| now.saturating_duration_since(since));
            let head = Head {
                policies: kept.policies.0,
                root: Hash::of(kept.root.map(|root| root.0)),
                state: if reason.is_some() { REJECTED } else { ALLOW },
                stale: u8::from(age.is_some()),
                age: U64::new(
                    age.map_or(0, |age| u64::try_from(age.as_nanos()).unwrap_or(u64::MAX)),
                ),
            };
            out.extend_from_slice(head.as_bytes());
            if let Some(reason) = reason {
                put_text(out, reason);
            }
        }
        sorted.len()
    };
    let (root, signed) = {
        let cache = signatures
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let mut sorted: Vec<(&Entry, &signature::Kept)> = cache.results.iter().collect();
        sorted.sort_unstable_by_key(|&(entry, _)| entry);
        for &(entry, kept) in &sorted {
            put_signature(out, entry, kept);
        }
        (cache.root, sorted.len())
    };
    let size = out.len() + CHECKSUM;
    let header = Header {
        version: U32::new(VERSION),
        size: U64::new(u64::try_from(size).expect("a usize fits in a u64")),
        policies: policies.0,
        root: Hash::of(root.map(|root| root.0)),
        verdicts: U32::new(u32::try_from(saved).expect("fewer than 2^32 verdicts are kept")),
        signatures: U32::new(u32::try_from(signed).expect("fewer than 2^32 results are kept")),
    };
    out[..size_of::<Header>()].copy_from_slice(header.as_bytes());
    let checksum = digest(&SHA256, out);
    out.extend_from_slice(checksum.as_ref());
}

/// Replaces what `verdicts` and `signatures` keep with what `bytes` holds, read at `now`.
///
/// A verdict saved stale is stale since as long before `now`, and dropped if that is before the clock's start. One saved
/// under other policies or another trust root than `current` loads under `current`'s, stale since `now` unless it was
/// already (D21, D31, D154).
///
/// # Errors
///
/// When `bytes` are of another format version, not the size their header says, fail their checksum or do not parse.
/// The caches are then left as they were.
///
/// # Panics
///
/// Never: a `usize` fits in a `u64`.
pub fn load(
    bytes: &[u8],
    current: Current,
    now: Instant,
    verdicts: &Verdicts,
    signatures: &Signatures,
) -> Result<Loaded, Refused> {
    let found = u64::try_from(bytes.len()).expect("a usize fits in a u64");
    // The version first: another version may lay out the rest differently.
    if let Some(version) = bytes
        .first_chunk()
        .map(|version| u32::from_le_bytes(*version))
        && version != VERSION
    {
        return Err(Refused::Version(version));
    }
    let smallest = Refused::Size {
        found,
        expected: u64::try_from(SMALLEST).expect("a usize fits in a u64"),
    };
    let (header, _) = Header::ref_from_prefix(bytes).map_err(|_| smallest)?;
    let expected = header.size.get();
    if expected != found {
        return Err(Refused::Size { found, expected });
    }
    let (content, checksum) = bytes
        .len()
        .checked_sub(CHECKSUM)
        .filter(|&end| end >= size_of::<Header>())
        .map(|end| bytes.split_at(end))
        .ok_or(smallest)?;
    if digest(&SHA256, content).as_ref() != checksum {
        return Err(Refused::Checksum);
    }
    let mut reader = Reader {
        rest: content.get(size_of::<Header>()..).unwrap_or_default(),
    };
    let moved = header.policies != current.policies.0;
    let count = header.verdicts.get();
    let mut kept: HashMap<Digest, Vec<Kept>> = HashMap::new();
    let mut loaded = 0;
    for _ in 0..count {
        let image = reader.digest("verdict image")?;
        let head = reader.fixed::<Head>("verdict")?;
        let verdict = match head.state {
            ALLOW => Verdict::Allow,
            REJECTED => Verdict::Rejected {
                reason: Arc::from(reader.text("rejection reason")?),
            },
            _ => return Err(Refused::Malformed("verdict state")),
        };
        let root = head.root.get("verdict trust root")?.map(RootHash);
        let policies = MatchHash(head.policies);
        let stale_since = match (head.stale, head.age.get()) {
            (0, 0) => None,
            (1, age) => match now.checked_sub(Duration::from_nanos(age)) {
                Some(since) => Some(since),
                None => continue,
            },
            _ => return Err(Refused::Malformed("verdict age")),
        };
        let (root, stale_since) = if moved || root != current.root {
            (current.root, Some(stale_since.unwrap_or(now)))
        } else {
            (root, stale_since)
        };
        let image = kept.entry(image).or_default();
        if image.iter().any(|kept| kept.policies == policies) {
            return Err(Refused::Malformed("verdict saved twice"));
        }
        image.push(Kept {
            policies,
            root,
            verdict,
            stale_since,
        });
        loaded += 1;
    }
    let root = header.root.get("signature trust root")?.map(RootHash);
    let count = header.signatures.get();
    let mut results = HashMap::new();
    for _ in 0..count {
        let (entry, kept) = reader.signature()?;
        if results.insert(entry, kept).is_some() {
            return Err(Refused::Malformed("signature result saved twice"));
        }
    }
    if !reader.rest.is_empty() {
        return Err(Refused::Malformed("end"));
    }
    let signed = results.len();
    *verdicts
        .kept
        .write()
        .unwrap_or_else(PoisonError::into_inner) = kept;
    *signatures
        .cache
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = Cache { root, results };
    Ok(Loaded {
        verdicts: loaded,
        signatures: signed,
    })
}

/// Puts `bytes` at `path` whole: written to a temporary file of mode 0600 beside it, synced, renamed over it, and the
/// rename synced. It blocks.
///
/// # Errors
///
/// When `path` names no parent directory (`InvalidInput`), when the temporary file cannot be made, written or renamed,
/// or when the directory cannot be synced.
pub fn write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "cache path names no parent directory",
            )
        })?;
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| e.error)?;
    std::fs::File::open(dir)?.sync_all()
}

impl Hash {
    fn of(hash: Option<[u8; 32]>) -> Self {
        Self {
            present: u8::from(hash.is_some()),
            hash: hash.unwrap_or_default(),
        }
    }

    /// The hash; `what` names it when malformed.
    fn get(&self, what: &'static str) -> Result<Option<[u8; 32]>, Refused> {
        match self.present {
            0 if self.hash == [0; 32] => Ok(None),
            1 => Ok(Some(self.hash)),
            _ => Err(Refused::Malformed(what)),
        }
    }
}

/// Writes a signature result: its entry, then its result, then what it attests.
fn put_signature(out: &mut Vec<u8>, entry: &Entry, kept: &signature::Kept) {
    put_digest(out, &entry.target);
    match &entry.source {
        Source::Bundle { manifest, bundle } => {
            out.push(0);
            put_digest(out, manifest);
            put_digest(out, bundle);
        }
        Source::Layer {
            manifest,
            index,
            payload,
        } => {
            out.push(1);
            put_digest(out, manifest);
            let index = u64::try_from(*index).expect("a usize fits in a u64");
            out.extend_from_slice(U64::new(index).as_bytes());
            put_digest(out, payload);
        }
    }
    out.extend_from_slice(Hash::of(entry.public_key).as_bytes());
    match &kept.signed {
        Ok(signed) => {
            out.push(0);
            put_signed(out, signed);
        }
        Err(Failure::Missing) => out.push(1),
        Err(Failure::Invalid(reason)) => {
            out.push(2);
            put_text(out, reason);
        }
        Err(Failure::Oversize(size)) => {
            out.push(3);
            out.extend_from_slice(U64::new(*size).as_bytes());
        }
        Err(Failure::UnknownIssuer(issuer)) => {
            out.push(4);
            put_text(out, issuer);
        }
        Err(Failure::Mismatch(signed)) => {
            out.push(5);
            put_signed(out, signed);
        }
    }
    match &kept.attests {
        None => out.push(0),
        Some(predicate_type) => {
            out.push(1);
            put_text(out, predicate_type);
        }
    }
}

fn put_signed(out: &mut Vec<u8>, signed: &Signed) {
    match signed {
        Signed::Certificate { subject, issuer } => {
            out.push(0);
            put_text(out, subject);
            put_text(out, issuer);
        }
        Signed::Key => out.push(1),
    }
}

fn put_digest(out: &mut Vec<u8>, digest: &Digest) {
    let (algorithm, encoded) = (digest.algorithm(), digest.encoded());
    let length = algorithm.len() + 1 + encoded.len();
    out.push(u8::try_from(length).expect("a digest's text is at most 135 bytes"));
    out.extend_from_slice(algorithm.as_bytes());
    out.push(b':');
    out.extend_from_slice(encoded.as_bytes());
}

fn put_text(out: &mut Vec<u8>, text: &str) {
    let length = u32::try_from(text.len()).expect("a string kept is under 4 GiB");
    out.extend_from_slice(U32::new(length).as_bytes());
    out.extend_from_slice(text.as_bytes());
}

/// Reads a file's content past its header; each read names what it reads, for a [`Refused::Malformed`].
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn fixed<T: FromBytes + KnownLayout + Immutable + Unaligned>(
        &mut self,
        what: &'static str,
    ) -> Result<&'a T, Refused> {
        let (value, rest) = T::ref_from_prefix(self.rest).map_err(|_| Refused::Malformed(what))?;
        self.rest = rest;
        Ok(value)
    }

    fn bytes(&mut self, length: usize, what: &'static str) -> Result<&'a [u8], Refused> {
        let (bytes, rest) = self
            .rest
            .split_at_checked(length)
            .ok_or(Refused::Malformed(what))?;
        self.rest = rest;
        Ok(bytes)
    }

    fn byte(&mut self, what: &'static str) -> Result<u8, Refused> {
        Ok(*self.fixed::<u8>(what)?)
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, Refused> {
        Ok(self.fixed::<U64>(what)?.get())
    }

    fn text(&mut self, what: &'static str) -> Result<&'a str, Refused> {
        let length = usize::try_from(self.fixed::<U32>(what)?.get()).unwrap_or(usize::MAX);
        std::str::from_utf8(self.bytes(length, what)?).map_err(|_| Refused::Malformed(what))
    }

    fn digest(&mut self, what: &'static str) -> Result<Digest, Refused> {
        let length = self.byte(what)?;
        let text = std::str::from_utf8(self.bytes(usize::from(length), what)?)
            .map_err(|_| Refused::Malformed(what))?;
        Digest::parse(text).map_err(|_| Refused::Malformed(what))
    }

    fn signed(&mut self) -> Result<Signed, Refused> {
        match self.byte("signer")? {
            0 => Ok(Signed::Certificate {
                subject: self.text("certificate subject")?.to_owned(),
                issuer: self.text("certificate issuer")?.to_owned(),
            }),
            1 => Ok(Signed::Key),
            _ => Err(Refused::Malformed("signer")),
        }
    }

    fn signature(&mut self) -> Result<(Entry, signature::Kept), Refused> {
        let target = self.digest("signature target")?;
        let source = match self.byte("signature source")? {
            0 => Source::Bundle {
                manifest: self.digest("signature manifest")?,
                bundle: self.digest("signature bundle")?,
            },
            1 => Source::Layer {
                manifest: self.digest("signature manifest")?,
                index: usize::try_from(self.u64("signature layer")?)
                    .map_err(|_| Refused::Malformed("signature layer"))?,
                payload: self.digest("signature payload")?,
            },
            _ => return Err(Refused::Malformed("signature source")),
        };
        let public_key = self.fixed::<Hash>("signature key")?.get("signature key")?;
        let signed = match self.byte("signature result")? {
            0 => Ok(self.signed()?),
            1 => Err(Failure::Missing),
            2 => Err(Failure::Invalid(self.text("signature failure")?.to_owned())),
            3 => Err(Failure::Oversize(self.u64("signature size")?)),
            4 => Err(Failure::UnknownIssuer(
                self.text("signature issuer")?.to_owned(),
            )),
            5 => Err(Failure::Mismatch(self.signed()?)),
            _ => return Err(Refused::Malformed("signature result")),
        };
        let attests = match self.byte("signature attestation")? {
            0 => None,
            1 => Some(self.text("signature attestation")?.to_owned()),
            _ => return Err(Refused::Malformed("signature attestation")),
        };
        Ok((
            Entry {
                target,
                source,
                public_key,
            },
            signature::Kept { signed, attests },
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::{Key, Lookup};

    /// The hash of all the policies, at save.
    const ALL: MatchHash = MatchHash([9; 32]);
    const P: MatchHash = MatchHash([1; 32]);
    const Q: MatchHash = MatchHash([2; 32]);
    const ROOT: Option<RootHash> = Some(RootHash([3; 32]));
    const OTHER_ROOT: Option<RootHash> = Some(RootHash([4; 32]));
    const HOUR: Duration = Duration::from_secs(3600);
    const SAME: Current = Current {
        policies: ALL,
        root: ROOT,
    };
    const PENDING: Lookup = Lookup {
        verdict: Verdict::Pending,
        stale: false,
    };

    fn image(n: usize) -> Digest {
        Digest::parse(&format!("sha256:{n:064x}")).expect("a digest parses")
    }

    fn put(verdicts: &Verdicts, image: Digest, kept: Kept) {
        let mut verdicts = verdicts.kept.write().unwrap();
        verdicts.entry(image).or_default().push(kept);
    }

    fn kept(policies: MatchHash, verdict: Verdict, stale_since: Option<Instant>) -> Kept {
        Kept {
            policies,
            root: ROOT,
            verdict,
            stale_since,
        }
    }

    fn key(image: &Digest, policies: MatchHash, root: Option<RootHash>) -> Key<'_> {
        Key {
            image,
            policies,
            root,
        }
    }

    /// A result of each kind, from each source, with and without a key and an attestation.
    fn results() -> HashMap<Entry, signature::Kept> {
        let certificate = Signed::Certificate {
            subject: "https://subject.test".into(),
            issuer: "https://issuer.test".into(),
        };
        [
            Ok(certificate.clone()),
            Ok(Signed::Key),
            Err(Failure::Missing),
            Err(Failure::Invalid("bad".into())),
            Err(Failure::Oversize(1 << 40)),
            Err(Failure::UnknownIssuer("GitHub".into())),
            Err(Failure::Mismatch(certificate)),
        ]
        .into_iter()
        .enumerate()
        .map(|(n, signed)| {
            let source = if n % 2 == 0 {
                Source::Bundle {
                    manifest: image(n + 100),
                    bundle: image(n + 200),
                }
            } else {
                Source::Layer {
                    manifest: image(n + 100),
                    index: n,
                    payload: image(n + 200),
                }
            };
            let entry = Entry {
                target: image(n),
                source,
                public_key: (n % 3 == 0).then_some([7; 32]),
            };
            let attests = (n % 2 == 1).then(|| "https://slsa.dev/provenance/v1".to_owned());
            (entry, signature::Kept { signed, attests })
        })
        .collect()
    }

    /// Caches of an allow and a rejection of image 1, a stale allow of image 2, and an unverifiable and a pending
    /// verdict, which are not saved; the results of [`results`].
    fn caches(now: Instant) -> (Verdicts, Signatures) {
        let (verdicts, signatures) = empty();
        put(&verdicts, image(1), kept(P, Verdict::Allow, None));
        let rejected = Verdict::Rejected {
            reason: "no signature, ü".into(),
        };
        put(&verdicts, image(1), kept(Q, rejected, None));
        let since = now - Duration::from_secs(10);
        put(&verdicts, image(2), kept(P, Verdict::Allow, Some(since)));
        let unverifiable = Verdict::Unverifiable {
            reason: "no trust root".into(),
            retry_at: now,
        };
        put(&verdicts, image(3), kept(P, unverifiable, None));
        put(&verdicts, image(4), kept(P, Verdict::Pending, None));
        *signatures.cache.lock().unwrap() = Cache {
            root: ROOT,
            results: results(),
        };
        (verdicts, signatures)
    }

    fn saved(verdicts: &Verdicts, signatures: &Signatures, now: Instant) -> Vec<u8> {
        let mut out = vec![0xff; 3];
        save(verdicts, signatures, ALL, now, &mut out);
        out
    }

    fn empty() -> (Verdicts, Signatures) {
        let verdicts = Verdicts::default();
        verdicts.set_stale_max(HOUR);
        (verdicts, Signatures::new(0))
    }

    /// Loads `bytes` into empty caches, read with [`SAME`] at `now`.
    fn loaded(bytes: &[u8], now: Instant) -> Result<(Verdicts, Signatures), Refused> {
        let (verdicts, signatures) = empty();
        load(bytes, SAME, now, &verdicts, &signatures)?;
        Ok((verdicts, signatures))
    }

    /// `bytes` with their header's size and their checksum set again, as if saved so.
    fn resealed(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.truncate(bytes.len() - CHECKSUM);
        let size = u64::try_from(bytes.len() + CHECKSUM).unwrap();
        bytes[4..12].copy_from_slice(&size.to_le_bytes());
        let checksum = digest(&SHA256, &bytes);
        bytes.extend_from_slice(checksum.as_ref());
        bytes
    }

    /// `bytes` with the byte at `at` set to `byte`, resealed.
    fn tampered(bytes: &[u8], at: usize, byte: u8) -> Vec<u8> {
        let mut bytes = bytes.to_vec();
        bytes[at] = byte;
        resealed(bytes)
    }

    /// `bytes`, of one entry, with it saved twice and counted at `count`, resealed.
    fn twice(bytes: &[u8], count: usize) -> Vec<u8> {
        let end = bytes.len() - CHECKSUM;
        let mut twice = bytes[..end].to_vec();
        twice.extend_from_slice(&bytes[size_of::<Header>()..end]);
        twice[count..count + 4].copy_from_slice(&2_u32.to_le_bytes());
        twice.extend_from_slice(&[0; CHECKSUM]);
        resealed(twice)
    }

    #[test]
    fn saved_caches_load_the_same_lookups_and_save_the_same_bytes() {
        let now = Instant::now();
        let (verdicts, signatures) = caches(now);
        let bytes = saved(&verdicts, &signatures, now);

        let later = now + Duration::from_secs(5);
        let (again, signed) = empty();
        let loaded = load(&bytes, SAME, later, &again, &signed);
        assert_eq!(
            loaded,
            Ok(Loaded {
                verdicts: 3,
                signatures: 7
            })
        );
        for n in 1..=4 {
            let image = image(n);
            for policies in [P, Q] {
                let before = verdicts.get(key(&image, policies, ROOT));
                let after = again.get(key(&image, policies, ROOT));
                match before.verdict {
                    Verdict::Allow | Verdict::Rejected { .. } => assert_eq!(after, before),
                    _ => assert_eq!(after, PENDING),
                }
            }
        }
        let stale_since = again.kept.read().unwrap()[&image(2)][0].stale_since;
        assert_eq!(stale_since, Some(later - Duration::from_secs(10)));
        let cache = signed.cache.lock().unwrap();
        assert_eq!((cache.root, &cache.results), (ROOT, &results()));
        drop(cache);
        assert_eq!(saved(&again, &signed, later), bytes);
    }

    #[test]
    fn empty_caches_save_the_smallest_file() {
        let (verdicts, signatures) = empty();
        let bytes = saved(&verdicts, &signatures, Instant::now());
        assert_eq!(bytes.len(), SMALLEST);
        let (verdicts, signatures) = loaded(&bytes, Instant::now()).expect("an empty file loads");
        assert!(verdicts.kept.read().unwrap().is_empty());
        assert_eq!(signatures.cache.lock().unwrap().root, None);
    }

    #[test]
    fn a_damaged_file_is_refused_naming_why_and_leaves_the_caches_as_they_were() {
        let now = Instant::now();
        let (verdicts, signatures) = caches(now);
        let bytes = saved(&verdicts, &signatures, now);
        let size = u64::try_from(bytes.len()).unwrap();
        let smallest = u64::try_from(SMALLEST).unwrap();

        let mut flipped = bytes.clone();
        flipped[bytes.len() / 2] ^= 1;
        let mut later = bytes.clone();
        later[0] = 2;
        let mut longer = bytes.clone();
        longer.push(0);
        let mut no_checksum = bytes[..size_of::<Header>()].to_vec();
        no_checksum[4..12].copy_from_slice(&85_u64.to_le_bytes());
        let short = |found| Refused::Size {
            found,
            expected: smallest,
        };
        for (damaged, refused) in [
            (flipped, Refused::Checksum),
            (
                bytes[..bytes.len() - 1].to_vec(),
                Refused::Size {
                    found: size - 1,
                    expected: size,
                },
            ),
            (
                longer,
                Refused::Size {
                    found: size + 1,
                    expected: size,
                },
            ),
            (later, Refused::Version(2)),
            (vec![2, 0], short(2)),
            (bytes[..40].to_vec(), short(40)),
            (no_checksum, short(85)),
        ] {
            let (kept, signed) = caches(now);
            assert_eq!(load(&damaged, SAME, now, &kept, &signed), Err(refused));
            assert_eq!(saved(&kept, &signed, now), bytes);
        }
        assert_eq!(
            Refused::Version(2).to_string(),
            "format version 2, where this agent reads 1"
        );
        assert_eq!(short(1).to_string(), "1 bytes, where 117 are expected");
    }

    #[test]
    fn a_file_that_passes_its_checksum_but_does_not_parse_is_refused() {
        let now = Instant::now();
        let (verdicts, signatures) = empty();
        put(&verdicts, image(1), kept(P, Verdict::Allow, None));
        let bytes = saved(&verdicts, &signatures, now);
        // The header, then the verdict's digest: its length, then 71 bytes of text.
        let head = size_of::<Header>() + 1 + 71;
        let state = head + 32 + 33;
        let mut more = bytes.clone();
        more.insert(bytes.len() - CHECKSUM, 0);
        for (bytes, what) in [
            (tampered(&bytes, state, 2), "verdict state"),
            (tampered(&bytes, state + 1, 2), "verdict age"),
            (tampered(&bytes, state + 2, 1), "verdict age"),
            (tampered(&bytes, head + 32, 2), "verdict trust root"),
            (tampered(&bytes, head + 32, 0), "verdict trust root"),
            (
                tampered(&bytes, size_of::<Header>() + 1, b'x'),
                "verdict image",
            ),
            (
                tampered(&bytes, size_of::<Header>() + 1, 0xff),
                "verdict image",
            ),
            (tampered(&bytes, 44, 2), "signature trust root"),
            (tampered(&bytes, 77, 2), "verdict image"),
            (twice(&bytes, 77), "verdict saved twice"),
            (resealed(more), "end"),
        ] {
            assert_eq!(loaded(&bytes, now).err(), Some(Refused::Malformed(what)));
        }
        let rejected = Verdicts::default();
        let reason = "é".into();
        put(
            &rejected,
            image(1),
            kept(P, Verdict::Rejected { reason }, None),
        );
        let bytes = saved(&rejected, &signatures, now);
        let reason = size_of::<Header>() + 72 + size_of::<Head>() + 4;
        let error = loaded(&tampered(&bytes, reason, 0xff), now).err();
        assert_eq!(error, Some(Refused::Malformed("rejection reason")));
    }

    #[test]
    fn a_malformed_signature_result_is_refused() {
        let now = Instant::now();
        let (verdicts, signatures) = empty();
        let entry = Entry {
            target: image(1),
            source: Source::Bundle {
                manifest: image(2),
                bundle: image(3),
            },
            public_key: None,
        };
        let result = signature::Kept {
            signed: Ok(Signed::Key),
            attests: None,
        };
        signatures
            .cache
            .lock()
            .unwrap()
            .results
            .insert(entry, result);
        let bytes = saved(&verdicts, &signatures, now);
        // The header, the target, the source's tag and digests, the key, the result's tag and signer, the attestation.
        let source = size_of::<Header>() + 72;
        let key = source + 1 + 2 * 72;
        let (result, signer, attests) = (key + 33, key + 34, key + 35);
        for (bytes, what) in [
            (tampered(&bytes, source, 2), "signature source"),
            (tampered(&bytes, key, 2), "signature key"),
            (tampered(&bytes, result, 6), "signature result"),
            (tampered(&bytes, signer, 2), "signer"),
            (tampered(&bytes, attests, 2), "signature attestation"),
            (twice(&bytes, 81), "signature result saved twice"),
        ] {
            assert_eq!(loaded(&bytes, now).err(), Some(Refused::Malformed(what)));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_verdict_saved_under_other_policies_or_another_root_loads_stale_from_load() {
        let now = Instant::now();
        let (verdicts, signatures) = caches(now);
        let bytes = saved(&verdicts, &signatures, now);
        let one = image(1);
        let stale = |verdict| Lookup {
            verdict,
            stale: true,
        };

        let (moved, signed) = empty();
        moved.set_stale_max(Duration::from_secs(60));
        let current = Current {
            policies: P,
            root: ROOT,
        };
        load(&bytes, current, now, &moved, &signed).expect("the file loads");
        assert_eq!(moved.get(key(&one, P, ROOT)), stale(Verdict::Allow));
        let since = moved.kept.read().unwrap()[&image(2)][0].stale_since;
        let already = Some(now - Duration::from_secs(10));
        assert_eq!(since, already, "a verdict stale already keeps its time");
        tokio::time::advance(Duration::from_secs(59)).await;
        assert_eq!(moved.get(key(&one, P, ROOT)), stale(Verdict::Allow));
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(moved.get(key(&one, P, ROOT)), PENDING);

        let (rooted, signed) = empty();
        let current = Current {
            policies: ALL,
            root: OTHER_ROOT,
        };
        load(&bytes, current, Instant::now(), &rooted, &signed).expect("the file loads");
        let rejected = rooted.get(key(&one, Q, OTHER_ROOT));
        assert!(rejected.stale && matches!(rejected.verdict, Verdict::Rejected { .. }));
        assert_eq!(rooted.get(key(&one, Q, ROOT)), PENDING);
        assert_eq!(
            signed.cache.lock().unwrap().root,
            ROOT,
            "results keep their root"
        );
    }

    #[test]
    fn a_verdict_stale_since_before_the_clock_is_dropped() {
        let now = Instant::now();
        let (verdicts, signatures) = empty();
        put(&verdicts, image(1), kept(P, Verdict::Allow, Some(now)));
        put(&verdicts, image(2), kept(P, Verdict::Allow, None));
        let mut bytes = saved(&verdicts, &signatures, now);
        let age = size_of::<Header>() + 72 + size_of::<Head>() - 8;
        bytes[age..age + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        let (verdicts, _) = loaded(&resealed(bytes), now).expect("the file loads");
        assert_eq!(verdicts.get(key(&image(1), P, ROOT)), PENDING);
        assert_eq!(
            verdicts.get(key(&image(2), P, ROOT)).verdict,
            Verdict::Allow
        );
    }

    /// Any caches, of one trust root as the engine keeps them, save, load and save the same.
    #[test]
    fn any_caches_round_trip() {
        let now = Instant::now();
        for seed in 0..256 {
            let mut rng = fastrand::Rng::with_seed(seed);
            let root = rng.bool().then(|| RootHash([rng.u8(..); 32]));
            let (verdicts, signatures) = empty();
            for _ in 0..rng.usize(0..24) {
                let (image, policies) = (any_digest(&mut rng), MatchHash([rng.u8(0..3); 32]));
                let verdict = match rng.u8(0..4) {
                    0 => Verdict::Allow,
                    1 => Verdict::Rejected {
                        reason: any_text(&mut rng).into(),
                    },
                    2 => Verdict::Unverifiable {
                        reason: any_text(&mut rng).into(),
                        retry_at: now,
                    },
                    _ => Verdict::Pending,
                };
                let stale_since = rng
                    .bool()
                    .then(|| now - Duration::from_nanos(rng.u64(0..1 << 40)));
                let mut kept = verdicts.kept.write().unwrap();
                let image = kept.entry(image).or_default();
                if image.iter().all(|kept| kept.policies != policies) {
                    image.push(Kept {
                        policies,
                        root,
                        verdict,
                        stale_since,
                    });
                }
            }
            let mut cache = signatures.cache.lock().unwrap();
            cache.root = root;
            for _ in 0..rng.usize(0..8) {
                let (entry, kept) = any_result(&mut rng);
                cache.results.insert(entry, kept);
            }
            drop(cache);

            let bytes = saved(&verdicts, &signatures, now);
            let (again, signed) = empty();
            let current = Current {
                policies: ALL,
                root,
            };
            load(&bytes, current, now, &again, &signed).expect("saved caches load");
            for (image, kept) in verdicts.kept.read().unwrap().iter() {
                for kept in kept {
                    let key = key(image, kept.policies, root);
                    let expected = match kept.verdict {
                        Verdict::Allow | Verdict::Rejected { .. } => verdicts.get(key),
                        _ => PENDING,
                    };
                    assert_eq!(again.get(key), expected, "seed {seed}");
                }
            }
            assert_eq!(
                signed.cache.lock().unwrap().results,
                signatures.cache.lock().unwrap().results,
                "seed {seed}"
            );
            assert_eq!(saved(&again, &signed, now), bytes, "seed {seed}");
        }
    }

    fn any_text(rng: &mut fastrand::Rng) -> String {
        let length = rng.usize(0..8);
        std::iter::repeat_with(|| rng.char(..))
            .take(length)
            .collect()
    }

    fn any_digest(rng: &mut fastrand::Rng) -> Digest {
        let n = rng.u64(0..6);
        let text = if rng.bool() {
            format!("sha256:{n:064x}")
        } else {
            format!("sha512:{n:0128x}")
        };
        Digest::parse(&text).expect("a digest parses")
    }

    fn any_signer(rng: &mut fastrand::Rng) -> Signed {
        if rng.bool() {
            Signed::Key
        } else {
            Signed::Certificate {
                subject: any_text(rng),
                issuer: any_text(rng),
            }
        }
    }

    fn any_result(rng: &mut fastrand::Rng) -> (Entry, signature::Kept) {
        let source = if rng.bool() {
            Source::Bundle {
                manifest: any_digest(rng),
                bundle: any_digest(rng),
            }
        } else {
            Source::Layer {
                manifest: any_digest(rng),
                index: rng.usize(..),
                payload: any_digest(rng),
            }
        };
        let signed = match rng.u8(0..6) {
            0 => Ok(any_signer(rng)),
            1 => Err(Failure::Missing),
            2 => Err(Failure::Invalid(any_text(rng))),
            3 => Err(Failure::Oversize(rng.u64(..))),
            4 => Err(Failure::UnknownIssuer(any_text(rng))),
            _ => Err(Failure::Mismatch(any_signer(rng))),
        };
        let entry = Entry {
            target: any_digest(rng),
            source,
            public_key: rng.bool().then(|| [rng.u8(..); 32]),
        };
        let attests = rng.bool().then(|| any_text(rng));
        (entry, signature::Kept { signed, attests })
    }

    #[test]
    fn a_write_replaces_the_file_whole_with_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.bin");
        write(&path, b"one").unwrap();
        write(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert!(write(&dir.path().join("missing/cache.bin"), b"").is_err());
    }

    #[test]
    fn a_write_refuses_a_path_with_no_parent_directory() {
        for path in ["cache.bin", "/"] {
            let error = write(Path::new(path), b"").unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{path}");
        }
    }
}
