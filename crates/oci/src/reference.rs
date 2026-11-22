//! Image references, parsed and normalized as containerd's CRI plugin does (D11, D15, D81).
//!
//! Ported from `github.com/distribution/reference` v0.6.0, as containerd v2.4.2 vendors it (`reference.go`,
//! `normalize.go`, `regexp.go`), and from the part of `github.com/opencontainers/go-digest` v1.0.0 that checks a digest
//! (`Digest.Validate`, `Algorithm.Validate`). (D25)
//!
//! The library matches references with regular expressions; the grammar is written out here, and the tests ask
//! containerd's own code about the same strings. A [`Reference`] can only be made by [`Reference::parse_docker_ref`]
//! and [`Reference::parse_normalized_named`]: there is no constructor from parts and no `From<String>`, so one that
//! exists is normalized.

use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::Write as _;

/// `NameTotalLengthMax`: the longest repository path.
const PATH_LENGTH_MAX: usize = 255;
/// The registry of a name without one, and the one `index.docker.io` stands for.
const DEFAULT_DOMAIN: &str = "docker.io";
const LEGACY_DEFAULT_DOMAIN: &str = "index.docker.io";
/// The namespace of official images on the default registry.
const OFFICIAL_REPO_PREFIX: &str = "library/";
/// The tag of a name that has neither tag nor digest.
const DEFAULT_TAG: &str = "latest";
/// The longest tag.
const TAG_MAX: usize = 128;

/// A reference that is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReferenceError {
    /// The text is not `[domain/]path[:tag][@digest]`.
    #[error("invalid reference format")]
    InvalidFormat,
    /// The repository name has an upper-case letter.
    #[error("repository name must be lowercase")]
    Uppercase,
    /// The repository path is longer than 255 characters.
    #[error("repository name must not be more than 255 characters")]
    TooLong,
    /// The text is a 64 character hexadecimal string, which names an image ID, not a repository.
    #[error("invalid repository name, cannot specify 64-byte hexadecimal strings")]
    ImageId,
    /// The digest names an algorithm other than sha256, sha384 or sha512.
    #[error("unsupported digest algorithm")]
    DigestUnsupported,
    /// The digest is not the right length for its algorithm.
    #[error("invalid checksum digest length")]
    DigestLength,
    /// The digest is not lower-case hexadecimal.
    #[error("invalid checksum digest format")]
    DigestFormat,
}

/// A digest that names a known algorithm and holds a hash of its size.
///
/// It holds its hex inline, so parsing, cloning and keying a map with one never allocate (D107). Digests order by
/// algorithm, then hash.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest {
    algorithm: Algorithm,
    /// The hash in lower-case hex, then zeros up to the longest algorithm's size.
    hex: [u8; HEX_MAX],
}

/// The hex size of sha512, the longest algorithm.
const HEX_MAX: usize = 128;

/// One of the algorithms go-digest registers by default.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    fn parse(name: &str) -> Option<Self> {
        match name {
            "sha256" => Some(Self::Sha256),
            "sha384" => Some(Self::Sha384),
            "sha512" => Some(Self::Sha512),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }

    /// The length of its hash in hex.
    fn size(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha384 => 96,
            Self::Sha512 => HEX_MAX,
        }
    }
}

impl Digest {
    /// `Digest.Validate`: the algorithm must be one go-digest registers by default, and the hash lower-case hex of
    /// its size.
    ///
    /// # Errors
    ///
    /// When `text` is not `<algorithm>:<hex>`, names another algorithm, or has a hash of the wrong length.
    pub fn parse(text: &str) -> Result<Self, ReferenceError> {
        let (algorithm, encoded) = match text.split_once(':') {
            Some((algorithm, encoded)) if !algorithm.is_empty() && !encoded.is_empty() => {
                (algorithm, encoded)
            }
            _ => return Err(ReferenceError::DigestFormat),
        };
        let algorithm = Algorithm::parse(algorithm).ok_or(ReferenceError::DigestUnsupported)?;
        if !encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ReferenceError::DigestFormat);
        }
        if encoded.len() != algorithm.size() {
            return Err(ReferenceError::DigestLength);
        }
        let mut hex = [0; HEX_MAX];
        hex[..encoded.len()].copy_from_slice(encoded.as_bytes());
        Ok(Self { algorithm, hex })
    }

    /// The digest of `hash`, made by the algorithm `name`; `None` when go-digest does not register `name` or `hash`
    /// is not its size.
    pub(crate) fn from_hash(name: &str, hash: &[u8]) -> Option<Self> {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let algorithm = Algorithm::parse(name)?;
        if hash.len() * 2 != algorithm.size() {
            return None;
        }
        let mut hex = [0; HEX_MAX];
        for ([high, low], byte) in hex.as_chunks_mut::<2>().0.iter_mut().zip(hash) {
            *high = DIGITS[usize::from(byte >> 4)];
            *low = DIGITS[usize::from(byte & 0xf)];
        }
        Some(Self { algorithm, hex })
    }

    /// The algorithm, such as `sha256`.
    #[must_use]
    pub fn algorithm(&self) -> &'static str {
        self.algorithm.name()
    }

    /// The hash, in lower-case hexadecimal.
    ///
    /// # Panics
    ///
    /// Never: `parse` admits only hex digits, which are ASCII.
    #[must_use]
    pub fn encoded(&self) -> &str {
        std::str::from_utf8(&self.hex[..self.algorithm.size()])
            .expect("`parse` admits only hex digits, which are ASCII")
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm(), self.encoded())
    }
}

impl Hash for Digest {
    /// Hashes the algorithm and its hex, not the zeros after it.
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
        self.hex[..self.algorithm.size()].hash(state);
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Digest")
            .field("algorithm", &self.algorithm())
            .field("encoded", &self.encoded())
            .finish()
    }
}

/// A normalized image reference: a repository with a tag, a digest, both, or neither.
///
/// The repository is `domain/path`. The domain is empty for the one name the library cannot split, a first segment
/// that is not a valid domain but is a valid path component (`my_registry.example/app`): the whole name is then the
/// path, as in the library.
///
/// The name and tag share one string, so parsing allocates once and [`Reference::name`] borrows (D107).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Reference {
    /// `domain/path`, then `:tag` when there is one.
    text: String,
    /// The length of the domain, zero when there is none.
    domain: usize,
    /// The length of the name, where the tag's colon is.
    name: usize,
    digest: Option<Digest>,
}

impl Reference {
    /// `ParseDockerRef`: what containerd's CRI plugin makes of an image name. The name is normalized (`nginx` is
    /// `docker.io/library/nginx`); a name with a tag and a digest keeps only the digest; a name with neither gets the
    /// tag `latest`.
    ///
    /// # Errors
    ///
    /// When the text is not a valid reference, has an upper-case repository name, is an image ID, or has a digest
    /// that is not valid.
    pub fn parse_docker_ref(text: &str) -> Result<Self, ReferenceError> {
        let mut named = Self::parse_normalized_named(text)?;
        if named.digest.is_some() {
            named.text.truncate(named.name);
        } else if named.tag().is_none() {
            named.text.push(':');
            named.text.push_str(DEFAULT_TAG);
        }
        Ok(named)
    }

    /// `ParseNormalizedNamed`: the name is normalized, and a missing tag stays missing.
    ///
    /// # Errors
    ///
    /// As [`Reference::parse_docker_ref`].
    pub fn parse_normalized_named(text: &str) -> Result<Self, ReferenceError> {
        let (domain, prefix, remote) = normalize(text)?;
        // Room for `parse_docker_ref`'s default tag, so that it does not grow the string again.
        let mut normalized = String::with_capacity(
            domain.len() + 1 + prefix.len() + remote.len() + 1 + DEFAULT_TAG.len(),
        );
        normalized.push_str(domain);
        normalized.push('/');
        normalized.push_str(prefix);
        normalized.push_str(remote);
        Self::parse(normalized)
    }

    /// `Parse`: the reference as written, without normalization. Its `ErrNameEmpty` is left out: the text always has
    /// a domain and a slash.
    fn parse(mut text: String) -> Result<Self, ReferenceError> {
        let Split {
            domain,
            name,
            end,
            digest,
        } = split(&text)?;
        text.truncate(end);
        Ok(Self {
            text,
            domain,
            name,
            digest,
        })
    }

    /// The registry, such as `docker.io` or `registry.example:5000`.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.text[..self.domain]
    }

    /// The repository below the registry, such as `library/nginx`.
    #[must_use]
    pub fn path(&self) -> &str {
        let start = if self.domain == 0 { 0 } else { self.domain + 1 };
        &self.text[start..self.name]
    }

    /// The repository name, `domain/path`: what policies match (D11).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.text[..self.name]
    }

    /// The tag, if the reference has one.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.text.get(self.name + 1..)
    }

    /// The digest, if the reference has one.
    #[must_use]
    pub fn digest(&self) -> Option<&Digest> {
        self.digest.as_ref()
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)?;
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

/// The longest reference on Docker Hub [`Repository`] normalizes: `docker.io/`, a path, a tag and a sha512 digest.
const HUB_MAX: usize =
    DEFAULT_DOMAIN.len() + 1 + PATH_LENGTH_MAX + 1 + TAG_MAX + 1 + "sha512:".len() + HEX_MAX;

/// The repository name of a reference, normalized as [`Reference::parse_normalized_named`] normalizes it, without
/// allocating (D107, D189).
///
/// A name already normalized is borrowed. One on Docker Hub written short, such as `nginx`, is normalized into a
/// buffer inside the value.
#[derive(Clone, Copy)]
pub struct Repository<'a>(Name<'a>);

#[derive(Clone, Copy)]
#[expect(
    clippy::large_enum_variant,
    reason = "the buffer keeps a short name off the heap (D107)"
)]
enum Name<'a> {
    /// The text is its own normalized form, and the name its start.
    Text(&'a str),
    /// The normalized text, the name its first `len` bytes.
    Hub { text: [u8; HUB_MAX], len: usize },
}

impl<'a> Repository<'a> {
    /// Parses `text` as [`Reference::parse_normalized_named`] does, and keeps its [`Reference::name`].
    ///
    /// # Errors
    ///
    /// As [`Reference::parse_normalized_named`].
    ///
    /// # Panics
    ///
    /// Never: the buffer is written from strings.
    pub fn parse(text: &'a str) -> Result<Self, ReferenceError> {
        let (domain, prefix, remote) = normalize(text)?;
        let rest = text
            .strip_prefix(domain)
            .and_then(|rest| rest.strip_prefix('/'))
            .and_then(|rest| rest.strip_prefix(prefix));
        if rest == Some(remote) {
            let Split { name, .. } = split(text)?;
            return Ok(Self(Name::Text(&text[..name])));
        }
        let mut buffer = [0; HUB_MAX];
        let Some(len) = write(&mut buffer, [domain, "/", prefix, remote]) else {
            // Longer than any valid reference on Docker Hub: the owned parse tells why.
            return Err(Reference::parse_normalized_named(text)
                .err()
                .unwrap_or(ReferenceError::TooLong));
        };
        let normalized = str::from_utf8(&buffer[..len]).expect("written from strings");
        let Split { name, .. } = split(normalized)?;
        Ok(Self(Name::Hub {
            text: buffer,
            len: name,
        }))
    }

    /// The repository name, `domain/path`, as [`Reference::name`] has it: what policies match (D11).
    ///
    /// # Panics
    ///
    /// Never: the name is written from strings, and ends where `Parse` splits it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Name::Text(name) => name,
            Name::Hub { text, len } => str::from_utf8(&text[..*len]).expect("written from strings"),
        }
    }
}

impl fmt::Debug for Repository<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Repository").field(&self.as_str()).finish()
    }
}

/// A reference written out as [`Reference::parse_docker_ref`] normalizes it, the name containerd keeps an image by,
/// without allocating when it fits a buffer inside the value (D107, D189).
pub struct DockerRef(Written);

#[expect(
    clippy::large_enum_variant,
    reason = "the buffer keeps a reference off the heap (D107)"
)]
enum Written {
    /// The text is the buffer's first `len` bytes.
    Buffer { text: [u8; HUB_MAX], len: usize },
    /// Too long for the buffer, on a registry with a long domain name.
    Owned(String),
}

impl DockerRef {
    /// Parses `text` as [`Reference::parse_docker_ref`] does, and keeps its text: `name@digest`, `name:tag`, or
    /// `name:latest` when it has neither.
    ///
    /// # Errors
    ///
    /// As [`Reference::parse_docker_ref`].
    ///
    /// # Panics
    ///
    /// Never: the buffer is written from strings.
    pub fn parse(text: &str) -> Result<Self, ReferenceError> {
        let (domain, prefix, remote) = normalize(text)?;
        let mut buffer = [0; HUB_MAX];
        let written = write(&mut buffer, [domain, "/", prefix, remote]).map(|len| {
            let normalized = str::from_utf8(&buffer[..len]).expect("written from strings");
            split(normalized).map(|split| (split, len))
        });
        let Some((
            Split {
                name, end, digest, ..
            },
            len,
        )) = written.transpose()?
        else {
            return owned(text);
        };
        let len = match digest {
            Some(digest) => {
                let mut free = buffer.get_mut(name..).unwrap_or_default();
                let room = free.len();
                write!(free, "@{digest}")
                    .ok()
                    .map(|()| name + room - free.len())
            }
            None if end == name => {
                write(&mut buffer[name..], [":", DEFAULT_TAG]).map(|tag| name + tag)
            }
            None => Some(len),
        };
        match len {
            Some(len) => Ok(Self(Written::Buffer { text: buffer, len })),
            None => owned(text),
        }
    }

    /// The reference as [`Reference::parse_docker_ref`]'s text shows it.
    ///
    /// # Panics
    ///
    /// Never: the buffer is written from strings.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match &self.0 {
            Written::Buffer { text, len } => {
                str::from_utf8(&text[..*len]).expect("written from strings")
            }
            Written::Owned(text) => text,
        }
    }
}

impl fmt::Debug for DockerRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DockerRef").field(&self.as_str()).finish()
    }
}

/// [`DockerRef`] past its buffer: the owned parse, written out.
fn owned(text: &str) -> Result<DockerRef, ReferenceError> {
    Reference::parse_docker_ref(text)
        .map(|reference| DockerRef(Written::Owned(reference.to_string())))
}

/// Writes `parts` at the start of `buffer`, and gives the length written, or `None` when they do not fit.
fn write<const N: usize>(buffer: &mut [u8], parts: [&str; N]) -> Option<usize> {
    let room = buffer.len();
    let mut free = buffer;
    parts
        .into_iter()
        .try_for_each(|part| free.write_all(part.as_bytes()))
        .ok()
        .map(|()| room - free.len())
}

/// `ParseNormalizedNamed`'s first checks, and the parts of `text`'s normalized form: `domain/prefix+remote`.
fn normalize(text: &str) -> Result<(&str, &'static str, &str), ReferenceError> {
    if is_image_id(text) {
        return Err(ReferenceError::ImageId);
    }
    let (domain, prefix, remote) = split_docker_domain(text);
    if crate::has_upper(remote.split(':').next().unwrap_or(remote)) {
        return Err(ReferenceError::Uppercase);
    }
    Ok((domain, prefix, remote))
}

/// Where `Parse` splits a normalized reference: the lengths of its domain, its name and its name with the tag, and
/// its digest.
struct Split {
    domain: usize,
    name: usize,
    end: usize,
    digest: Option<Digest>,
}

/// `Parse`: the reference as written, without normalization. Its `ErrNameEmpty` is left out: a normalized text always
/// has a domain and a slash.
fn split(text: &str) -> Result<Split, ReferenceError> {
    let Some((name, tag, digest)) = split_reference(text) else {
        return Err(if split_reference(&crate::go_lower(text)).is_some() {
            ReferenceError::Uppercase
        } else {
            ReferenceError::InvalidFormat
        });
    };
    let (domain, path) = split_name(name).unwrap_or(("", name));
    if path.len() > PATH_LENGTH_MAX {
        return Err(ReferenceError::TooLong);
    }
    Ok(Split {
        domain: domain.len(),
        name: name.len(),
        end: name.len() + tag.map_or(0, |tag| 1 + tag.len()),
        digest: digest.map(Digest::parse).transpose()?,
    })
}

/// `splitDockerDomain`: the registry of a name, and the repository below it, as a prefix and the rest of the name. A
/// first segment is a registry when it has a `.` or `:`, is `localhost`, or has an upper-case letter; any other name
/// is on Docker Hub, where `nginx` is `library/nginx`.
fn split_docker_domain(name: &str) -> (&str, &'static str, &str) {
    let Some((maybe_domain, maybe_remote)) = name.split_once('/') else {
        return (DEFAULT_DOMAIN, OFFICIAL_REPO_PREFIX, name);
    };
    let (domain, remote) = if maybe_domain == "localhost" {
        (maybe_domain, maybe_remote)
    } else if maybe_domain == LEGACY_DEFAULT_DOMAIN {
        (DEFAULT_DOMAIN, maybe_remote)
    } else if maybe_domain.contains(['.', ':']) || crate::has_upper(maybe_domain) {
        (maybe_domain, maybe_remote)
    } else {
        (DEFAULT_DOMAIN, name)
    };
    if domain == DEFAULT_DOMAIN && !remote.contains('/') {
        (domain, OFFICIAL_REPO_PREFIX, remote)
    } else {
        (domain, "", remote)
    }
}

/// `anchoredIdentifierRegexp`: 64 lower-case hexadecimal characters.
fn is_image_id(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `ReferenceRegexp`: `name[:tag][@digest]` with the parts as the library's patterns have them.
fn split_reference(text: &str) -> Option<(&str, Option<&str>, Option<&str>)> {
    let (head, digest) = match text.split_once('@') {
        Some((head, digest)) => (head, Some(digest)),
        None => (text, None),
    };
    if digest.is_some_and(|digest| !is_digest(digest)) {
        return None;
    }
    // A colon starts the tag unless a slash follows it: that colon is a port.
    let (name, tag) = match head.rsplit_once(':') {
        Some((name, tag)) if !tag.contains('/') => (name, Some(tag)),
        _ => (head, None),
    };
    if tag.is_some_and(|tag| !is_tag(tag)) {
        return None;
    }
    split_name(name)?;
    Some((name, tag, digest))
}

/// `anchoredNameRegexp`: the domain, when the first segment is one and the rest is a path, and the path. A name whose
/// first segment is no domain is all path.
fn split_name(name: &str) -> Option<(&str, &str)> {
    if let Some((first, rest)) = name.split_once('/')
        && is_domain_and_port(first)
        && is_remote_name(rest)
    {
        return Some((first, rest));
    }
    is_remote_name(name).then_some(("", name))
}

/// `domainAndPort`: a host name or a bracketed IPv6 address, and an optional `:port`.
fn is_domain_and_port(text: &str) -> bool {
    let (host_ok, port) = if let Some(bracketed) = text.strip_prefix('[') {
        let Some((inner, after)) = bracketed.split_once(']') else {
            return false;
        };
        let inner_ok =
            !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
        let port = match after.strip_prefix(':') {
            Some(port) => Some(port),
            None if after.is_empty() => None,
            None => return false,
        };
        (inner_ok, port)
    } else {
        let (host, port) = match text.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (text, None),
        };
        (host.split('.').all(is_domain_component), port)
    };
    host_ok && port.is_none_or(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
}

/// `domainNameComponent`: letters and digits, hyphens inside.
fn is_domain_component(part: &str) -> bool {
    let bytes = part.as_bytes();
    let alphanumeric = |b: &u8| b.is_ascii_alphanumeric();
    bytes.first().is_some_and(alphanumeric)
        && bytes.last().is_some_and(alphanumeric)
        && bytes.iter().all(|b| alphanumeric(b) || *b == b'-')
}

/// `remoteName`: path components separated by `/`.
fn is_remote_name(text: &str) -> bool {
    text.split('/').all(is_path_component)
}

/// `pathComponent`: runs of `[a-z0-9]` separated by one of `.`, `_`, `__` or any number of `-`.
fn is_path_component(part: &str) -> bool {
    let bytes = part.as_bytes();
    let alphanumeric = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !bytes.first().is_some_and(|b| alphanumeric(*b))
        || !bytes.last().is_some_and(|b| alphanumeric(*b))
    {
        return false;
    }
    let mut rest = bytes;
    while !rest.is_empty() {
        let separator = rest.iter().take_while(|b| !alphanumeric(**b)).count();
        let separator_run = &rest[..separator];
        let valid = match separator_run {
            [] | [b'.' | b'_'] | [b'_', b'_'] => true,
            run => run.iter().all(|b| *b == b'-'),
        };
        if !valid {
            return false;
        }
        rest = &rest[separator..];
        rest = &rest[rest.iter().take_while(|b| alphanumeric(**b)).count()..];
    }
    true
}

/// `tag`: `[\w][\w.-]{0,127}`.
fn is_tag(text: &str) -> bool {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = text.as_bytes();
    (1..=TAG_MAX).contains(&bytes.len())
        && word(bytes[0])
        && bytes[1..]
            .iter()
            .all(|b| word(*b) || *b == b'.' || *b == b'-')
}

/// `digestPat`: an algorithm of letter-led alphanumeric parts, a colon, and at least 32 hexadecimal digits.
fn is_digest(text: &str) -> bool {
    let Some((algorithm, hex)) = text.split_once(':') else {
        return false;
    };
    let part = |part: &str| {
        part.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && part.bytes().all(|b| b.is_ascii_alphanumeric())
    };
    let mut parts = algorithm.split(['-', '_', '+', '.']);
    parts.all(part) && hex.len() >= 32 && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_algorithm_starts_with_a_letter_and_a_digest_is_hexadecimal() {
        let hex = "a".repeat(32);
        assert!(is_digest(&format!("sha256:{hex}")));
        assert!(is_digest(&format!("sha256+b64.u_x-y:{hex}")));
        assert!(!is_digest(&format!("9sha:{hex}")));
        assert!(!is_digest(&format!("sha-:{hex}")));
        assert!(
            !is_digest(&format!("sh__a:{hex}")),
            "a separator is followed by a letter"
        );
        assert!(!is_digest(&format!("sha256:{}", "g".repeat(32))));
        assert!(!is_digest(&format!("sha256:{}", "a".repeat(31))));
        assert!(!is_digest(&hex));
    }

    #[test]
    fn a_colon_at_either_end_is_no_reference() {
        assert_eq!(split_reference(":"), None);
        assert_eq!(split_reference(":tag"), None);
        assert_eq!(split_reference("a/:tag"), None);
        assert_eq!(
            split_reference("a:5000/b:t"),
            Some(("a:5000/b", Some("t"), None))
        );
    }

    const SHA: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn a_repository_and_a_docker_ref_are_what_the_owned_parses_give() {
        let long = |length: usize| "a".repeat(length);
        let far = format!("{}.test/", long(300));
        let domains = [
            far.as_str(),
            "",
            "docker.io/",
            "index.docker.io/",
            "localhost/",
            "localhost:5000/",
            "reg.test:5000/",
            "my_registry.example/",
            "Reg.Test/",
            "[::1]:5000/",
            "a:b/",
        ];
        let paths = [
            String::new(),
            "nginx".to_owned(),
            "library/nginx".to_owned(),
            "myuser/app".to_owned(),
            "a/b/c".to_owned(),
            "Up".to_owned(),
            "a__b-c.d".to_owned(),
            "a/".to_owned(),
            "a".repeat(64),
            long(247),
            long(248),
            format!("myuser/{}", long(248)),
            format!("myuser/{}", long(249)),
        ];
        let tags = [
            String::new(),
            ":1".to_owned(),
            ":Tag-1.0_x".to_owned(),
            ":".to_owned(),
            ":-x".to_owned(),
            format!(":{}", long(128)),
            format!(":{}", long(129)),
        ];
        let digests = [
            String::new(),
            format!("@{SHA}"),
            format!("@sha512:{}", long(128)),
            "@sha256:abc".to_owned(),
            format!("@md5:{}", long(32)),
        ];
        for domain in domains {
            for path in &paths {
                for tag in &tags {
                    for digest in &digests {
                        let text = format!("{domain}{path}{tag}{digest}");
                        let owned = Reference::parse_normalized_named(&text);
                        assert_eq!(
                            Repository::parse(&text)
                                .map(|repository| repository.as_str().to_owned()),
                            owned.map(|reference| reference.name().to_owned()),
                            "{text}"
                        );
                        assert_eq!(
                            DockerRef::parse(&text).map(|docker| docker.as_str().to_owned()),
                            Reference::parse_docker_ref(&text).map(|docker| docker.to_string()),
                            "{text}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_repository_already_normalized_is_borrowed_and_a_short_one_is_written_out() {
        let text = "reg.test/app:1";
        let Repository(Name::Text(name)) = Repository::parse(text).unwrap() else {
            panic!("{text} is normalized");
        };
        assert_eq!(name, "reg.test/app");
        assert!(std::ptr::eq(name.as_ptr(), text.as_ptr()));
        let longest = format!(
            "{}:{}@sha512:{}",
            "a".repeat(247),
            "a".repeat(128),
            "a".repeat(128)
        );
        assert_eq!(
            format!("docker.io/library/{longest}").len(),
            HUB_MAX,
            "the longest reference on Docker Hub fills the buffer"
        );
        for (text, name) in [
            ("nginx", "docker.io/library/nginx"),
            ("index.docker.io/x/y", "docker.io/x/y"),
            (
                longest.as_str(),
                &format!("docker.io/library/{}", "a".repeat(247)),
            ),
        ] {
            let repository = Repository::parse(text).unwrap();
            assert!(matches!(repository.0, Name::Hub { .. }), "{text}");
            assert_eq!(repository.as_str(), name);
        }
        assert_eq!(
            format!("{:?}", Repository::parse("nginx").unwrap()),
            r#"Repository("docker.io/library/nginx")"#
        );
    }

    #[test]
    fn a_docker_ref_is_written_in_its_buffer_unless_too_long() {
        let far = format!("{}.test/app", "a".repeat(600));
        for (text, written) in [
            ("nginx", "docker.io/library/nginx:latest"),
            ("reg.test/app:1", "reg.test/app:1"),
            (
                &format!("reg.test/app:1@{SHA}"),
                &format!("reg.test/app@{SHA}"),
            ),
        ] {
            let docker = DockerRef::parse(text).unwrap();
            assert!(matches!(docker.0, Written::Buffer { .. }), "{text}");
            assert_eq!(docker.as_str(), written);
        }
        let docker = DockerRef::parse(&far).unwrap();
        assert!(matches!(docker.0, Written::Owned(_)));
        assert_eq!(docker.as_str(), format!("{far}:latest"));
        assert_eq!(
            format!("{:?}", DockerRef::parse("nginx").unwrap()),
            r#"DockerRef("docker.io/library/nginx:latest")"#
        );
    }

    fn docker(text: &str) -> String {
        Reference::parse_docker_ref(text)
            .unwrap_or_else(|e| panic!("{text}: {e}"))
            .to_string()
    }

    #[test]
    fn names_are_normalized_as_the_cri_plugin_does() {
        for (text, normalized) in [
            ("nginx", "docker.io/library/nginx:latest"),
            ("nginx:1.27", "docker.io/library/nginx:1.27"),
            ("library/nginx", "docker.io/library/nginx:latest"),
            ("docker.io/nginx", "docker.io/library/nginx:latest"),
            ("index.docker.io/nginx", "docker.io/library/nginx:latest"),
            ("index.docker.io/org/app:1", "docker.io/org/app:1"),
            ("org/app", "docker.io/org/app:latest"),
            ("localhost/app", "localhost/app:latest"),
            ("localhost:5000/app", "localhost:5000/app:latest"),
            ("registry.example/app", "registry.example/app:latest"),
            (
                "registry.example:5000/a/b:v1",
                "registry.example:5000/a/b:v1",
            ),
            ("[::1]:5000/app", "[::1]:5000/app:latest"),
            ("Registry.Example/app", "Registry.Example/app:latest"),
            ("UPPER/app", "UPPER/app:latest"),
        ] {
            assert_eq!(docker(text), normalized, "{text}");
        }
    }

    #[test]
    fn a_name_with_a_digest_keeps_only_the_digest() {
        assert_eq!(
            docker(&format!("nginx:1.27@{SHA}")),
            format!("docker.io/library/nginx@{SHA}")
        );
        assert_eq!(
            docker(&format!("nginx@{SHA}")),
            format!("docker.io/library/nginx@{SHA}")
        );
        let named =
            Reference::parse_normalized_named(&format!("nginx:1.27@{SHA}")).expect("a name");
        assert_eq!(named.tag(), Some("1.27"));
        assert_eq!(
            named.digest().map(ToString::to_string),
            Some(SHA.to_owned())
        );
        let bare = Reference::parse_normalized_named("nginx").expect("a name");
        assert_eq!(bare.tag(), None);
        assert_eq!((bare.domain(), bare.path()), ("docker.io", "library/nginx"));
        assert_eq!(bare.name(), "docker.io/library/nginx");
    }

    #[test]
    fn a_first_segment_that_is_no_domain_makes_the_whole_name_a_path() {
        let named = Reference::parse_normalized_named("my_registry.example/app").expect("a name");
        assert_eq!(
            (named.domain(), named.path()),
            ("", "my_registry.example/app")
        );
        assert_eq!(named.name(), "my_registry.example/app");
    }

    #[test]
    fn invalid_names_are_refused() {
        let hex = "a".repeat(64);
        let long = format!("registry.example/{}", "a".repeat(256));
        for (text, error) in [
            ("", ReferenceError::InvalidFormat),
            ("org/App", ReferenceError::Uppercase),
            // Go lowers `İ` to `i`, so the tag is upper case rather than invalid.
            ("nginx:\u{130}", ReferenceError::Uppercase),
            ("\u{130}/app", ReferenceError::Uppercase),
            ("a//b", ReferenceError::InvalidFormat),
            ("a/-b", ReferenceError::InvalidFormat),
            ("a/b-", ReferenceError::InvalidFormat),
            ("a/b___c", ReferenceError::InvalidFormat),
            ("a/b._c", ReferenceError::InvalidFormat),
            ("nginx:", ReferenceError::InvalidFormat),
            ("nginx:bad tag", ReferenceError::InvalidFormat),
            ("nginx@sha256", ReferenceError::InvalidFormat),
            ("nginx@sha256:abc", ReferenceError::InvalidFormat),
            ("nginx:a:b", ReferenceError::InvalidFormat),
            ("nginx@@x", ReferenceError::InvalidFormat),
            ("[::g]/app", ReferenceError::InvalidFormat),
            (hex.as_str(), ReferenceError::ImageId),
            (long.as_str(), ReferenceError::TooLong),
        ] {
            assert_eq!(Reference::parse_docker_ref(text), Err(error), "{text:?}");
        }
        assert_eq!(
            Reference::parse_docker_ref(&format!("nginx@sha1:{}", "a".repeat(40))),
            Err(ReferenceError::DigestUnsupported)
        );
        assert_eq!(
            Reference::parse_docker_ref(&format!("nginx@sha256:{}", "a".repeat(63))),
            Err(ReferenceError::DigestLength)
        );
        assert_eq!(
            Reference::parse_docker_ref(&format!("nginx@sha256:{}", "A".repeat(64))),
            Err(ReferenceError::DigestFormat)
        );
    }

    #[test]
    fn tags_are_up_to_128_characters_of_a_word_and_dots_and_hyphens() {
        assert!(Reference::parse_docker_ref(&format!("nginx:{}", "a".repeat(128))).is_ok());
        assert!(Reference::parse_docker_ref(&format!("nginx:{}", "a".repeat(129))).is_err());
        for tag in ["_x", "1.2-3_4", "A"] {
            assert!(
                Reference::parse_docker_ref(&format!("nginx:{tag}")).is_ok(),
                "{tag}"
            );
        }
        for tag in [".x", "-x", "a+b"] {
            assert!(
                Reference::parse_docker_ref(&format!("nginx:{tag}")).is_err(),
                "{tag}"
            );
        }
    }

    #[test]
    fn digests_of_sha384_and_sha512_are_known() {
        for (algorithm, size) in [("sha384", 96), ("sha512", 128)] {
            let text = format!("nginx@{algorithm}:{}", "b".repeat(size));
            assert!(Reference::parse_docker_ref(&text).is_ok(), "{text}");
        }
        let digest = Digest::parse(SHA).expect("a digest");
        assert_eq!((digest.algorithm(), digest.encoded().len()), ("sha256", 64));
    }

    #[test]
    fn a_digest_prints_hashes_and_compares_by_its_text() {
        let hash = |digest: &Digest| {
            let mut hasher = std::hash::DefaultHasher::new();
            digest.hash(&mut hasher);
            hasher.finish()
        };
        let texts = [
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "b".repeat(64)),
            format!("sha512:{}", "a".repeat(128)),
        ];
        let digests = texts
            .each_ref()
            .map(|t| Digest::parse(t).expect("a digest"));
        for (text, digest) in texts.iter().zip(&digests) {
            assert_eq!(digest.to_string(), *text);
            let again = Digest::parse(text).expect("a digest");
            assert_eq!((&again, hash(&again)), (digest, hash(digest)));
        }
        for (i, a) in digests.iter().enumerate() {
            for b in &digests[i + 1..] {
                assert_ne!(a, b);
                assert_ne!(hash(a), hash(b), "{a} and {b}");
            }
        }
        let [first, ..] = &digests;
        assert_eq!(
            format!("{first:?}"),
            format!(
                "Digest {{ algorithm: \"sha256\", encoded: \"{}\" }}",
                "a".repeat(64)
            )
        );
    }

    #[test]
    fn a_path_component_has_one_separator_between_alphanumerics() {
        for good in ["a", "a.b", "a_b", "a__b", "a-b", "a---b", "a.b-c_d", "0a"] {
            assert!(is_path_component(good), "{good}");
        }
        for bad in [
            "", ".", "a.", ".a", "a..b", "a___b", "a._b", "a-_b", "A", "a/b", "a b",
        ] {
            assert!(!is_path_component(bad), "{bad}");
        }
    }

    #[test]
    fn domains_are_dotted_labels_or_a_bracketed_address_with_an_optional_port() {
        for good in [
            "a",
            "a.io",
            "a-b.io:5000",
            "1.2.3.4:80",
            "[::1]",
            "[fe80::1]:5000",
            "A.IO",
        ] {
            assert!(is_domain_and_port(good), "{good}");
        }
        for bad in [
            "", "-a", "a-", "a..b", "a:", "a:x", "[]", "[::1", "[::1]x", "[::1]:", "[::g]", "a_b",
        ] {
            assert!(!is_domain_and_port(bad), "{bad}");
        }
    }
}
