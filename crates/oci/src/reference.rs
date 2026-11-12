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

/// `NameTotalLengthMax`: the longest repository path.
const PATH_LENGTH_MAX: usize = 255;
/// The registry of a name without one, and the one `index.docker.io` stands for.
const DEFAULT_DOMAIN: &str = "docker.io";
const LEGACY_DEFAULT_DOMAIN: &str = "index.docker.io";
/// The namespace of official images on the default registry.
const OFFICIAL_REPO_PREFIX: &str = "library/";
/// The tag of a name that has neither tag nor digest.
const DEFAULT_TAG: &str = "latest";

/// A reference that is not valid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ReferenceError {
    /// The text is empty.
    #[error("repository name must have at least one component")]
    Empty,
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
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Digest {
    algorithm: String,
    encoded: String,
}

impl Digest {
    /// `Digest.Validate`: the algorithm must be one go-digest registers by default, and the hash lower-case hex of
    /// its size.
    fn parse(text: &str) -> Result<Self, ReferenceError> {
        let (algorithm, encoded) = match text.split_once(':') {
            Some((algorithm, encoded)) if !algorithm.is_empty() && !encoded.is_empty() => {
                (algorithm, encoded)
            }
            _ => return Err(ReferenceError::DigestFormat),
        };
        let size = match algorithm {
            "sha256" => 64,
            "sha384" => 96,
            "sha512" => 128,
            _ => return Err(ReferenceError::DigestUnsupported),
        };
        if !encoded
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(ReferenceError::DigestFormat);
        }
        if encoded.len() != size {
            return Err(ReferenceError::DigestLength);
        }
        Ok(Self {
            algorithm: algorithm.to_owned(),
            encoded: encoded.to_owned(),
        })
    }

    /// The algorithm, such as `sha256`.
    #[must_use]
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    /// The hash, in lower-case hexadecimal.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm, self.encoded)
    }
}

/// A normalized image reference: a repository with a tag, a digest, both, or neither.
///
/// The repository is `domain/path`. The domain is empty for the one name the library cannot split, a first segment
/// that is not a valid domain but is a valid path component (`my_registry.example/app`): the whole name is then the
/// path, as in the library.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Reference {
    domain: String,
    path: String,
    tag: Option<String>,
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
            named.tag = None;
        } else if named.tag.is_none() {
            named.tag = Some(DEFAULT_TAG.to_owned());
        }
        Ok(named)
    }

    /// `ParseNormalizedNamed`: the name is normalized, and a missing tag stays missing.
    ///
    /// # Errors
    ///
    /// As [`Reference::parse_docker_ref`].
    pub fn parse_normalized_named(text: &str) -> Result<Self, ReferenceError> {
        if is_image_id(text) {
            return Err(ReferenceError::ImageId);
        }
        let (domain, remainder) = split_docker_domain(text);
        let remote = remainder.split(':').next().unwrap_or(&remainder);
        if remote.to_lowercase() != remote {
            return Err(ReferenceError::Uppercase);
        }
        Self::parse(&format!("{domain}/{remainder}"))
    }

    /// `Parse`: the reference as written, without normalization.
    fn parse(text: &str) -> Result<Self, ReferenceError> {
        let Some((name, tag, digest)) = split_reference(text) else {
            return Err(if text.is_empty() {
                ReferenceError::Empty
            } else if split_reference(&text.to_lowercase()).is_some() {
                ReferenceError::Uppercase
            } else {
                ReferenceError::InvalidFormat
            });
        };
        let (domain, path) = split_name(name).unwrap_or(("", name));
        if path.len() > PATH_LENGTH_MAX {
            return Err(ReferenceError::TooLong);
        }
        Ok(Self {
            domain: domain.to_owned(),
            path: path.to_owned(),
            tag: tag.map(str::to_owned),
            digest: digest.map(Digest::parse).transpose()?,
        })
    }

    /// The registry, such as `docker.io` or `registry.example:5000`.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The repository below the registry, such as `library/nginx`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The repository name, `domain/path`: what policies match (D11).
    #[must_use]
    pub fn name(&self) -> String {
        if self.domain.is_empty() {
            self.path.clone()
        } else {
            format!("{}/{}", self.domain, self.path)
        }
    }

    /// The tag, if the reference has one.
    #[must_use]
    pub fn tag(&self) -> Option<&str> {
        self.tag.as_deref()
    }

    /// The digest, if the reference has one.
    #[must_use]
    pub fn digest(&self) -> Option<&Digest> {
        self.digest.as_ref()
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name())?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

/// `splitDockerDomain`: the registry of a name, and the repository below it. A first segment is a registry when it
/// has a `.` or `:`, is `localhost`, or has an upper-case letter; any other name is on Docker Hub, where
/// `nginx` is `library/nginx`.
fn split_docker_domain(name: &str) -> (String, String) {
    let Some((maybe_domain, maybe_remote)) = name.split_once('/') else {
        return (
            DEFAULT_DOMAIN.to_owned(),
            format!("{OFFICIAL_REPO_PREFIX}{name}"),
        );
    };
    let (domain, remote) = if maybe_domain == "localhost" {
        (maybe_domain, maybe_remote)
    } else if maybe_domain == LEGACY_DEFAULT_DOMAIN {
        (DEFAULT_DOMAIN, maybe_remote)
    } else if maybe_domain.contains(['.', ':']) || maybe_domain.to_lowercase() != maybe_domain {
        (maybe_domain, maybe_remote)
    } else {
        (DEFAULT_DOMAIN, name)
    };
    if domain == DEFAULT_DOMAIN && !remote.contains('/') {
        (domain.to_owned(), format!("{OFFICIAL_REPO_PREFIX}{remote}"))
    } else {
        (domain.to_owned(), remote.to_owned())
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
    (1..=128).contains(&bytes.len())
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
