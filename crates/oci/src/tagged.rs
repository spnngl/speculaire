//! A tag of an image, named as containerd's CRI plugin names it, and the key it is announced under (D123).

use std::fmt;

use crate::reference::{Digest, Reference};

/// What a tag key hashes before the name, so that no tag key is the digest of content a node holds.
const DOMAIN: &[u8] = b"speculaire tag\0";

/// A normalized repository with a tag and no digest, `docker.io/library/nginx:1.27`, and its key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tagged {
    /// A reference with a tag and no digest.
    reference: Reference,
    key: Digest,
}

impl Tagged {
    /// Parses a name as `ParseNormalizedNamed` does, keeping it only when it has a tag and no digest.
    ///
    /// `nginx:1.27` is `docker.io/library/nginx:1.27`. A name without a tag is `None` rather than `latest`: a runtime
    /// lists the tags it holds, and a request names its tag.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let reference = Reference::parse_normalized_named(text).ok()?;
        if reference.digest().is_some() {
            return None;
        }
        let tag = reference.tag()?;
        let key = crate::hash::of_parts(
            "sha256",
            &[DOMAIN, reference.name().as_bytes(), b":", tag.as_bytes()],
        )?;
        Some(Self { reference, key })
    }

    /// The repository, `domain/path`.
    #[must_use]
    pub fn name(&self) -> &str {
        self.reference.name()
    }

    /// The tag.
    ///
    /// # Panics
    ///
    /// Never: `parse` keeps only a reference with a tag.
    #[must_use]
    pub fn tag(&self) -> &str {
        self.reference
            .tag()
            .expect("`parse` keeps only a reference with a tag")
    }

    /// The key a node announces the tag under: the SHA-256 of a domain prefix and the name with its tag.
    #[must_use]
    pub const fn key(&self) -> &Digest {
        &self.key
    }
}

impl fmt::Display for Tagged {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.reference.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn named(text: &str) -> String {
        Tagged::parse(text)
            .unwrap_or_else(|| panic!("{text} has a tag"))
            .to_string()
    }

    #[test]
    fn a_tag_is_named_as_containerd_names_it() {
        assert_eq!(named("busybox:1.37"), "docker.io/library/busybox:1.37");
        assert_eq!(
            named("docker.io/busybox:1.37"),
            "docker.io/library/busybox:1.37"
        );
        assert_eq!(
            named("index.docker.io/library/busybox:1.37"),
            "docker.io/library/busybox:1.37"
        );
        assert_eq!(named("ghcr.io/org/app:v1"), "ghcr.io/org/app:v1");
        assert_eq!(
            named("registry.example:5000/app:v1"),
            "registry.example:5000/app:v1"
        );
    }

    #[test]
    fn a_name_without_a_tag_or_with_a_digest_is_no_tag() {
        let digest = format!("sha256:{}", "a".repeat(64));
        assert_eq!(Tagged::parse("busybox"), None, "no default tag");
        assert_eq!(Tagged::parse(&format!("busybox@{digest}")), None);
        assert_eq!(Tagged::parse(&format!("busybox:1.37@{digest}")), None);
        assert_eq!(Tagged::parse("Busybox:1.37"), None);
        assert_eq!(Tagged::parse(":1.37"), None);
    }

    #[test]
    fn the_key_of_a_tag_depends_on_its_normalized_name_only() {
        let short = Tagged::parse("busybox:1.37").map(|t| t.key().clone());
        let long = Tagged::parse("docker.io/library/busybox:1.37").map(|t| t.key().clone());
        assert_eq!(short, long);
        assert_ne!(
            short,
            Tagged::parse("busybox:1.36").map(|t| t.key().clone())
        );
        assert_ne!(
            short,
            Tagged::parse("ghcr.io/library/busybox:1.37").map(|t| t.key().clone())
        );
    }

    #[test]
    fn the_key_of_a_tag_is_not_the_digest_of_its_name() {
        let Some(tagged) = Tagged::parse("busybox:1.37") else {
            panic!("busybox:1.37 has a tag");
        };
        let key = tagged.key();
        assert_eq!(key.algorithm(), "sha256");
        assert_ne!(
            Some(key.clone()),
            crate::hash::of("sha256", b"docker.io/library/busybox:1.37")
        );
        assert_eq!(tagged.name(), "docker.io/library/busybox");
        assert_eq!(tagged.tag(), "1.37");
    }
}
