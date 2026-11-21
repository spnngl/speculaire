//! Image globs: which images a policy covers (D11) and which the gate exempts (D18).
//!
//! Ported from sigstore policy-controller v0.15.1 `pkg/apis/glob/glob.go` (`Compile`, Copyright 2022 The Sigstore
//! Authors, Apache-2.0, `NOTICE`). `*` matches any run of characters but `/`, `**` any run at all, and the glob matches
//! the whole name. It differs where D142 says:
//! - A glob matches [`Reference::name`], the normalised repository without its tag or digest (D81). A glob that names
//!   a tag or a digest would match nothing, so it is refused.
//! - `index.docker.io/` at the start reads as `docker.io/`, Docker Hub's name in a normalised reference; `*` and `*/*`
//!   expand to Docker Hub's as upstream (`glob.go:39-46`).
//! - The deprecated fallback of `glob.go:91-95`, a match against the name as the pod spec wrote it, is left out.

use std::fmt;

use regex_automata::meta::{self, Regex};
use serde::{Deserialize, Serialize, Serializer};
use speculaire_oci::reference::Reference;

/// Docker Hub, as a normalised reference names it.
const DOCKER_HUB: &str = "docker.io/";
/// Docker Hub, as go-containerregistry names it and policy-controller's globs spell it (`glob.go:27`).
const INDEX_DOCKER_HUB: &str = "index.docker.io/";

/// A glob over normalised image names, built only from text that [`Glob::new`] accepts; two are equal when their texts
/// are.
#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "String")]
pub struct Glob {
    text: String,
    regex: Regex,
}

/// Why [`Glob::new`] refused a glob.
#[derive(Debug, thiserror::Error)]
pub enum GlobError {
    /// A character outside policy-controller's set (`glob.go:33`), or no character at all.
    #[error("`{0}` is not a glob: use letters, digits and `-_:/*.` only")]
    Characters(String),
    /// A tag or a digest: a glob matches the repository name (D142).
    #[error("`{0}` names a tag or a digest, but a glob matches the repository name only")]
    Tag(String),
    /// The translated expression is over regex-automata's size limits.
    #[error("`{0}` is too large: {1}")]
    TooLarge(String, Box<meta::BuildError>),
}

impl Glob {
    /// The glob `text`, as a policy or the config writes it.
    ///
    /// # Errors
    ///
    /// When `text` is empty, holds a character outside `[a-zA-Z0-9-_:/*.]`, or names a tag or a digest.
    pub fn new(text: &str) -> Result<Self, GlobError> {
        let expanded = match text {
            "*" => "docker.io/library/*",
            "*/*" => "docker.io/*/*",
            other => other,
        };
        let expanded = expanded
            .strip_prefix(INDEX_DOCKER_HUB)
            .map_or_else(|| expanded.to_owned(), |rest| format!("{DOCKER_HUB}{rest}"));
        let allowed = |c: char| c.is_ascii_alphanumeric() || "-_:/*.@".contains(c);
        if expanded.is_empty() || !expanded.chars().all(allowed) {
            return Err(GlobError::Characters(text.to_owned()));
        }
        // A colon in the last segment, or any `@`, can only stand before a tag or a digest: a port is in the first.
        let last = expanded.rsplit('/').next().unwrap_or(&expanded);
        if expanded.contains('@') || last.contains(':') {
            return Err(GlobError::Tag(text.to_owned()));
        }
        let regex = Regex::new(&translate(&expanded))
            .map_err(|e| GlobError::TooLarge(text.to_owned(), Box::new(e)))?;
        Ok(Self {
            text: text.to_owned(),
            regex,
        })
    }

    /// Whether the glob matches the name of `reference`.
    #[must_use]
    pub fn matches(&self, reference: &Reference) -> bool {
        self.is_match(reference.name())
    }

    /// Whether the glob matches `name`, a [`Reference::name`].
    pub(crate) fn is_match(&self, name: &str) -> bool {
        self.regex.is_match(name)
    }
}

/// The expression `glob.go:54-63` makes: `.` is literal, `**` any text, `*` any text without `/`, all anchored.
fn translate(glob: &str) -> String {
    let mut pattern = String::with_capacity(glob.len() * 2 + 2);
    pattern.push('^');
    let mut chars = glob.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '.' => pattern.push_str(r"\."),
            '*' if chars.next_if_eq(&'*').is_some() => pattern.push_str(".*"),
            '*' => pattern.push_str("[^/]*"),
            other => pattern.push(other),
        }
    }
    pattern.push('$');
    pattern
}

impl fmt::Display for Glob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl PartialEq for Glob {
    fn eq(&self, other: &Self) -> bool {
        self.text == other.text
    }
}

impl Eq for Glob {}

impl Serialize for Glob {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.text)
    }
}

impl TryFrom<String> for Glob {
    type Error = GlobError;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::new(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(glob: &str, image: &str) -> bool {
        let reference = Reference::parse_docker_ref(image).unwrap();
        Glob::new(glob).unwrap().matches(&reference)
    }

    #[test]
    fn globs_of_the_same_text_are_equal_and_serialise_as_it() {
        let glob = Glob::new("reg.test/**").unwrap();
        assert_eq!(glob, Glob::new("reg.test/**").unwrap());
        assert_ne!(glob, Glob::new("reg.test/*").unwrap());
        assert_eq!(serde_json::to_string(&glob).unwrap(), r#""reg.test/**""#);
    }

    /// policy-controller v0.15.1 `pkg/apis/glob/glob_test.go:21-87`, each row as D142 reads it.
    #[test]
    fn policy_controller_globs_match_as_upstream_on_the_repository_name() {
        for (image, glob) in [
            ("foo", "index.docker.io/library/*"),
            ("foo", "index.docker.io/*/*"),
            ("foo", "index.docker.io/**"),
            ("foo", "**"),
            ("myuser/myapp", "index.docker.io/myuser/*"),
            ("myuser/myapp", "index.docker.io/*/*"),
            ("myuser/myapp", "index.docker.io/**"),
            ("myuser/myapp", "**"),
            ("ghcr.io/foo/bar", "ghcr.io/*/*"),
            ("ghcr.io/foo/bar", "ghcr.io/**"),
            ("ghcr.io/foo", "ghcr.io/**"),
            ("ghcr.io/foo", "ghc**"),
            ("ghcr.io/foo", "**"),
            ("ghcr.io/foo", "*/**"),
            ("ghcr.io/foo", "ghcr.io/foo*"),
            ("ghcr.io/foo", "ghcr.io/foo**"),
            ("foo", "*"),
            ("myuser/myapp", "*/*"),
            // Rows that upstream matches with a tag (`:latest`) match the name without it.
            ("foo", "index.docker.io/library/foo"),
            ("myuser/myapp", "index.docker.io/myuser/myapp"),
            // The name a normalised reference gives Docker Hub matches as `index.docker.io/` does.
            ("foo", "docker.io/library/foo"),
            ("foo", "docker.io/library/*"),
            (
                "ghcr.io/foo@sha256:5504f2a95018e3d8a52d80d9e1a128c6ea337581808ff9fe96f5628ce2336350",
                "ghcr.io/foo",
            ),
        ] {
            assert!(matches(glob, image), "{glob} matches {image}");
        }
        for (image, glob) in [
            ("ghcr.io/foo", "ghcr.io/*/*"),
            ("prefix-ghcr.io/foo", "ghcr.io/foo"),
            ("ghcr.io/foo-suffix", "ghcr.io/foo"),
            ("ghcrxio/foo", "ghcr.io/**"),
            // `*` stays within one path segment.
            ("ghcr.io/foo/bar", "ghcr.io/*"),
            ("myuser/myapp", "*"),
            // Upstream matches these through `index.docker.io`, or its deprecated fallback on the text as written.
            ("foo", "index.docker.**"),
            ("foo", "inde**"),
            ("foo", "foo"),
            ("foo", "foo*"),
            ("foo", "foo**"),
            ("myuser/myapp", "myuser/myapp"),
        ] {
            assert!(!matches(glob, image), "{glob} does not match {image}");
        }
    }

    #[test]
    fn a_glob_outside_the_characters_or_naming_a_tag_or_digest_is_refused() {
        for glob in [".+", "[a-z]*", "", "ghcr.io/foo bar"] {
            assert!(
                matches!(Glob::new(glob), Err(GlobError::Characters(_))),
                "{glob}"
            );
        }
        for glob in [
            "index.docker.io/library/foo:latest",
            "index.docker.io/library/foo:*",
            "index.docker.io/library/*:latest",
            "ghcr.io/**:v1",
            "ghcr.io/foo@sha256:5504f2a95018e3d8a52d80d9e1a128c6ea337581808ff9fe96f5628ce2336350",
        ] {
            assert!(matches!(Glob::new(glob), Err(GlobError::Tag(_))), "{glob}");
        }
    }

    #[test]
    fn a_port_is_part_of_the_name() {
        assert!(matches(
            "registry.example:5000/**",
            "registry.example:5000/app:v1"
        ));
        assert!(!matches("registry.example:5000/**", "registry.example/app"));
    }

    #[test]
    fn the_glob_prints_as_written() {
        assert_eq!(Glob::new("*").unwrap().to_string(), "*");
    }
}
