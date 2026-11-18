//! Identity patterns, `subjectRegExp` and `issuerRegExp`, which match only the whole text (D136).

use std::fmt;

use regex_automata::meta::{self, Regex};
use regex_syntax::hir::{Hir, Look};

/// A regular expression that matches a whole string, built only by [`Pattern::new`].
#[derive(Clone, Debug)]
pub struct Pattern {
    text: String,
    regex: Regex,
}

/// Why [`Pattern::new`] refused a pattern.
#[derive(Debug, thiserror::Error)]
pub enum PatternError {
    /// The pattern does not parse on its own.
    #[error("`{0}` is not a regular expression: {1}")]
    Syntax(String, Box<regex_syntax::Error>),
    /// The pattern is over regex-automata's size limits.
    #[error("`{0}` is too large: {1}")]
    TooLarge(String, Box<meta::BuildError>),
}

impl Pattern {
    /// The pattern `text`, parsed alone, then anchored at both ends.
    ///
    /// # Errors
    ///
    /// When `text` does not parse alone, as `a)|(.*` does not, or is too large to build.
    pub fn new(text: &str) -> Result<Self, PatternError> {
        let parsed = regex_syntax::parse(text)
            .map_err(|e| PatternError::Syntax(text.to_owned(), Box::new(e)))?;
        let whole = Hir::concat(vec![Hir::look(Look::Start), parsed, Hir::look(Look::End)]);
        let regex = meta::Builder::new()
            .build_from_hir(&whole)
            .map_err(|e| PatternError::TooLarge(text.to_owned(), Box::new(e)))?;
        Ok(Self {
            text: text.to_owned(),
            regex,
        })
    }

    /// Whether the pattern matches all of `text`.
    #[must_use]
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pattern_matches_the_whole_text_only() {
        let pattern = Pattern::new("https://github.com/myorg/.*").unwrap();
        assert_eq!(pattern.to_string(), "https://github.com/myorg/.*");
        assert!(
            pattern.is_match(
                "https://github.com/myorg/app/.github/workflows/release.yml@refs/tags/v1"
            )
        );
        assert!(!pattern.is_match("https://github.com/myorg-evil/x"));
        assert!(!pattern.is_match("https://evil.example/https://github.com/myorg/x"));
        let prefix = Pattern::new("https://github.com/myorg/").unwrap();
        assert!(!prefix.is_match("https://github.com/myorg/app"));
    }

    #[test]
    fn an_alternation_cannot_escape_the_anchors() {
        let pattern = Pattern::new("a|b").unwrap();
        assert!(!pattern.is_match("ax"));
        assert!(!pattern.is_match("xb"));
        assert!(matches!(
            Pattern::new("a)|(.*"),
            Err(PatternError::Syntax(..))
        ));
    }

    #[test]
    fn a_line_end_is_not_a_text_end() {
        let pattern = Pattern::new("https://accounts.google.com").unwrap();
        assert!(!pattern.is_match("https://accounts.google.com\n"));
        let anchored = Pattern::new("^a$").unwrap();
        assert!(!anchored.is_match("a\nb"));
    }
}
