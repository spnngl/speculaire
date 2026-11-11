use std::ops::Range;

use serde::de::DeserializeOwned;
use toml::de::DeTable;

/// Text that is not a valid file: the key, and the line and column when TOML knows them.
///
/// A [`LoadError`](crate::containerd::config::LoadError) or a
/// [`HostsError`](crate::containerd::hosts::HostsError) adds the file.
#[derive(Debug)]
pub struct ParseError {
    key: String,
    position: Option<(usize, usize)>,
    message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some((line, column)) = self.position {
            write!(f, "line {line}, column {column}: ")?;
        }
        if !self.key.is_empty() {
            write!(f, "{}: ", self.key)?;
        }
        f.write_str(&self.message)
    }
}

impl std::error::Error for ParseError {}

impl ParseError {
    pub(crate) fn new(key: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            position: None,
            message: message.into(),
        }
    }

    /// The dotted key that holds the error, such as `host."a.io".ca`; empty for a syntax error outside any key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The line and column (both from 1) of the error, when TOML knows them.
    #[must_use]
    pub fn position(&self) -> Option<(usize, usize)> {
        self.position
    }
}

/// The line and column of a byte span's start in `text`.
fn position(text: &str, span: Option<Range<usize>>) -> Option<(usize, usize)> {
    span.map(|span| {
        let before = text.get(..span.start).unwrap_or(text);
        let line = before.lines().count().max(1) + usize::from(before.ends_with('\n'));
        let column = before.rsplit('\n').next().unwrap_or(before).chars().count() + 1;
        (line, column)
    })
}

/// Parses TOML text into `T`, after `fold` renamed the keys that name a field in another case (go-toml matches them
/// so). Keys `T` does not name are ignored, as containerd ignores them. go-toml refuses a byte order mark.
pub(crate) fn from_toml<T: DeserializeOwned>(
    text: &str,
    fold: impl FnOnce(&mut DeTable<'_>),
) -> Result<T, ParseError> {
    if text.starts_with('\u{feff}') {
        return Err(ParseError {
            key: String::new(),
            position: Some((1, 1)),
            message: "unexpected byte order mark".to_owned(),
        });
    }
    let mut document = DeTable::parse(text).map_err(|e| ParseError {
        key: String::new(),
        position: position(text, e.span()),
        message: e.message().to_owned(),
    })?;
    fold(document.as_mut());
    let deserializer = toml::de::Deserializer::from(document);
    serde_path_to_error::deserialize(deserializer).map_err(|e| {
        let key = e.path().to_string();
        let e = e.into_inner();
        ParseError {
            key,
            position: position(text, e.span()),
            message: e.message().to_owned(),
        }
    })
}

/// Reads a TOML value, which no longer has a position, into `T`.
pub(crate) fn from_value<T: DeserializeOwned>(value: toml::Value) -> Result<T, ParseError> {
    serde_path_to_error::deserialize(value).map_err(|e| {
        let key = e.path().to_string();
        ParseError::new(key, e.into_inner().to_string())
    })
}
