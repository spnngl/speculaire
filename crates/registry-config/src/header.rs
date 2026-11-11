use std::collections::BTreeMap;

use secrecy::SecretString;
use serde::Deserialize;

/// HTTP headers a registry config adds to the requests to a registry: names as written, values secret.
///
/// A value can be a token (`Authorization`), so it is a [`SecretString`] (D37): it prints as `[REDACTED]`.
pub type Headers = BTreeMap<String, Vec<SecretString>>;

/// The value of a `header` key in `hosts.toml`: a string, or an array of strings.
#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum HeaderValue {
    One(SecretString),
    Many(Vec<SecretString>),
}

impl HeaderValue {
    pub(crate) fn values(&self) -> Vec<SecretString> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}
