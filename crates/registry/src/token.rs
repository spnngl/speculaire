//! Bearer tokens: asked of the realm a challenge names, and kept until they expire.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

/// How long a token that names no lifetime lasts: the distribution spec's default.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(60);

/// The share of a lifetime a token is used for: it is replaced a little before the registry stops accepting it.
const LIFETIME_NUMERATOR: u32 = 9;
const LIFETIME_DENOMINATOR: u32 = 10;

/// What identifies a token: the registry host it is for, and what it allows.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    /// The `host:port` of the registry.
    pub(crate) authority: String,
    /// The scope, such as `repository:library/busybox:pull`.
    pub(crate) scope: String,
}

struct Held {
    token: SecretString,
    expires: Instant,
}

/// The tokens in use, per host and scope, in memory (D88).
#[derive(Default)]
pub(crate) struct Tokens {
    held: Mutex<HashMap<Key, Held>>,
}

impl Tokens {
    /// The token for `key` if one is held that has not expired.
    pub(crate) fn get(&self, key: &Key, now: Instant) -> Option<SecretString> {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match held.get(key) {
            Some(entry) if entry.expires > now => Some(entry.token.clone()),
            Some(_) => {
                held.remove(key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn put(&self, key: Key, token: SecretString, lifetime: Duration, now: Instant) {
        let expires = now + lifetime * LIFETIME_NUMERATOR / LIFETIME_DENOMINATOR;
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key, Held { token, expires });
    }

    /// Forgets the token for `key`, which the registry refused.
    pub(crate) fn forget(&self, key: &Key) {
        self.held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(key);
    }
}

/// The answer of a token endpoint.
#[derive(Deserialize)]
struct Answer {
    token: Option<SecretString>,
    access_token: Option<SecretString>,
    expires_in: Option<u64>,
}

/// What a token endpoint's body says: the token, and how long it lasts.
///
/// `token` is the distribution spec's name for it, `access_token` `OAuth2`'s; the first wins. A lifetime under 60 s is
/// raised to the default, as the spec says clients may assume.
pub(crate) fn parse_answer(body: &[u8]) -> Option<(SecretString, Duration)> {
    let answer: Answer = serde_json::from_slice(body).ok()?;
    let token = [answer.token, answer.access_token]
        .into_iter()
        .flatten()
        .find(|token| !token.expose_secret().is_empty())?;
    let lifetime = answer.expires_in.map_or(DEFAULT_LIFETIME, |s| {
        Duration::from_secs(s).max(DEFAULT_LIFETIME)
    });
    Some((token, lifetime))
}

/// The query of a token request: `service` and `scope`, percent-encoded.
pub(crate) fn query(service: &str, scope: &str) -> String {
    let encode = |text: &str| utf8_percent_encode(text, NON_ALPHANUMERIC).to_string();
    let mut parts = Vec::new();
    if !service.is_empty() {
        parts.push(format!("service={}", encode(service)));
    }
    if !scope.is_empty() {
        parts.push(format!("scope={}", encode(scope)));
    }
    parts.join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(scope: &str) -> Key {
        Key {
            authority: "registry.example".to_owned(),
            scope: scope.to_owned(),
        }
    }

    #[test]
    fn a_token_is_held_until_nine_tenths_of_its_lifetime() {
        let tokens = Tokens::default();
        let start = Instant::now();
        tokens.put(
            key("a"),
            SecretString::from("t".to_owned()),
            Duration::from_secs(100),
            start,
        );
        let held = |at: Duration| {
            tokens
                .get(&key("a"), start + at)
                .map(|t| t.expose_secret().to_owned())
        };
        assert_eq!(held(Duration::from_secs(89)).as_deref(), Some("t"));
        assert_eq!(held(Duration::from_secs(90)), None);
        // Expired tokens are gone.
        assert_eq!(held(Duration::ZERO), None);
        assert!(tokens.get(&key("b"), start).is_none());
    }

    #[test]
    fn a_forgotten_token_is_gone_and_scopes_are_apart() {
        let tokens = Tokens::default();
        let now = Instant::now();
        tokens.put(
            key("a"),
            SecretString::from("ta".to_owned()),
            Duration::from_secs(60),
            now,
        );
        tokens.put(
            key("b"),
            SecretString::from("tb".to_owned()),
            Duration::from_secs(60),
            now,
        );
        tokens.forget(&key("a"));
        assert!(tokens.get(&key("a"), now).is_none());
        assert_eq!(tokens.get(&key("b"), now).unwrap().expose_secret(), "tb");
    }

    #[test]
    fn the_answer_has_a_token_and_a_lifetime_of_at_least_a_minute() {
        let read = |body: &str| {
            parse_answer(body.as_bytes()).map(|(t, d)| (t.expose_secret().to_owned(), d))
        };
        assert_eq!(
            read(r#"{"token":"abc","expires_in":300}"#),
            Some(("abc".to_owned(), Duration::from_secs(300)))
        );
        assert_eq!(
            read(r#"{"access_token":"def"}"#),
            Some(("def".to_owned(), Duration::from_secs(60)))
        );
        assert_eq!(
            read(r#"{"token":"abc","access_token":"def","expires_in":5}"#),
            Some(("abc".to_owned(), Duration::from_secs(60)))
        );
        assert_eq!(
            read(r#"{"token":"","access_token":"def"}"#).unwrap().0,
            "def"
        );
        assert_eq!(read(r#"{"token":""}"#), None);
        assert_eq!(read("{}"), None);
        assert_eq!(read("not json"), None);
        assert_eq!(read(r#"{"token":5}"#), None);
    }

    #[test]
    fn the_query_names_what_is_set_and_encodes_it() {
        assert_eq!(
            query("registry.docker.io", "repository:library/busybox:pull"),
            "service=registry%2Edocker%2Eio&scope=repository%3Alibrary%2Fbusybox%3Apull"
        );
        assert_eq!(
            query("", "repository:a:pull"),
            "scope=repository%3Aa%3Apull"
        );
        assert_eq!(query("s", ""), "service=s");
        assert_eq!(query("", ""), "");
    }
}
