//! The `WWW-Authenticate` header of a registry's 401: what it asks the client to do (RFC 9110 § 11.6.1).
//!
//! A registry answers `Bearer realm="https://auth.example/token",service="registry.example",scope="repository:app:pull"`
//! and the client fetches a token there (the distribution spec's token authentication), or `Basic realm="..."`.

/// One challenge: an authentication scheme and its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The scheme in lower case: `bearer` or `basic`.
    pub scheme: String,
    /// The parameters, names in lower case, values unquoted, in order.
    pub params: Vec<(String, String)>,
}

impl Challenge {
    /// The value of the parameter `name`, which is in lower case.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The challenges of one header value, or of several joined by commas, which is how HTTP combines headers.
///
/// Text that is no challenge ends the list: what was read before it stays. A scheme without parameters, a quoted
/// string with escapes and unquoted token values are read; a parameter without a value ends its challenge.
#[must_use]
pub fn parse(header: &str) -> Vec<Challenge> {
    let mut challenges: Vec<Challenge> = Vec::new();
    let mut rest = header.trim_start();
    while !rest.is_empty() {
        let (word, after) = token(rest);
        if word.is_empty() {
            break;
        }
        let after = after.trim_start();
        // `name=value` after a scheme is a parameter of the current challenge; a word alone, or followed by a
        // token and no `=`, is a new scheme.
        if let Some(value_start) = after.strip_prefix('=')
            && let Some(current) = challenges.last_mut()
        {
            let (value, remaining) = value(value_start.trim_start());
            current.params.push((word.to_ascii_lowercase(), value));
            rest = skip_comma(remaining);
            continue;
        }
        challenges.push(Challenge {
            scheme: word.to_ascii_lowercase(),
            params: Vec::new(),
        });
        rest = skip_comma(after);
    }
    challenges
}

fn skip_comma(text: &str) -> &str {
    text.trim_start().trim_start_matches(',').trim_start()
}

/// The longest token at the start of `text` (RFC 9110 § 5.6.2), and what follows it.
fn token(text: &str) -> (&str, &str) {
    let end = text
        .find(|c: char| !(c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)))
        .unwrap_or(text.len());
    text.split_at(end)
}

/// A parameter value, a quoted string or a token, and what follows it.
fn value(text: &str) -> (String, &str) {
    let Some(quoted) = text.strip_prefix('"') else {
        let (word, rest) = token(text);
        return (word.to_owned(), rest);
    };
    let mut out = String::new();
    let mut chars = quoted.char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '"' => return (out, &quoted[at + 1..]),
            '\\' => {
                if let Some((_, escaped)) = chars.next() {
                    out.push(escaped);
                }
            }
            c => out.push(c),
        }
    }
    // No closing quote: the rest of the header is the value.
    (out, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer(realm: &str, service: &str, scope: &str) -> Challenge {
        Challenge {
            scheme: "bearer".to_owned(),
            params: vec![
                ("realm".to_owned(), realm.to_owned()),
                ("service".to_owned(), service.to_owned()),
                ("scope".to_owned(), scope.to_owned()),
            ],
        }
    }

    #[test]
    fn docker_hubs_challenge_is_read() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/busybox:pull""#;
        assert_eq!(
            parse(header),
            [bearer(
                "https://auth.docker.io/token",
                "registry.docker.io",
                "repository:library/busybox:pull"
            )]
        );
    }

    #[test]
    fn a_basic_challenge_and_several_challenges_are_read() {
        let challenges = parse(
            r#"Basic realm="registry", Bearer realm="https://t/x", error="insufficient_scope""#,
        );
        assert_eq!(challenges.len(), 2);
        assert_eq!(challenges[0].scheme, "basic");
        assert_eq!(challenges[0].param("realm"), Some("registry"));
        assert_eq!(challenges[1].scheme, "bearer");
        assert_eq!(challenges[1].param("error"), Some("insufficient_scope"));
        assert_eq!(challenges[1].param("service"), None);
    }

    #[test]
    fn names_and_schemes_are_lower_cased_and_values_are_not() {
        let challenges = parse(r#"BEARER Realm="https://T/Tok", SERVICE=Reg"#);
        assert_eq!(
            challenges,
            [Challenge {
                scheme: "bearer".to_owned(),
                params: vec![
                    ("realm".to_owned(), "https://T/Tok".to_owned()),
                    ("service".to_owned(), "Reg".to_owned()),
                ],
            }]
        );
    }

    #[test]
    fn quoted_strings_keep_commas_and_escapes() {
        let challenges = parse(r#"Bearer scope="repository:a:pull,push", realm="a\"b\\c""#);
        assert_eq!(challenges[0].param("scope"), Some("repository:a:pull,push"));
        assert_eq!(challenges[0].param("realm"), Some(r#"a"b\c"#));
    }

    #[test]
    fn what_is_no_challenge_gives_none_or_what_came_before() {
        for text in ["", "   ", "=", "\"x\""] {
            assert_eq!(parse(text).len(), 0, "{text:?}");
        }
        let challenges = parse(r#"Basic realm="r", "#);
        assert_eq!(challenges.len(), 1);
        // A quote that never closes takes the rest of the header.
        assert_eq!(
            parse(r#"Bearer realm="open"#)[0].param("realm"),
            Some("open")
        );
        // A scheme with no parameters.
        assert_eq!(parse("Negotiate")[0].params, []);
    }
}
