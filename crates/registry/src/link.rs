//! The `Link` header of a paginated answer: where the next page is (RFC 8288 § 3).
//!
//! The referrers API answers with `Link: </v2/<name>/referrers/<digest>?n=10&last=...>; rel="next"` when its list
//! does not fit one answer (distribution-spec v1.1.1-57-g9727462 `spec.md:675-677`).

/// The URI-reference of the first link whose relation types include `next`, as written: relative or absolute.
///
/// The value is a list of `<uri>` each followed by `;`-separated parameters, the lists of several headers joined by
/// commas. Parameter names and relation types are compared case-insensitively, a `rel` may be a token or a quoted
/// string of space-separated types, and a link's second `rel` is ignored (RFC 8288 § 2.1.1, § 3.3). A link that is
/// no `<uri>` ends the list, and an empty URI, which is the page itself, is never the next one.
#[must_use]
pub fn next(value: &str) -> Option<&str> {
    let mut rest = value;
    loop {
        let (uri, after) = rest
            .trim_start_matches([' ', '\t', ','])
            .strip_prefix('<')?
            .split_once('>')?;
        let (params, tail) = split(after, ',');
        if !uri.is_empty() && rel(params).is_some_and(is_next) {
            return Some(uri);
        }
        rest = tail?;
    }
}

/// The value of the first `rel` parameter of `params`, unquoted.
fn rel(params: &str) -> Option<&str> {
    let mut rest = params;
    loop {
        let (param, tail) = split(rest, ';');
        let (name, value) = param.split_once('=').unwrap_or((param, ""));
        if name.trim().eq_ignore_ascii_case("rel") {
            let value = value.trim();
            return Some(
                value
                    .strip_prefix('"')
                    .and_then(|quoted| quoted.strip_suffix('"'))
                    .unwrap_or(value),
            );
        }
        rest = tail?;
    }
}

fn is_next(types: &str) -> bool {
    types
        .split_ascii_whitespace()
        .any(|kind| kind.eq_ignore_ascii_case("next"))
}

/// The text before the first `separator` outside a quoted string, and the text after it if there is one.
fn split(text: &str, separator: char) -> (&str, Option<&str>) {
    let (mut quoted, mut escaped) = (false, false);
    for (at, c) in text.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            _ if c == separator && !quoted => {
                return (&text[..at], Some(&text[at + c.len_utf8()..]));
            }
            _ => {}
        }
    }
    (text, None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_next_link_of_the_referrers_api_is_found() {
        let uri = "/v2/app/referrers/sha256:aa?n=10&last=sha256:bb";
        assert_eq!(next(&format!(r#"<{uri}>; rel="next""#)), Some(uri));
        assert_eq!(next(&format!("<{uri}>;rel=next")), Some(uri));
        assert_eq!(
            next(r#"<https://r.example/v2/app/referrers/sha256:aa?last=x>; REL="Next""#),
            Some("https://r.example/v2/app/referrers/sha256:aa?last=x")
        );
    }

    #[test]
    fn the_next_link_is_found_among_others() {
        assert_eq!(
            next(r#"</prev>; rel="prev", </next>; title="a, b; rel=next"; rel="last next""#),
            Some("/next")
        );
        assert_eq!(
            next(r#"</a>; rel="prev" , </b> ; rel = "next" ; type="x""#),
            Some("/b")
        );
        assert_eq!(
            next(r#"</a>; title="\"; rel=next", </b>; rel=next"#),
            Some("/b")
        );
        assert_eq!(
            next(r#"</a>; rel="prev"; rel="next", </b>; rel=next"#),
            Some("/b")
        );
        // A backslash escapes only inside a quoted string.
        assert_eq!(next(r"</a>; title=x\, </b>; rel=next"), Some("/b"));
    }

    #[test]
    fn no_next_link_is_none() {
        for value in [
            "",
            ",",
            r#"</a>; rel="prev""#,
            r#"</a>; rel="nextpage""#,
            "</a>; rel",
            "</a>; next",
            r#"<>; rel="next""#,
            r#"/a; rel="next""#,
            r#"</a; rel="next""#,
            r#"junk, </a>; rel="next""#,
            "<\u{e9}",
        ] {
            assert_eq!(next(value), None, "{value:?}");
        }
    }
}
