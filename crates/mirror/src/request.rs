//! What a request asks for: a route of the pull API, and a `Range`.

pub use hyper::Method;
use speculaire_oci::reference::Digest;

/// What the runtime pulls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `/v2/<name>/manifests/<digest>`.
    Manifest,
    /// `/v2/<name>/blobs/<digest>`.
    Blob,
    /// `/v2/<name>/referrers/<digest>`.
    Referrers,
}

impl Kind {
    /// The `kind` label of the mirror's metrics.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::Blob => "blob",
            Self::Referrers => "referrers",
        }
    }
}

/// What a pull names: a digest, or a tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reference {
    /// `sha256:<hex>`: content, found by its hash.
    Digest(Digest),
    /// A tag: a name that someone has to resolve, which on containerd is a miss (D6) and on CRI-O is the relay's to
    /// resolve at upstream (D66).
    Tag(String),
}

impl Reference {
    /// The digest, when it is one.
    #[must_use]
    pub const fn digest(&self) -> Option<&Digest> {
        match self {
            Self::Digest(digest) => Some(digest),
            Self::Tag(_) => None,
        }
    }

    /// A reference by its text: a digest, else a tag (`[\w][\w.-]{0,127}`), else `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        if let Ok(digest) = Digest::parse(text) {
            return Some(Self::Digest(digest));
        }
        let mut chars = text.chars();
        let first = chars.next()?;
        let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        (word(first) && text.len() <= 128 && chars.all(|c| word(c) || c == '.' || c == '-'))
            .then(|| Self::Tag(text.to_owned()))
    }
}

/// A request the mirror answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route<'a> {
    /// `GET /v2/`: the runtime's check that this is a registry.
    Ping,
    /// A pull of `kind`.
    Pull {
        /// What is pulled.
        kind: Kind,
        /// The repository name, `docker.io/library/busybox` on CRI-O, where the first segment is the registry the
        /// image comes from (D66).
        name: &'a str,
        /// What the name is pulled by; `None` when it is no digest and no tag, which is a miss.
        reference: Option<Reference>,
        /// Whether only the head of the response is wanted.
        head: bool,
    },
}

/// The route of a request, or `None` when it is none of the pull API's: the mirror answers those with a 404 too.
///
/// Query parameters, such as containerd's `ns`, are ignored.
#[must_use]
pub fn route<'a>(method: &Method, path: &'a str) -> Option<Route<'a>> {
    let head = match *method {
        Method::GET => false,
        Method::HEAD => true,
        _ => return None,
    };
    let rest = path.strip_prefix("/v2/")?;
    if rest.is_empty() {
        return Some(Route::Ping);
    }
    let (rest, reference) = rest.rsplit_once('/')?;
    let (name, kind) = rest.rsplit_once('/')?;
    if name.split('/').any(str::is_empty) {
        return None;
    }
    let kind = match kind {
        "manifests" => Kind::Manifest,
        "blobs" => Kind::Blob,
        "referrers" => Kind::Referrers,
        _ => return None,
    };
    Some(Route::Pull {
        kind,
        name,
        reference: Reference::parse(reference),
        head,
    })
}

/// A byte range of a body of `size` bytes, both ends included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// The first byte.
    pub first: u64,
    /// The last byte.
    pub last: u64,
}

impl Span {
    /// How many bytes it holds.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.last - self.first + 1
    }

    /// The whole of a body of `size` bytes: `None` for an empty one, which has no bytes to name.
    #[must_use]
    pub const fn whole(size: u64) -> Option<Self> {
        match size.checked_sub(1) {
            Some(last) => Some(Self { first: 0, last }),
            None => None,
        }
    }
}

/// What a `Range` header asks of a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ranged {
    /// No range, or one that is ignored: the whole body.
    Whole,
    /// A satisfiable single range.
    Part(Span),
    /// A single range that starts at or after the end: 416.
    Unsatisfiable,
}

/// Reads a `Range` header against a body of `size` bytes: `bytes=a-b`, `bytes=a-` and `bytes=-n`, one range. Another
/// unit, a list of ranges and text that is no range are ignored, as RFC 9110 § 14.2 allows: the whole body follows. A
/// range that ends before it starts is unsatisfiable, as the distribution-spec conformance suite wants (`run.go`, the
/// `bytes=500-0` request).
#[must_use]
pub fn range(header: Option<&str>, size: u64) -> Ranged {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else {
        return Ranged::Whole;
    };
    if spec.contains(',') {
        return Ranged::Whole;
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return Ranged::Whole;
    };
    let (first, last) = (first.trim(), last.trim());
    let number = |text: &str| text.parse::<u64>().ok();
    match (first.is_empty(), last.is_empty()) {
        // `bytes=-n`: the last n bytes.
        (true, false) => match number(last) {
            Some(0) => Ranged::Unsatisfiable,
            Some(n) => match Span::whole(size) {
                Some(_) => Ranged::Part(Span {
                    first: size.saturating_sub(n),
                    last: size - 1,
                }),
                None => Ranged::Unsatisfiable,
            },
            None => Ranged::Whole,
        },
        // `bytes=a-`.
        (false, true) => match number(first) {
            Some(a) if a < size => Ranged::Part(Span {
                first: a,
                last: size - 1,
            }),
            Some(_) => Ranged::Unsatisfiable,
            None => Ranged::Whole,
        },
        // `bytes=a-b`.
        (false, false) => match (number(first), number(last)) {
            (Some(a), Some(b)) if a > b => Ranged::Unsatisfiable,
            (Some(a), Some(b)) if a < size => Ranged::Part(Span {
                first: a,
                last: b.min(size - 1),
            }),
            (Some(_), Some(_)) => Ranged::Unsatisfiable,
            _ => Ranged::Whole,
        },
        (true, true) => Ranged::Whole,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn pull(method: &Method, path: &str) -> Option<(Kind, bool, bool)> {
        match route(method, path)? {
            Route::Pull {
                kind,
                reference,
                head,
                ..
            } => Some((kind, reference.is_some_and(|r| r.digest().is_some()), head)),
            Route::Ping => None,
        }
    }

    #[test]
    fn the_ping_and_the_three_pulls_are_routes() {
        assert_eq!(route(&Method::GET, "/v2/"), Some(Route::Ping));
        assert_eq!(route(&Method::HEAD, "/v2/"), Some(Route::Ping));
        for (segment, kind) in [
            ("manifests", Kind::Manifest),
            ("blobs", Kind::Blob),
            ("referrers", Kind::Referrers),
        ] {
            let path = format!("/v2/library/busybox/{segment}/{SHA}");
            assert_eq!(pull(&Method::GET, &path), Some((kind, true, false)));
            assert_eq!(pull(&Method::HEAD, &path), Some((kind, true, true)));
        }
    }

    #[test]
    fn the_name_may_have_any_number_of_segments_and_is_kept() {
        for name in ["a", "a/b", "a/b/c/d", "docker.io/library/busybox"] {
            let path = format!("/v2/{name}/blobs/{SHA}");
            assert_eq!(pull(&Method::GET, &path), Some((Kind::Blob, true, false)));
            let Some(Route::Pull { name: got, .. }) = route(&Method::GET, &path) else {
                panic!("no pull");
            };
            assert_eq!(got, name);
        }
    }

    #[test]
    fn a_tag_is_a_pull_without_a_digest_and_a_bad_reference_names_nothing() {
        assert_eq!(
            pull(&Method::GET, "/v2/library/busybox/manifests/latest"),
            Some((Kind::Manifest, false, false))
        );
        let reference = |text: &str| match route(&Method::GET, &format!("/v2/a/manifests/{text}")) {
            Some(Route::Pull { reference, .. }) => reference,
            other => panic!("{other:?}"),
        };
        assert_eq!(
            reference("1.37.2-alpine_3"),
            Some(Reference::Tag("1.37.2-alpine_3".to_owned()))
        );
        assert_eq!(reference("_x"), Some(Reference::Tag("_x".to_owned())));
        assert_eq!(
            reference(&"a".repeat(128)),
            Some(Reference::Tag("a".repeat(128)))
        );
        for bad in [
            "sha256:short",
            ".x",
            "-x",
            "a:b",
            &"a".repeat(129),
            "a%20b",
            "é",
        ] {
            assert_eq!(reference(bad), None, "{bad}");
        }
        assert_eq!(
            pull(&Method::GET, "/v2/a/blobs/sha256:short"),
            Some((Kind::Blob, false, false))
        );
    }

    #[test]
    fn everything_else_is_no_route() {
        for (method, path) in [
            (Method::POST, "/v2/a/blobs/uploads/"),
            (Method::PUT, "/v2/"),
            (Method::DELETE, "/v2/a/manifests/x"),
            (Method::GET, "/"),
            (Method::GET, "/v2"),
            (Method::GET, "/v3/a/blobs/x"),
            (Method::GET, "/v2/blobs/x"),
            (Method::GET, "/v2/a/tags/list"),
            (Method::GET, "/v2//blobs/x"),
            (Method::GET, "/v2/a//blobs/x"),
            (Method::GET, "/v2/a/blobs/x/y"),
            (Method::GET, "/v2/a/unknown/x"),
        ] {
            assert_eq!(route(&method, path), None, "{method} {path}");
        }
    }

    #[test]
    fn labels_are_those_of_the_metrics_catalog() {
        let labels: Vec<_> = [Kind::Manifest, Kind::Blob, Kind::Referrers]
            .map(Kind::label)
            .to_vec();
        assert_eq!(labels, ["manifest", "blob", "referrers"]);
    }

    fn part(first: u64, last: u64) -> Ranged {
        Ranged::Part(Span { first, last })
    }

    #[test]
    fn single_ranges_are_read_against_the_size() {
        for (header, want) in [
            ("bytes=0-0", part(0, 0)),
            ("bytes=500-1499", part(500, 999)),
            ("bytes=100-199", part(100, 199)),
            ("bytes=500-", part(500, 999)),
            ("bytes=-500", part(500, 999)),
            ("bytes=-5000", part(0, 999)),
            ("bytes=900-5000", part(900, 999)),
            ("bytes=999-999", part(999, 999)),
            (" bytes=1-2 ", part(1, 2)),
            ("bytes= 1 - 2 ", part(1, 2)),
        ] {
            assert_eq!(range(Some(header), 1000), want, "{header}");
        }
    }

    #[test]
    fn a_range_past_the_end_is_unsatisfiable() {
        for header in [
            "bytes=1000-",
            "bytes=1000-2000",
            "bytes=5000-10000",
            "bytes=500-0",
            "bytes=-0",
        ] {
            assert_eq!(range(Some(header), 1000), Ranged::Unsatisfiable, "{header}");
        }
        assert_eq!(range(Some("bytes=-1"), 0), Ranged::Unsatisfiable);
        assert_eq!(range(Some("bytes=0-"), 0), Ranged::Unsatisfiable);
    }

    #[test]
    fn what_is_no_single_byte_range_is_ignored() {
        for header in [
            None,
            Some(""),
            Some("items=0-1"),
            Some("bytes=0-1,5-6"),
            Some("bytes=a-b"),
            Some("bytes=-"),
            Some("bytes=1"),
            Some("bytes"),
            Some("bytes=99999999999999999999-"),
            Some("bytes=-99999999999999999999"),
        ] {
            assert_eq!(range(header, 1000), Ranged::Whole, "{header:?}");
        }
    }

    #[test]
    fn spans_count_their_bytes_and_the_whole_has_none_when_empty() {
        assert_eq!(Span { first: 5, last: 9 }.bytes(), 5);
        assert_eq!(Span::whole(3), Some(Span { first: 0, last: 2 }));
        assert_eq!(Span::whole(0), None);
    }
}
