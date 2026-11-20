//! The NRI version a runtime links, inferred as NRI infers it when the runtime does not announce it (D15, D64, D166).

// Ported from containerd/nri v0.12.3 `pkg/api/version.go:34-205` (`InferVersionFromRuntime` and its table) and
// `pkg/version/version.go:65-119` (`FindClosestMatch`, `stripGitSuffix`), and from golang.org/x/mod v0.32.0
// `semver/semver.go:113-141,178-320` (`Compare`, `parse`), which they call.

use std::cmp::Ordering;

/// What NRI announces when it cannot tell its own version (`UnknownVersion`, `pkg/version/version.go:29`).
pub const UNKNOWN: &str = "0.0.0-unknown";

/// What NRI announces when built within its own repository (`DevelVersion`, `pkg/version/version.go:32`).
pub const DEVEL: &str = "(devel)";

/// Why no NRI version is inferred; the texts are NRI's (`pkg/api/version.go:38,43`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InferError {
    /// NRI's table names containerd and CRI-O only.
    #[error("can't infer version for unknown runtime {0:?}")]
    UnknownRuntime(String),
    /// The runtime version is not semver, or older than the table's first release.
    #[error("failed to find latest version for {0:?}")]
    NoMatch(String),
}

/// containerd's releases and the NRI version each links, oldest first (`pkg/api/version.go:56-105`).
const CONTAINERD: &[(&str, &str)] = &[
    ("v1.7.0", "v0.3.0"),
    ("v1.7.7", "v0.4.0"),
    ("v1.7.14", "v0.6.0"),
    ("v1.7.16", "v0.6.1"),
    ("v1.7.26", "v0.8.0"),
    ("v2.2.0", "v0.10.0"),
    ("v2.2.1", "v0.11.0"),
];

/// CRI-O's releases and the NRI version each links, oldest first (`pkg/api/version.go:106-204`).
const CRIO: &[(&str, &str)] = &[
    ("v1.26.0", "v0.2.0"),
    ("v1.26.2", "v0.3.0"),
    ("v1.26.4", PSEUDO_0_3_1),
    ("v1.27.0", "v0.3.0"),
    ("v1.27.1", PSEUDO_0_3_1),
    ("v1.29.0", "v0.5.0"),
    ("v1.29.2", "v0.6.0"),
    ("v1.31.0", "v0.6.1"),
    ("v1.32.0", "v0.9.0"),
    ("v1.33.0", "v0.9.1-0.20250219030224-e597e7849f24"),
    ("v1.34.0", "v0.10.0"),
    ("v1.35.0", "v0.11.0"),
];

const PSEUDO_0_3_1: &str = "v0.3.1-0.20230504231226-94185418e253";

/// The NRI version `runtime` at `version` links: that of the latest release in NRI's table at or before `version`.
///
/// NRI's table lists every release, each mapped to its NRI version. This one keeps only the releases where the NRI
/// version changes, which yields the same answer for every version.
///
/// # Errors
///
/// When `runtime` is neither `containerd` nor `cri-o`, or `version` is not semver or is older than the table.
///
/// # Panics
///
/// Never: the tables list semver releases.
pub fn infer(runtime: &str, version: &str) -> Result<&'static str, InferError> {
    let table = match runtime {
        "containerd" => CONTAINERD,
        "cri-o" => CRIO,
        _ => return Err(InferError::UnknownRuntime(runtime.to_owned())),
    };
    let no_match = || InferError::NoMatch(version.to_owned());
    let wanted = Semver::parse(strip_git_suffix(version)).ok_or_else(no_match)?;
    table
        .iter()
        .take_while(|(release, _)| {
            let release = Semver::parse(release).expect("NRI's table lists semver releases");
            release.cmp(&wanted) != Ordering::Greater
        })
        .last()
        .map(|&(_, nri)| nri)
        .ok_or_else(no_match)
}

/// `version` without a `git describe` suffix (`-N-gSHA1[.*]`), which semver would order before the release it follows.
fn strip_git_suffix(version: &str) -> &str {
    let Some(parsed) = Semver::parse(version) else {
        return version;
    };
    if !parsed.build.is_empty() {
        return version;
    }
    let Some((commits, rest)) = parsed
        .prerelease
        .strip_prefix('-')
        .and_then(|pre| pre.split_once('-'))
    else {
        return version;
    };
    let Some(sha1) = rest.strip_prefix('g') else {
        return version;
    };
    let sha1 = sha1.split_once('.').map_or(sha1, |(sha1, _)| sha1);
    // Go's `strconv.ParseInt(_, _, 64)`, which Rust's matches: an optional sign, then digits within i64.
    if commits.parse::<i64>().is_err() || i64::from_str_radix(sha1, 16).is_err() {
        return version;
    }
    version
        .strip_suffix(parsed.prerelease)
        .expect("a version ends with its prerelease when it has no build")
}

/// A semantic version as Go's `semver` reads it: `v`, then one to three numbers, a prerelease and build metadata.
#[derive(Debug, Clone, Copy)]
struct Semver<'a> {
    major: &'a str,
    minor: &'a str,
    patch: &'a str,
    /// With its leading `-`, or empty.
    prerelease: &'a str,
    /// With its leading `+`, or empty.
    build: &'a str,
}

impl<'a> Semver<'a> {
    /// `version` read as `semver.parse` does (`semver.go:178-231`): `vMAJOR` and `vMAJOR.MINOR` stand for `.0`s.
    fn parse(version: &'a str) -> Option<Self> {
        let rest = version.strip_prefix('v')?;
        let (major, rest) = number(rest)?;
        let Some(rest) = rest.strip_prefix('.') else {
            return rest.is_empty().then_some(Self::release(major, "0", "0"));
        };
        let (minor, rest) = number(rest)?;
        let Some(rest) = rest.strip_prefix('.') else {
            return rest.is_empty().then_some(Self::release(major, minor, "0"));
        };
        let (patch, rest) = number(rest)?;
        let (prerelease, build) = rest.split_at(rest.find('+').unwrap_or(rest.len()));
        let prerelease_valid = prerelease.is_empty()
            || prerelease
                .strip_prefix('-')
                .is_some_and(|pre| identifiers(pre, true));
        let build_valid = build.is_empty()
            || build
                .strip_prefix('+')
                .is_some_and(|build| identifiers(build, false));
        (prerelease_valid && build_valid).then_some(Self {
            major,
            minor,
            patch,
            prerelease,
            build,
        })
    }

    const fn release(major: &'a str, minor: &'a str, patch: &'a str) -> Self {
        Self {
            major,
            minor,
            patch,
            prerelease: "",
            build: "",
        }
    }
}

impl Ord for Semver<'_> {
    /// `semver.Compare` (`semver.go:119-141`): the numbers, then the prerelease; build metadata is ignored.
    fn cmp(&self, other: &Self) -> Ordering {
        numeric(self.major, other.major)
            .then_with(|| numeric(self.minor, other.minor))
            .then_with(|| numeric(self.patch, other.patch))
            .then_with(|| prerelease(self.prerelease, other.prerelease))
    }
}

impl PartialOrd for Semver<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Semver<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Semver<'_> {}

/// The decimal number `text` starts with, without leading zeros, and what follows it (`parseInt`, `semver.go:233-248`).
fn number(text: &str) -> Option<(&str, &str)> {
    let end = text
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(text.len());
    let (digits, rest) = text.split_at(end);
    let valid = digits.len() == 1 || !digits.is_empty() && !digits.starts_with('0');
    valid.then_some((digits, rest))
}

/// Whether `text` is dot-separated identifiers of `[0-9A-Za-z-]`, none empty, and in a prerelease no number with a
/// leading zero (`parsePrerelease` and `parseBuild`, `semver.go:250-312`).
fn identifiers(text: &str, prerelease: bool) -> bool {
    text.split('.').all(|identifier| {
        let numeric = identifier.bytes().all(|b| b.is_ascii_digit());
        let leading_zero = numeric && identifier.len() > 1 && identifier.starts_with('0');
        !identifier.is_empty()
            && identifier
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !(prerelease && leading_zero)
    })
}

/// Two numbers without leading zeros, of any length, compared (`compareInt`, `semver.go:322-337`).
fn numeric(x: &str, y: &str) -> Ordering {
    x.len().cmp(&y.len()).then_with(|| x.cmp(y))
}

/// Two prereleases compared, each empty or with its leading `-` (`comparePrerelease`, `semver.go:339-399`): a release
/// orders after its prereleases, and numeric identifiers before the others.
fn prerelease(x: &str, y: &str) -> Ordering {
    match (x.strip_prefix('-'), y.strip_prefix('-')) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => {
            let (mut x, mut y) = (x.split('.'), y.split('.'));
            loop {
                match (x.next(), y.next()) {
                    (None, None) => return Ordering::Equal,
                    (None, Some(_)) => return Ordering::Less,
                    (Some(_), None) => return Ordering::Greater,
                    (Some(dx), Some(dy)) => {
                        let order = identifier(dx, dy);
                        if order != Ordering::Equal {
                            return order;
                        }
                    }
                }
            }
        }
    }
}

fn identifier(x: &str, y: &str) -> Ordering {
    let is_numeric = |text: &str| text.bytes().all(|b| b.is_ascii_digit());
    match (is_numeric(x), is_numeric(y)) {
        (true, true) => numeric(x, y),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => x.cmp(y),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_runtime_infers_its_latest_release_at_or_before_its_version() {
        for (runtime, version, nri) in [
            ("containerd", "v1.7.0", "v0.3.0"),
            ("containerd", "v1.7.6", "v0.3.0"),
            ("containerd", "v1.7.7", "v0.4.0"),
            ("containerd", "v2.1.6", "v0.8.0"),
            ("containerd", "v2.2.1", "v0.11.0"),
            ("containerd", "v2.4.2", "v0.11.0"),
            ("containerd", "v2.2.1-rc.1", "v0.10.0"),
            ("containerd", "v2.2.1+meta", "v0.11.0"),
            ("containerd", "v2.2.1-3-gabc", "v0.11.0"),
            ("containerd", "v2.2.0-225-ge9dc15b7a.m", "v0.10.0"),
            ("containerd", "v2.2", "v0.10.0"),
            ("containerd", "v3", "v0.11.0"),
            ("cri-o", "v1.26.4", PSEUDO_0_3_1),
            ("cri-o", "v1.27.0", "v0.3.0"),
            ("cri-o", "v1.35.10", "v0.11.0"),
        ] {
            assert_eq!(infer(runtime, version), Ok(nri), "{runtime} {version}");
        }
    }

    #[test]
    fn a_version_not_semver_or_older_than_the_table_infers_nothing() {
        for version in [
            "",
            "2.4.2",
            "v1.6.99",
            "v1.7.0-rc.1",
            "v1.7.0-3-gabc+meta",
            "v2.2.01",
            "v2.2.1-01",
            "v2.2.1-",
            "v2.2.1-a..b",
            "v2.2.1+",
            "v2.2.1-é",
            "v2.",
            "v2.2.",
            "v2.2.1.4",
            "vx",
        ] {
            let error = InferError::NoMatch(version.to_owned());
            assert_eq!(infer("containerd", version), Err(error), "{version:?}");
        }
        assert_eq!(
            infer("docker", "v29.0.0").unwrap_err().to_string(),
            r#"can't infer version for unknown runtime "docker""#
        );
        assert_eq!(
            infer("cri-o", "1.37.2").unwrap_err().to_string(),
            r#"failed to find latest version for "1.37.2""#
        );
    }

    #[test]
    fn a_git_suffix_is_stripped_only_when_it_counts_commits_after_a_hexadecimal_sha1() {
        for (version, stripped) in [
            ("v2.2.0-225-ge9dc15b7a.m", "v2.2.0"),
            ("v2.2.0-225-gabc", "v2.2.0"),
            ("v2.2.0-1-g-1", "v2.2.0"),
            ("v2.2.0-225-gxyz", "v2.2.0-225-gxyz"),
            ("v2.2.0-225-abc", "v2.2.0-225-abc"),
            ("v2.2.0-x-gabc", "v2.2.0-x-gabc"),
            ("v2.2.0-225", "v2.2.0-225"),
            ("v2.2.0-225-gabc+meta", "v2.2.0-225-gabc+meta"),
            ("v2.2.0", "v2.2.0"),
            ("2.2.0-225-gabc", "2.2.0-225-gabc"),
        ] {
            assert_eq!(strip_git_suffix(version), stripped, "{version}");
        }
    }

    #[test]
    fn semver_orders_as_gos() {
        let ordered = [
            "v1.0.0-1",
            "v1.0.0-2",
            "v1.0.0-10",
            "v1.0.0-a",
            "v1.0.0-a.1",
            "v1.0.0-a.b",
            "v1.0.0-b",
            "v1.0.0",
            "v1.0.1",
            "v1.2.0",
            "v1.10.0",
            "v2.0.0",
            "v10.0.0",
        ];
        for (i, x) in ordered.iter().enumerate() {
            for (j, y) in ordered.iter().enumerate() {
                let (x, y) = (Semver::parse(x).unwrap(), Semver::parse(y).unwrap());
                assert_eq!(x.cmp(&y), i.cmp(&j), "{x:?} {y:?}");
                assert_eq!(x.partial_cmp(&y), Some(i.cmp(&j)));
                assert_eq!(x == y, i == j);
            }
        }
        assert_eq!(Semver::parse("v1.0.0+a"), Semver::parse("v1.0.0+b"));
        assert_eq!(Semver::parse("v1"), Semver::parse("v1.0.0"));
    }
}
