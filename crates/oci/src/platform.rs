//! Platforms, parsed, normalized, formatted and matched as containerd does (D15, D81).
//!
//! Ported from `github.com/containerd/platforms` v1.0.0-rc.5, as containerd v2.4.2 vendors it (`platforms.go`,
//! `database.go`, `compare.go`), for Linux. The data is `oci-spec`'s [`Platform`]. (D25)
//!
//! Matching a Windows platform needs the library's OS version logic, which a Linux node never uses: [`Matcher::only`]
//! refuses one. Candidates of any OS are matched.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use oci_spec::image::{Arch, Os, Platform, PlatformBuilder};

/// What a specifier that leaves out its OS or its architecture takes from the process (`runtime.GOOS`,
/// `runtime.GOARCH`, and the ARM variant of `cpuVariant`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    /// The OS in Go's names, such as `linux`.
    pub os: String,
    /// The architecture in Go's names, such as `amd64` or `arm64`.
    pub arch: String,
    /// The CPU variant of a 32-bit ARM host, such as `v7`; empty otherwise.
    pub variant: String,
}

impl Host {
    /// The platform this binary runs on, in Go's names. Only the architectures the agent ships for have one.
    #[must_use]
    pub fn current() -> Self {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            "x86" => "386",
            other => other,
        };
        Self {
            os: std::env::consts::OS.replace("macos", "darwin"),
            arch: arch.to_owned(),
            variant: String::new(),
        }
    }
}

/// A platform specifier or a matcher that cannot be used.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformError {
    /// The specifier is not a platform.
    #[error("invalid platform specifier {0:?}")]
    Invalid(String),
    /// A matcher for this OS is not supported.
    #[error("matching platforms of {0} is not supported")]
    UnsupportedOs(String),
}

/// A platform as strings, as the library holds it; empty for a field a platform does not have.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
struct Plain {
    os: String,
    architecture: String,
    variant: String,
    os_version: String,
    os_features: Vec<String>,
}

impl From<&Platform> for Plain {
    fn from(platform: &Platform) -> Self {
        Self {
            os: platform.os().to_string(),
            architecture: platform.architecture().to_string(),
            variant: platform.variant().clone().unwrap_or_default(),
            os_version: platform.os_version().clone().unwrap_or_default(),
            os_features: platform.os_features().clone().unwrap_or_default(),
        }
    }
}

impl Plain {
    fn into_platform(self) -> Platform {
        let some = |text: String| if text.is_empty() { None } else { Some(text) };
        let mut builder = PlatformBuilder::default()
            .os(Os::from(self.os.as_str()))
            .architecture(Arch::from(self.architecture.as_str()));
        if let Some(variant) = some(self.variant) {
            builder = builder.variant(variant);
        }
        if let Some(version) = some(self.os_version) {
            builder = builder.os_version(version);
        }
        if !self.os_features.is_empty() {
            builder = builder.os_features(self.os_features);
        }
        builder
            .build()
            .unwrap_or_else(|_| unreachable!("the OS and architecture are set"))
    }
}

fn is_known_os(os: &str) -> bool {
    matches!(
        os,
        "aix"
            | "android"
            | "darwin"
            | "dragonfly"
            | "freebsd"
            | "hurd"
            | "illumos"
            | "ios"
            | "js"
            | "linux"
            | "nacl"
            | "netbsd"
            | "openbsd"
            | "plan9"
            | "solaris"
            | "windows"
            | "zos"
    )
}

fn is_known_arch(arch: &str) -> bool {
    matches!(
        arch,
        "386"
            | "amd64"
            | "amd64p32"
            | "arm"
            | "armbe"
            | "arm64"
            | "arm64be"
            | "ppc64"
            | "ppc64le"
            | "loong64"
            | "mips"
            | "mipsle"
            | "mips64"
            | "mips64le"
            | "mips64p32"
            | "mips64p32le"
            | "ppc"
            | "riscv"
            | "riscv64"
            | "s390"
            | "s390x"
            | "sparc"
            | "sparc64"
            | "wasm"
    )
}

/// `normalizeOS`.
fn normalize_os(os: &str, host: &Host) -> String {
    if os.is_empty() {
        return host.os.clone();
    }
    let os = os.to_lowercase();
    if os == "macos" {
        "darwin".to_owned()
    } else {
        os
    }
}

/// `normalizeArch`.
fn normalize_arch(arch: &str, variant: &str) -> (String, String) {
    let (arch, variant) = (arch.to_lowercase(), variant.to_lowercase());
    let (arch, variant) = match arch.as_str() {
        "i386" => ("386", String::new()),
        "x86_64" | "x86-64" | "amd64" => (
            "amd64",
            if variant == "v1" {
                String::new()
            } else {
                variant
            },
        ),
        "aarch64" | "arm64" => (
            "arm64",
            match variant.as_str() {
                "8" | "v8" | "v8.0" => String::new(),
                "9" | "9.0" | "v9.0" => "v9".to_owned(),
                _ => variant,
            },
        ),
        "armhf" => ("arm", "v7".to_owned()),
        "armel" => ("arm", "v6".to_owned()),
        "arm" => (
            "arm",
            match variant.as_str() {
                "" | "7" => "v7".to_owned(),
                "5" | "6" | "8" => format!("v{variant}"),
                _ => variant,
            },
        ),
        _ => return (arch, variant),
    };
    (arch.to_owned(), variant)
}

/// `Normalize`: the OS and architecture in their canonical names, and the OS features sorted, without duplicates.
fn normalize_plain(platform: &Plain, host: &Host) -> Plain {
    let (architecture, variant) = normalize_arch(&platform.architecture, &platform.variant);
    let mut os_features = platform.os_features.clone();
    os_features.sort();
    os_features.dedup();
    Plain {
        os: normalize_os(&platform.os, host),
        architecture,
        variant,
        os_version: platform.os_version.clone(),
        os_features,
    }
}

/// `Normalize` of a [`Platform`].
#[must_use]
pub fn normalize(platform: &Platform, host: &Host) -> Platform {
    normalize_plain(&Plain::from(platform), host).into_platform()
}

fn is_os_component(part: &str) -> Option<(&str, &str, &str)> {
    // `^([A-Za-z0-9_-]+)(?:\(([A-Za-z0-9_.%-]*)((?:\+[A-Za-z0-9_.%-]+)*)\))?$`
    let os_char = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    let option_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '%' | '-');
    let (os, rest) = match part.find('(') {
        Some(open) => (&part[..open], Some(&part[open + 1..])),
        None => (part, None),
    };
    if os.is_empty() || !os.chars().all(os_char) {
        return None;
    }
    let Some(rest) = rest else {
        return Some((os, "", ""));
    };
    let inner = rest.strip_suffix(')')?;
    let (version, features) = match inner.find('+') {
        Some(plus) => (&inner[..plus], &inner[plus..]),
        None => (inner, ""),
    };
    if !version.chars().all(option_char) {
        return None;
    }
    let features_ok = features.strip_prefix('+').is_none_or(|all| {
        all.split('+')
            .all(|f| !f.is_empty() && f.chars().all(option_char))
    });
    features_ok.then_some((os, version, features))
}

/// `url.PathUnescape`, for the one place the library calls it: `%XX` is a byte.
fn path_unescape(text: &str) -> Option<String> {
    if !text.contains('%') {
        return Some(text.to_owned());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(
                u8::from_str_radix(hex, 16)
                    .ok()
                    .filter(|_| hex.bytes().all(|b| b.is_ascii_hexdigit()))?,
            );
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// `parseOSFeatures`.
fn parse_os_features(text: &str) -> Option<Vec<String>> {
    let mut features = Vec::new();
    for raw in text.split('+') {
        let raw = raw.trim();
        if raw.is_empty() {
            return None;
        }
        let feature = path_unescape(raw)?;
        if !feature.is_empty() {
            features.push(feature);
        }
    }
    Some(features)
}

/// `Parse`: `os[(version[+feature…])]`, `arch`, `os/arch` or `os/arch/variant`. A specifier of one component is an
/// OS when it names a known one, and an architecture otherwise; what it leaves out comes from `host`.
///
/// # Errors
///
/// When the specifier has a wildcard, a component of other characters, an OS version that does not unescape, or
/// names no known OS or architecture.
pub fn parse(specifier: &str, host: &Host) -> Result<Platform, PlatformError> {
    let invalid = || PlatformError::Invalid(specifier.to_owned());
    if specifier.contains('*') {
        return Err(invalid());
    }
    let parts: Vec<&str> = specifier.splitn(4, '/').collect();
    let mut platform = Plain::default();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            let (os, version, features) = is_os_component(part).ok_or_else(invalid)?;
            platform.os = normalize_os(os, host);
            platform.os_version = path_unescape(version).ok_or_else(invalid)?;
            if let Some(features) = features.strip_prefix('+') {
                platform.os_features = parse_os_features(features).ok_or_else(invalid)?;
            }
        } else if part.is_empty()
            || !part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        {
            return Err(invalid());
        }
    }
    match parts.as_slice() {
        [_] => {
            if is_known_os(&platform.os) {
                platform.architecture.clone_from(&host.arch);
                if platform.architecture == "arm" && host.variant != "v7" {
                    platform.variant.clone_from(&host.variant);
                }
                return Ok(platform.into_platform());
            }
            let (arch, variant) = normalize_arch(parts[0], "");
            let variant = if arch == "arm" && variant == "v7" {
                String::new()
            } else {
                variant
            };
            if is_known_arch(&arch) {
                // The specifier named an architecture and was no OS: the OS is the host's, and the first component's
                // version and features stay.
                platform.os.clone_from(&host.os);
                platform.architecture = arch;
                platform.variant = variant;
                return Ok(platform.into_platform());
            }
            Err(invalid())
        }
        [_, arch] => {
            let (arch, variant) = normalize_arch(arch, "");
            platform.architecture.clone_from(&arch);
            platform.variant = if arch == "arm" && variant == "v7" {
                String::new()
            } else {
                variant
            };
            Ok(platform.into_platform())
        }
        [_, arch, variant] => {
            let (arch, variant) = normalize_arch(arch, variant);
            platform.variant = if arch == "arm64" && variant.is_empty() {
                "v8".to_owned()
            } else {
                variant
            };
            platform.architecture = arch;
            Ok(platform.into_platform())
        }
        _ => Err(invalid()),
    }
}

/// `path.Join` of non-empty elements, cleaned.
fn join_clean(elements: &[&str]) -> String {
    let joined = elements
        .iter()
        .filter(|element| !element.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        return String::new();
    }
    let rooted = joined.starts_with('/');
    let mut out: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if out.last().is_some_and(|last| *last != "..") {
                    out.pop();
                } else if !rooted {
                    out.push("..");
                }
            }
            part => out.push(part),
        }
    }
    let path = out.join("/");
    match (rooted, path.is_empty()) {
        (true, _) => format!("/{path}"),
        (false, true) => ".".to_owned(),
        (false, false) => path,
    }
}

/// `Format`: `os/arch[/variant]`, or `unknown` without an OS.
#[must_use]
pub fn format(platform: &Platform) -> String {
    let platform = Plain::from(platform);
    if platform.os.is_empty() {
        return "unknown".to_owned();
    }
    join_clean(&[&platform.os, &platform.architecture, &platform.variant])
}

fn encode_os_option(value: &str) -> String {
    value
        .replace('%', "%25")
        .replace('+', "%2B")
        .replace('(', "%28")
        .replace(')', "%29")
        .replace('/', "%2F")
}

/// `FormatAll`: [`format()`] with the OS version and features, `os(version+feature)/arch/variant`.
#[must_use]
pub fn format_all(platform: &Platform) -> String {
    let platform = Plain::from(platform);
    if platform.os.is_empty() {
        return "unknown".to_owned();
    }
    if platform.os_version.is_empty() && platform.os_features.is_empty() {
        return join_clean(&[&platform.os, &platform.architecture, &platform.variant]);
    }
    let mut features = platform.os_features.clone();
    features.sort();
    let mut formatted = Vec::new();
    let mut previous = "";
    for feature in &features {
        if feature.is_empty() || feature == previous {
            continue;
        }
        previous = feature;
        formatted.push(encode_os_option(feature));
    }
    let formatted = formatted.join("+");
    let version = encode_os_option(&platform.os_version);
    let mut os = platform.os.clone();
    if !version.is_empty() || !formatted.is_empty() {
        os.push('(');
        os.push_str(&version);
        if !formatted.is_empty() {
            os.push('+');
            os.push_str(&formatted);
        }
        os.push(')');
    }
    join_clean(&[&os, &platform.architecture, &platform.variant])
}

/// `arm64variantToVersion`: the `(major, minor)` pairs an arm64 variant implies, newest first.
static ARM64_VARIANTS: LazyLock<BTreeMap<String, Vec<(u32, u32)>>> = LazyLock::new(|| {
    let mut map = BTreeMap::new();
    map.insert("v8".to_owned(), vec![(8, 0)]);
    for minor in 0..=9 {
        map.insert(format!("v8.{minor}"), vec![(8, minor)]);
    }
    map.insert("v9".to_owned(), vec![(9, 0), (8, 5)]);
    for (minor, floor) in [
        (0, 5),
        (1, 6),
        (2, 7),
        (3, 8),
        (4, 9),
        (5, 9),
        (6, 9),
        (7, 9),
    ] {
        map.insert(format!("v9.{minor}"), vec![(9, minor), (8, floor)]);
    }
    map
});

/// `platformVector`: the platform and the ones its hardware also runs, best first.
fn platform_vector(platform: &Plain) -> Vec<Plain> {
    let with = |architecture: &str, variant: String| Plain {
        os: platform.os.clone(),
        architecture: architecture.to_owned(),
        variant,
        os_version: platform.os_version.clone(),
        os_features: platform.os_features.clone(),
    };
    let level = |variant: &str| variant.trim_start_matches('v').parse::<i64>().ok();
    let mut vector = vec![platform.clone()];
    match platform.architecture.as_str() {
        "amd64" => {
            if let Some(version) = level(&platform.variant).filter(|version| *version > 1) {
                for lower in (1..version).rev() {
                    vector.push(with("amd64", format!("v{lower}")));
                }
            }
            vector.push(with("386", String::new()));
        }
        "arm" => {
            if let Some(version) = level(&platform.variant).filter(|version| *version > 5) {
                for lower in (5..version).rev() {
                    vector.push(with("arm", format!("v{lower}")));
                }
            }
        }
        "arm64" => {
            let mut variant = if platform.variant.is_empty() {
                "v8".to_owned()
            } else {
                platform.variant.clone()
            };
            vector.clear();
            let Some(versions) = ARM64_VARIANTS.get(&variant) else {
                return vector;
            };
            for (major, top) in versions {
                for minor in (0..=*top).rev() {
                    let name = if minor == 0 {
                        format!("v{major}")
                    } else {
                        format!("v{major}.{minor}")
                    };
                    vector.push(with("arm64", name));
                }
            }
            if variant.starts_with("v8") || variant.starts_with("v9") {
                "v8".clone_into(&mut variant);
            }
            let _ = variant;
        }
        _ => {}
    }
    vector
}

/// Whether `features` holds every feature of `wanted`, both sorted: the library's walk, which stops at a feature of
/// `features` that sorts after the next wanted one.
fn has_features(features: &[String], wanted: &[String]) -> bool {
    if features.len() < wanted.len() {
        return false;
    }
    let mut j = 0;
    for feature in wanted {
        let mut found = false;
        while j < features.len() {
            if *feature == features[j] {
                found = true;
                j += 1;
                break;
            }
            if *feature < features[j] {
                return false;
            }
            j += 1;
        }
        if !found {
            return false;
        }
    }
    true
}

/// A matcher for the platforms a node can run, best first (`Only` and `OnlyStrict`).
#[derive(Clone, Debug)]
pub struct Matcher {
    host: Host,
    platforms: Vec<Plain>,
}

impl Matcher {
    /// `Only`: the platform and the compatible ones below it: `amd64/v3` also runs `v2`, `v1` and `386`; `arm64`
    /// runs `arm/v8` and the 32-bit ARM variants down to `v5`.
    ///
    /// # Errors
    ///
    /// For a Windows platform.
    pub fn only(platform: &Platform, host: &Host) -> Result<Self, PlatformError> {
        Self::new(platform, host, platform_vector)
    }

    /// `OnlyStrict`: the platform only.
    ///
    /// # Errors
    ///
    /// For a Windows platform.
    pub fn only_strict(platform: &Platform, host: &Host) -> Result<Self, PlatformError> {
        Self::new(platform, host, |platform| vec![platform.clone()])
    }

    fn new(
        platform: &Platform,
        host: &Host,
        vector: impl Fn(&Plain) -> Vec<Plain>,
    ) -> Result<Self, PlatformError> {
        let normalized = normalize_plain(&Plain::from(platform), host);
        if normalized.os == "windows" {
            return Err(PlatformError::UnsupportedOs(normalized.os));
        }
        let platforms = vector(&normalized)
            .iter()
            .map(|platform| normalize_plain(platform, host))
            .collect();
        Ok(Self {
            host: host.clone(),
            platforms,
        })
    }

    /// `matcher.Match` of each platform, any of them.
    #[must_use]
    pub fn matches(&self, candidate: &Platform) -> bool {
        self.platforms
            .iter()
            .any(|platform| self.matches_plain(platform, &Plain::from(candidate)))
    }

    fn matches_plain(&self, platform: &Plain, candidate: &Plain) -> bool {
        let normalized = normalize_plain(candidate, &self.host);
        platform.os == normalized.os
            && platform.architecture == normalized.architecture
            && platform.variant == normalized.variant
            && (normalized.os_features.is_empty()
                || has_features(&platform.os_features, &normalized.os_features))
    }

    /// `orderedPlatformComparer.Less`: whether `a` is a better match than `b`.
    #[must_use]
    pub fn less(&self, a: &Platform, b: &Platform) -> bool {
        self.less_plain(&Plain::from(a), &Plain::from(b))
    }

    fn less_plain(&self, a: &Plain, b: &Plain) -> bool {
        for platform in &self.platforms {
            let (a_matches, b_matches) = (
                self.matches_plain(platform, a),
                self.matches_plain(platform, b),
            );
            if a_matches && !b_matches {
                return true;
            }
            if a_matches || b_matches {
                if a_matches && b_matches && a.os_features.len() != b.os_features.len() {
                    return a.os_features.len() > b.os_features.len();
                }
                return false;
            }
        }
        if !a.os_features.is_empty() || !b.os_features.is_empty() {
            let (mut a, mut b) = (a.clone(), b.clone());
            a.os_features.clear();
            b.os_features.clear();
            return self.less_plain(&a, &b);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host() -> Host {
        Host {
            os: "linux".to_owned(),
            arch: "amd64".to_owned(),
            variant: String::new(),
        }
    }

    fn platform(os: &str, arch: &str, variant: &str) -> Platform {
        Plain {
            os: os.to_owned(),
            architecture: arch.to_owned(),
            variant: variant.to_owned(),
            ..Plain::default()
        }
        .into_platform()
    }

    #[test]
    fn specifiers_are_parsed_and_normalized() {
        for (specifier, formatted) in [
            ("linux/amd64", "linux/amd64"),
            ("linux/x86_64", "linux/amd64"),
            ("linux/aarch64", "linux/arm64"),
            ("linux/arm64/v8", "linux/arm64/v8"),
            ("linux/arm64/8", "linux/arm64/v8"),
            ("linux/arm", "linux/arm"),
            ("linux/arm/v7", "linux/arm/v7"),
            ("linux/armhf", "linux/arm"),
            ("linux/armel", "linux/arm/v6"),
            ("linux/arm/6", "linux/arm/v6"),
            ("macOS/arm64", "darwin/arm64"),
            ("linux/i386", "linux/386"),
            ("linux", "linux/amd64"),
            ("arm64", "linux/arm64"),
            ("windows/amd64", "windows/amd64"),
        ] {
            let parsed = parse(specifier, &host()).unwrap_or_else(|e| panic!("{specifier}: {e}"));
            assert_eq!(format(&parsed), formatted, "{specifier}");
        }
        let versioned = parse("windows(10.0.17763+win32k)/amd64", &host()).expect("a platform");
        assert_eq!(versioned.os_version().as_deref(), Some("10.0.17763"));
        assert_eq!(format_all(&versioned), "windows(10.0.17763+win32k)/amd64");
        let escaped = parse("windows(a%2Bb)/amd64", &host()).expect("a platform");
        assert_eq!(escaped.os_version().as_deref(), Some("a+b"));
        assert_eq!(format_all(&escaped), "windows(a%2Bb)/amd64");
    }

    #[test]
    fn invalid_specifiers_are_refused() {
        for bad in [
            "",
            "*",
            "linux/*",
            "linux/amd64/v8/x",
            "li nux/amd64",
            "linux//amd64",
            "linux/am d64",
            "nothing",
            "linux(a%zz)/amd64",
            "linux(+)/amd64",
            "linux(a+)/amd64",
            "linux(a",
            "(a)/b",
            "linux/amd64/",
        ] {
            assert!(parse(bad, &host()).is_err(), "{bad:?} is accepted");
        }
    }

    #[test]
    fn only_runs_the_compatible_variants() {
        let only = Matcher::only(&platform("linux", "amd64", "v3"), &host()).expect("a matcher");
        for (arch, variant, matched) in [
            ("amd64", "v3", true),
            ("amd64", "v2", true),
            ("amd64", "", true),
            ("amd64", "v4", false),
            ("386", "", true),
            ("arm64", "", false),
        ] {
            assert_eq!(
                only.matches(&platform("linux", arch, variant)),
                matched,
                "{arch}/{variant}"
            );
        }
        assert!(!only.matches(&platform("windows", "amd64", "")));
        let arm = Matcher::only(&platform("linux", "arm64", ""), &host()).expect("a matcher");
        for (arch, variant, matched) in [
            ("arm64", "", true),
            ("arm64", "v8", true),
            ("arm", "v8", true),
            ("arm", "v7", true),
            ("arm", "v5", true),
            ("arm", "v4", false),
            ("arm64", "v8.1", false),
            ("amd64", "", false),
        ] {
            assert_eq!(
                arm.matches(&platform("linux", arch, variant)),
                matched,
                "{arch}/{variant}"
            );
        }
        let newer = Matcher::only(&platform("linux", "arm64", "v9.2"), &host()).expect("a matcher");
        assert!(newer.matches(&platform("linux", "arm64", "v8.7")));
        assert!(newer.matches(&platform("linux", "arm64", "v9.1")));
        assert!(!newer.matches(&platform("linux", "arm64", "v8.8")));
        let unknown =
            Matcher::only(&platform("linux", "arm64", "v8.10"), &host()).expect("a matcher");
        assert!(!unknown.matches(&platform("linux", "arm64", "v8.10")));
    }

    #[test]
    fn only_strict_runs_the_platform_alone_and_a_windows_matcher_is_refused() {
        let strict =
            Matcher::only_strict(&platform("linux", "arm64", ""), &host()).expect("a matcher");
        assert!(strict.matches(&platform("linux", "arm64", "v8")));
        assert!(!strict.matches(&platform("linux", "arm", "v8")));
        assert!(Matcher::only(&platform("windows", "amd64", ""), &host()).is_err());
        assert!(Matcher::only_strict(&platform("Windows", "amd64", ""), &host()).is_err());
    }

    #[test]
    fn better_matches_sort_first() {
        let only = Matcher::only(&platform("linux", "arm64", ""), &host()).expect("a matcher");
        let (arm64, arm, other) = (
            platform("linux", "arm64", "v8"),
            platform("linux", "arm", "v7"),
            platform("linux", "amd64", ""),
        );
        assert!(only.less(&arm64, &arm));
        assert!(!only.less(&arm, &arm64));
        assert!(only.less(&arm, &other));
        assert!(!only.less(&other, &arm));
        assert!(!only.less(&other, &other));
    }

    #[test]
    fn os_features_must_all_be_present_and_more_of_them_sort_first() {
        let node = Plain {
            os: "linux".to_owned(),
            architecture: "amd64".to_owned(),
            os_features: vec!["a".to_owned(), "c".to_owned()],
            ..Plain::default()
        }
        .into_platform();
        let only = Matcher::only(&node, &host()).expect("a matcher");
        let with = |features: &[&str]| {
            Plain {
                os: "linux".to_owned(),
                architecture: "amd64".to_owned(),
                os_features: features.iter().map(|f| (*f).to_owned()).collect(),
                ..Plain::default()
            }
            .into_platform()
        };
        assert!(only.matches(&with(&[])));
        assert!(only.matches(&with(&["a"])));
        assert!(only.matches(&with(&["c", "a"])));
        assert!(!only.matches(&with(&["b"])));
        assert!(!only.matches(&with(&["a", "b", "c"])));
        assert!(only.less(&with(&["a", "c"]), &with(&["a"])));
        assert!(!only.less(&with(&["a"]), &with(&["a", "c"])));
    }

    #[test]
    fn paths_are_joined_and_cleaned_as_go_does() {
        assert_eq!(join_clean(&["linux", "amd64", ""]), "linux/amd64");
        assert_eq!(join_clean(&["a", "..", "b"]), "b");
        assert_eq!(join_clean(&["..", "..", "b"]), "../../b");
        assert_eq!(join_clean(&["a", ".."]), ".");
        assert_eq!(join_clean(&["/", "a"]), "/a");
        assert_eq!(join_clean(&["", ""]), "");
        assert_eq!(join_clean(&["a", ".", "b//c"]), "a/b/c");
    }

    #[test]
    fn the_host_is_this_binarys() {
        let host = Host::current();
        assert!(is_known_os(&host.os) || host.os == "darwin");
        assert!(is_known_arch(&host.arch));
    }
}
