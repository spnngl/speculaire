//! The value types of the config: each parses its TOML string once and prints it back unchanged.

use std::fmt;
use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use speculaire_reflect::prewarm::{Image, Images};

/// A value that a key does not accept; the message says what the key expects.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct InvalidValue(String);

/// Implements `TryFrom<String>` through `FromStr`, and `From<T> for String` through `Display`, for serde's
/// `try_from` and `into` attributes.
macro_rules! string_conversions {
    ($($t:ty),+ $(,)?) => {$(
        impl TryFrom<String> for $t {
            type Error = InvalidValue;
            fn try_from(s: String) -> Result<Self, InvalidValue> {
                s.parse()
            }
        }
        impl From<$t> for String {
            fn from(v: $t) -> String {
                v.to_string()
            }
        }
    )+};
}

string_conversions!(
    ByteSize,
    Loopback,
    RegistryName,
    PeerAddress,
    Absolute,
    TrustedRoot,
    TufUrl,
    ReflectorUrl,
    NodeName,
    LogFilter
);

/// A duration: a TOML integer or float of seconds, to the millisecond, such as `10` or `0.3` (D138).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span(Duration);

impl Span {
    pub(super) const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    pub(super) const fn from_millis(millis: u64) -> Self {
        Self(Duration::from_millis(millis))
    }

    /// The duration.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0
    }
}

impl<'de> Deserialize<'de> for Span {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(Seconds)
    }
}

/// Reads a [`Span`] from a TOML number; a string or any other type is refused as not a number of seconds.
struct Seconds;

impl Seconds {
    /// Reads `number` printed in decimal: a float prints as the shortest decimal that reads back to it, which is
    /// the one written for any float of up to 15 significant digits, so `0.3` is 300 ms, with no binary rounding.
    fn read<E: serde::de::Error>(number: impl fmt::Display) -> Result<Span, E> {
        let text = number.to_string();
        speculaire_time::duration::parse(&text)
            .map(Span)
            .map_err(|e| E::custom(format_args!("{e}, found {text}")))
    }
}

impl serde::de::Visitor<'_> for Seconds {
    type Value = Span;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a number of seconds, such as 10 or 0.3")
    }

    fn visit_i64<E: serde::de::Error>(self, n: i64) -> Result<Span, E> {
        Self::read(n)
    }

    fn visit_f64<E: serde::de::Error>(self, n: f64) -> Result<Span, E> {
        Self::read(n)
    }
}

impl Serialize for Span {
    /// Whole seconds as a TOML integer, which reading caps at `i64::MAX`, others as the float nearest their decimal,
    /// which prints back as it.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = self.to_string();
        match text.parse::<i64>() {
            Ok(secs) => serializer.serialize_i64(secs),
            Err(_) => serializer.serialize_f64(text.parse().map_err(serde::ser::Error::custom)?),
        }
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        speculaire_time::duration::display(self.0).fmt(f)
    }
}

/// A [`Span`] longer than zero: the period of a timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "Span", into = "Span")]
pub struct Interval(Span);

impl Interval {
    pub(super) const fn from_secs(secs: u64) -> Self {
        assert!(secs > 0, "an interval is longer than zero");
        Self(Span::from_secs(secs))
    }

    /// The duration, never zero.
    #[must_use]
    pub const fn get(self) -> Duration {
        self.0.get()
    }
}

impl TryFrom<Span> for Interval {
    type Error = InvalidValue;
    fn try_from(span: Span) -> Result<Self, InvalidValue> {
        if span.get().is_zero() {
            return Err(InvalidValue(
                "expected a number of seconds longer than zero, found 0".to_owned(),
            ));
        }
        Ok(Self(span))
    }
}

impl From<Interval> for Span {
    fn from(interval: Interval) -> Self {
        interval.0
    }
}

/// A size in bytes, written with a binary unit: `"64MiB"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ByteSize(u64);

/// The units [`ByteSize`] reads and prints, largest first.
const UNITS: [(&str, u64); 5] = [
    ("TiB", 1 << 40),
    ("GiB", 1 << 30),
    ("MiB", 1 << 20),
    ("KiB", 1 << 10),
    ("B", 1),
];

impl ByteSize {
    pub(super) const fn mebibytes(n: u64) -> Self {
        Self(n << 20)
    }

    /// The size in bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl FromStr for ByteSize {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        let invalid = || {
            InvalidValue(format!(
                "expected a size such as \"64MiB\" (units B, KiB, MiB, GiB, TiB), found {s:?}"
            ))
        };
        let digits = s.find(|c: char| !c.is_ascii_digit()).ok_or_else(invalid)?;
        let (number, unit) = s.split_at(digits);
        let number: u64 = number.parse().map_err(|_| invalid())?;
        let (_, scale) = UNITS
            .iter()
            .find(|(name, _)| *name == unit)
            .ok_or_else(invalid)?;
        number.checked_mul(*scale).map(Self).ok_or_else(invalid)
    }
}

impl fmt::Display for ByteSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (unit, scale) = UNITS
            .iter()
            .find(|(_, scale)| self.0 != 0 && self.0.is_multiple_of(*scale))
            .unwrap_or(&("B", 1));
        write!(f, "{}{unit}", self.0 / scale)
    }
}

/// A loopback `ip:port`: the mirror serves only containerd on the same node (D56).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct Loopback(SocketAddr);

impl Loopback {
    pub(super) const MIRROR: Self = Self(SocketAddr::V4(std::net::SocketAddrV4::new(
        std::net::Ipv4Addr::LOCALHOST,
        7480,
    )));

    /// The address.
    #[must_use]
    pub const fn get(self) -> SocketAddr {
        self.0
    }
}

impl FromStr for Loopback {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        match s.parse::<SocketAddr>() {
            Ok(addr) if addr.ip().is_loopback() => Ok(Self(addr)),
            _ => Err(InvalidValue(format!(
                "expected a loopback ip:port such as \"127.0.0.1:7480\", found {s:?}"
            ))),
        }
    }
}

impl fmt::Display for Loopback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A registry the runtime pulls from, as an image name starts with it: a host and an optional port, with no scheme,
/// path or wildcard (D83).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct RegistryName(pub(super) String);

impl RegistryName {
    /// The name, such as `docker.io` or `localhost:5000`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for RegistryName {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        let valid = !s.is_empty()
            && s.len() <= 255
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-.:[]".contains(&b));
        if valid {
            Ok(Self(s.to_owned()))
        } else {
            Err(InvalidValue(format!(
                "expected a registry host and optional port such as \"docker.io\" or \"localhost:5000\", found {s:?}"
            )))
        }
    }
}

impl fmt::Display for RegistryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The address peers fetch from: found at startup (D36), or set (D56).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum PeerAddress {
    /// The local IP of the reflector connection, on port 7481.
    #[default]
    Auto,
    /// This `ip:port`.
    Fixed(SocketAddr),
}

impl FromStr for PeerAddress {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        if s == "auto" {
            return Ok(Self::Auto);
        }
        s.parse()
            .map(Self::Fixed)
            .map_err(|_| InvalidValue(format!("expected \"auto\" or an ip:port, found {s:?}")))
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Fixed(addr) => addr.fmt(f),
        }
    }
}

/// How many blob bodies the peer API serves at once (D24).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(try_from = "Raw", into = "Raw")]
pub enum MaxUploads {
    /// Four per CPU.
    #[default]
    Auto,
    /// This many.
    Fixed(NonZeroU32),
}

impl MaxUploads {
    /// The cap: four per CPU the agent may run on, or the number set.
    #[must_use]
    pub fn get(self) -> NonZeroUsize {
        match self {
            // A count that cannot be read is one CPU.
            Self::Auto => std::thread::available_parallelism()
                .unwrap_or(NonZeroUsize::MIN)
                .saturating_mul(NonZeroUsize::MIN.saturating_add(3)),
            Self::Fixed(n) => NonZeroUsize::try_from(n).unwrap_or(NonZeroUsize::MAX),
        }
    }
}

/// What TOML holds for [`MaxUploads`]: the string `"auto"` or an integer.
#[derive(Deserialize, Serialize)]
#[serde(untagged)]
enum Raw {
    Text(String),
    Number(i64),
}

impl TryFrom<Raw> for MaxUploads {
    type Error = InvalidValue;
    fn try_from(raw: Raw) -> Result<Self, InvalidValue> {
        match raw {
            Raw::Text(s) if s == "auto" => Ok(Self::Auto),
            Raw::Number(n) => u32::try_from(n)
                .ok()
                .and_then(NonZeroU32::new)
                .map(Self::Fixed)
                .ok_or_else(|| {
                    InvalidValue(format!(
                        "expected \"auto\" or an integer from 1 to {}, found {n}",
                        u32::MAX
                    ))
                }),
            Raw::Text(s) => Err(InvalidValue(format!(
                "expected \"auto\" or an integer, found {s:?}"
            ))),
        }
    }
}

impl From<MaxUploads> for Raw {
    fn from(v: MaxUploads) -> Self {
        match v {
            MaxUploads::Auto => Self::Text("auto".to_owned()),
            MaxUploads::Fixed(n) => Self::Number(i64::from(n.get())),
        }
    }
}

/// A share in percent, from 0 to 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "i64", into = "i64")]
pub struct Percent(u8);

impl Percent {
    /// `n` percent, if `n` is at most 100.
    #[must_use]
    pub const fn new(n: u8) -> Option<Self> {
        if n <= 100 { Some(Self(n)) } else { None }
    }

    /// The share, from 0 to 100.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<i64> for Percent {
    type Error = InvalidValue;
    fn try_from(n: i64) -> Result<Self, InvalidValue> {
        u8::try_from(n)
            .ok()
            .and_then(Self::new)
            .ok_or_else(|| InvalidValue(format!("expected an integer from 0 to 100, found {n}")))
    }
}

impl From<Percent> for i64 {
    fn from(v: Percent) -> Self {
        Self::from(v.0)
    }
}

/// An absolute path: the agent runs from `/`, so a relative path would depend on how it was started.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct Absolute(PathBuf);

impl Absolute {
    /// # Panics
    ///
    /// When `path` is relative: defaults are absolute.
    pub(super) fn new(path: &str) -> Self {
        path.parse().expect("default paths are absolute")
    }

    /// The path.
    #[must_use]
    pub fn get(&self) -> &Path {
        &self.0
    }
}

impl FromStr for Absolute {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        let path = Path::new(s);
        if path.is_absolute() {
            Ok(Self(path.to_owned()))
        } else {
            Err(InvalidValue(format!(
                "expected an absolute path, found {s:?}"
            )))
        }
    }
}

impl fmt::Display for Absolute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Built from a `str`, so `display` is lossless.
        self.0.display().fmt(f)
    }
}

/// The Sigstore trust root (D26).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub enum TrustedRoot {
    /// The public-good root, followed through TUF; written `""`.
    #[default]
    PublicGood,
    /// A pinned `trusted_root.json`.
    Pinned(Absolute),
}

impl FromStr for TrustedRoot {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        if s.is_empty() {
            Ok(Self::PublicGood)
        } else {
            s.parse().map(Self::Pinned)
        }
    }
}

impl fmt::Display for TrustedRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PublicGood => Ok(()),
            Self::Pinned(path) => path.fmt(f),
        }
    }
}

/// The `https://` URL of a TUF repository: the host and the path its metadata is under (D143).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct TufUrl {
    authority: String,
    root: String,
}

impl TufUrl {
    /// `host` or `host:port`.
    #[must_use]
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// The path the metadata is under, with no trailing `/`: `""` for the top.
    #[must_use]
    pub fn root(&self) -> &str {
        &self.root
    }
}

impl Default for TufUrl {
    /// Sigstore's public-good repository.
    fn default() -> Self {
        Self {
            authority: "tuf-repo-cdn.sigstore.dev".to_owned(),
            root: String::new(),
        }
    }
}

impl FromStr for TufUrl {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        let invalid = || {
            InvalidValue(format!(
                "expected a URL such as \"https://tuf-repo-cdn.sigstore.dev\", found {s:?}"
            ))
        };
        let uri: http::Uri = s.parse().map_err(|_| invalid())?;
        // `Uri` takes `user:password@` into the authority, which `Display` and `Debug` would print (D37).
        if uri.scheme() != Some(&http::uri::Scheme::HTTPS) || uri.query().is_some() {
            return Err(invalid());
        }
        match uri.authority() {
            Some(authority) if !authority.as_str().contains('@') => Ok(Self {
                authority: authority.as_str().to_owned(),
                root: uri.path().trim_end_matches('/').to_owned(),
            }),
            _ => Err(invalid()),
        }
    }
}

impl fmt::Display for TufUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "https://{}{}", self.authority, self.root)
    }
}

/// The `https://` URL of the reflectors' load balancer (D2), or none, written `""`: then peers are off.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct ReflectorUrl(Option<http::Uri>);

impl ReflectorUrl {
    /// The URL, when one is set.
    #[must_use]
    pub const fn get(&self) -> Option<&http::Uri> {
        self.0.as_ref()
    }
}

impl FromStr for ReflectorUrl {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        if s.is_empty() {
            return Ok(Self(None));
        }
        let invalid = || {
            InvalidValue(format!(
                "expected \"\" or a URL such as \"https://reflector.example:7483\", found {s:?}"
            ))
        };
        let uri: http::Uri = s.parse().map_err(|_| invalid())?;
        let bare = uri.path_and_query().is_none_or(|p| p.as_str() == "/");
        // `Uri` takes `user:password@` into the authority, which `Display` and `Debug` would print (D37).
        let credentials = uri.authority().is_some_and(|a| a.as_str().contains('@'));
        if uri.scheme() == Some(&http::uri::Scheme::HTTPS)
            && uri.host().is_some()
            && bare
            && !credentials
        {
            Ok(Self(Some(uri)))
        } else {
            Err(invalid())
        }
    }
}

impl fmt::Display for ReflectorUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Uri` prints the path `/` it adds to a bare authority; the URL was checked to have no other path.
        match self.0.as_ref().and_then(http::Uri::authority) {
            None => Ok(()),
            Some(authority) => write!(f, "https://{authority}"),
        }
    }
}

/// `prewarm.images`: at most [`LIST_CAP`](speculaire_reflect::push::LIST_CAP) references CRI would pull, each kept as written (D60, D187).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct PrewarmImages(Images);

impl PrewarmImages {
    /// The entries.
    #[must_use]
    pub const fn get(&self) -> &Images {
        &self.0
    }
}

impl TryFrom<Vec<String>> for PrewarmImages {
    type Error = InvalidValue;
    fn try_from(texts: Vec<String>) -> Result<Self, InvalidValue> {
        let images = texts
            .iter()
            .map(|text| Image::parse(text).map_err(|err| InvalidValue(err.to_string())))
            .collect::<Result<_, _>>()?;
        Images::new(images)
            .map(Self)
            .map_err(|err| InvalidValue(err.to_string()))
    }
}

impl From<PrewarmImages> for Vec<String> {
    fn from(images: PrewarmImages) -> Self {
        images
            .0
            .as_slice()
            .iter()
            .map(|image| image.as_str().to_owned())
            .collect()
    }
}

/// A Kubernetes node name: a lowercase RFC 1123 subdomain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct NodeName(String);

impl NodeName {
    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for NodeName {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        let label = |l: &str| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        };
        if s.len() <= 253 && s.split('.').all(label) {
            Ok(Self(s.to_owned()))
        } else {
            Err(InvalidValue(format!(
                "expected a node name (lowercase RFC 1123 subdomain), found {s:?}"
            )))
        }
    }
}

impl fmt::Display for NodeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A log filter in `EnvFilter` syntax (D37), checked when read, with no whitespace around a directive (D137).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct LogFilter(String);

impl LogFilter {
    /// # Panics
    ///
    /// When `filter` does not parse: defaults do.
    pub(super) fn new(filter: &str) -> Self {
        filter.parse().expect("the default log filter parses")
    }

    /// The filter, as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The `EnvFilter` it describes.
    ///
    /// # Panics
    ///
    /// Never: [`FromStr`] built it from a string that parses.
    #[must_use]
    pub fn env_filter(&self) -> tracing_subscriber::EnvFilter {
        env_filter(&self.0).expect("a LogFilter parses: FromStr checked it")
    }
}

fn env_filter(
    s: &str,
) -> Result<tracing_subscriber::EnvFilter, tracing_subscriber::filter::ParseError> {
    tracing_subscriber::EnvFilter::builder().parse(s)
}

impl FromStr for LogFilter {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        // tracing-subscriber 0.3.23 `filter/env/directive.rs:143-155` walks a directive trimmed but slices it as given:
        // whitespace around one misreads it, or panics inside a character (tokio-rs/tracing#3297).
        if s.split(',').any(|directive| directive.trim() != directive) {
            return Err(InvalidValue(format!(
                "expected EnvFilter directives with no whitespace around them, found {s:?}"
            )));
        }
        env_filter(s).map(|_| Self(s.to_owned())).map_err(|e| {
            InvalidValue(format!(
                "expected an EnvFilter directive such as \"warn\", found {s:?}: {e}"
            ))
        })
    }
}

impl fmt::Display for LogFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value of `key = <literal>`, or TOML's error.
    fn read<T: serde::de::DeserializeOwned>(literal: &str) -> Result<T, toml::de::Error> {
        #[derive(Deserialize)]
        struct Key<T> {
            key: T,
        }
        toml::from_str::<Key<T>>(&format!("key = {literal}")).map(|k| k.key)
    }

    #[test]
    fn spans_are_numbers_of_seconds_that_print_as_written() {
        for (literal, duration) in [
            ("0", Duration::ZERO),
            ("10", Duration::from_secs(10)),
            ("0.3", Duration::from_millis(300)),
            ("0.001", Duration::from_millis(1)),
            ("1.25", Duration::from_millis(1250)),
            ("3600", Duration::from_hours(1)),
            (
                "9223372036854775807",
                Duration::from_secs(i64::MAX.unsigned_abs()),
            ),
        ] {
            let span: Span = read(literal).unwrap();
            assert_eq!(span.get(), duration, "{literal}");
            assert_eq!(span.to_string(), literal);
            assert_eq!(toml::Value::try_from(span).unwrap().to_string(), literal);
        }
        for (literal, printed) in [
            ("1e3", "1000"),
            ("1.0", "1"),
            ("0.300", "0.3"),
            ("2.5e-1", "0.25"),
        ] {
            assert_eq!(
                read::<Span>(literal).unwrap().to_string(),
                printed,
                "{literal}"
            );
        }
    }

    #[test]
    fn prewarm_images_print_as_written() {
        let literal =
            r#"["nginx", "registry.example/app@sha256:"#.to_owned() + &"ab".repeat(32) + "\"]";
        let images: PrewarmImages = read(&literal).unwrap();
        assert_eq!(toml::Value::try_from(images).unwrap().to_string(), literal);
    }

    #[test]
    fn spans_refuse_strings_signs_and_finer_than_a_millisecond() {
        for literal in [
            r#""10s""#, r#""10""#, "-1", "-0.0", "0.0001", "0.0015", "1.5e-4", "nan", "inf",
            "1e19", "true",
        ] {
            let err = read::<Span>(literal).unwrap_err().to_string();
            assert!(err.contains("a number of seconds"), "{literal}: {err}");
        }
        assert!(read::<Interval>("0").is_err());
        assert!(read::<Interval>("0.0").is_err());
        assert_eq!(
            read::<Interval>("0.001").unwrap().get(),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn values_print_as_written() {
        for s in [
            "0B", "1B", "1023B", "1KiB", "64MiB", "1536KiB", "2GiB", "1TiB",
        ] {
            assert_eq!(s.parse::<ByteSize>().unwrap().to_string(), s);
        }
        for s in ["127.0.0.1:7480", "[::1]:7480"] {
            assert_eq!(s.parse::<Loopback>().unwrap().to_string(), s);
        }
        for s in [
            "docker.io",
            "localhost:5000",
            "[::1]:5000",
            "registry-1.docker.io",
        ] {
            assert_eq!(s.parse::<RegistryName>().unwrap().to_string(), s);
        }
        for s in [
            "",
            "https://docker.io",
            "docker.io/library",
            "*.example.com",
            "a b",
            "dock\u{e9}r.io",
        ] {
            assert!(s.parse::<RegistryName>().is_err(), "{s:?}");
        }
        for s in ["", "https://reflector.example:7483", "https://10.0.0.1"] {
            assert_eq!(s.parse::<ReflectorUrl>().unwrap().to_string(), s);
        }
        for s in ["auto", "10.0.0.1:7481", "[::1]:7481"] {
            assert_eq!(s.parse::<PeerAddress>().unwrap().to_string(), s);
        }
        for s in ["", "/etc/speculaire/trusted_root.json"] {
            assert_eq!(s.parse::<TrustedRoot>().unwrap().to_string(), s);
        }
        for s in [
            "https://tuf-repo-cdn.sigstore.dev",
            "https://mirror.example:8443/sigstore/tuf",
        ] {
            assert_eq!(s.parse::<TufUrl>().unwrap().to_string(), s);
        }
        for s in ["node-1", "a.b-c.d0", "123"] {
            assert_eq!(s.parse::<NodeName>().unwrap().to_string(), s);
        }
    }

    #[test]
    fn values_hold_what_was_written() {
        assert_eq!("64MiB".parse::<ByteSize>().unwrap().get(), 64 << 20);
        assert_eq!("auto".parse::<PeerAddress>().ok(), Some(PeerAddress::Auto));
        assert_eq!(
            "10.0.0.1:7481".parse::<PeerAddress>().ok(),
            Some(PeerAddress::Fixed("10.0.0.1:7481".parse().unwrap()))
        );
        assert_eq!(
            "".parse::<TrustedRoot>().ok(),
            Some(TrustedRoot::PublicGood)
        );
        assert_eq!(
            "/etc/root.json".parse::<TrustedRoot>().ok(),
            Some(TrustedRoot::Pinned(Absolute::new("/etc/root.json")))
        );
        assert_eq!("".parse::<ReflectorUrl>().unwrap().get(), None);
        let url = "https://reflector.example:7483"
            .parse::<ReflectorUrl>()
            .unwrap();
        assert_eq!(
            url.get().and_then(http::Uri::host),
            Some("reflector.example")
        );
        assert_eq!("node-1".parse::<NodeName>().unwrap().as_str(), "node-1");
        let tuf = "https://mirror.example:8443/tuf/"
            .parse::<TufUrl>()
            .unwrap();
        assert_eq!(
            (tuf.authority(), tuf.root()),
            ("mirror.example:8443", "/tuf")
        );
        let tuf = TufUrl::default();
        assert_eq!(
            (tuf.authority(), tuf.root()),
            ("tuf-repo-cdn.sigstore.dev", "")
        );
    }

    #[test]
    fn max_uploads_reads_auto_or_a_positive_integer() {
        assert_eq!(
            MaxUploads::try_from(Raw::Text("auto".to_owned())).ok(),
            Some(MaxUploads::Auto)
        );
        assert!(MaxUploads::try_from(Raw::Text("many".to_owned())).is_err());
        assert_eq!(
            MaxUploads::try_from(Raw::Number(8)).ok(),
            Some(MaxUploads::Fixed(NonZeroU32::new(8).unwrap()))
        );
        assert!(MaxUploads::try_from(Raw::Number(0)).is_err());
        assert_eq!(Percent::try_from(0).ok().map(Percent::get), Some(0));
        assert_eq!(Percent::try_from(100).ok().map(Percent::get), Some(100));
        assert!(Percent::try_from(101).is_err());
        assert!(Percent::try_from(-1).is_err());
        assert_eq!(i64::from(Percent::new(80).unwrap()), 80);
        assert!(MaxUploads::try_from(Raw::Number(-1)).is_err());
    }

    #[test]
    fn max_uploads_is_four_per_cpu_unless_set() {
        let cpus = std::thread::available_parallelism().unwrap().get();
        assert_eq!(MaxUploads::Auto.get().get(), 4 * cpus);
        assert_eq!(
            MaxUploads::Fixed(NonZeroU32::new(3).unwrap()).get().get(),
            3
        );
    }

    #[test]
    fn node_names_hold_to_rfc_1123_lengths() {
        let label = "a".repeat(63);
        assert!(label.parse::<NodeName>().is_ok());
        assert!("a".repeat(64).parse::<NodeName>().is_err());
        // Three labels of 63, one of 61 and three dots: 253 bytes, the longest a name may be.
        let longest = [label.as_str(), &label, &label, &"a".repeat(61)].join(".");
        assert_eq!(longest.len(), 253);
        assert!(longest.parse::<NodeName>().is_ok());
        assert!(format!("{longest}a").parse::<NodeName>().is_err());
    }

    #[test]
    fn invalid_values_are_refused() {
        assert!("64MB".parse::<ByteSize>().is_err());
        assert!("MiB".parse::<ByteSize>().is_err());
        assert!("16777216TiB".parse::<ByteSize>().is_err(), "overflow");
        assert!("0.0.0.0:7480".parse::<Loopback>().is_err());
        assert!("10.0.0.1:7480".parse::<Loopback>().is_err());
        assert!("etc/policy.yaml".parse::<Absolute>().is_err());
        for s in [
            "http://reflector:7483",
            "https://reflector:7483/v1",
            "reflector:7483",
            "https://alice@reflector:7483",
        ] {
            assert!(s.parse::<ReflectorUrl>().is_err(), "{s}");
        }
        for s in ["", "Node-1", "-node", "node-", "node_1", "a..b"] {
            assert!(s.parse::<NodeName>().is_err(), "{s}");
        }
        assert!("info,[".parse::<LogFilter>().is_err());
        for s in ["auto2", "10.0.0.1", ":7481"] {
            assert!(s.parse::<PeerAddress>().is_err(), "{s}");
        }
        assert!("relative/root.json".parse::<TrustedRoot>().is_err());
        for s in [
            "",
            "http://tuf.example",
            "tuf.example",
            "https://alice@tuf.example",
            "https://tuf.example/?a=b",
        ] {
            assert!(s.parse::<TufUrl>().is_err(), "{s}");
        }
    }

    #[test]
    fn a_log_filter_with_whitespace_around_a_directive_is_refused() {
        // The first panicked inside tracing-subscriber: scheduled fuzz run 44074175851 (D137).
        for s in ["\tq\u{feff}[", " warn", "warn ", "info, x=debug", "info ,x"] {
            assert!(s.parse::<LogFilter>().is_err(), "{s:?}");
        }
        assert!("info,,x=debug".parse::<LogFilter>().is_ok());
    }
}
