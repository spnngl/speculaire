//! The value types of the config: each parses its TOML string once and prints it back unchanged.

use std::fmt;
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

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
    Span,
    Interval,
    ByteSize,
    Loopback,
    PeerAddress,
    Absolute,
    TrustedRoot,
    ReflectorUrl,
    NodeName,
    LogFilter
);

/// A duration written as `humantime` reads it: `"300ms"`, `"10m"`, `"1h"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
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

impl FromStr for Span {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        humantime::parse_duration(s).map(Self).map_err(|e| {
            InvalidValue(format!(
                "expected a duration such as \"300ms\" or \"10m\", found {s:?}: {e}"
            ))
        })
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        humantime::format_duration(self.0).fmt(f)
    }
}

/// A [`Span`] longer than zero: the period of a timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
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

impl FromStr for Interval {
    type Err = InvalidValue;
    fn from_str(s: &str) -> Result<Self, InvalidValue> {
        let span: Span = s.parse()?;
        if span.get().is_zero() {
            return Err(InvalidValue(format!(
                "expected a duration longer than zero, found {s:?}"
            )));
        }
        Ok(Self(span))
    }
}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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
        if uri.scheme() == Some(&http::uri::Scheme::HTTPS) && uri.host().is_some() && bare {
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

/// A log filter in `EnvFilter` syntax (D37), checked when read.
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

    #[test]
    fn values_print_as_written() {
        for s in ["300ms", "10s", "10m", "1h", "1h 30m"] {
            assert_eq!(s.parse::<Span>().unwrap().to_string(), s);
        }
        for s in [
            "0B", "1B", "1023B", "1KiB", "64MiB", "1536KiB", "2GiB", "1TiB",
        ] {
            assert_eq!(s.parse::<ByteSize>().unwrap().to_string(), s);
        }
        for s in ["127.0.0.1:7480", "[::1]:7480"] {
            assert_eq!(s.parse::<Loopback>().unwrap().to_string(), s);
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
        assert!(MaxUploads::try_from(Raw::Number(-1)).is_err());
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
        assert!("0s".parse::<Interval>().is_err());
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
    }
}
