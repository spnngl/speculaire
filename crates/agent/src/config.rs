//! The agent's settings (D30, D47): one TOML file, parsed into these types or refused.
//!
//! `packaging/config.toml` lists every key at its default; the tests below hold it equal to [`Config::default`].

mod value;

use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
pub use value::{
    Absolute, ByteSize, Interval, InvalidValue, LogFilter, Loopback, MaxUploads, NodeName,
    PeerAddress, ReflectorUrl, Span, TrustedRoot,
};

/// Where the agent reads its settings when `--config` names no other file (D30).
pub const DEFAULT_PATH: &str = "/etc/speculaire/config.toml";

/// Every setting of the agent.
///
/// Each field is a TOML table named like it, except `role`. Every key is optional, and missing keys take their default.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// What this agent runs as (D2).
    pub role: Restart<Role>,
    /// `[config]`: how the agent watches its files (D30).
    pub config: Files,
    /// `[identity]`: the node's mTLS identity (D16).
    pub identity: Identity,
    /// `[gate]`: the NRI admission gate.
    pub gate: Gate,
    /// `[nri]`: the connection to the runtime's NRI (D9, D64).
    pub nri: Nri,
    /// `[verify]`: signature verification (D26, D21).
    pub verify: Verify,
    /// `[sbom]`: SBOM attestations (D12).
    pub sbom: Sbom,
    /// `[mirror]`: the local registry mirror the runtime pulls through (D14, D66).
    pub mirror: Mirror,
    /// `[peer]`: the peer API other nodes fetch from (D3).
    pub peer: Peer,
    /// `[blob_cache]`: the blobs the mirror keeps on CRI-O, which keeps none itself (D67).
    pub blob_cache: BlobCache,
    /// `[metrics]`: the `/metrics`, `/readyz` and `/livez` listener (D42).
    pub metrics: Metrics,
    /// `[reflector]`: where agents find reflectors, and how a reflector serves them (D2).
    pub reflector: Reflector,
    /// `[prewarm]`: images a reflector has every node pull ahead of use (D51).
    pub prewarm: Prewarm,
    /// `[log]`: diagnostic logs (D37).
    pub log: Log,
    /// `[audit]`: the audit log (D37).
    pub audit: Audit,
    /// `[shutdown]`: how the agent stops (D39).
    pub shutdown: Shutdown,
}

impl Config {
    /// Puts back the running value of every restart key (D47) that `self` changes, and returns their names.
    ///
    /// The destructuring names every key, so a new key does not compile until it is classed here.
    pub fn keep_restart_keys(&mut self, running: &Self) -> Vec<&'static str> {
        fn keep<T: Clone + PartialEq>(
            kept: &mut Vec<&'static str>,
            key: &'static str,
            new: &mut Restart<T>,
            old: &Restart<T>,
        ) {
            if new != old {
                new.clone_from(old);
                kept.push(key);
            }
        }
        let Self {
            role,
            config: Files { poll_interval: _ },
            identity: Identity { certificate, ca },
            gate:
                Gate {
                    mode: _,
                    wait: _,
                    unmatched: _,
                    exempt: _,
                },
            nri: Nri { socket },
            verify:
                Verify {
                    policy: _,
                    trusted_root: _,
                    stale_max: _,
                },
            sbom: Sbom { max_size: _ },
            mirror: Mirror { address: mirror },
            peer:
                Peer {
                    address: peer,
                    max_uploads: _,
                    deny_ttl: _,
                },
            blob_cache: BlobCache { max_size: _ },
            metrics: Metrics { address: metrics },
            reflector:
                Reflector {
                    url,
                    members,
                    listen,
                },
            prewarm: Prewarm {
                images: _,
                seeds: _,
            },
            log: Log { filter: _ },
            audit: Audit { enabled: _ },
            shutdown: Shutdown { drain_timeout: _ },
        } = self;
        let mut kept = Vec::new();
        keep(&mut kept, "role", role, &running.role);
        keep(
            &mut kept,
            "identity.certificate",
            certificate,
            &running.identity.certificate,
        );
        keep(&mut kept, "identity.ca", ca, &running.identity.ca);
        keep(&mut kept, "nri.socket", socket, &running.nri.socket);
        keep(&mut kept, "mirror.address", mirror, &running.mirror.address);
        keep(&mut kept, "peer.address", peer, &running.peer.address);
        keep(
            &mut kept,
            "metrics.address",
            metrics,
            &running.metrics.address,
        );
        keep(&mut kept, "reflector.url", url, &running.reflector.url);
        keep(
            &mut kept,
            "reflector.members",
            members,
            &running.reflector.members,
        );
        keep(
            &mut kept,
            "reflector.listen",
            listen,
            &running.reflector.listen,
        );
        kept
    }
}

/// A key that only a restart applies (D47): a reload keeps the running value and logs a warning.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Restart<T>(T);

impl<T> Restart<T> {
    /// The value.
    pub const fn get(&self) -> &T {
        &self.0
    }
}

/// What an agent runs as (D2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// An agent on a worker node.
    #[default]
    Agent,
    /// An agent on a control-plane node that also serves the reflector API.
    Reflector,
}

/// `[config]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Files {
    /// How often the agent checks its files for changes (D30).
    pub poll_interval: Interval,
}

impl Default for Files {
    fn default() -> Self {
        Self {
            poll_interval: Interval::from_secs(10),
        }
    }
}

/// `[identity]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Identity {
    /// The kubelet client certificate and its key, in one PEM file (D16).
    pub certificate: Restart<Absolute>,
    /// The cluster CA (D16).
    pub ca: Restart<Absolute>,
}

impl Default for Identity {
    fn default() -> Self {
        Self {
            certificate: Restart(Absolute::new(
                "/var/lib/kubelet/pki/kubelet-client-current.pem",
            )),
            ca: Restart(Absolute::new("/etc/kubernetes/pki/ca.crt")),
        }
    }
}

/// `[gate]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gate {
    /// Whether a failed check only logs or also rejects (ARCHITECTURE.md § Gate, D54).
    pub mode: Mode,
    /// How long `CreateContainer` waits for a pending verdict (D41).
    pub wait: Span,
    /// What happens to an image that no policy matches (D23).
    pub unmatched: Unmatched,
    /// `[gate.exempt]`: containers the gate allows without a check (D18).
    pub exempt: Exempt,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            mode: Mode::Audit,
            wait: Span::from_millis(300),
            unmatched: Unmatched::Deny,
            exempt: Exempt::default(),
        }
    }
}

/// `gate.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Allow every container; log and count what `Enforce` would reject.
    #[default]
    Audit,
    /// Reject containers whose image fails its policies.
    Enforce,
}

/// `gate.unmatched` (D23).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Unmatched {
    /// Reject the image.
    #[default]
    Deny,
    /// Start the image without any signature check.
    Allow,
}

/// `[gate.exempt]` (D18).
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Exempt {
    /// Namespaces, by exact name.
    pub namespaces: Vec<String>,
    /// Globs on the normalised pod-spec image name (D11), checked when the gate compiles them.
    pub images: Vec<String>,
}

/// `[nri]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Nri {
    /// The runtime's NRI socket (D9, D64).
    pub socket: Restart<Absolute>,
}

impl Default for Nri {
    fn default() -> Self {
        Self {
            socket: Restart(Absolute::new("/var/run/nri/nri.sock")),
        }
    }
}

/// `[verify]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Verify {
    /// The policy file (D26).
    pub policy: Absolute,
    /// The Sigstore trust root (D26).
    pub trusted_root: TrustedRoot,
    /// How long a stale verdict keeps serving during re-verification (D21).
    pub stale_max: Span,
}

impl Default for Verify {
    fn default() -> Self {
        Self {
            policy: Absolute::new("/etc/speculaire/policy.yaml"),
            trusted_root: TrustedRoot::PublicGood,
            stale_max: Span::from_secs(3600),
        }
    }
}

/// `[sbom]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Sbom {
    /// The largest SBOM the agent reads (D12).
    pub max_size: ByteSize,
}

impl Default for Sbom {
    fn default() -> Self {
        Self {
            max_size: ByteSize::mebibytes(64),
        }
    }
}

/// `[blob_cache]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlobCache {
    /// The size above which the least recently served blobs are evicted (D67).
    pub max_size: ByteSize,
}

impl Default for BlobCache {
    fn default() -> Self {
        Self {
            max_size: ByteSize::mebibytes(20 << 10),
        }
    }
}

/// `[mirror]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Mirror {
    /// Where the mirror listens, on loopback only (D56).
    pub address: Restart<Loopback>,
}

impl Default for Mirror {
    fn default() -> Self {
        Self {
            address: Restart(Loopback::MIRROR),
        }
    }
}

/// `[peer]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Peer {
    /// The address other nodes fetch from (D36, D56).
    pub address: Restart<PeerAddress>,
    /// How many blob bodies the peer API serves at once (D24).
    pub max_uploads: MaxUploads,
    /// How long a peer that sent a wrong digest is skipped (D52).
    pub deny_ttl: Span,
}

impl Default for Peer {
    fn default() -> Self {
        Self {
            address: Restart(PeerAddress::Auto),
            max_uploads: MaxUploads::Auto,
            deny_ttl: Span::from_secs(600),
        }
    }
}

/// `[metrics]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Metrics {
    /// Where `/metrics`, `/readyz` and `/livez` listen (D42, D45).
    pub address: Restart<SocketAddr>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            address: Restart(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 7482))),
        }
    }
}

/// `[reflector]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Reflector {
    /// The reflectors' load balancer; none turns peers off (D2).
    pub url: Restart<ReflectorUrl>,
    /// Every reflector; the same list on each of them (D2).
    pub members: Restart<Vec<Member>>,
    /// Where a reflector serves agents; read only with `role = "reflector"`.
    pub listen: Restart<SocketAddr>,
}

impl Default for Reflector {
    fn default() -> Self {
        Self {
            url: Restart(ReflectorUrl::default()),
            members: Restart(Vec::new()),
            listen: Restart(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 7483))),
        }
    }
}

/// One entry of `reflector.members`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    /// The member's node name, as its kubelet certificate names it (D16).
    pub node: NodeName,
    /// Where the member's reflector API listens.
    pub address: SocketAddr,
}

/// `[prewarm]`, read only with `role = "reflector"`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Prewarm {
    /// Image references every node pulls ahead of use, checked when the reflector resolves them (D26).
    pub images: Vec<String>,
    /// How many agents pull each image from upstream before the rest pull from peers (D51).
    pub seeds: NonZeroU32,
}

impl Default for Prewarm {
    fn default() -> Self {
        Self {
            images: Vec::new(),
            seeds: NonZeroU32::new(2).expect("2 is not zero"),
        }
    }
}

/// `[log]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    /// Which diagnostic events reach the log (D37).
    pub filter: LogFilter,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            filter: LogFilter::new("warn"),
        }
    }
}

/// `[audit]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Audit {
    /// Whether audit events are written (D37).
    pub enabled: bool,
}

/// `[shutdown]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Shutdown {
    /// How long in-flight transfers may finish after SIGTERM (D39).
    pub drain_timeout: Span,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self {
            drain_timeout: Span::from_secs(10),
        }
    }
}

/// A config file that could not be read or parsed.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// The file could not be read.
    #[error("cannot read {}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The file is not a valid config.
    #[error("invalid config {}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// What is wrong, and where.
        source: ParseError,
    },
}

/// Text that is not a valid config: the key, and the line and column when TOML knows them.
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
    /// The dotted key that holds the error, such as `gate.mode`; empty for a syntax error outside any key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// Parses config text.
///
/// # Errors
///
/// When the text is not TOML, holds an unknown key, or a value that its key refuses.
pub fn parse(text: &str) -> Result<Config, ParseError> {
    let position = |span: Option<std::ops::Range<usize>>| {
        span.map(|span| {
            let before = text.get(..span.start).unwrap_or(text);
            let line = before.lines().count().max(1) + usize::from(before.ends_with('\n'));
            let column = before.rsplit('\n').next().unwrap_or(before).chars().count() + 1;
            (line, column)
        })
    };
    let document = toml::de::DeTable::parse(text).map_err(|e| ParseError {
        key: String::new(),
        position: position(e.span()),
        message: e.message().to_owned(),
    })?;
    let deserializer = toml::de::Deserializer::from(document);
    serde_path_to_error::deserialize(deserializer).map_err(|e| {
        let key = e.path().to_string();
        let e = e.into_inner();
        ParseError {
            key,
            position: position(e.span()),
            message: e.message().to_owned(),
        }
    })
}

/// Reads and parses a config file.
///
/// # Errors
///
/// When the file cannot be read, or [`parse`] refuses it.
pub fn load(path: &Path) -> Result<Config, LoadError> {
    let text = std::fs::read_to_string(path).map_err(|source| LoadError::Read {
        path: path.to_owned(),
        source,
    })?;
    parse(&text).map_err(|source| LoadError::Parse {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference file, with each commented key (`#key = value`) uncommented; prose comments (`# text`) stay.
    fn uncommented() -> String {
        include_str!("../../../packaging/config.toml")
            .lines()
            .map(|line| match line.strip_prefix('#') {
                Some(key) if key.starts_with(|c: char| c.is_ascii_lowercase()) => key,
                _ => line,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_reference_file_parses_to_the_defaults() {
        assert_eq!(parse(&uncommented()).unwrap(), Config::default());
    }

    #[test]
    fn the_reference_file_lists_every_key_as_the_defaults_print() {
        let file: toml::Table = uncommented().parse().unwrap();
        let defaults = toml::Table::try_from(Config::default()).unwrap();
        assert_eq!(
            file, defaults,
            "packaging/config.toml differs from Config::default()"
        );
    }

    /// Dotted names the docs write in backticks that are not keys: the file's name, D30's typo example, and the
    /// switch D54 refuses to add.
    const NOT_KEYS: [&str; 3] = ["config.toml", "gate.unmached", "gate.enabled"];

    #[test]
    fn every_key_the_docs_name_is_in_the_reference_file() {
        fn paths(table: &toml::Table, prefix: &str, out: &mut Vec<String>) {
            for (key, value) in table {
                let path = format!("{prefix}{key}");
                if let toml::Value::Table(inner) = value {
                    paths(inner, &format!("{path}."), out);
                }
                out.push(path);
            }
        }
        let file: toml::Table = uncommented().parse().unwrap();
        let mut known = Vec::new();
        paths(&file, "", &mut known);

        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut docs = vec![root.join("ARCHITECTURE.md")];
        for dir in ["docs", "docs/decisions"] {
            for entry in std::fs::read_dir(root.join(dir)).unwrap() {
                let path = entry.unwrap().path();
                // TODECIDE.md holds open questions, whose keys do not exist yet.
                if path.extension().is_some_and(|e| e == "md") && !path.ends_with("TODECIDE.md") {
                    docs.push(path);
                }
            }
        }
        let mut missing = Vec::new();
        for doc in &docs {
            let text = std::fs::read_to_string(doc).unwrap();
            for span in text.split('`').skip(1).step_by(2) {
                let name = span.split_whitespace().next().unwrap_or_default();
                let Some((table, _)) = name.split_once('.') else {
                    continue;
                };
                let named = file.contains_key(table)
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b'.');
                if named && !NOT_KEYS.contains(&name) && !known.iter().any(|k| k == name) {
                    missing.push(format!(
                        "{}: {name}",
                        doc.strip_prefix(&root).unwrap_or(doc).display()
                    ));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "keys missing from packaging/config.toml: {missing:#?}"
        );
    }

    #[test]
    fn a_reload_keeps_restart_keys_and_takes_live_ones() {
        let running = Config::default();
        let mut new =
            parse("[metrics]\naddress = \"127.0.0.1:9000\"\n[log]\nfilter = \"debug\"\n").unwrap();
        assert_eq!(new.keep_restart_keys(&running), ["metrics.address"]);
        assert_eq!(new.metrics, running.metrics);
        assert_eq!(new.log.filter.as_str(), "debug");
    }

    #[test]
    fn errors_name_the_key_and_its_position() {
        let cases = [
            (
                "[gate]\nunmached = \"deny\"\n",
                "gate.unmached",
                "unknown field",
            ),
            (
                "[gate]\nmode = \"strict\"\n",
                "gate.mode",
                "unknown variant",
            ),
            (
                "[mirror]\naddress = \"0.0.0.0:7480\"\n",
                "mirror.address",
                "loopback",
            ),
            (
                "[peer]\nmax_uploads = 0\n",
                "peer.max_uploads",
                "integer from 1",
            ),
            (
                "[[reflector.members]]\nnode = \"cp-1\"\naddress = \"10.0.0.1\"\n",
                "reflector.members[0].address",
                "",
            ),
            ("rol = \"agent\"\n", "rol", "unknown field"),
        ];
        for (text, key, message) in cases {
            let err = parse(text).unwrap_err();
            assert_eq!(err.key(), key, "{text}");
            let shown = err.to_string();
            assert!(
                shown.starts_with("line ") && shown.contains(key) && shown.contains(message),
                "{text}: {shown}"
            );
        }
        let err = parse("[gate\n").unwrap_err();
        assert!(err.to_string().starts_with("line 1, column "), "{err}");
    }
}
