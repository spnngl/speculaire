//! The cluster's upstream registries (D94, D112). `just e2e-up` starts each as `<cluster>-<role>.e2e.test`, on the
//! default port of its scheme, pushes the test images to each, and points every node's runtime at them; the agents
//! mirror them like any registry. Their access logs are the oracle of the suites: a blob a node got from a peer is a
//! blob it did not `GET` here.

mod start;

use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

pub use start::{COSIGN_PUBLIC_KEY, CRIO_AUTH_FILE, SIGNED, UNSIGNED, start};

use crate::registry::{PASSWORD, PLATFORM, USER, docker, fail, regctl_after};
use crate::{Cluster, Failure};

/// Which of the cluster's upstream registries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// D94's `registry:3`, on plain HTTP, which each node's runtime config names.
    Plain,
    /// zot, on plain HTTP, which each node's runtime config names: the referrers API.
    Referrers,
    /// `registry:2` behind a token server, on TLS: the CA and the login are only in each node's runtime config.
    Private,
    /// `registry:3`, on TLS: the CA is in each node's system trust store, and no runtime config names it.
    Public,
}

impl Kind {
    /// Every kind, in the order `just e2e-up` starts them.
    pub const ALL: [Self; 4] = [Self::Plain, Self::Referrers, Self::Private, Self::Public];

    /// The word between the cluster's name and `.e2e.test`.
    fn role(self) -> &'static str {
        match self {
            Self::Plain => "upstream",
            Self::Referrers => "referrers",
            Self::Private => "private",
            Self::Public => "public",
        }
    }
}

/// A registry; `just e2e-up` starts it and `just e2e-down` removes it.
pub struct Upstream {
    name: String,
    kind: Kind,
}

impl Cluster {
    /// The cluster's upstream registry of `kind`.
    #[must_use]
    pub fn upstream(&self, kind: Kind) -> Upstream {
        Upstream {
            name: format!("{}-{}.e2e.test", self.name, kind.role()),
            kind,
        }
    }
}

impl Upstream {
    /// The name a node pulls by.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.name
    }

    /// The `regctl registry` commands that reach it from kind's network: plain HTTP, or TLS with any certificate, and
    /// the login the private one asks for.
    fn reach(&self) -> String {
        let name = &self.name;
        match self.kind {
            Kind::Plain | Kind::Referrers => {
                format!("regctl registry set --skip-check --tls disabled {name} >/dev/null")
            }
            Kind::Public => {
                format!("regctl registry set --skip-check --tls insecure {name} >/dev/null")
            }
            Kind::Private => format!(
                "regctl registry set --skip-check --tls insecure {name} >/dev/null \
                 && regctl registry login -u {USER} -p {PASSWORD} {name} >/dev/null"
            ),
        }
    }

    /// Runs `script` in a `regctl` container that reaches this registry, with its login, and returns its stdout.
    ///
    /// # Errors
    ///
    /// When the container or `script` fails.
    pub fn regctl(&self, script: &str) -> Result<String, Failure> {
        regctl_after(&self.reach(), script)
    }

    /// The digest of `reference`, `<repository>:<tag>`, which [`SIGNED`] and [`UNSIGNED`] name.
    ///
    /// # Errors
    ///
    /// When `regctl` fails or prints no digest.
    pub fn digest(&self, reference: &str) -> Result<Digest, Failure> {
        self.regctl(&format!("regctl image digest {}/{reference}", self.name))?
            .trim()
            .parse()
    }

    /// Pushes a new image, `<repository>:1`, of one layer of `size` random bytes: no node holds any of its blobs.
    ///
    /// # Errors
    ///
    /// When `regctl` fails or writes a manifest without its digests.
    pub fn push(&self, repository: &str, size: u64) -> Result<Image, Failure> {
        let reference = format!("{}/{repository}:1", self.name);
        let manifest = self.regctl(&format!(
            "mkdir /tmp/layer && head -c {size} /dev/urandom >/tmp/layer/random \
                 && regctl image create --platform {PLATFORM} {reference} \
                 && regctl image mod --replace --layer-add dir=/tmp/layer {reference} >/dev/null \
                 && regctl manifest get --format raw-body {reference}"
        ))?;
        let blobs = blobs(&manifest).ok_or_else(|| fail("regctl manifest get", &manifest))?;
        Ok(Image { reference, blobs })
    }

    /// Every request the registry has answered, in order.
    ///
    /// # Errors
    ///
    /// When `docker logs` fails.
    pub fn requests(&self) -> Result<Vec<Request>, Failure> {
        // registry's access log goes to stdout, its other entries to stderr; zot logs everything to stderr.
        Ok(docker(&["logs", &self.name])?
            .lines()
            .filter_map(Request::parse)
            .collect())
    }

    /// How many `GET`s each blob of `image` has had.
    ///
    /// # Errors
    ///
    /// When `docker logs` fails.
    pub fn blob_gets(&self, image: &Image) -> Result<BTreeMap<Digest, usize>, Failure> {
        let mut gets: BTreeMap<Digest, usize> =
            image.blobs.iter().map(|b| (b.clone(), 0)).collect();
        for request in self.requests()? {
            if let Some(count) = request.blob().and_then(|digest| gets.get_mut(&digest)) {
                *count += 1;
            }
        }
        Ok(gets)
    }
}

/// The digests of an image manifest's config and layers, in that order.
fn blobs(manifest: &str) -> Option<Vec<Digest>> {
    let manifest: serde_json::Value = serde_json::from_str(manifest).ok()?;
    std::iter::once(manifest.get("config")?)
        .chain(manifest.get("layers")?.as_array()?)
        .map(|descriptor| descriptor.get("digest")?.as_str()?.parse().ok())
        .collect()
}

/// An image of the upstream.
#[derive(Debug)]
pub struct Image {
    /// What a node pulls, `<upstream>/<repository>:1`.
    pub reference: String,
    /// Its config and its layers: the blobs a pull fetches.
    pub blobs: Vec<Digest>,
}

/// A `sha256` digest, written `sha256:<64 hex digits>`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Digest {
    hex: String,
}

impl Digest {
    /// The hex digits, which name the blob's file.
    #[must_use]
    pub fn hex(&self) -> &str {
        &self.hex
    }
}

impl FromStr for Digest {
    type Err = Failure;

    fn from_str(s: &str) -> Result<Self, Failure> {
        match s.strip_prefix("sha256:") {
            Some(hex)
                if hex.len() == 64
                    && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) =>
            {
                Ok(Self {
                    hex: hex.to_owned(),
                })
            }
            _ => Err(fail(
                "parse a digest",
                &format!("{s:?} is not sha256:<64 hex digits>"),
            )),
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.hex)
    }
}

/// An entry of a registry's access log.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// The address it came from: a node's tells its requests from the other nodes'.
    pub client: IpAddr,
    /// Such as `GET` or `HEAD`.
    pub method: String,
    /// Such as `/v2/peers/a/blobs/sha256:...`.
    pub path: String,
    /// The response's status.
    pub status: u16,
    /// The `User-Agent` header, which tells the agent's requests from the runtime's (D111); empty without one.
    pub user_agent: String,
}

impl Request {
    /// Parses an access log entry, of `registry` or of zot; `None` for their other entries.
    pub(crate) fn parse(line: &str) -> Option<Self> {
        if line.starts_with('{') {
            Self::parse_zot(line)
        } else {
            Self::parse_combined(line)
        }
    }

    /// Parses a line of the combined log format,
    /// `<client> - - [<time>] "<method> <path> <protocol>" <status> <size> "<referer>" "<user agent>"`.
    fn parse_combined(line: &str) -> Option<Self> {
        let (client, _) = line.split_once(' ')?;
        let (_, rest) = line.split_once("] \"")?;
        let (request, rest) = rest.split_once("\" ")?;
        let mut request = request.split(' ');
        let (method, path, _protocol) = (request.next()?, request.next()?, request.next()?);
        let (_, user_agent) = rest.strip_suffix('"')?.rsplit_once('"')?;
        Some(Self {
            client: client.parse().ok()?,
            method: method.to_owned(),
            path: path.to_owned(),
            status: rest.split(' ').next()?.parse().ok()?,
            user_agent: user_agent.to_owned(),
        })
    }

    /// Parses zot's JSON entry of a request, whose `message` is `HTTP API` and whose `clientIP` is `ip:port`.
    fn parse_zot(line: &str) -> Option<Self> {
        let entry: serde_json::Value = serde_json::from_str(line).ok()?;
        if entry.get("message")? != "HTTP API" {
            return None;
        }
        let text = |key: &str| Some(entry.get(key)?.as_str()?.to_owned());
        let user_agent = entry
            .pointer("/headers/User-Agent/0")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        Some(Self {
            client: text("clientIP")?.parse::<SocketAddr>().ok()?.ip(),
            method: text("method")?,
            path: text("path")?,
            status: u16::try_from(entry.get("statusCode")?.as_u64()?).ok()?,
            user_agent: user_agent.to_owned(),
        })
    }

    /// The digest of a blob `GET`, `/v2/<repository>/blobs/<digest>`.
    #[must_use]
    pub fn blob(&self) -> Option<Digest> {
        if self.method != "GET" {
            return None;
        }
        let (_, digest) = self.path.strip_prefix("/v2/")?.rsplit_once("/blobs/")?;
        digest.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn an_access_log_line_parses_and_the_other_entries_do_not() {
        let line = format!(
            r#"172.18.0.3 - - [13/Nov/2026:11:04:24 +0000] "GET /v2/peers/a/blobs/{DIGEST} HTTP/1.1" 200 157 "" "containerd/v2.4.2""#
        );
        let request = Request::parse(&line).unwrap();
        assert_eq!(
            request,
            Request {
                client: IpAddr::from([172, 18, 0, 3]),
                method: "GET".to_owned(),
                path: format!("/v2/peers/a/blobs/{DIGEST}"),
                status: 200,
                user_agent: "containerd/v2.4.2".to_owned(),
            }
        );
        assert_eq!(request.blob().unwrap().to_string(), DIGEST);
        let ipv6 = line.replacen("172.18.0.3", "fc00:f853:ccd:e793::3", 1);
        assert_eq!(
            Request::parse(&ipv6).unwrap().client,
            "fc00:f853:ccd:e793::3".parse::<IpAddr>().unwrap()
        );
        let entry = r#"time="2026-11-13T11:04:24Z" level=info msg="response completed" http.request.method=GET http.request.uri="/v2/""#;
        assert_eq!(Request::parse(entry), None);
    }

    #[test]
    fn a_zot_request_entry_parses_and_its_other_entries_do_not() {
        let line = format!(
            r#"{{"time":"2026-11-15T13:54:17Z","level":"info","message":"HTTP API","clientIP":"[fc00:f853:ccd:e793::3]:41234","method":"GET","path":"/v2/e2e/signed/referrers/{DIGEST}","statusCode":200,"latency":"0s","bodySize":1302,"headers":{{"Accept":["*/*"],"User-Agent":["speculaire/0.1.0"]}}}}"#
        );
        assert_eq!(
            Request::parse(&line).unwrap(),
            Request {
                client: "fc00:f853:ccd:e793::3".parse().unwrap(),
                method: "GET".to_owned(),
                path: format!("/v2/e2e/signed/referrers/{DIGEST}"),
                status: 200,
                user_agent: "speculaire/0.1.0".to_owned(),
            }
        );
        let anonymous = r#"{"message":"HTTP API","clientIP":"172.18.0.3:41234","method":"HEAD","path":"/v2/","statusCode":401,"headers":{}}"#;
        assert_eq!(Request::parse(anonymous).unwrap().user_agent, "");
        let other = r#"{"level":"info","message":"getting manifest","method":"GET","path":"/v2/","statusCode":200}"#;
        assert_eq!(Request::parse(other), None);
    }

    #[test]
    fn only_a_blob_get_names_a_blob() {
        let request = |method: &str, path: &str| Request {
            client: IpAddr::from([172, 18, 0, 3]),
            method: method.to_owned(),
            path: path.to_owned(),
            status: 200,
            user_agent: String::new(),
        };
        assert_eq!(
            request("HEAD", &format!("/v2/a/blobs/{DIGEST}")).blob(),
            None
        );
        assert_eq!(
            request("GET", &format!("/v2/a/manifests/{DIGEST}")).blob(),
            None
        );
        assert_eq!(request("GET", "/v2/a/blobs/uploads/").blob(), None);
    }

    #[test]
    fn a_digest_is_sha256_and_64_lowercase_hex_digits() {
        assert_eq!(DIGEST.parse::<Digest>().unwrap().hex(), &DIGEST[7..]);
        for s in [
            "",
            "sha256:",
            "sha512:00",
            &DIGEST.to_uppercase(),
            &DIGEST[..70],
            "sha256:../../etc/passwd",
        ] {
            assert!(s.parse::<Digest>().is_err(), "{s}");
        }
    }

    #[test]
    fn a_manifest_lists_its_config_then_its_layers() {
        let manifest =
            format!(r#"{{"config":{{"digest":"{DIGEST}"}},"layers":[{{"digest":"{DIGEST}"}}]}}"#);
        assert_eq!(blobs(&manifest).unwrap().len(), 2);
        assert_eq!(
            blobs(r#"{"config":{"digest":"sha256:00"},"layers":[]}"#),
            None
        );
    }
}
