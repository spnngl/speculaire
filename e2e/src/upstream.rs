//! The cluster's upstream registry (D94). `just e2e-up` starts it as `<cluster>-upstream.e2e.test`, on port 80, and
//! points every node's runtime at it over plain HTTP; the agents mirror it like any registry. Its access log is the
//! oracle of the peer suites: a blob a node got from a peer is a blob it did not `GET` here.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use crate::registry::{PLATFORM, docker, fail, regctl};
use crate::{Cluster, Failure};

/// The registry; `just e2e-up` starts it and `just e2e-down` removes it.
pub struct Upstream {
    name: String,
}

impl Cluster {
    /// The cluster's upstream registry.
    #[must_use]
    pub fn upstream(&self) -> Upstream {
        Upstream {
            name: format!("{}-upstream.e2e.test", self.name),
        }
    }
}

impl Upstream {
    /// The name a node pulls by.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.name
    }

    /// Pushes a new image, `<repository>:1`, of one layer of `size` random bytes: no node holds any of its blobs.
    ///
    /// # Errors
    ///
    /// When `regctl` fails or writes a manifest without its digests.
    pub fn push(&self, repository: &str, size: u64) -> Result<Image, Failure> {
        let reference = format!("{}/{repository}:1", self.name);
        let manifest = regctl(
            &self.name,
            &format!(
                "mkdir /tmp/layer && head -c {size} /dev/urandom >/tmp/layer/random \
                 && regctl image create --platform {PLATFORM} {reference} \
                 && regctl image mod --replace --layer-add dir=/tmp/layer {reference} >/dev/null \
                 && regctl manifest get --format raw-body {reference}"
            ),
        )?;
        let blobs = blobs(&manifest).ok_or_else(|| fail("regctl manifest get", &manifest))?;
        Ok(Image { reference, blobs })
    }

    /// Every request the registry has answered, in order.
    ///
    /// # Errors
    ///
    /// When `docker logs` fails.
    pub fn requests(&self) -> Result<Vec<Request>, Failure> {
        // The access log goes to stdout, the other entries to stderr.
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

/// A line of the registry's access log.
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// Such as `GET` or `HEAD`.
    pub method: String,
    /// Such as `/v2/peers/a/blobs/sha256:...`.
    pub path: String,
    /// The response's status.
    pub status: u16,
}

impl Request {
    /// Parses a line of the combined log format, `<client> - - [<time>] "<method> <path> <protocol>" <status> ...`;
    /// `None` for the registry's other entries.
    fn parse(line: &str) -> Option<Self> {
        let (_, rest) = line.split_once("] \"")?;
        let (request, rest) = rest.split_once("\" ")?;
        let mut request = request.split(' ');
        let (method, path, _protocol) = (request.next()?, request.next()?, request.next()?);
        Some(Self {
            method: method.to_owned(),
            path: path.to_owned(),
            status: rest.split(' ').next()?.parse().ok()?,
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
                method: "GET".to_owned(),
                path: format!("/v2/peers/a/blobs/{DIGEST}"),
                status: 200,
            }
        );
        assert_eq!(request.blob().unwrap().to_string(), DIGEST);
        let entry = r#"time="2026-11-13T11:04:24Z" level=info msg="response completed" http.request.method=GET http.request.uri="/v2/""#;
        assert_eq!(Request::parse(entry), None);
    }

    #[test]
    fn only_a_blob_get_names_a_blob() {
        let request = |method: &str, path: &str| Request {
            method: method.to_owned(),
            path: path.to_owned(),
            status: 200,
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
