//! An image index read for discovery: the manifest the node runs, and `BuildKit`'s attestation manifests of it (D49).
//!
//! `BuildKit` lists an attestation manifest after the runnable ones, with the platform `unknown/unknown` and two
//! annotations: `vnd.docker.reference.type: attestation-manifest`, and `vnd.docker.reference.digest`, the manifest it
//! attests (buildkit v0.34.1 `docs/attestations/attestation-storage.md:92-124`).

use oci_spec::image::{Arch, Os, Platform, PlatformBuilder};
use serde::Deserialize;

use crate::manifest::MAX_DESCRIPTORS;
use crate::platform::{Host, Matcher};
use crate::reference::Digest;
use crate::referrers::{Error, MANIFEST};

/// A Docker v2 image manifest, which containerd runs like an OCI one.
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
/// The value of `vnd.docker.reference.type` on an attestation manifest.
const ATTESTATION_MANIFEST: &str = "attestation-manifest";

/// An image index, or a Docker manifest list, as discovery reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Index {
    entries: Vec<Entry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    digest: Digest,
    role: Role,
}

/// What an entry of the index is to discovery.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Role {
    /// An image manifest a runtime may pick: for its platform or, without one, for its config's.
    Image(Option<Platform>),
    /// A nested index, or a type containerd cannot run: a runtime may pick it too, but it names no image manifest.
    Other(Option<Platform>),
    /// A `BuildKit` attestation manifest of the entry with this digest.
    Attestation(Digest),
}

#[derive(Deserialize)]
struct RawIndex {
    manifests: Option<Vec<RawEntry>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawEntry {
    media_type: Option<String>,
    digest: Option<String>,
    platform: Option<RawPlatform>,
    annotations: Option<RawAnnotations>,
}

/// A platform with the spec's dotted names, which `oci-spec` 0.10's `Platform` does not read.
#[derive(Deserialize)]
struct RawPlatform {
    architecture: String,
    os: String,
    #[serde(rename = "os.version")]
    os_version: Option<String>,
    #[serde(rename = "os.features")]
    os_features: Option<Vec<String>>,
    variant: Option<String>,
}

#[derive(Deserialize)]
struct RawAnnotations {
    #[serde(rename = "vnd.docker.reference.type")]
    reference_type: Option<String>,
    #[serde(rename = "vnd.docker.reference.digest")]
    reference_digest: Option<String>,
}

impl RawPlatform {
    fn parse(self) -> Platform {
        platform(
            &self.os,
            &self.architecture,
            self.variant,
            self.os_version,
            self.os_features,
        )
    }
}

/// An OCI platform; an empty optional field is absent.
fn platform(
    os: &str,
    architecture: &str,
    variant: Option<String>,
    os_version: Option<String>,
    os_features: Option<Vec<String>>,
) -> Platform {
    let mut builder = PlatformBuilder::default()
        .os(Os::from(os))
        .architecture(Arch::from(architecture));
    if let Some(variant) = variant.filter(|text| !text.is_empty()) {
        builder = builder.variant(variant);
    }
    if let Some(version) = os_version.filter(|text| !text.is_empty()) {
        builder = builder.os_version(version);
    }
    if let Some(features) = os_features.filter(|list| !list.is_empty()) {
        builder = builder.os_features(features);
    }
    builder
        .build()
        .expect("the builder's required OS and architecture are set")
}

impl RawEntry {
    /// The entry, or `None` for one `BuildKit` says to ignore: another reference type, or an attestation manifest that
    /// does not name a valid digest.
    fn parse(self) -> Result<Option<Entry>, Error> {
        let digest = Digest::parse(&self.digest.ok_or(Error::Missing("digest"))?)?;
        let annotations = self.annotations.unwrap_or(RawAnnotations {
            reference_type: None,
            reference_digest: None,
        });
        let role = match annotations.reference_type.as_deref() {
            Some(ATTESTATION_MANIFEST) => {
                match annotations.reference_digest.as_deref().map(Digest::parse) {
                    Some(Ok(of)) => Role::Attestation(of),
                    _ => return Ok(None),
                }
            }
            Some(_) => return Ok(None),
            None => {
                let platform = self.platform.map(RawPlatform::parse);
                match self.media_type.as_deref() {
                    Some(MANIFEST | DOCKER_MANIFEST) => Role::Image(platform),
                    _ => Role::Other(platform),
                }
            }
        };
        Ok(Some(Entry { digest, role }))
    }
}

impl Index {
    /// Reads an image index or a Docker manifest list.
    ///
    /// # Errors
    ///
    /// When the bytes are no JSON object with a `manifests` array, it lists too many, an entry lacks its digest or
    /// has a bad one, or a platform lacks its OS or architecture.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let raw: RawIndex = serde_json::from_slice(bytes)?;
        let manifests = raw.manifests.ok_or(Error::NotAnIndex)?;
        if manifests.len() > MAX_DESCRIPTORS {
            return Err(Error::TooMany);
        }
        let entries = manifests
            .into_iter()
            .filter_map(|entry| entry.parse().transpose())
            .collect::<Result<_, _>>()?;
        Ok(Self { entries })
    }

    /// The image manifest containerd picks for `host`'s default platform, as `images.Manifest` picks it with
    /// `platforms.Default()` (containerd v2.4.2 `core/images/image.go:214-240`,
    /// `internal/cri/server/images/service.go:122`).
    ///
    /// Of the entries whose platform the host runs, or that have none, the best match comes first, the first listed
    /// among equals, and one without a platform last. Attestation manifests are never picked. containerd checks the
    /// config's platform of an entry without one, which this cannot: such an entry stands for an image the host runs.
    /// `None` when nothing matches, when the pick is a nested index or a type containerd does not run, or for a
    /// Windows host.
    #[must_use]
    pub fn platform_manifest(&self, host: &Host) -> Option<&Digest> {
        let node = platform(&host.os, &host.arch, Some(host.variant.clone()), None, None);
        let matcher = Matcher::only(&node, host).ok()?;
        let (best, _) = self
            .entries
            .iter()
            .filter_map(|entry| {
                let platform = match &entry.role {
                    Role::Image(platform) | Role::Other(platform) => platform.as_ref(),
                    Role::Attestation(_) => return None,
                };
                platform
                    .is_none_or(|platform| matcher.matches(platform))
                    .then_some((entry, platform))
            })
            // `sort.SliceStable` then the first: a later entry wins only when strictly better.
            .reduce(|best, next| {
                if better(&matcher, next.1, best.1) {
                    next
                } else {
                    best
                }
            })?;
        match best.role {
            Role::Image(_) => Some(&best.digest),
            Role::Other(_) | Role::Attestation(_) => None,
        }
    }

    /// The attestation manifests of the entry `of`, in index order.
    #[must_use]
    pub fn attestations(&self, of: &Digest) -> Vec<&Digest> {
        self.entries
            .iter()
            .filter(|entry| matches!(&entry.role, Role::Attestation(subject) if subject == of))
            .map(|entry| &entry.digest)
            .collect()
    }
}

/// containerd's comparator of index entries: whether `a` sorts before `b`.
fn better(matcher: &Matcher, a: Option<&Platform>, b: Option<&Platform>) -> bool {
    match (a, b) {
        (None, _) => false,
        (Some(_), None) => true,
        (Some(a), Some(b)) => matcher.less(a, b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> Digest {
        Digest::parse(&format!("sha256:{}", format!("{n:02x}").repeat(32))).unwrap()
    }

    fn host(arch: &str, variant: &str) -> Host {
        Host {
            os: "linux".to_owned(),
            arch: arch.to_owned(),
            variant: variant.to_owned(),
        }
    }

    /// An entry: its digest, media type and `os/arch[/variant]`, `-` for none.
    fn entry(n: u8, media_type: &str, platform: &str) -> String {
        let platform = match platform.split('/').collect::<Vec<_>>().as_slice() {
            [os, arch] => format!(r#","platform":{{"os":"{os}","architecture":"{arch}"}}"#),
            [os, arch, variant] => format!(
                r#","platform":{{"os":"{os}","architecture":"{arch}","variant":"{variant}"}}"#
            ),
            _ => String::new(),
        };
        format!(
            r#"{{"mediaType":"{media_type}","digest":"{}","size":1{platform}}}"#,
            digest(n)
        )
    }

    /// A `BuildKit` attestation manifest `n` of the entry `of`.
    fn attestation(n: u8, of: u8) -> String {
        format!(
            r#"{{"mediaType":"{MANIFEST}","digest":"{}","size":1,
                "annotations":{{"vnd.docker.reference.digest":"{}","vnd.docker.reference.type":"attestation-manifest"}},
                "platform":{{"architecture":"unknown","os":"unknown"}}}}"#,
            digest(n),
            digest(of)
        )
    }

    fn index(entries: &[String]) -> Index {
        Index::parse(format!(r#"{{"manifests":[{}]}}"#, entries.join(",")).as_bytes()).unwrap()
    }

    #[test]
    fn the_host_platform_is_picked_among_several() {
        let multi = index(&[
            entry(1, MANIFEST, "linux/arm/v7"),
            entry(2, MANIFEST, "linux/arm64/v8"),
            entry(3, MANIFEST, "linux/amd64"),
            entry(4, MANIFEST, "windows/amd64"),
        ]);
        assert_eq!(
            multi.platform_manifest(&host("amd64", "")),
            Some(&digest(3))
        );
        assert_eq!(
            multi.platform_manifest(&host("arm64", "")),
            Some(&digest(2))
        );
        assert_eq!(
            multi.platform_manifest(&host("arm", "v7")),
            Some(&digest(1))
        );
        assert_eq!(multi.platform_manifest(&host("s390x", "")), None);
        let windows = Host {
            os: "windows".to_owned(),
            ..host("amd64", "")
        };
        assert_eq!(multi.platform_manifest(&windows), None);
    }

    #[test]
    fn a_compatible_platform_is_picked_when_the_exact_one_is_missing_and_the_first_wins_ties() {
        let arm = index(&[
            entry(1, MANIFEST, "linux/arm/v6"),
            entry(2, DOCKER_MANIFEST, "linux/arm/v7"),
            entry(3, MANIFEST, "linux/arm/v7"),
        ]);
        assert_eq!(arm.platform_manifest(&host("arm64", "")), Some(&digest(2)));
        let untagged = index(&[entry(1, MANIFEST, "-"), entry(2, MANIFEST, "linux/386")]);
        assert_eq!(
            untagged.platform_manifest(&host("amd64", "")),
            Some(&digest(2))
        );
        assert_eq!(
            untagged.platform_manifest(&host("arm64", "")),
            Some(&digest(1))
        );
    }

    #[test]
    fn a_nested_index_names_no_manifest() {
        let nested = index(&[
            entry(1, "application/vnd.oci.image.index.v1+json", "linux/amd64"),
            entry(2, MANIFEST, "linux/386"),
        ]);
        assert_eq!(nested.platform_manifest(&host("amd64", "")), None);
    }

    #[test]
    fn attestation_manifests_are_skipped_and_found_by_their_subject() {
        let built = index(&[
            attestation(9, 3),
            entry(1, MANIFEST, "linux/arm64"),
            entry(3, MANIFEST, "linux/amd64"),
            attestation(8, 1),
            attestation(7, 3),
        ]);
        assert_eq!(
            built.platform_manifest(&host("amd64", "")),
            Some(&digest(3))
        );
        assert_eq!(built.attestations(&digest(3)), [&digest(9), &digest(7)]);
        assert_eq!(built.attestations(&digest(1)), [&digest(8)]);
        assert_eq!(built.attestations(&digest(2)), Vec::<&Digest>::new());
        // Even with the host's platform, an attestation manifest is never the platform's.
        let only = index(&[
            attestation(9, 3).replace("unknown\",\"os\":\"unknown", "amd64\",\"os\":\"linux")
        ]);
        assert_eq!(only.platform_manifest(&host("amd64", "")), None);
        assert_eq!(only.attestations(&digest(3)), [&digest(9)]);
    }

    #[test]
    fn other_reference_types_and_attestations_without_a_subject_are_ignored() {
        let text = format!(
            r#"{{"manifests":[
                {{"mediaType":"{MANIFEST}","digest":"{}","annotations":{{"vnd.docker.reference.type":"other","vnd.docker.reference.digest":"{}"}},"platform":{{"os":"linux","architecture":"amd64"}}}},
                {{"mediaType":"{MANIFEST}","digest":"{}","annotations":{{"vnd.docker.reference.type":"attestation-manifest","vnd.docker.reference.digest":"sha256:0"}}}}
            ]}}"#,
            digest(1),
            digest(3),
            digest(2)
        );
        let parsed = Index::parse(text.as_bytes()).unwrap();
        assert_eq!(parsed, Index { entries: vec![] });
    }

    #[test]
    fn what_is_no_index_is_refused() {
        assert!(matches!(Index::parse(b"{}"), Err(Error::NotAnIndex)));
        assert!(matches!(
            Index::parse(br#"{"manifests":[{"mediaType":"x"}]}"#),
            Err(Error::Missing("digest"))
        ));
        assert!(matches!(
            Index::parse(br#"{"manifests":[{"digest":"sha256:00"}]}"#),
            Err(Error::Digest(_))
        ));
        for text in [
            "",
            "[]",
            r#"{"manifests":null}"#,
            &format!(
                r#"{{"manifests":[{{"digest":"{}","platform":{{"os":"linux"}}}}]}}"#,
                digest(1)
            ),
        ] {
            assert!(Index::parse(text.as_bytes()).is_err(), "{text:?}");
        }
        let item = entry(1, MANIFEST, "linux/amd64");
        let text = format!(
            r#"{{"manifests":[{}]}}"#,
            vec![item.as_str(); MAX_DESCRIPTORS + 1].join(",")
        );
        assert!(matches!(Index::parse(text.as_bytes()), Err(Error::TooMany)));
    }

    #[test]
    fn dotted_platform_fields_are_read() {
        let text = format!(
            r#"{{"manifests":[{{"mediaType":"{MANIFEST}","digest":"{}","platform":{{"os":"linux","architecture":"amd64","os.version":"1","os.features":["b"]}}}}]}}"#,
            digest(1)
        );
        let parsed = Index::parse(text.as_bytes()).unwrap();
        let Role::Image(Some(platform)) = &parsed.entries[0].role else {
            panic!("an image with a platform: {parsed:?}");
        };
        assert_eq!(platform.os_version().as_deref(), Some("1"));
        assert_eq!(
            platform.os_features().as_deref(),
            Some(&["b".to_owned()][..])
        );
    }
}
