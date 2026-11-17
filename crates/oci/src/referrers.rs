//! OCI 1.1 referrers: the index that lists the artifacts of a manifest, and the artifact manifests it lists (D43).
//!
//! Discovery asks the referrers API for the index of an image's digest, or pulls the fallback tag when the API answers
//! 404 (distribution-spec v1.1.1-57-g9727462 `spec.md:625-636,712-714,786-805`). Each listed manifest names the image
//! in its `subject` (image-spec v1.1.1-38-g4feed4a `manifest.md:100-103`, `image-index.md:93-96`). A legacy cosign
//! signature is a manifest of its own under the `.sig` tag, with no subject.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer};

use crate::manifest::MAX_DESCRIPTORS;
use crate::reference::{Digest, ReferenceError};

/// A Sigstore bundle, as cosign v3 and GitHub attestations write it (cosign v3.1.3 `pkg/cosign/bundle/constants.go:17`).
pub const BUNDLE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
/// The empty descriptor's type, `{}` (image-spec `manifest.md:160-169`).
pub const EMPTY: &str = "application/vnd.oci.empty.v1+json";
/// A cosign attestation stored as a referrer, which never counts (D43; cosign v3.1.3
/// `internal/pkg/oci/remote/remote.go:24`).
pub const COSIGN_ATTESTATION: &str = "application/vnd.dev.cosign.artifact.att.v1+json";
/// The layer of a legacy cosign `.sig` manifest (cosign v3.1.3 `pkg/types/media.go:28`).
pub const SIMPLE_SIGNING: &str = "application/vnd.dev.cosign.simplesigning.v1+json";
/// An OCI image index, the referrers API's answer (`spec.md:630`).
pub const INDEX: &str = "application/vnd.oci.image.index.v1+json";
/// An OCI image manifest.
pub const MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

/// The longest encoded part of a referrers tag (`spec.md:795`).
const TAG_ENCODED_MAX: usize = 64;

/// A descriptor of a blob or a manifest, with the fields discovery reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    /// The media type of the content it points to.
    pub media_type: String,
    /// The digest of the content.
    pub digest: Digest,
    /// The size of the content in bytes.
    pub size: u64,
    /// The artifact's type: in a referrers index, the manifest's `artifactType` or else its config's media type
    /// (`spec.md:632-634`). Never empty: an empty one is absent.
    pub artifact_type: Option<String>,
}

impl Descriptor {
    /// Whether the manifest it points to may hold a Sigstore bundle, to be told by [`Referrer::is_bundle`].
    ///
    /// The type may be the bundle's, or absent, or the empty type: ghcr.io lists bundle referrers with the empty type
    /// (sigstore-rs v0.15.0 `src/cosign/client.rs:239-243`). Any other type, [`COSIGN_ATTESTATION`] among them, is no
    /// bundle.
    #[must_use]
    pub fn may_be_bundle(&self) -> bool {
        matches!(self.artifact_type.as_deref(), None | Some(BUNDLE | EMPTY))
    }
}

/// A referrers index or a referrer manifest that cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The bytes are no JSON of the expected shape.
    #[error("not JSON of the expected shape: {0}")]
    Json(#[from] serde_json::Error),
    /// It has no `manifests` array.
    #[error("not an image index")]
    NotAnIndex,
    /// It has no `config` with `layers`.
    #[error("not an image manifest")]
    NotAManifest,
    /// It lists too many descriptors.
    #[error("more than {MAX_DESCRIPTORS} descriptors")]
    TooMany,
    /// A descriptor's digest is not one.
    #[error("a descriptor has a bad digest: {0}")]
    Digest(#[from] ReferenceError),
    /// A descriptor lacks a required field, named here.
    #[error("a descriptor has no `{0}`")]
    Missing(&'static str),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDescriptor {
    media_type: Option<String>,
    digest: Option<String>,
    size: Option<u64>,
    artifact_type: Option<String>,
}

impl RawDescriptor {
    fn parse(self) -> Result<Descriptor, Error> {
        Ok(Descriptor {
            media_type: self.media_type.ok_or(Error::Missing("mediaType"))?,
            digest: Digest::parse(&self.digest.ok_or(Error::Missing("digest"))?)?,
            size: self.size.ok_or(Error::Missing("size"))?,
            artifact_type: present(self.artifact_type),
        })
    }
}

/// A subject: only its digest matters.
#[derive(Deserialize)]
struct RawSubject {
    digest: Option<String>,
}

#[derive(Deserialize)]
struct RawIndex {
    /// Absent when it is no index.
    #[serde(default, deserialize_with = "listed")]
    manifests: Option<Vec<RawDescriptor>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawManifest {
    subject: Option<RawSubject>,
    artifact_type: Option<String>,
    config: Option<RawDescriptor>,
    layers: Option<Vec<RawDescriptor>>,
    /// Any JSON: one that is no object of strings leaves the manifest a referrer, with fewer annotations.
    annotations: Option<serde_json::Value>,
}

/// A list that is present, `null` as empty: Go writes an empty list so, and Google's Artifact Registry answers so for
/// a manifest without referrers (D133).
fn listed<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    field: D,
) -> Result<Option<Vec<T>>, D::Error> {
    Ok(Some(Option::deserialize(field)?.unwrap_or_default()))
}

/// `text`, unless it is absent or empty: the spec treats both alike (`spec.md:633-634`).
fn present(text: Option<String>) -> Option<String> {
    text.filter(|text| !text.is_empty())
}

/// The entries of `annotations` whose values are strings.
fn strings(annotations: Option<serde_json::Value>) -> BTreeMap<String, String> {
    let Some(serde_json::Value::Object(map)) = annotations else {
        return BTreeMap::new();
    };
    map.into_iter()
        .filter_map(|(key, value)| match value {
            serde_json::Value::String(value) => Some((key, value)),
            _ => None,
        })
        .collect()
}

fn descriptors(list: Vec<RawDescriptor>) -> Result<Vec<Descriptor>, Error> {
    if list.len() > MAX_DESCRIPTORS {
        return Err(Error::TooMany);
    }
    list.into_iter().map(RawDescriptor::parse).collect()
}

/// The `manifests` of a referrers index: the referrers API's answer, or the index under the fallback tag.
///
/// # Errors
///
/// When the bytes are no JSON object with a `manifests` array or `null`, it lists too many, or a descriptor lacks its
/// media type, digest or size, or has a bad digest.
pub fn index(bytes: &[u8]) -> Result<Vec<Descriptor>, Error> {
    let raw: RawIndex = serde_json::from_slice(bytes)?;
    descriptors(raw.manifests.ok_or(Error::NotAnIndex)?)
}

/// A referrer: an image manifest that holds an artifact, such as a Sigstore bundle or a legacy cosign signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Referrer {
    /// The manifest it refers to; a legacy `.sig` manifest has none.
    pub subject: Option<Digest>,
    /// Its `artifactType`. Never empty: an empty one is absent.
    pub artifact_type: Option<String>,
    /// Its config blob.
    pub config: Descriptor,
    /// Its layer blobs, in order.
    pub layers: Vec<Descriptor>,
    /// Its annotations whose values are strings, as the image-spec has them (`annotations.md`).
    pub annotations: BTreeMap<String, String>,
}

impl Referrer {
    /// Reads an image manifest as a referrer.
    ///
    /// # Errors
    ///
    /// When the bytes are no JSON object with `config` and `layers`, it lists too many layers, a descriptor lacks its
    /// media type, digest or size, or a digest is bad, the subject's included.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let raw: RawManifest = serde_json::from_slice(bytes)?;
        let (Some(config), Some(layers)) = (raw.config, raw.layers) else {
            return Err(Error::NotAManifest);
        };
        let subject = raw
            .subject
            .map(|subject| {
                let digest = subject.digest.ok_or(Error::Missing("digest"))?;
                Ok::<_, Error>(Digest::parse(&digest)?)
            })
            .transpose()?;
        Ok(Self {
            subject,
            artifact_type: present(raw.artifact_type),
            config: config.parse()?,
            layers: descriptors(layers)?,
            annotations: strings(raw.annotations),
        })
    }

    /// The type a referrers index lists it under: its `artifactType`, else its config's media type (`spec.md:632-634`).
    /// One with neither `artifactType` nor subject, such as a legacy `.sig` manifest, is listed under its first layer's
    /// media type: [`SIMPLE_SIGNING`] for a `.sig` (D124).
    #[must_use]
    pub fn listed_type(&self) -> &str {
        match (&self.artifact_type, &self.subject, self.layers.first()) {
            (Some(artifact_type), ..) => artifact_type,
            (None, None, Some(layer)) => &layer.media_type,
            (None, ..) => &self.config.media_type,
        }
    }

    /// Whether it holds a Sigstore bundle.
    ///
    /// Its `artifactType` says so. Without one, tools fall back to the config's media type (image-spec
    /// `manifest.md:264`), but cosign's is the empty type, which says nothing; so without one, or with the empty
    /// type, a layer of the bundle's type says so.
    #[must_use]
    pub fn is_bundle(&self) -> bool {
        match self.artifact_type.as_deref() {
            Some(BUNDLE) => true,
            None | Some(EMPTY) => self.layers.iter().any(|layer| layer.media_type == BUNDLE),
            Some(_) => false,
        }
    }

    /// Every blob, the config first.
    pub fn blobs(&self) -> impl Iterator<Item = &Descriptor> {
        std::iter::once(&self.config).chain(&self.layers)
    }
}

/// The referrers fallback tag of `digest`, `<alg>-<hex>`, whose index lists its referrers when the registry has no
/// referrers API (`spec.md:712-714,791-805`).
///
/// The hex is cut to its first 64 digits, as the spec cuts it, so a sha512 digest gives a valid tag.
#[must_use]
pub fn fallback_tag(digest: &Digest) -> String {
    let encoded = digest.encoded();
    let encoded = encoded.get(..TAG_ENCODED_MAX).unwrap_or(encoded);
    format!("{}-{encoded}", digest.algorithm())
}

/// The legacy cosign signature tag of `digest`, `<alg>-<hex>.sig`, with the whole hex (cosign v3.1.3
/// `pkg/oci/remote/remote.go:107-120,154-170`).
///
/// cosign's `.att` and `.sbom` tags are never formed: attestations count only as Sigstore bundles (D43).
#[must_use]
pub fn signature_tag(digest: &Digest) -> String {
    format!("{}-{}.sig", digest.algorithm(), digest.encoded())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> String {
        format!("sha256:{}", format!("{n:02x}").repeat(32))
    }

    fn descriptor(media_type: &str, n: u8, artifact_type: Option<&str>) -> Descriptor {
        Descriptor {
            media_type: media_type.to_owned(),
            digest: Digest::parse(&digest(n)).unwrap(),
            size: 2,
            artifact_type: artifact_type.map(str::to_owned),
        }
    }

    #[test]
    fn a_referrers_index_lists_its_descriptors() {
        let text = format!(
            r#"{{"schemaVersion":2,"mediaType":"{INDEX}","manifests":[
                {{"mediaType":"{MANIFEST}","digest":"{}","size":2,"artifactType":"{BUNDLE}","annotations":{{"a":"b"}}}},
                {{"mediaType":"{MANIFEST}","digest":"{}","size":2,"artifactType":""}},
                {{"mediaType":"{INDEX}","digest":"{}","size":2}}
            ]}}"#,
            digest(1),
            digest(2),
            digest(3)
        );
        assert_eq!(
            index(text.as_bytes()).unwrap(),
            [
                descriptor(MANIFEST, 1, Some(BUNDLE)),
                descriptor(MANIFEST, 2, None),
                descriptor(INDEX, 3, None),
            ]
        );
        assert_eq!(index(br#"{"manifests":[]}"#).unwrap(), []);
    }

    #[test]
    fn a_null_list_of_manifests_lists_none() {
        // Google's Artifact Registry answers so for a manifest without referrers, behind registry.k8s.io and
        // mirror.gcr.io.
        let text = format!(r#"{{"schemaVersion":2,"mediaType":"{INDEX}","manifests":null}}"#);
        assert_eq!(index(text.as_bytes()).unwrap(), []);
    }

    #[test]
    fn what_is_no_referrers_index_is_refused() {
        let full = |field: &str| {
            let mut fields = vec![
                format!(r#""mediaType":"{MANIFEST}""#),
                format!(r#""digest":"{}""#, digest(1)),
                r#""size":2"#.to_owned(),
            ];
            fields.retain(|text| !text.contains(field));
            format!(r#"{{"manifests":[{{{}}}]}}"#, fields.join(","))
        };
        for (field, name) in [
            ("mediaType", "mediaType"),
            ("digest", "digest"),
            ("size", "size"),
        ] {
            assert!(
                matches!(index(full(field).as_bytes()), Err(Error::Missing(missing)) if missing == name),
                "{field}"
            );
        }
        assert!(matches!(index(b"{}"), Err(Error::NotAnIndex)));
        assert!(matches!(
            index(br#"{"config":{},"layers":[]}"#),
            Err(Error::NotAnIndex)
        ));
        assert!(matches!(
            index(br#"{"manifests":[{"mediaType":"x","digest":"md5:00","size":1}]}"#),
            Err(Error::Digest(_))
        ));
        for text in [
            "",
            "[]",
            r#"{"manifests":{}}"#,
            r#"{"manifests":[{"mediaType":"x","digest":"sha256:00","size":-1}]}"#,
            r#"{"manifests":[{"mediaType":"x","digest":"sha256:00","size":1.5}]}"#,
        ] {
            assert!(index(text.as_bytes()).is_err(), "{text:?}");
        }
    }

    #[test]
    fn an_index_with_too_many_descriptors_is_refused() {
        let item = format!(r#"{{"mediaType":"x","digest":"{}","size":1}}"#, digest(7));
        let list = |n: usize| vec![item.as_str(); n].join(",");
        let text = format!(r#"{{"manifests":[{}]}}"#, list(MAX_DESCRIPTORS + 1));
        assert!(matches!(index(text.as_bytes()), Err(Error::TooMany)));
        let text = format!(r#"{{"manifests":[{}]}}"#, list(MAX_DESCRIPTORS));
        assert_eq!(index(text.as_bytes()).unwrap().len(), MAX_DESCRIPTORS);
    }

    #[test]
    fn a_descriptor_may_be_a_bundle_unless_it_says_otherwise() {
        for (artifact_type, may) in [
            (Some(BUNDLE), true),
            (None, true),
            (Some(EMPTY), true),
            (Some(COSIGN_ATTESTATION), false),
            (Some("application/spdx+json"), false),
        ] {
            assert_eq!(
                descriptor(MANIFEST, 1, artifact_type).may_be_bundle(),
                may,
                "{artifact_type:?}"
            );
        }
    }

    /// A bundle referrer as cosign v3 writes it (`docs/research/sigstore-and-referrers.md` § 2).
    fn bundle_manifest(artifact_type: Option<&str>, layer: &str) -> String {
        let artifact_type =
            artifact_type.map_or_else(String::new, |t| format!(r#""artifactType":"{t}","#));
        format!(
            r#"{{"schemaVersion":2,"mediaType":"{MANIFEST}",{artifact_type}
                "config":{{"mediaType":"{EMPTY}","digest":"{}","size":2}},
                "layers":[{{"mediaType":"{layer}","digest":"{}","size":2}}],
                "subject":{{"mediaType":"{MANIFEST}","digest":"{}","size":2}}}}"#,
            digest(4),
            digest(5),
            digest(6)
        )
    }

    #[test]
    fn a_bundle_referrer_is_read_with_its_subject_and_blobs() {
        let referrer = Referrer::parse(bundle_manifest(Some(BUNDLE), BUNDLE).as_bytes()).unwrap();
        assert_eq!(
            referrer,
            Referrer {
                subject: Some(Digest::parse(&digest(6)).unwrap()),
                artifact_type: Some(BUNDLE.to_owned()),
                config: descriptor(EMPTY, 4, None),
                layers: vec![descriptor(BUNDLE, 5, None)],
                annotations: BTreeMap::new(),
            }
        );
        assert!(referrer.is_bundle());
        assert_eq!(
            referrer
                .blobs()
                .map(|blob| blob.digest.to_string())
                .collect::<Vec<_>>(),
            [digest(4), digest(5)]
        );
    }

    #[test]
    fn a_referrer_is_a_bundle_by_its_type_or_else_by_a_layer() {
        for (artifact_type, layer, bundle) in [
            (Some(BUNDLE), "x", true),
            (None, BUNDLE, true),
            (Some(""), BUNDLE, true),
            (Some(EMPTY), BUNDLE, true),
            (None, "x", false),
            (Some(EMPTY), "x", false),
            (Some(COSIGN_ATTESTATION), BUNDLE, false),
        ] {
            let referrer =
                Referrer::parse(bundle_manifest(artifact_type, layer).as_bytes()).unwrap();
            assert_eq!(referrer.is_bundle(), bundle, "{artifact_type:?} {layer}");
        }
    }

    #[test]
    fn a_legacy_signature_has_no_subject() {
        let text = format!(
            r#"{{"schemaVersion":2,"mediaType":"{MANIFEST}",
                "config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"{}","size":233}},
                "layers":[{{"mediaType":"{SIMPLE_SIGNING}","digest":"{}","size":250,
                    "annotations":{{"dev.cosignproject.cosign/signature":"MEUC"}}}}]}}"#,
            digest(1),
            digest(2)
        );
        let referrer = Referrer::parse(text.as_bytes()).unwrap();
        assert_eq!(referrer.subject, None);
        assert!(!referrer.is_bundle());
        assert_eq!(referrer.layers[0].media_type, SIMPLE_SIGNING);
        assert_eq!(referrer.listed_type(), SIMPLE_SIGNING);
    }

    #[test]
    fn a_referrer_is_listed_under_its_type_else_its_configs() {
        let typed = Referrer::parse(bundle_manifest(Some(BUNDLE), "x").as_bytes()).unwrap();
        assert_eq!(typed.listed_type(), BUNDLE);
        // With a subject, the config's type, as the spec has it, though the layer is a bundle.
        let untyped = Referrer::parse(bundle_manifest(None, BUNDLE).as_bytes()).unwrap();
        assert_eq!(untyped.listed_type(), EMPTY);
        let bare = format!(
            r#"{{"config":{{"mediaType":"{EMPTY}","digest":"{}","size":2}},"layers":[]}}"#,
            digest(1)
        );
        assert_eq!(
            Referrer::parse(bare.as_bytes()).unwrap().listed_type(),
            EMPTY
        );
    }

    #[test]
    fn only_annotations_that_are_strings_are_read() {
        let with = |annotations: &str| {
            let text = format!(
                r#"{{"config":{{"mediaType":"{EMPTY}","digest":"{}","size":2}},"layers":[],
                    "annotations":{annotations}}}"#,
                digest(1)
            );
            Referrer::parse(text.as_bytes()).unwrap().annotations
        };
        assert_eq!(
            with(r#"{"a":"b","n":1,"o":{}}"#),
            BTreeMap::from([("a".to_owned(), "b".to_owned())])
        );
        assert!(with(r#"["a"]"#).is_empty());
        assert!(with("null").is_empty());
    }

    #[test]
    fn what_is_no_referrer_is_refused() {
        assert!(matches!(
            Referrer::parse(br#"{"manifests":[]}"#),
            Err(Error::NotAManifest)
        ));
        assert!(matches!(
            Referrer::parse(br#"{"config":{"mediaType":"x","digest":"x","size":1}}"#),
            Err(Error::NotAManifest)
        ));
        let config = format!(r#"{{"mediaType":"x","digest":"{}","size":1}}"#, digest(1));
        for (text, missing) in [
            (
                r#"{"config":{"mediaType":"x","size":1},"layers":[]}"#.to_owned(),
                "digest",
            ),
            (
                format!(
                    r#"{{"config":{config},"layers":[{{"digest":"{}","size":1}}]}}"#,
                    digest(2)
                ),
                "mediaType",
            ),
            (
                format!(r#"{{"config":{config},"layers":[],"subject":{{}}}}"#),
                "digest",
            ),
        ] {
            assert!(
                matches!(Referrer::parse(text.as_bytes()), Err(Error::Missing(m)) if m == missing),
                "{text}"
            );
        }
        assert!(matches!(
            Referrer::parse(
                format!(r#"{{"config":{config},"layers":[],"subject":{{"digest":"sha256:0"}}}}"#)
                    .as_bytes()
            ),
            Err(Error::Digest(_))
        ));
    }

    #[test]
    fn tags_are_formed_from_the_digest() {
        let sha256 = Digest::parse(&digest(0xab)).unwrap();
        let hex = "ab".repeat(32);
        assert_eq!(fallback_tag(&sha256), format!("sha256-{hex}"));
        assert_eq!(signature_tag(&sha256), format!("sha256-{hex}.sig"));
        let sha512 = Digest::parse(&format!("sha512:{}", "a".repeat(128))).unwrap();
        assert_eq!(fallback_tag(&sha512), format!("sha512-{}", "a".repeat(64)));
        assert_eq!(
            signature_tag(&sha512),
            format!("sha512-{}.sig", "a".repeat(128))
        );
    }
}
