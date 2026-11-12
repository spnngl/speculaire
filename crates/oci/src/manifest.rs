//! What a manifest points to: the blobs of an image, or the manifests of an index (D67, D88).
//!
//! The relay reads a manifest it serves to know which digests it may serve below it. Only the descriptors' digests are
//! read, from the OCI and the Docker v2 forms, which agree on the fields it needs.

use serde::Deserialize;

use crate::reference::{Digest, ReferenceError};

/// The most descriptors a manifest may list. Registries limit a manifest to 4 MiB, which is under this at the
/// shortest descriptor.
const MAX_DESCRIPTORS: usize = 20_000;

/// The digests a manifest points to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Children {
    /// An image manifest: its config and its layers, in order.
    Image {
        /// The config blob.
        config: Digest,
        /// The layer blobs.
        layers: Vec<Digest>,
    },
    /// An image index or Docker manifest list: the manifests of its platforms.
    Index {
        /// The manifests.
        manifests: Vec<Digest>,
    },
}

impl Children {
    /// Every digest, the config first.
    #[must_use]
    pub fn digests(&self) -> Vec<&Digest> {
        match self {
            Self::Image { config, layers } => std::iter::once(config).chain(layers).collect(),
            Self::Index { manifests } => manifests.iter().collect(),
        }
    }
}

/// A manifest that cannot be read.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The bytes are no JSON of the shape of a manifest.
    #[error("not a manifest: {0}")]
    Json(#[from] serde_json::Error),
    /// It lists no `manifests`, and no `config` with `layers`: a Docker v1 manifest, or no manifest.
    #[error("neither an image manifest nor an index")]
    Unsupported,
    /// It lists too many descriptors.
    #[error("more than {MAX_DESCRIPTORS} descriptors")]
    TooMany,
    /// A descriptor's digest is not one.
    #[error("a descriptor has a bad digest: {0}")]
    Digest(#[from] ReferenceError),
}

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
}

#[derive(Deserialize)]
struct Document {
    manifests: Option<Vec<Descriptor>>,
    config: Option<Descriptor>,
    layers: Option<Vec<Descriptor>>,
}

/// The digests that `bytes`, a manifest, points to.
///
/// A document with `manifests` is an index, whatever else it has; one with `config` and `layers` is an image manifest.
///
/// # Errors
///
/// When the bytes are no manifest of either kind, or a digest in it is malformed.
pub fn children(bytes: &[u8]) -> Result<Children, Error> {
    let document: Document = serde_json::from_slice(bytes)?;
    let digests = |list: Vec<Descriptor>| -> Result<Vec<Digest>, Error> {
        if list.len() > MAX_DESCRIPTORS {
            return Err(Error::TooMany);
        }
        list.into_iter()
            .map(|descriptor| Digest::parse(&descriptor.digest).map_err(Error::from))
            .collect()
    };
    match document {
        Document {
            manifests: Some(manifests),
            ..
        } => Ok(Children::Index {
            manifests: digests(manifests)?,
        }),
        Document {
            config: Some(config),
            layers: Some(layers),
            ..
        } => Ok(Children::Image {
            config: Digest::parse(&config.digest)?,
            layers: digests(layers)?,
        }),
        _ => Err(Error::Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> String {
        format!("sha256:{}", format!("{n:02x}").repeat(32))
    }

    #[test]
    fn an_image_manifest_points_to_its_config_and_layers_in_order() {
        let text = format!(
            r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{{"mediaType":"x","digest":"{}","size":1}},"layers":[{{"digest":"{}","size":1}},{{"digest":"{}"}}]}}"#,
            digest(1),
            digest(2),
            digest(3)
        );
        let parsed = children(text.as_bytes()).unwrap();
        assert_eq!(
            parsed,
            Children::Image {
                config: Digest::parse(&digest(1)).unwrap(),
                layers: vec![
                    Digest::parse(&digest(2)).unwrap(),
                    Digest::parse(&digest(3)).unwrap()
                ],
            }
        );
        assert_eq!(
            parsed
                .digests()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            [digest(1), digest(2), digest(3)]
        );
    }

    #[test]
    fn an_index_and_a_docker_manifest_list_point_to_their_manifests() {
        for media_type in [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ] {
            let text = format!(
                r#"{{"schemaVersion":2,"mediaType":"{media_type}","manifests":[{{"digest":"{}","platform":{{"os":"linux","architecture":"arm64"}}}},{{"digest":"{}"}}]}}"#,
                digest(4),
                digest(5)
            );
            assert_eq!(
                children(text.as_bytes()).unwrap(),
                Children::Index {
                    manifests: vec![
                        Digest::parse(&digest(4)).unwrap(),
                        Digest::parse(&digest(5)).unwrap()
                    ],
                }
            );
        }
        let empty = children(br#"{"manifests":[]}"#).unwrap();
        assert_eq!(
            empty,
            Children::Index {
                manifests: Vec::new()
            }
        );
        assert_eq!(empty.digests().len(), 0);
    }

    #[test]
    fn what_is_no_manifest_is_refused() {
        for text in [
            "",
            "[]",
            "{}",
            r#"{"schemaVersion":1,"fsLayers":[{"blobSum":"sha256:x"}]}"#,
            r#"{"config":{"digest":"sha256:00"}}"#,
            r#"{"layers":[]}"#,
            r#"{"manifests":[{"digest":"md5:00"}]}"#,
            r#"{"manifests":[{}]}"#,
            r#"{"config":{"digest":"nope"},"layers":[]}"#,
            r#"{"config":{"digest":"sha256:00"},"layers":[{"digest":""}]}"#,
        ] {
            assert!(children(text.as_bytes()).is_err(), "{text:?}");
        }
        assert!(matches!(children(b"{}"), Err(Error::Unsupported)));
        assert!(matches!(
            children(br#"{"manifests":[{"digest":"x"}]}"#),
            Err(Error::Digest(_))
        ));
    }

    #[test]
    fn a_manifest_with_too_many_descriptors_is_refused() {
        let item = format!(r#"{{"digest":"{}"}}"#, digest(7));
        let list = vec![item; MAX_DESCRIPTORS + 1].join(",");
        let text = format!(r#"{{"manifests":[{list}]}}"#);
        assert!(matches!(children(text.as_bytes()), Err(Error::TooMany)));
        let list = vec![format!(r#"{{"digest":"{}"}}"#, digest(7)); MAX_DESCRIPTORS].join(",");
        assert!(children(format!(r#"{{"manifests":[{list}]}}"#).as_bytes()).is_ok());
        assert!(matches!(
            children(
                format!(
                    r#"{{"config":{{"digest":"{}"}},"layers":[{}]}}"#,
                    digest(1),
                    vec![format!(r#"{{"digest":"{}"}}"#, digest(7)); MAX_DESCRIPTORS + 1].join(",")
                )
                .as_bytes()
            ),
            Err(Error::TooMany)
        ));
    }

    #[test]
    fn an_index_wins_over_a_config() {
        let text = format!(
            r#"{{"config":{{"digest":"{}"}},"layers":[],"manifests":[{{"digest":"{}"}}]}}"#,
            digest(1),
            digest(2)
        );
        assert!(matches!(
            children(text.as_bytes()),
            Ok(Children::Index { .. })
        ));
    }
}
