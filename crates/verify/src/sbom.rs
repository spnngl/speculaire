//! The SBOM a policy can require (D12, D150), in either of two tiers: an attestation of an SBOM predicate type signed
//! by an authority's signer, or the SBOM a BuildKit attestation manifest of the image's index holds, that index signed
//! by an authority's signer (D49).
//!
//! An SBOM passes when it parses as SPDX 2.3 JSON or CycloneDX ≥ 1.4 JSON and lists a package; it is counted, never
//! built. A `.sbom` tag is never read: discovery does not fetch it (D121).

use std::borrow::Cow;
use std::collections::HashSet;
use std::num::NonZeroUsize;

use serde::Deserialize;
use serde::de::IgnoredAny;
use sigstore_verify::types::Bundle;
use speculaire_artifacts::{Artifact, Kind, Store};
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::{self, Referrer};

use crate::Policy;
use crate::signature::{self, Blob, Signatures, Signed, Unverifiable, blob, read, sources};
use crate::statement::Statement;
use crate::trust::TrustRoot;

/// cosign's SPDX predicate type (cosign v3.1.3 `pkg/types/predicate.go`).
const SPDX: &str = "https://spdx.dev/Document";
/// GitHub's SPDX predicate type, the document's version appended (`actions/attest` v4.2.2 `src/sbom.ts:85`).
const SPDX_2_3: &str = "https://spdx.dev/Document/v2.3";
/// The CycloneDX predicate type, of cosign and GitHub alike.
const CYCLONEDX: &str = "https://cyclonedx.org/bom";

/// The predicate types of an SBOM attestation (D150), in the order they are looked for, and their formats.
const PREDICATE_TYPES: [(&str, Format); 3] = [
    (SPDX, Format::Spdx),
    (SPDX_2_3, Format::Spdx),
    (CYCLONEDX, Format::CycloneDx),
];

/// The media type of a BuildKit attestation layer: an in-toto statement.
const IN_TOTO: &str = "application/vnd.in-toto+json";

/// The ID of an SPDX document itself, in its relationships.
const SPDX_DOCUMENT: &str = "SPDXRef-DOCUMENT";

/// An image's SBOM result: the SBOM that passes, or why none does.
pub type SbomResult = Result<Listed, Failure>;

/// An SBOM that passes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listed {
    /// Who signed its attestation, or the index that holds it.
    pub signed: Signed,
    /// The packages it lists.
    pub packages: NonZeroUsize,
}

/// Why no SBOM passes: the reason of the SBOM that came closest, in the order below.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    /// Neither tier holds an SBOM. An SBOM only in a `.sbom` tag is missing.
    #[error("SBOM missing")]
    Missing,
    /// An SBOM attestation, or the index holding a BuildKit SBOM, that no authority's signer signs.
    #[error("SBOM unsigned: {0}")]
    Unsigned(signature::Failure),
    /// Its size, as its manifest lists it, above `sbom.max_size`: discovery left it out (D150).
    #[error("SBOM over sbom.max_size: {0} bytes")]
    Oversize(u64),
    /// Neither SPDX 2.3 JSON nor CycloneDX ≥ 1.4 JSON, as its predicate type says it is.
    #[error("SBOM unparsable: {0}")]
    Unparsable(String),
    /// It parses, and lists no package but the image it describes.
    #[error("SBOM without packages")]
    Empty,
}

impl Failure {
    /// How close the SBOM came to passing.
    const fn closeness(&self) -> u8 {
        match self {
            Self::Missing => 0,
            Self::Unsigned(_) => 1,
            Self::Oversize(_) => 2,
            Self::Unparsable(_) => 3,
            Self::Empty => 4,
        }
    }

    /// The reason of an attestation of an SBOM predicate type that fails as a signature.
    fn of_attestation(failure: signature::Failure) -> Self {
        match failure {
            signature::Failure::Missing => Self::Missing,
            signature::Failure::Oversize(size) => Self::Oversize(size),
            failure => Self::Unsigned(failure),
        }
    }
}

/// The closer of two SBOMs' reasons, the first on a tie.
fn closer(closest: Failure, failure: Failure) -> Failure {
    if failure.closeness() > closest.closeness() {
        failure
    } else {
        closest
    }
}

/// An SBOM format, as an SBOM's predicate type names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// SPDX 2.3 JSON.
    Spdx,
    /// CycloneDX ≥ 1.4 JSON.
    CycloneDx,
}

impl Format {
    /// The format of an SBOM of `predicate_type`, if it is an SBOM predicate type (D150).
    #[must_use]
    pub fn of(predicate_type: &str) -> Option<Self> {
        PREDICATE_TYPES
            .iter()
            .find(|(sbom, _)| *sbom == predicate_type)
            .map(|(_, format)| *format)
    }

    /// The packages `document` lists: an SPDX document's packages but the ones it describes, such as the image
    /// itself, or a CycloneDX BOM's top-level components. Every other value is skipped unbuilt.
    ///
    /// # Errors
    ///
    /// [`Failure::Unparsable`] when `document` is not of the format, or of another version, and [`Failure::Empty`]
    /// when it lists no package.
    pub fn packages(self, document: &str) -> Result<NonZeroUsize, Failure> {
        let count = match self {
            Self::Spdx => spdx(document)?,
            Self::CycloneDx => cyclonedx(document)?,
        };
        NonZeroUsize::new(count).ok_or(Failure::Empty)
    }
}

/// An SPDX 2.3 JSON document, its packages' IDs and what says which packages it describes.
#[derive(Deserialize)]
struct Spdx<'a> {
    #[serde(rename = "spdxVersion", borrow)]
    version: Cow<'a, str>,
    #[serde(default, borrow)]
    packages: Vec<Package<'a>>,
    #[serde(rename = "documentDescribes", default, borrow)]
    describes: Vec<Cow<'a, str>>,
    #[serde(default, borrow)]
    relationships: Vec<Relationship<'a>>,
}

#[derive(Deserialize)]
struct Package<'a> {
    #[serde(rename = "SPDXID", borrow)]
    id: Cow<'a, str>,
}

#[derive(Deserialize)]
struct Relationship<'a> {
    #[serde(rename = "spdxElementId", borrow)]
    element: Cow<'a, str>,
    #[serde(rename = "relationshipType", borrow)]
    kind: Cow<'a, str>,
    #[serde(rename = "relatedSpdxElement", borrow)]
    related: Cow<'a, str>,
}

/// The packages of the SPDX 2.3 JSON `document` that it does not describe.
fn spdx(document: &str) -> Result<usize, Failure> {
    let spdx: Spdx<'_> = serde_json::from_str(document).map_err(|e| unparsable("SPDX", &e))?;
    if spdx.version != "SPDX-2.3" {
        return Err(Failure::Unparsable(
            "spdxVersion is not SPDX-2.3".to_owned(),
        ));
    }
    let mut described: HashSet<&str> = spdx.describes.iter().map(AsRef::as_ref).collect();
    for relationship in &spdx.relationships {
        match &*relationship.kind {
            "DESCRIBES" if relationship.element == SPDX_DOCUMENT => {
                described.insert(&*relationship.related);
            }
            "DESCRIBED_BY" if relationship.related == SPDX_DOCUMENT => {
                described.insert(&*relationship.element);
            }
            _ => {}
        }
    }
    Ok(spdx
        .packages
        .iter()
        .filter(|package| !described.contains(&*package.id))
        .count())
}

/// A CycloneDX JSON BOM, its top-level components counted.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDx<'a> {
    #[serde(borrow)]
    bom_format: Cow<'a, str>,
    #[serde(borrow)]
    spec_version: Cow<'a, str>,
    #[serde(default)]
    components: Vec<IgnoredAny>,
}

/// The top-level components of the CycloneDX ≥ 1.4 JSON `document`.
fn cyclonedx(document: &str) -> Result<usize, Failure> {
    let bom: CycloneDx<'_> =
        serde_json::from_str(document).map_err(|e| unparsable("CycloneDX", &e))?;
    let minor = bom
        .spec_version
        .strip_prefix("1.")
        .and_then(|minor| minor.parse::<u32>().ok());
    if bom.bom_format != "CycloneDX" || minor.is_none_or(|minor| minor < 4) {
        return Err(Failure::Unparsable(
            "bomFormat is not CycloneDX, or specVersion below 1.4".to_owned(),
        ));
    }
    Ok(bom.components.len())
}

/// Where `format` JSON fails to parse, without the document's text.
fn unparsable(format: &str, e: &serde_json::Error) -> Failure {
    Failure::Unparsable(format!(
        "not {format} JSON at line {} column {}",
        e.line(),
        e.column()
    ))
}

impl Signatures {
    /// The SBOM of `target` that `policy` requires (D12): one an authority's signer attests among `artifacts`, else
    /// one a BuildKit attestation manifest of the index `target` holds, the index signed by an authority's signer,
    /// each verified against `root`.
    ///
    /// # Errors
    ///
    /// When the store cannot give a blob it was not asked before, and its manifest does not list it above
    /// `sbom.max_size`.
    pub async fn sbom(
        &self,
        store: &Store,
        target: &Digest,
        artifacts: &[Artifact],
        policy: &Policy,
        root: &TrustRoot,
    ) -> Result<SbomResult, Unverifiable> {
        let mut closest = Failure::Missing;
        for authority in policy.authorities() {
            for (predicate_type, format) in PREDICATE_TYPES {
                let result = match self
                    .attested(
                        store,
                        target,
                        artifacts,
                        &authority.signer,
                        root,
                        predicate_type,
                    )
                    .await?
                {
                    Ok(attested) => {
                        attestation(store, &attested.bundle, format)
                            .await?
                            .map(|packages| Listed {
                                signed: attested.signed,
                                packages,
                            })
                    }
                    Err(failure) => Err(Failure::of_attestation(failure)),
                };
                match result {
                    Ok(listed) => return Ok(Ok(listed)),
                    Err(failure) => closest = closer(closest, failure),
                }
            }
        }
        Ok(
            match self
                .buildkit(store, target, artifacts, policy, root)
                .await?
            {
                Ok(listed) => Ok(listed),
                Err(failure) => Err(closer(closest, failure)),
            },
        )
    }

    /// The SBOM a BuildKit attestation manifest listed in the index `target` holds, read unsigned, that passes when an
    /// authority's signer signs the index (D49).
    async fn buildkit(
        &self,
        store: &Store,
        target: &Digest,
        artifacts: &[Artifact],
        policy: &Policy,
        root: &TrustRoot,
    ) -> Result<SbomResult, Unverifiable> {
        let found = layers(store, target, artifacts, self.max_size()).await?;
        if found == Err(Failure::Missing) {
            return Ok(Err(Failure::Missing));
        }
        let sources = sources(target, artifacts);
        let mut unsigned = signature::Failure::Missing;
        for authority in policy.authorities() {
            match self
                .signature(store, root, target, &sources, &authority.signer)
                .await?
            {
                Ok(signed) => return Ok(found.map(|packages| Listed { signed, packages })),
                Err(failure) => unsigned = signature::closer(unsigned, failure),
            }
        }
        Ok(Err(Failure::Unsigned(unsigned)))
    }
}

/// The packages of the first SBOM that passes in the in-toto layers of the BuildKit attestation manifests among
/// `artifacts` that the index `target` lists, read unsigned: the layers after it are neither read nor parsed.
async fn layers(
    store: &Store,
    target: &Digest,
    artifacts: &[Artifact],
    max_size: u64,
) -> Result<Result<NonZeroUsize, Failure>, Unverifiable> {
    let attestations: Vec<&Artifact> = artifacts
        .iter()
        .filter(|artifact| artifact.kind == Kind::Attestation)
        .collect();
    if attestations.is_empty() {
        return Ok(Err(Failure::Missing));
    }
    // A record is untrusted: only what the signed index lists counts.
    let listed = referrers::index(&read(store, target).await?).unwrap_or_default();
    let mut closest = Failure::Missing;
    for attestation in attestations
        .into_iter()
        .filter(|attestation| listed.iter().any(|d| d.digest == attestation.manifest))
    {
        let Ok(manifest) = Referrer::parse(&read(store, &attestation.manifest).await?) else {
            continue;
        };
        for layer in manifest.layers.iter().filter(|l| l.media_type == IN_TOTO) {
            let result = match blob(store, &attestation.manifest, &layer.digest, max_size).await? {
                Blob::Kept(bytes) => statement(&bytes),
                // An oversize layer may be any statement: it counts only when nothing comes closer.
                Blob::Oversize { size, .. } => Err(Failure::Oversize(size)),
            };
            match result {
                Ok(packages) => return Ok(Ok(packages)),
                Err(failure) => closest = closer(closest, failure),
            }
        }
    }
    Ok(Err(closest))
}

/// The packages of the `format` SBOM the verified bundle `bundle` attests.
async fn attestation(
    store: &Store,
    bundle: &Digest,
    format: Format,
) -> Result<Result<NonZeroUsize, Failure>, Unverifiable> {
    let bytes = read(store, bundle).await?;
    let bundle = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| Bundle::from_json(text).ok());
    let predicate = bundle
        .as_ref()
        .and_then(|bundle| Statement::of(bundle).ok())
        .and_then(|statement| statement.predicate());
    Ok(match predicate {
        Some(predicate) => format.packages(predicate),
        None => Err(Failure::Unparsable(
            "the attestation holds no predicate".to_owned(),
        )),
    })
}

/// The packages of the SBOM the in-toto statement `bytes` holds, [`Failure::Missing`] when it holds none.
fn statement(bytes: &[u8]) -> Result<NonZeroUsize, Failure> {
    let Ok(statement) = Statement::parse(bytes) else {
        return Err(Failure::Missing);
    };
    let Some(format) = Format::of(statement.predicate_type()) else {
        return Err(Failure::Missing);
    };
    match statement.predicate() {
        Some(predicate) => format.packages(predicate),
        None => Err(Failure::Unparsable(
            "the statement holds no predicate".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPDX_SEED: &str = include_str!("../../../fuzz/seeds/sbom/spdx.json");
    const CYCLONEDX_SEED: &str = include_str!("../../../fuzz/seeds/sbom/cyclonedx.json");

    fn spdx_of(packages: &str, extra: &str) -> String {
        format!(r#"{{"spdxVersion":"SPDX-2.3","packages":[{packages}]{extra}}}"#)
    }

    #[test]
    fn each_sbom_predicate_type_names_its_format_and_no_other_does() {
        assert_eq!(Format::of(SPDX), Some(Format::Spdx));
        assert_eq!(Format::of(SPDX_2_3), Some(Format::Spdx));
        assert_eq!(Format::of(CYCLONEDX), Some(Format::CycloneDx));
        assert_eq!(Format::of("https://spdx.dev/Document/v2.2"), None);
        assert_eq!(Format::of("https://slsa.dev/provenance/v1"), None);
    }

    #[test]
    fn the_recorded_sboms_list_their_packages_but_the_described_image() {
        assert_eq!(Format::Spdx.packages(SPDX_SEED), Ok(NonZeroUsize::MIN));
        assert_eq!(
            Format::CycloneDx.packages(CYCLONEDX_SEED),
            Ok(NonZeroUsize::new(2).expect("two"))
        );
    }

    #[test]
    fn a_package_the_document_describes_by_either_relationship_or_field_is_not_counted() {
        let packages = r#"{"SPDXID":"a"},{"SPDXID":"b"},{"SPDXID":"c"},{"SPDXID":"d"}"#;
        let relationship = |element: &str, kind: &str, related: &str| {
            format!(
                r#"{{"spdxElementId":"{element}","relationshipType":"{kind}","relatedSpdxElement":"{related}"}}"#
            )
        };
        let extra = format!(
            r#","documentDescribes":["a"],"relationships":[{},{},{},{},{}]"#,
            relationship(SPDX_DOCUMENT, "DESCRIBES", "b"),
            relationship("c", "DESCRIBED_BY", SPDX_DOCUMENT),
            // Only the document's own description counts.
            relationship("a", "DESCRIBES", "d"),
            relationship("d", "DESCRIBED_BY", "a"),
            relationship(SPDX_DOCUMENT, "CONTAINS", "d"),
        );

        assert_eq!(
            Format::Spdx.packages(&spdx_of(packages, &extra)),
            Ok(NonZeroUsize::MIN)
        );
    }

    #[test]
    fn a_document_without_packages_is_empty() {
        assert_eq!(Format::Spdx.packages(&spdx_of("", "")), Err(Failure::Empty));
        assert_eq!(
            Format::Spdx.packages(r#"{"spdxVersion":"SPDX-2.3"}"#),
            Err(Failure::Empty)
        );
        assert_eq!(
            Format::CycloneDx.packages(r#"{"bomFormat":"CycloneDX","specVersion":"1.4"}"#),
            Err(Failure::Empty)
        );
    }

    #[test]
    fn another_version_or_format_is_unparsable_without_its_text() {
        let bom = |format: &str, version: &str| {
            format!(r#"{{"bomFormat":"{format}","specVersion":"{version}","components":[{{}}]}}"#)
        };
        for version in ["1.4", "1.6", "1.17"] {
            assert_eq!(
                Format::CycloneDx.packages(&bom("CycloneDX", version)),
                Ok(NonZeroUsize::MIN),
                "{version}"
            );
        }
        for (format, version) in [
            ("CycloneDX", "1.3"),
            ("CycloneDX", "2.4"),
            ("CycloneDX", "1.x"),
            ("SWID", "1.6"),
        ] {
            assert!(
                matches!(
                    Format::CycloneDx.packages(&bom(format, version)),
                    Err(Failure::Unparsable(_))
                ),
                "{format} {version}"
            );
        }
        assert_eq!(
            Format::Spdx.packages(r#"{"spdxVersion":"SPDX-2.2","packages":[{"SPDXID":"a"}]}"#),
            Err(Failure::Unparsable(
                "spdxVersion is not SPDX-2.3".to_owned()
            ))
        );
        assert_eq!(
            Format::Spdx.packages("{\n\"packages\": 7}"),
            Err(Failure::Unparsable(
                "not SPDX JSON at line 2 column 13".to_owned()
            ))
        );
        assert_eq!(
            Format::CycloneDx.packages("[secret]"),
            Err(Failure::Unparsable(
                "not CycloneDX JSON at line 1 column 2".to_owned()
            ))
        );
    }

    #[test]
    fn a_statement_holds_an_sbom_only_of_an_sbom_predicate_type_with_a_predicate() {
        let text = |predicate_type: &str, predicate: &str| {
            format!(
                r#"{{"_type":"https://in-toto.io/Statement/v1","predicateType":"{predicate_type}"{predicate}}}"#
            )
        };
        let sbom = format!(r#","predicate":{SPDX_SEED}"#);

        assert_eq!(statement(b"not JSON"), Err(Failure::Missing));
        assert_eq!(
            statement(text("https://slsa.dev/provenance/v1", &sbom).as_bytes()),
            Err(Failure::Missing)
        );
        assert_eq!(
            statement(text(SPDX, &sbom).as_bytes()),
            Ok(NonZeroUsize::MIN)
        );
        assert!(matches!(
            statement(text(SPDX, "").as_bytes()),
            Err(Failure::Unparsable(_))
        ));
    }

    #[test]
    fn the_closest_reason_wins_and_the_first_on_a_tie() {
        let unparsable = Failure::Unparsable("first".to_owned());
        let reasons = [
            Failure::Missing,
            Failure::Unsigned(signature::Failure::Missing),
            Failure::Oversize(1),
            unparsable.clone(),
            Failure::Empty,
        ];
        for (at, closest) in reasons.iter().enumerate() {
            for further in &reasons[..at] {
                assert_eq!(closer(further.clone(), closest.clone()), *closest);
                assert_eq!(closer(closest.clone(), further.clone()), *closest);
            }
        }
        assert_eq!(
            closer(unparsable.clone(), Failure::Unparsable("second".to_owned())),
            unparsable
        );
    }
}
