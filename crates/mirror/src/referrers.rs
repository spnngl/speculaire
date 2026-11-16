//! The referrers the peer API lists (D124): the artifacts a node's artifact store holds about a manifest, as an image
//! index (distribution-spec v1.1.1-57-g9727462 `spec.md:620-682`).
//!
//! The index is a hint, as any registry's: a reader fetches each manifest it lists by digest and checks that it names
//! the target. A legacy `.sig` manifest names none.

use std::collections::BTreeMap;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full};
use hyper::Response;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use serde::Serialize;
use speculaire_oci::reference::Digest;
use speculaire_oci::referrers::{INDEX, Referrer};
use speculaire_runtime::content::Content;
use tracing::warn;

use crate::pulls::Body;
use crate::serve::{MAX_MANIFEST, media_type, never};

/// The header that says a filter was applied (`spec.md:681`).
const FILTERS_APPLIED: &str = "oci-filters-applied";

/// The artifacts a node holds: their manifests and blobs by digest, and which manifests are about a target.
///
/// The artifact store implements it, so that the mirror serves artifacts without depending on their discovery.
pub trait Referrers: Content {
    /// The manifests of the artifacts held about the manifest `target`, each once.
    fn referrers(&self, target: &Digest) -> Vec<Digest>;
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u8,
    media_type: &'static str,
    manifests: Vec<Listed>,
}

/// A descriptor of the index, with what the spec has it carry of its manifest (`spec.md:632-635`).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Listed {
    media_type: String,
    digest: String,
    size: u64,
    artifact_type: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    annotations: BTreeMap<String, String>,
}

/// The referrers index of `target`: every artifact `artifacts` holds about it, or only those listed under
/// `artifact_type` when one is given, which the `OCI-Filters-Applied` header then says. None is an empty index.
pub(crate) async fn index<R: Referrers>(
    artifacts: &R,
    target: &Digest,
    artifact_type: Option<&str>,
) -> Response<Body> {
    let mut manifests = Vec::new();
    for digest in artifacts.referrers(target) {
        if let Some(listed) = listed(artifacts, &digest).await
            && artifact_type.is_none_or(|wanted| wanted == listed.artifact_type)
        {
            manifests.push(listed);
        }
    }
    let index = Index {
        schema_version: 2,
        media_type: INDEX,
        manifests,
    };
    let body = Bytes::from(serde_json::to_vec(&index).expect("an index of strings is always JSON"));
    let length = body.len();
    let mut response = Response::new(Full::new(body).map_err(never).boxed_unsync());
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(INDEX));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
    if artifact_type.is_some() {
        headers.insert(FILTERS_APPLIED, HeaderValue::from_static("artifactType"));
    }
    response
}

/// The descriptor of the artifact manifest `digest`, unless it cannot be read as one.
async fn listed<R: Referrers>(artifacts: &R, digest: &Digest) -> Option<Listed> {
    let read = match artifacts.open(digest).await {
        Ok(blob) => blob?.read_all(MAX_MANIFEST).await,
        Err(err) => Err(err),
    };
    let bytes = match read {
        Ok(bytes) => bytes,
        Err(err) => {
            warn!(%digest, error = %err, "an artifact manifest cannot be read: it is not listed");
            return None;
        }
    };
    let Ok(referrer) = Referrer::parse(&bytes) else {
        warn!(%digest, "an artifact the store holds is no image manifest: it is not listed");
        return None;
    };
    let media_type = media_type(&bytes)?.to_str().ok()?.to_owned();
    Some(Listed {
        media_type,
        digest: digest.to_string(),
        size: bytes.len() as u64,
        artifact_type: referrer.listed_type().to_owned(),
        annotations: referrer.annotations,
    })
}
