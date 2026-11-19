//! The legacy cosign `.sig` (D8, D147): each layer of its manifest is a simple signing payload, signed by a certificate
//! or a key, with the Rekor entry cosign logged it under in an annotation.
//!
//! A layer counts as a signature of the image its payload's `critical.image.docker-manifest-digest` names, as for
//! `cosign verify` (cosign v3.1.3 `pkg/cosign/verifiers.go:43-46`): a `.sig` has no subject, so the payload is the
//! only binding. It is then verified as a v0.1 bundle, whose inclusion promise (SET) is the transparency log entry.

use std::collections::HashMap;

use serde::Deserialize;
use sigstore_verify::types::bundle::{
    InclusionPromise, LogId, MediaType, MessageSignature, PublicKeyIdentifier, SignatureContent,
    TransparencyLogEntry, VerificationMaterial, VerificationMaterialContent, X509Certificate,
};
use sigstore_verify::types::{
    Bundle, CanonicalizedBody, DerCertificate, KindVersion, LogIndex, LogKeyId, Sha256Hash,
    SignatureBytes, SignedTimestamp,
};
use speculaire_oci::reference::Digest;

use crate::policy::PublicKey;
use crate::signature::{Failure, SignatureResult, verified};
use crate::trust::{TrustRoot, chain};

/// The annotation of a layer that holds its signature, in base64.
const SIGNATURE: &str = "dev.cosignproject.cosign/signature";
/// The annotation of a layer that holds its Fulcio certificate, in PEM; absent or empty when a key signed it.
const CERTIFICATE: &str = "dev.sigstore.cosign/certificate";
/// The annotation of a layer that holds Rekor's answer to its upload: the entry and its SET.
const SET: &str = "dev.sigstore.cosign/bundle";

/// A `.sig` manifest, as far as it is read.
#[derive(Deserialize)]
struct Manifest {
    layers: Vec<Layer>,
}

#[derive(Deserialize)]
struct Layer {
    #[serde(default)]
    annotations: HashMap<String, String>,
}

/// The [`SET`] annotation (sigstore-rs v0.15.0 `src/cosign/bundle.rs:59-118`).
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Logged {
    signed_entry_timestamp: String,
    payload: Entry,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Entry {
    body: String,
    integrated_time: i64,
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: String,
}

/// A simple signing payload, as far as it binds an image.
#[derive(Deserialize)]
struct SimpleSigning {
    critical: Critical,
}

#[derive(Deserialize)]
struct Critical {
    image: Image,
}

#[derive(Deserialize)]
struct Image {
    #[serde(rename = "docker-manifest-digest")]
    digest: String,
}

/// Verifies layer `layer` of `manifest`, a `.sig` manifest, over `payload`, its simple signing payload, as a signature
/// of `target` against `root`: by the certificate it holds, whatever its identity, or by `key` when a key signed it.
///
/// # Errors
///
/// [`Failure::Invalid`] when `payload` names another image, when the layer holds no SET, or when it does not verify;
/// otherwise as [`crate::signature::verify`].
pub fn verify(
    root: &TrustRoot,
    target: &Digest,
    manifest: &[u8],
    layer: usize,
    payload: &[u8],
    key: Option<&PublicKey>,
) -> SignatureResult {
    let signed = image(payload)?;
    if signed != *target {
        return Err(Failure::Invalid(format!(
            "the .sig signs {signed}, not this image"
        )));
    }
    verified(root, payload, &bundle(manifest, layer)?, key)
}

/// The image `payload` names.
fn image(payload: &[u8]) -> Result<Digest, Failure> {
    let payload: SimpleSigning =
        serde_json::from_slice(payload).map_err(|e| invalid("its simple signing payload", &e))?;
    Digest::parse(&payload.critical.image.digest)
        .map_err(|e| invalid("the image its payload names", &e))
}

/// Layer `layer` of `manifest` as a v0.1 bundle of a message signature over its payload.
fn bundle(manifest: &[u8], layer: usize) -> Result<Bundle, Failure> {
    let manifest: Manifest =
        serde_json::from_slice(manifest).map_err(|e| invalid("its .sig manifest", &e))?;
    let annotations = &manifest
        .layers
        .get(layer)
        .ok_or_else(|| Failure::Invalid(format!("the .sig has no layer {layer}")))?
        .annotations;
    let annotation = |name| annotations.get(name).filter(|value| !value.is_empty());
    let signature = annotation(SIGNATURE).ok_or_else(|| {
        Failure::Invalid(format!(
            "the .sig has no signature (annotation {SIGNATURE})"
        ))
    })?;
    let logged = annotation(SET)
        .ok_or_else(|| Failure::Invalid(format!("the .sig has no SET (annotation {SET})")))?;
    let material = match annotation(CERTIFICATE) {
        Some(pem) => VerificationMaterialContent::X509CertificateChain {
            certificates: vec![X509Certificate::new(
                DerCertificate::from_pem(pem).map_err(|e| invalid("its certificate", &e))?,
            )],
        },
        None => VerificationMaterialContent::PublicKey(PublicKeyIdentifier::new("")),
    };
    let signature =
        SignatureBytes::from_base64(signature).map_err(|e| invalid("its signature", &e))?;
    Ok(Bundle::new(
        MediaType::Bundle0_1,
        VerificationMaterial::new(material).with_tlog_entries(vec![entry(logged)?]),
        SignatureContent::MessageSignature(MessageSignature::new(signature)),
    ))
}

/// The Rekor entry of the [`SET`] annotation `logged`, with its SET as the inclusion promise.
fn entry(logged: &str) -> Result<TransparencyLogEntry, Failure> {
    let set = |e: &dyn std::error::Error| invalid("its SET", e);
    let logged: Logged = serde_json::from_str(logged).map_err(|e| set(&e))?;
    let entry = logged.payload;
    let id = Sha256Hash::from_hex(&entry.log_id).map_err(|e| set(&e))?;
    Ok(TransparencyLogEntry::new(
        LogIndex::try_from(entry.log_index).map_err(|e| set(&e))?,
        LogId::new(LogKeyId::new(id.as_bytes().to_vec())),
        // A `.sig` is a message signature, which Rekor v1 logs as a hashedrekord.
        KindVersion::HashedRekordV001,
        CanonicalizedBody::from_base64(&entry.body).map_err(|e| set(&e))?,
    )
    .with_integrated_time(jiff::Timestamp::from_second(entry.integrated_time).map_err(|e| set(&e))?)
    .with_inclusion_promise(InclusionPromise::new(
        SignedTimestamp::from_base64(&logged.signed_entry_timestamp).map_err(|e| set(&e))?,
    )))
}

fn invalid(what: &str, error: &dyn std::error::Error) -> Failure {
    Failure::Invalid(format!("{what}: {}", chain(error)))
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    /// The recorded `.sig` of the `legacy-sig` case, its payload, and the image it signs.
    const MANIFEST: &str = include_str!(
        "../../../fixtures/sigstore/layouts/legacy-sig/blobs/sha256/9390ade129eb1c390b04bacebdd1a7edef608b1d3717d7421ee6b89a5a7f0e73"
    );
    const PAYLOAD: &[u8] = include_bytes!(
        "../../../fixtures/sigstore/layouts/legacy-sig/blobs/sha256/1e6dcfc6a19dcd80fe62b428bbf4bb10ad08e7319401e20792d59f88163193bd"
    );
    const IMAGE: &str = "sha256:167b7290fd4fd86b9040b699e97cd3471b960281d4158e3bd655df2f68e0eb73";

    fn root() -> TrustRoot {
        TrustRoot::parse(include_bytes!(
            "../../../fixtures/sigstore/trusted_root.json"
        ))
        .expect("the recorded trusted root parses")
    }

    /// [`MANIFEST`] with `annotation` of its layer set to `value`.
    fn annotated(annotation: &str, value: &str) -> Vec<u8> {
        let mut manifest: Value = serde_json::from_str(MANIFEST).expect("the manifest is JSON");
        manifest["layers"][0]["annotations"][annotation] = Value::from(value);
        manifest.to_string().into_bytes()
    }

    fn check(manifest: &[u8], layer: usize, payload: &[u8]) -> SignatureResult {
        let image = Digest::parse(IMAGE).expect("a digest");
        verify(&root(), &image, manifest, layer, payload, None)
    }

    #[test]
    fn a_layer_without_a_certificate_was_signed_by_a_key() {
        assert_eq!(
            check(&annotated(CERTIFICATE, ""), 0, PAYLOAD),
            Err(Failure::Mismatch(crate::signature::Signed::Key))
        );
    }

    #[test]
    fn a_layer_without_a_signature_names_the_missing_annotation() {
        assert_eq!(
            check(&annotated(SIGNATURE, ""), 0, PAYLOAD),
            Err(Failure::Invalid(format!(
                "the .sig has no signature (annotation {SIGNATURE})"
            )))
        );
    }

    #[test]
    fn a_missing_layer_is_named() {
        assert_eq!(
            check(MANIFEST.as_bytes(), 1, PAYLOAD),
            Err(Failure::Invalid("the .sig has no layer 1".to_owned()))
        );
    }

    #[test]
    fn a_payload_naming_no_image_is_invalid() {
        let Err(Failure::Invalid(reason)) = check(MANIFEST.as_bytes(), 0, b"{}") else {
            panic!("a payload without `critical` is invalid");
        };
        assert!(
            reason.starts_with("its simple signing payload: "),
            "{reason}"
        );
    }
}
