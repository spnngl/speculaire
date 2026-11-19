//! The in-toto statement a Sigstore bundle's DSSE envelope signs (D43, D149): its type and its raw predicate.
//!
//! Its subjects are sigstore-verify's to bind to the image (`crates/sigstore-verify/src/artifact.rs:50-101` at
//! sigstore-verify-v0.16.0), so they are skipped here.

use std::borrow::Cow;

use serde::Deserialize;
use serde_json::value::RawValue;
use sigstore_verify::types::Bundle;
use sigstore_verify::types::bundle::SignatureContent;

/// The DSSE payload type of an in-toto statement.
const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// The statement versions read: v1, as GitHub's `actions/attest` and cosign v3 write, and v0.1, as cosign v2 does.
const TYPES: [&str; 2] = [
    "https://in-toto.io/Statement/v1",
    "https://in-toto.io/Statement/v0.1",
];

/// An in-toto statement, borrowed from its DSSE payload.
#[derive(Debug, Deserialize)]
pub struct Statement<'a> {
    #[serde(rename = "_type", borrow)]
    kind: Cow<'a, str>,
    #[serde(rename = "predicateType", borrow)]
    predicate_type: Cow<'a, str>,
    /// Absent is an empty predicate, as in-toto v1 allows.
    #[serde(borrow, default)]
    predicate: Option<&'a RawValue>,
}

/// Why a payload is no in-toto statement.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The bundle signs a message digest, not a DSSE envelope.
    #[error("the bundle holds no DSSE envelope")]
    NotDsse,
    /// The envelope's payload type is another than in-toto's.
    #[error("the DSSE payload type is {0}, not {PAYLOAD_TYPE}")]
    PayloadType(String),
    /// The payload is not a statement's JSON.
    #[error("not an in-toto statement: {0}")]
    Json(String),
    /// The statement's `_type` is no version read.
    #[error("in-toto statement type {0} is not read")]
    Kind(String),
}

impl<'a> Statement<'a> {
    /// The statement `bundle` signs. It is the signer's claim only once the bundle verifies.
    ///
    /// # Errors
    ///
    /// When `bundle` holds no DSSE envelope of an in-toto statement, or its payload does not parse as one.
    pub fn of(bundle: &'a Bundle) -> Result<Self, Error> {
        let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
            return Err(Error::NotDsse);
        };
        if envelope.payload_type != PAYLOAD_TYPE {
            return Err(Error::PayloadType(envelope.payload_type.clone()));
        }
        Self::parse(envelope.payload.as_bytes())
    }

    /// Parses `payload`, a DSSE envelope's payload, as an in-toto statement.
    ///
    /// # Errors
    ///
    /// When it is not a statement's JSON, or its `_type` is no version read.
    pub fn parse(payload: &'a [u8]) -> Result<Self, Error> {
        let statement: Self =
            serde_json::from_slice(payload).map_err(|e| Error::Json(e.to_string()))?;
        if !TYPES.contains(&statement.kind.as_ref()) {
            return Err(Error::Kind(statement.kind.into_owned()));
        }
        Ok(statement)
    }

    /// What the statement attests, such as `https://slsa.dev/provenance/v1`.
    #[must_use]
    pub fn predicate_type(&self) -> &str {
        &self.predicate_type
    }

    /// The predicate's JSON, unparsed; `None` when the statement has none.
    #[must_use]
    pub fn predicate(&self) -> Option<&'a str> {
        self.predicate.map(RawValue::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recorded bundle: the cosign v3 signature of the `keyless` case.
    const BUNDLE: &str = include_str!("../../../fuzz/seeds/bundle/keyless.json");

    #[test]
    fn a_bundle_signs_the_statement_of_its_envelope() {
        let bundle = Bundle::from_json(BUNDLE).expect("the recorded bundle parses");

        let statement = Statement::of(&bundle).expect("a DSSE envelope of a statement");

        assert_eq!(
            statement.predicate_type(),
            "https://sigstore.dev/cosign/sign/v1"
        );
    }

    #[test]
    fn a_bundle_over_a_message_digest_signs_no_statement() {
        let mut json: serde_json::Value =
            serde_json::from_str(BUNDLE).expect("the recorded bundle is JSON");
        let object = json.as_object_mut().expect("a bundle is an object");
        object.remove("dsseEnvelope");
        object.insert(
            "messageSignature".to_owned(),
            serde_json::json!({
                "messageDigest": {"algorithm": "SHA2_256", "digest": "AAAA"},
                "signature": "AAAA",
            }),
        );
        let bundle = Bundle::from_json(&json.to_string()).expect("a message signature bundle");

        assert_eq!(
            Statement::of(&bundle).expect_err("no envelope"),
            Error::NotDsse
        );
    }

    #[test]
    fn a_bundle_of_another_payload_type_signs_no_statement() {
        let text = BUNDLE.replace(PAYLOAD_TYPE, "text/plain");
        let bundle = Bundle::from_json(&text).expect("the edited bundle parses");

        assert_eq!(
            Statement::of(&bundle)
                .expect_err("another payload type")
                .to_string(),
            "the DSSE payload type is text/plain, not application/vnd.in-toto+json"
        );
    }

    #[test]
    fn a_statement_keeps_its_predicate_type_and_raw_predicate() {
        let payload = br#"{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https:\/\/slsa.dev/provenance/v1","predicate":{"a": [1, 2]}}"#;

        let statement = Statement::parse(payload).expect("a v1 statement");

        assert_eq!(statement.predicate_type(), "https://slsa.dev/provenance/v1");
        assert_eq!(statement.predicate(), Some(r#"{"a": [1, 2]}"#));
    }

    #[test]
    fn a_statement_of_version_0_1_without_a_predicate_parses() {
        let payload = br#"{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"t"}"#;

        let statement = Statement::parse(payload).expect("a v0.1 statement");

        assert_eq!(statement.predicate(), None);
    }

    #[test]
    fn another_type_or_no_predicate_type_is_no_statement() {
        assert_eq!(
            Statement::parse(br#"{"_type":"https://in-toto.io/Statement/v2","predicateType":"t"}"#)
                .expect_err("an unknown version")
                .to_string(),
            "in-toto statement type https://in-toto.io/Statement/v2 is not read"
        );
        assert!(matches!(
            Statement::parse(br#"{"_type":"https://in-toto.io/Statement/v1"}"#),
            Err(Error::Json(_))
        ));
    }
}
