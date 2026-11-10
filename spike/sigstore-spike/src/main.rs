//! Spike 06: offline verification of a GitHub `attest-build-provenance` bundle.
//!
//! `sigstore-spike verify <artifact> <bundle> <trusted_root.json> <san-regex> <issuer>`
//! Exit codes: 0 verified, 2 usage or input, 10 cryptographic verification, 11 predicate type,
//! 12 SAN does not match the regex, 13 issuer does not match.

use std::fs::{self, File};
use std::process::ExitCode;

use regex::Regex;
use sigstore_trust_root::TrustedRoot;
use sigstore_types::intoto::Statement;
use sigstore_types::{Bundle, SignatureContent};
use sigstore_verify::{VerificationPolicy, Verifier};

const SLSA_V1: &str = "https://slsa.dev/provenance/v1";

fn fail(code: u8, what: &str, detail: impl std::fmt::Display) -> ExitCode {
    eprintln!("{what}: {detail}");
    ExitCode::from(code)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, cmd, artifact, bundle, root, san, issuer] = args.as_slice() else {
        return fail(2, "usage", "sigstore-spike verify <artifact> <bundle> <trusted_root.json> <san-regex> <issuer>");
    };
    if cmd != "verify" {
        return fail(2, "usage", "only `verify`");
    }
    let regex = match Regex::new(san) {
        Ok(r) => r,
        Err(e) => return fail(2, "san regex", e),
    };
    let bundle = match fs::read_to_string(bundle).map_err(|e| e.to_string()).and_then(|j| Bundle::from_json(&j).map_err(|e| e.to_string())) {
        Ok(b) => b,
        Err(e) => return fail(2, "bundle", e),
    };
    let root = match fs::read_to_string(root).map_err(|e| e.to_string()).and_then(|j| TrustedRoot::from_json(&j).map_err(|e| e.to_string())) {
        Ok(r) => r,
        Err(e) => return fail(2, "trusted root", e),
    };
    let file = match File::open(artifact) {
        Ok(f) => f,
        Err(e) => return fail(2, "artifact", e),
    };
    let verifier = match Verifier::new(&root) {
        Ok(v) => v,
        Err(e) => return fail(2, "trusted root", e),
    };
    // The issuer is part of the policy; the SAN is matched by regex afterwards, as speculaire's policy does.
    let policy = VerificationPolicy::any_identity().require_issuer(issuer);
    let result = match verifier.verify_reader(file, &bundle, &policy) {
        Ok(r) => r,
        Err(e) => {
            let code = if e.to_string().to_lowercase().contains("issuer") { 13 } else { 10 };
            return fail(code, "verification failed", e);
        }
    };
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return fail(11, "predicate", "bundle is not a DSSE envelope");
    };
    let statement: Statement = match serde_json::from_slice(envelope.payload.as_bytes()) {
        Ok(s) => s,
        Err(e) => return fail(11, "predicate", e),
    };
    if statement.predicate_type != SLSA_V1 {
        return fail(11, "predicate", format!("{} is not {SLSA_V1}", statement.predicate_type));
    }
    let Some(identity) = result.identity() else {
        return fail(12, "identity", "certificate has no SAN");
    };
    if !regex.is_match(identity.as_str()) {
        return fail(12, "identity", format!("{} does not match {san}", identity.as_str()));
    }
    println!("verified: san={} issuer={} predicate={} tlog={} cert={}", identity.as_str(), result.issuer().unwrap_or_default(), statement.predicate_type, result.tlog_verified(), result.certificate_verified());
    ExitCode::SUCCESS
}
