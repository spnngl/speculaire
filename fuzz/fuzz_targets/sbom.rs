//! Arbitrary bytes as an SBOM must never panic, and an SBOM counts the same packages in compact JSON.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::sbom(data));
