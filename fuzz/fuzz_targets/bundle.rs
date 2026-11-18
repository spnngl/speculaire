//! Arbitrary bytes as a Sigstore bundle from the artifact store must never panic, and a bundle that verifies must verify
//! the same again.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::bundle(data));
