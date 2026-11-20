//! Arbitrary bytes as the trunk of an NRI socket must never panic, and each connection must read its frames' payloads.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::nri_mux(data));
