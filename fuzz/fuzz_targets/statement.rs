//! Arbitrary bytes as the DSSE payload of a Sigstore bundle must never panic, and a statement that parses must parse
//! back from its parts.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::statement(data));
