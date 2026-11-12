//! Arbitrary bytes as a CRI-O credential file must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::auth_json(data));
