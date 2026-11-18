//! Arbitrary bytes as the policy file must never panic, and a file that parses must hold its invariants.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::policy(data));
