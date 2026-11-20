//! Arbitrary bytes as NRI's plugin connection must never panic, and each request read must round-trip.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::nri_request(data));
