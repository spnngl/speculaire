//! Arbitrary bytes as a legacy `.sig` layer's payload or manifest must never panic, and a layer that verifies must
//! verify the same again.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::simplesigning(data));
