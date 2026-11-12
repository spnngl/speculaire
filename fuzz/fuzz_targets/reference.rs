//! Arbitrary bytes as an image reference must never panic, and a reference that parses must be a fixed point of the parser.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::reference(data));
