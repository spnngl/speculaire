//! Arbitrary bytes as frames of a connection to the reflector must never panic, and a message read must write back.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::reflect_frame(data));
