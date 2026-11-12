//! Arbitrary bytes as a platform specifier must never panic, and a platform that parses must normalize to itself.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::platform(data));
