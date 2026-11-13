//! Arbitrary bytes as any message the reflector reads must never panic, and what parses must encode back to itself.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::reflect(data));
