//! Arbitrary bytes as a duration must never panic, and a duration read must print as text that reads back to it.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::duration(data));
