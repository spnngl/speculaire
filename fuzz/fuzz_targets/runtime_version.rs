//! The version a runtime reports must never panic when read, and a release prints as it parses.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::runtime_version(data));
