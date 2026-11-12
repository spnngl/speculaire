//! The challenge of a registry's 401 must never panic when read.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::www_authenticate(data));
