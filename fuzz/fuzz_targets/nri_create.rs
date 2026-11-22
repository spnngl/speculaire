//! Arbitrary bytes as a `CreateContainerRequest` must never panic, and read as prost decodes them.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::nri_create(data));
