//! Reading the answer of CRI-O's inspect API to GET /config, then the settings in its body, must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::crio_inspect(data));
