//! The response of CRI-O's inspect API to GET /config must never panic, and its settings are those of its body.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::crio_inspect(data));
