//! The head of a peer's answer to a fetch must never panic when read.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::peer_response(data));
