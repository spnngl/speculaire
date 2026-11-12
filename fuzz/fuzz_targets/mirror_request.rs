//! A request path and a Range header, as a client sends them, must never panic, and a range must lie in the body.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::mirror_request(data));
