//! A token endpoint's answer must never panic when read.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| speculaire_fuzz::token_answer(data));
